//! Action source selection and fetch for `audit`.
//!
//! Chooses which files of a referenced action are worth scanning (remote
//! actions via the GitHub trees API, local `uses: ./...` actions from disk),
//! fetches them, and routes each file to the matching content scanner in
//! `audit`. Remote action source is untrusted input: it is scanned, never
//! executed.

use anyhow::{Context, Result};
use serde_norway::Value;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::audit::{
    AuditCollector, collect_step_run_blocks, scan_dockerfile_content, scan_js_content,
    scan_py_content, scan_shell_content,
};
use crate::config::Config;
use crate::github::GitHubClient;
use crate::workflow::{self, ActionRef, LocalActionRef};

pub(crate) fn remote_action_scan_key(action: &ActionRef) -> String {
    format!("{}@{}", action.full_name(), action.ref_string)
}

/// Third-party dependency dirs, not the action's own source. An action that
/// commits `node_modules/` would otherwise cost thousands of per-file fetches
/// for zero signal. `dist/` is excluded — a bundled `dist/index.js` is the
/// code that actually runs and must still be scanned.
const VENDORED_DIRS: &[&str] = &["node_modules", "site-packages", ".venv", "venv"];

/// Matches whole path components, so `node_modules_helper.js` is not affected.
fn is_vendored_path(path: &str) -> bool {
    path.split('/')
        .any(|component| VENDORED_DIRS.contains(&component))
}

/// Max action source files fetched concurrently. Bounds the fan-out so a
/// file-heavy action doesn't burst into a rate-limit-exhausting wave.
const MAX_CONCURRENT_FILE_FETCHES: usize = 8;

/// Which scanner handles a given action source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceFileKind {
    ActionYml,
    JavaScript,
    Python,
    Dockerfile,
}

/// Whether all selected action source files were fetched and parsed well
/// enough to support a durable "clean" verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionScanStatus {
    Complete,
    Incomplete,
}

impl ActionScanStatus {
    fn from_complete(complete: bool) -> Self {
        if complete {
            Self::Complete
        } else {
            Self::Incomplete
        }
    }
}

/// Select the files in a fetched action tree worth scanning, each paired with
/// its scanner, in tree order. Pure (no I/O) so the filtering is unit testable.
fn select_source_files(
    tree: &[crate::github::TreeEntry],
    base: &str,
) -> Vec<(String, SourceFileKind)> {
    let mut targets = Vec::new();
    for entry in tree {
        if entry.entry_type != "blob" {
            continue;
        }
        let path = &entry.path;
        if is_vendored_path(path) {
            continue;
        }
        if !base.is_empty() && path != base && !path.starts_with(&format!("{base}/")) {
            continue;
        }
        let relative = if base.is_empty() {
            path.as_str()
        } else {
            path.strip_prefix(base)
                .unwrap_or(path)
                .trim_start_matches('/')
        };
        let filename = path.rsplit('/').next().unwrap_or(path);
        let whole_repo = base.is_empty();
        let kind = if relative == "action.yml"
            || relative == "action.yaml"
            || whole_repo && matches!(filename, "action.yml" | "action.yaml")
        {
            SourceFileKind::ActionYml
        } else if is_javascript_source(path) {
            SourceFileKind::JavaScript
        } else if path.ends_with(".py") {
            SourceFileKind::Python
        } else if relative == "Dockerfile"
            || whole_repo && filename == "Dockerfile"
            || path.ends_with(".dockerfile")
        {
            SourceFileKind::Dockerfile
        } else {
            continue;
        };
        targets.push((path.clone(), kind));
    }
    targets
}

fn force_include_remote_action_entrypoints(
    targets: &mut Vec<(String, SourceFileKind)>,
    contents: &[Option<Result<String>>],
) {
    let metadata: Vec<(String, String)> = targets
        .iter()
        .zip(contents)
        .filter_map(|((path, kind), content)| {
            if *kind != SourceFileKind::ActionYml {
                return None;
            }
            let Some(Ok(content)) = content.as_ref() else {
                return None;
            };
            Some((path.clone(), content.clone()))
        })
        .collect();

    for (path, content) in metadata {
        let Ok(yaml) = serde_norway::from_str::<Value>(&content) else {
            continue;
        };
        let base = path.rsplit_once('/').map_or("", |(base, _)| base);
        for entrypoint in action_yml_entrypoint_paths(&yaml, base) {
            push_unique_source_target(targets, entrypoint, SourceFileKind::JavaScript);
        }
    }
}

fn force_include_local_action_entrypoints(
    action_dir: &Path,
    targets: &mut Vec<(PathBuf, SourceFileKind)>,
) {
    let metadata_paths: Vec<PathBuf> = targets
        .iter()
        .filter_map(|(path, kind)| (*kind == SourceFileKind::ActionYml).then_some(path.clone()))
        .collect();

    for path in metadata_paths {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(yaml) = serde_norway::from_str::<Value>(&content) else {
            continue;
        };
        for entrypoint in action_yml_entrypoint_paths(&yaml, "") {
            let path = action_dir.join(&entrypoint);
            if local_entrypoint_is_regular_file(&path) {
                push_unique_local_source_target(targets, path, SourceFileKind::JavaScript);
            }
        }
    }
}

fn action_yml_entrypoint_paths(yaml: &Value, base: &str) -> Vec<String> {
    let Some(runs) = yaml.get("runs").and_then(|r| r.as_mapping()) else {
        return Vec::new();
    };

    ["main", "pre", "post"]
        .into_iter()
        .filter_map(|key| runs.get(key).and_then(|v| v.as_str()))
        .filter_map(|path| normalize_action_entrypoint_path(base, path))
        .collect()
}

fn normalize_action_entrypoint_path(base: &str, path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || path.contains('\\') {
        return None;
    }
    let rel = Path::new(path);
    if rel.is_absolute() {
        return None;
    }

    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?.to_string()),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if parts.is_empty() {
        return None;
    }

    let rel = parts.join("/");
    if base.is_empty() {
        Some(rel)
    } else {
        Some(format!("{base}/{rel}"))
    }
}

fn push_unique_source_target(
    targets: &mut Vec<(String, SourceFileKind)>,
    path: String,
    kind: SourceFileKind,
) {
    if !targets.iter().any(|(existing, _)| existing == &path) {
        targets.push((path, kind));
    }
}

fn push_unique_local_source_target(
    targets: &mut Vec<(PathBuf, SourceFileKind)>,
    path: PathBuf,
    kind: SourceFileKind,
) {
    if !targets.iter().any(|(existing, _)| existing == &path) {
        targets.push((path, kind));
    }
}

fn local_entrypoint_is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or_default()
}

async fn fetch_remote_source_files(
    client: &GitHubClient,
    action: &ActionRef,
    targets: &[(String, SourceFileKind)],
) -> (Vec<Option<Result<String>>>, bool) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_FILE_FETCHES));
    let mut fetches = tokio::task::JoinSet::new();
    for (index, (path, _)) in targets.iter().enumerate() {
        let client = client.clone();
        let owner = action.owner.clone();
        let repo = action.repo.clone();
        let git_ref = action.ref_string.clone();
        let path = path.clone();
        let semaphore = Arc::clone(&semaphore);
        fetches.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            let content = client.fetch_file(&owner, &repo, &path, &git_ref).await;
            (index, content)
        });
    }

    let mut contents: Vec<Option<Result<String>>> = (0..targets.len()).map(|_| None).collect();
    let mut complete = true;
    while let Some(joined) = fetches.join_next().await {
        match joined {
            Ok((index, content)) => {
                if content.is_err() {
                    complete = false;
                }
                contents[index] = Some(content);
            }
            Err(_) => {
                complete = false;
            }
        }
    }

    (contents, complete)
}

fn collect_local_source_files(action_dir: &Path) -> Result<Vec<(PathBuf, SourceFileKind)>> {
    fn visit(dir: &Path, base: &Path, targets: &mut Vec<(PathBuf, SourceFileKind)>) -> Result<()> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            entries.push(entry?);
        }
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");

            if is_vendored_path(&relative) {
                continue;
            }

            // `file_type()` does not follow symlinks, so a symlinked entry is
            // neither file nor dir here and is skipped. Deliberate: it keeps
            // traversal inside the action directory (a symlink can't redirect
            // the scan outside it) at the cost of not scanning symlinked source
            // — an acceptable trade-off since local actions are first-party.
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                visit(&path, base, targets)?;
            } else if file_type.is_file()
                && let Some(kind) = source_file_kind(&relative)
            {
                targets.push((path, kind));
            }
        }
        Ok(())
    }

    let mut targets = Vec::new();
    visit(action_dir, action_dir, &mut targets)?;
    Ok(targets)
}

fn source_file_kind(relative: &str) -> Option<SourceFileKind> {
    if relative == "action.yml" || relative == "action.yaml" {
        Some(SourceFileKind::ActionYml)
    } else if is_javascript_source(relative) {
        Some(SourceFileKind::JavaScript)
    } else if relative.ends_with(".py") {
        Some(SourceFileKind::Python)
    } else if relative == "Dockerfile" || relative.ends_with(".dockerfile") {
        Some(SourceFileKind::Dockerfile)
    } else {
        None
    }
}

fn is_javascript_source(path: &str) -> bool {
    path.ends_with(".js")
        || path.ends_with(".ts")
        || path.ends_with(".mjs")
        || path.ends_with(".cjs")
}

fn local_action_dir(repo_root: &Path, action: &LocalActionRef) -> Result<PathBuf> {
    let Some(rel) = action.path.strip_prefix("./") else {
        anyhow::bail!("local action path must start with ./");
    };
    let rel_path = Path::new(rel);
    if rel.is_empty()
        || !rel_path
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        anyhow::bail!("local action path escapes the repository");
    }

    let action_dir = repo_root.join(rel);
    if workflow::open_child_dir_path(repo_root, rel_path)?.is_none() {
        anyhow::bail!("{} is not a directory", action_dir.display());
    }
    Ok(action_dir)
}

pub(crate) fn scan_local_action_source(
    repo_root: &Path,
    action: &LocalActionRef,
    collector: &mut AuditCollector,
    config: &Config,
) -> Result<ActionScanStatus> {
    let action_dir = local_action_dir(repo_root, action)?;
    let mut targets = collect_local_source_files(&action_dir)?;
    force_include_local_action_entrypoints(&action_dir, &mut targets);
    if targets.is_empty() {
        return Ok(ActionScanStatus::Complete);
    }

    let mut complete = true;
    for (path, kind) in targets {
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        let relative = path
            .strip_prefix(&action_dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let source_label = format!("{} ({relative})", action.path);
        match kind {
            SourceFileKind::ActionYml => match serde_norway::from_str::<Value>(&content) {
                Ok(yaml) => {
                    scan_action_yml_runs(&yaml, &source_label, &action.path, collector, config);
                }
                Err(_) => {
                    complete = false;
                }
            },
            SourceFileKind::JavaScript => {
                scan_js_content(&content, &source_label, &action.path, collector, config);
            }
            SourceFileKind::Python => {
                scan_py_content(&content, &source_label, &action.path, collector, config);
            }
            SourceFileKind::Dockerfile => {
                scan_dockerfile_content(&content, &source_label, &action.path, collector, config);
            }
        }
    }

    Ok(ActionScanStatus::from_complete(complete))
}

pub(crate) async fn scan_action_source(
    client: &GitHubClient,
    action: &ActionRef,
    collector: &mut AuditCollector,
    config: &Config,
) -> Result<ActionScanStatus> {
    let action_name = format!("{}@{}", action.full_name(), short_sha(&action.ref_string));
    let tree = client
        .fetch_tree(&action.owner, &action.repo, &action.ref_string)
        .await?;

    let base = action.subpath.as_deref().unwrap_or("");
    let mut targets = select_source_files(&tree, base);
    if targets.is_empty() {
        return Ok(ActionScanStatus::Complete);
    }

    // Fetch concurrently, then scan in tree order so findings are
    // deterministic regardless of which fetch lands first. A failed fetch
    // makes the scan incomplete, so the caller will not cache a clean verdict.
    let (mut contents, mut complete) = fetch_remote_source_files(client, action, &targets).await;
    let initial_len = targets.len();
    force_include_remote_action_entrypoints(&mut targets, &contents);
    if targets.len() > initial_len {
        let (new_contents, new_complete) =
            fetch_remote_source_files(client, action, &targets[initial_len..]).await;
        contents.extend(new_contents);
        complete &= new_complete;
    }

    for ((path, kind), content) in targets.iter().zip(contents) {
        let content = match content {
            Some(Ok(content)) => content,
            _ => continue,
        };
        let source_label = format!("{} ({path})", action.full_name());
        match kind {
            SourceFileKind::ActionYml => match serde_norway::from_str::<Value>(&content) {
                Ok(yaml) => {
                    scan_action_yml_runs(&yaml, &source_label, &action_name, collector, config);
                }
                Err(_) => {
                    complete = false;
                }
            },
            SourceFileKind::JavaScript => {
                scan_js_content(&content, &source_label, &action_name, collector, config);
            }
            SourceFileKind::Python => {
                scan_py_content(&content, &source_label, &action_name, collector, config);
            }
            SourceFileKind::Dockerfile => {
                scan_dockerfile_content(&content, &source_label, &action_name, collector, config);
            }
        }
    }

    Ok(ActionScanStatus::from_complete(complete))
}

fn scan_action_yml_runs(
    yaml: &Value,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    // runs.steps[].run (composite actions), including nested parallel groups.
    // base_line 0: positions are block-relative — the block is never located
    // inside the fetched file.
    if let Some(steps) = yaml.get("runs").and_then(|r| r.get("steps")) {
        for run in collect_step_run_blocks(steps) {
            scan_shell_content(run, source_file, 0, action_name, collector, config);
        }
    }

    // runs.args (some actions use shell: bash with inline scripts)
    if let Some(args) = yaml.get("runs").and_then(|r| r.get("args")) {
        if let Some(args) = args.as_str() {
            scan_shell_content(args, source_file, 0, action_name, collector, config);
        } else if let Some(args) = args.as_sequence() {
            for arg in args {
                if let Some(arg) = arg.as_str() {
                    scan_shell_content(arg, source_file, 0, action_name, collector, config);
                }
            }
        }
    }
}

pub(crate) fn short_sha(sha: &str) -> &str {
    if sha.len() >= 7 { &sha[..7] } else { sha }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static DEFAULT_CONFIG: LazyLock<Config> = LazyLock::new(Config::default);

    #[test]
    fn scan_action_yml_composite_steps() {
        let yaml: serde_norway::Value = serde_norway::from_str(
            r#"
runs:
  using: composite
  steps:
    - run: curl -L https://example.com/install.sh -o install.sh
"#,
        )
        .unwrap();
        let mut c = AuditCollector::new(false);
        scan_action_yml_runs(&yaml, "action.yml", "test-action", &mut c, &DEFAULT_CONFIG);
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn scan_action_yml_composite_parallel_steps() {
        let yaml: serde_norway::Value = serde_norway::from_str(
            r#"
runs:
  using: composite
  steps:
    - parallel:
        - run: curl https://example.com/install.sh | sh
"#,
        )
        .unwrap();
        let mut c = AuditCollector::new(false);
        scan_action_yml_runs(&yaml, "action.yml", "test-action", &mut c, &DEFAULT_CONFIG);
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    #[test]
    fn scan_action_yml_args() {
        let yaml: serde_norway::Value = serde_norway::from_str(
            r#"
runs:
  using: node20
  args: |
    curl -L https://example.com/install.sh -o install.sh
"#,
        )
        .unwrap();
        let mut c = AuditCollector::new(false);
        scan_action_yml_runs(&yaml, "action.yml", "test-action", &mut c, &DEFAULT_CONFIG);
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn scan_action_yml_sequence_args() {
        let yaml: serde_norway::Value = serde_norway::from_str(
            r#"
runs:
  using: node20
  args:
    - --flag
    - curl -L https://example.com/install.sh -o install.sh
"#,
        )
        .unwrap();
        let mut c = AuditCollector::new(false);
        scan_action_yml_runs(&yaml, "action.yml", "test-action", &mut c, &DEFAULT_CONFIG);
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn scan_action_yml_no_runs_key() {
        let yaml: serde_norway::Value = serde_norway::from_str("name: test\n").unwrap();
        let mut c = AuditCollector::new(false);
        scan_action_yml_runs(&yaml, "action.yml", "test-action", &mut c, &DEFAULT_CONFIG);
        assert!(c.findings.is_empty());
    }

    #[test]
    fn short_sha_full() {
        assert_eq!(
            short_sha("abcdef1234567890abcdef1234567890abcdef12"),
            "abcdef1"
        );
    }

    #[test]
    fn short_sha_short() {
        assert_eq!(short_sha("abc"), "abc");
    }

    #[test]
    fn remote_action_scan_key_includes_subpath() {
        let mut first = ActionRef {
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            subpath: Some("a".to_string()),
            ref_string: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
            ref_type: workflow::RefType::Sha,
            tag_comment: None,
            line_number: 1,
            raw_line: String::new(),
        };
        let mut second = first.clone();
        second.subpath = Some("b".to_string());

        assert_ne!(
            remote_action_scan_key(&first),
            remote_action_scan_key(&second)
        );
        first.subpath = None;
        assert_ne!(
            remote_action_scan_key(&first),
            remote_action_scan_key(&second)
        );
    }

    // ── vendored-path filtering ────────────────────────────────────────

    #[test]
    fn vendored_path_skips_dependency_dirs() {
        assert!(is_vendored_path("node_modules/lodash/index.js"));
        assert!(is_vendored_path("dist/node_modules/x.js")); // nested
        assert!(is_vendored_path(
            ".venv/lib/python3.12/site-packages/requests/api.py"
        ));
        assert!(is_vendored_path("venv/bin/thing.py"));
        assert!(is_vendored_path("tools/site-packages/pkg.py"));
    }

    #[test]
    fn vendored_path_keeps_action_code() {
        // The action's own bundled/source files must still be scanned.
        assert!(!is_vendored_path("dist/index.js"));
        assert!(!is_vendored_path("src/main.ts"));
        assert!(!is_vendored_path("action.yml"));
        assert!(!is_vendored_path("scripts/setup.py"));
    }

    #[test]
    fn vendored_path_matches_whole_components_only() {
        // Substrings and lookalike names must not be skipped.
        assert!(!is_vendored_path("node_modules_helper.js"));
        assert!(!is_vendored_path("my_vendor/index.js"));
        assert!(!is_vendored_path("src/venvironment.py"));
    }

    // ── select_source_files ────────────────────────────────────────────

    fn tree_entry(path: &str, entry_type: &str) -> crate::github::TreeEntry {
        crate::github::TreeEntry {
            path: path.into(),
            entry_type: entry_type.into(),
        }
    }

    #[test]
    fn action_yml_entrypoint_paths_stay_in_action_subpath() {
        let yaml: serde_norway::Value = serde_norway::from_str(
            r#"
runs:
  using: node20
  pre: ./preload
  main: dist/runner
  post: ../outside
"#,
        )
        .unwrap();

        assert_eq!(
            action_yml_entrypoint_paths(&yaml, "actions/sub"),
            vec![
                "actions/sub/dist/runner".to_string(),
                "actions/sub/preload".to_string()
            ]
        );
        assert!(normalize_action_entrypoint_path("", "/tmp/runner").is_none());
        assert!(normalize_action_entrypoint_path("", r"dist\\runner").is_none());
    }

    #[test]
    fn select_source_files_classifies_and_filters_in_order() {
        let tree = vec![
            tree_entry("action.yml", "blob"),
            tree_entry("sub/action.yaml", "blob"),
            tree_entry("dist/index.js", "blob"), // bundled action code — kept
            tree_entry("dist/index.mjs", "blob"),
            tree_entry("src/main.cjs", "blob"),
            tree_entry("src/main.ts", "blob"),
            tree_entry("setup.py", "blob"),
            tree_entry("Dockerfile", "blob"),
            tree_entry("sub/Dockerfile", "blob"),
            tree_entry("README.md", "blob"), // not scannable
            tree_entry("node_modules/dep/i.js", "blob"), // vendored — skipped
            tree_entry("src", "tree"),       // directory entry — skipped
        ];
        let got = select_source_files(&tree, "");
        assert_eq!(
            got,
            vec![
                ("action.yml".to_string(), SourceFileKind::ActionYml),
                ("sub/action.yaml".to_string(), SourceFileKind::ActionYml),
                ("dist/index.js".to_string(), SourceFileKind::JavaScript),
                ("dist/index.mjs".to_string(), SourceFileKind::JavaScript),
                ("src/main.cjs".to_string(), SourceFileKind::JavaScript),
                ("src/main.ts".to_string(), SourceFileKind::JavaScript),
                ("setup.py".to_string(), SourceFileKind::Python),
                ("Dockerfile".to_string(), SourceFileKind::Dockerfile),
                ("sub/Dockerfile".to_string(), SourceFileKind::Dockerfile),
            ]
        );
    }

    #[test]
    fn select_source_files_scopes_to_subpath_base() {
        let tree = vec![
            tree_entry("action-a/action.yml", "blob"),
            tree_entry("action-a/index.js", "blob"),
            tree_entry("action-b/action.yml", "blob"), // different subpath — excluded
        ];
        let got = select_source_files(&tree, "action-a");
        assert_eq!(
            got,
            vec![
                ("action-a/action.yml".to_string(), SourceFileKind::ActionYml),
                ("action-a/index.js".to_string(), SourceFileKind::JavaScript),
            ]
        );
    }

    #[test]
    fn select_source_files_subpath_base_requires_path_boundary() {
        let tree = vec![
            tree_entry("action-a/action.yml", "blob"),
            tree_entry("action-a/index.js", "blob"),
            tree_entry("action-abcd/action.yml", "blob"),
            tree_entry("action-abcd/index.js", "blob"),
        ];
        let got = select_source_files(&tree, "action-a");
        assert_eq!(
            got,
            vec![
                ("action-a/action.yml".to_string(), SourceFileKind::ActionYml),
                ("action-a/index.js".to_string(), SourceFileKind::JavaScript),
            ]
        );
    }

    #[test]
    fn select_source_files_empty_when_nothing_scannable() {
        let tree = vec![
            tree_entry("README.md", "blob"),
            tree_entry("LICENSE", "blob"),
            tree_entry("node_modules/x/index.js", "blob"),
        ];
        assert!(select_source_files(&tree, "").is_empty());
    }

    #[test]
    fn collect_local_source_files_filters_vendored_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join(".github/actions/local");
        std::fs::create_dir_all(action_dir.join("node_modules/dep")).unwrap();
        std::fs::create_dir_all(action_dir.join("dist")).unwrap();
        std::fs::create_dir_all(action_dir.join("src")).unwrap();
        std::fs::write(action_dir.join("action.yml"), "name: local\n").unwrap();
        std::fs::write(
            action_dir.join("dist/helper.mjs"),
            "fetch('https://example.com/x')",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("dist/index.js"),
            "fetch('https://example.com/x')",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("src/main.cjs"),
            "fetch('https://example.com/x')",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("node_modules/dep/index.js"),
            "fetch('https://evil.example/x')",
        )
        .unwrap();

        let got = collect_local_source_files(&action_dir).unwrap();
        let paths: Vec<_> = got
            .iter()
            .map(|(path, _)| {
                path.strip_prefix(&action_dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            paths,
            vec![
                "action.yml",
                "dist/helper.mjs",
                "dist/index.js",
                "src/main.cjs"
            ]
        );
    }

    #[test]
    fn scan_local_action_source_finds_composite_fetches() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join(".github/actions/local");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            r#"
runs:
  using: composite
  steps:
    - run: curl -fsSL https://example.com/install.sh | bash
"#,
        )
        .unwrap();

        let action = LocalActionRef {
            path: "./.github/actions/local".to_string(),
            line_number: 12,
        };
        let mut collector = AuditCollector::new(false);
        let status =
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap();
        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(collector.findings.len(), 1);
        assert!(collector.findings[0].description.contains("piped to shell"));
        assert_eq!(
            collector.findings[0].source_file,
            "./.github/actions/local (action.yml)"
        );
    }

    #[test]
    fn scan_local_action_source_includes_metadata_entrypoint() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join(".github/actions/local");
        std::fs::create_dir_all(action_dir.join("dist")).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            r#"
runs:
  using: node20
  main: dist/runner
"#,
        )
        .unwrap();
        std::fs::write(
            action_dir.join("dist/runner"),
            r#"fetch("https://example.com/install")"#,
        )
        .unwrap();

        let action = LocalActionRef {
            path: "./.github/actions/local".to_string(),
            line_number: 12,
        };
        let mut collector = AuditCollector::new(false);
        let status =
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(collector.findings.len(), 1);
        assert_eq!(
            collector.findings[0].source_file,
            "./.github/actions/local (dist/runner)"
        );
    }

    #[test]
    fn scan_local_action_source_rejects_parent_escape() {
        let dir = tempfile::TempDir::new().unwrap();
        let action = LocalActionRef {
            path: "./../outside".to_string(),
            line_number: 1,
        };
        let mut collector = AuditCollector::new(false);
        assert!(
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).is_err()
        );
    }

    #[test]
    fn scan_local_action_source_rejects_symlinked_action_root() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        std::fs::write(outside.path().join("action.yml"), "name: outside\n").unwrap();
        let actions_dir = dir.path().join(".github/actions");
        std::fs::create_dir_all(&actions_dir).unwrap();
        std::os::unix::fs::symlink(outside.path(), actions_dir.join("local")).unwrap();

        let action = LocalActionRef {
            path: "./.github/actions/local".to_string(),
            line_number: 1,
        };
        let mut collector = AuditCollector::new(false);
        let err = scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("Refusing to scan symlinked directory")
        );
        assert!(collector.findings.is_empty());
    }

    #[tokio::test]
    async fn scan_action_source_reports_incomplete_when_any_file_fetch_fails() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/o/r/git/trees/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [
                    { "path": "action.yml", "type": "blob" },
                    { "path": "dist/index.js", "type": "blob" }
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/action.yml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("runs:\n  using: node20\n  main: dist/index.js\n"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/dist/index.js"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = GitHubClient::with_base("t".into(), server.uri());
        let action = ActionRef {
            owner: "o".into(),
            repo: "r".into(),
            subpath: None,
            ref_string: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ref_type: workflow::RefType::Sha,
            tag_comment: Some("v1.0.0".into()),
            line_number: 1,
            raw_line: String::new(),
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Incomplete);
        assert!(
            collector.findings.is_empty(),
            "failed fetch should not invent findings, only block clean caching"
        );
    }

    #[tokio::test]
    async fn scan_action_source_includes_metadata_entrypoint() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/o/r/git/trees/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [
                    { "path": "action.yml", "type": "blob" },
                    { "path": "dist/runner", "type": "blob" }
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/action.yml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("runs:\n  using: node20\n  main: dist/runner\n"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/dist/runner"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"fetch("https://example.com/install")"#),
            )
            .mount(&server)
            .await;

        let client = GitHubClient::with_base("t".into(), server.uri());
        let action = ActionRef {
            owner: "o".into(),
            repo: "r".into(),
            subpath: None,
            ref_string: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ref_type: workflow::RefType::Sha,
            tag_comment: Some("v1.0.0".into()),
            line_number: 1,
            raw_line: String::new(),
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(collector.findings.len(), 1);
        assert_eq!(collector.findings[0].source_file, "o/r (dist/runner)");
    }

    #[tokio::test]
    async fn repo_scan_includes_subpath_metadata_entrypoint() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/o/r/git/trees/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [
                    { "path": "sub/action.yml", "type": "blob" },
                    { "path": "sub/runner", "type": "blob" }
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/sub/action.yml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("runs:\n  using: node20\n  main: runner\n"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/sub/runner"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"fetch("https://example.com/install")"#),
            )
            .mount(&server)
            .await;

        let client = GitHubClient::with_base("t".into(), server.uri());
        let action = ActionRef {
            owner: "o".into(),
            repo: "r".into(),
            subpath: None,
            ref_string: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ref_type: workflow::RefType::Sha,
            tag_comment: Some("v1.0.0".into()),
            line_number: 1,
            raw_line: String::new(),
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(collector.findings.len(), 1);
        assert_eq!(collector.findings[0].source_file, "o/r (sub/runner)");
    }
}
