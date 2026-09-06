//! Action source selection and fetch for `audit`.
//!
//! Chooses which files of a referenced action are worth scanning (remote
//! actions via the GitHub trees API, local `uses: ./...` actions from disk),
//! fetches them, and routes each file to the matching content scanner in
//! `audit`. Remote action source is untrusted input: it is scanned, never
//! executed.

use anyhow::{Context, Result};
use regex::Regex;
use serde_norway::Value;
use std::collections::{HashSet, VecDeque};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

use crate::audit::{
    AuditCollector, ShellScanState, collect_step_run_blocks_with_directory, extract_job_run_blocks,
    push_docker_ref_result, scan_dockerfile_content, scan_js_content, scan_py_content,
    scan_shell_content, scan_shell_content_with_state_at,
};
use crate::audit_shell::shell_words;
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

fn is_nonruntime_support_path(path: &str) -> bool {
    path.split('/').any(|component| {
        matches!(
            component,
            ".github" | "__test__" | "__tests__" | "test" | "tests" | "docs" | "examples"
        )
    })
}

/// Max action source files fetched concurrently. Bounds the fan-out so a
/// file-heavy action doesn't burst into a rate-limit-exhausting wave.
const MAX_CONCURRENT_FILE_FETCHES: usize = 8;
const MAX_SOURCE_FILES: usize = 512;
const MAX_SOURCE_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_SOURCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ACTION_GRAPH_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ACTION_GRAPH_NODES: usize = 32;
const MAX_ACTION_GRAPH_DEPTH: usize = 8;

static JS_LOCAL_DEPENDENCY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:\bfrom\s+|\bimport\s+)["'](?P<path>\.\.?/[^"']+)["']"#).unwrap()
});
static JS_LOADER_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\b(?:require|import)\s*\(\s*(?P<argument>[^)\r\n]*)\)"#).unwrap()
});
static PYTHON_RELATIVE_IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*from\s+(?P<module>\.+[A-Za-z0-9_.]*)\s+import\b").unwrap()
});
static SHELL_LOCAL_SOURCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^\s*(?:source|\.)\s+["']?(?P<path>\.{1,2}/[^\s"';]+)"#).unwrap()
});
static SHELL_ACTION_SOURCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^\s*(?:source|\.)\s+["']?(?:\$GITHUB_ACTION_PATH|\$\{GITHUB_ACTION_PATH\}|\$PSScriptRoot)[/\\](?P<path>[^\s"';]+)"#,
    )
    .unwrap()
});
static ACTION_PATH_CD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*(?:cd|pushd)\s+["']?(?:\$GITHUB_ACTION_PATH|\$\{GITHUB_ACTION_PATH\}|\$\{\{\s*github\.action_path\s*\}\})(?P<suffix>(?:/[A-Za-z0-9._-]+)*)["']?\s*$"#,
    )
    .unwrap()
});
static ACTION_CWD_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[;&|]\s*|\s)["']?\.(?:/|\\)(?P<path>[^\s"'`;|&()]+)"#).unwrap()
});

fn cap_targets_prioritizing_entrypoints<T>(
    targets: &mut Vec<T>,
    initial_len: usize,
) -> Option<usize> {
    if targets.len() <= MAX_SOURCE_FILES {
        return None;
    }
    let added = targets.split_off(initial_len);
    let keep_initial = MAX_SOURCE_FILES.saturating_sub(added.len().min(MAX_SOURCE_FILES));
    targets.truncate(keep_initial);
    targets.extend(added.into_iter().take(MAX_SOURCE_FILES - keep_initial));
    Some(keep_initial)
}

/// Which scanner handles a given action source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceFileKind {
    ActionYml,
    WorkflowYml,
    JavaScript,
    Python,
    Shell,
    Dockerfile,
}

type LocalSourceCollection = (Vec<(PathBuf, SourceFileKind)>, Vec<PathBuf>, bool);

/// Whether all selected action source files were fetched and parsed well
/// enough to support a durable "clean" verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionScanStatus {
    Complete,
    Incomplete,
}

#[derive(Debug, Default)]
struct NestedUses {
    complete: bool,
    remote: Vec<ActionRef>,
    local: Vec<String>,
}

impl NestedUses {
    fn complete() -> Self {
        Self {
            complete: true,
            ..Self::default()
        }
    }
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
        let kind = if path == base && is_reusable_workflow(path) {
            SourceFileKind::WorkflowYml
        } else if matches!(relative, "action.yml" | "action.yaml") {
            SourceFileKind::ActionYml
        } else {
            // Runtime source is added from action metadata and then followed
            // through statically resolvable in-repository dependencies.
            continue;
        };
        targets.push((path.clone(), kind));
    }
    targets
}

fn force_include_remote_action_entrypoints(
    targets: &mut Vec<(String, SourceFileKind)>,
    contents: &[Option<Result<String>>],
) -> bool {
    let mut complete = true;
    let metadata: Vec<(String, String)> = targets
        .iter()
        .zip(contents)
        .filter_map(|((path, kind), content)| {
            if *kind != SourceFileKind::ActionYml {
                return None;
            }
            let Some(Ok(content)) = content.as_ref() else {
                complete = false;
                return None;
            };
            Some((path.clone(), content.clone()))
        })
        .collect();

    for (path, content) in metadata {
        let Ok(yaml) = serde_norway::from_str::<Value>(&content) else {
            complete = false;
            continue;
        };
        let base = path.rsplit_once('/').map_or("", |(base, _)| base);
        complete &= action_yml_runtime_paths_complete(&yaml, base);
        for (entrypoint, kind) in action_yml_entrypoint_paths(&yaml, base) {
            push_unique_source_target(targets, entrypoint, kind);
        }
        for (helper, kind) in action_yml_helper_paths(&yaml, base) {
            push_unique_source_target(targets, helper, kind);
        }
        if let Some(dockerfile) = action_yml_dockerfile_path(&yaml, base) {
            push_unique_source_target(targets, dockerfile, SourceFileKind::Dockerfile);
        }
    }
    complete
}

fn force_include_local_action_entrypoints(
    repo_root: &Path,
    action_dir: &Path,
    targets: &mut Vec<(PathBuf, SourceFileKind)>,
) -> bool {
    let mut complete = true;
    let metadata_paths: Vec<PathBuf> = targets
        .iter()
        .filter_map(|(path, kind)| (*kind == SourceFileKind::ActionYml).then_some(path.clone()))
        .collect();

    for path in metadata_paths {
        let Ok(Some(content)) = read_local_source_file(repo_root, &path) else {
            complete = false;
            continue;
        };
        let Ok(yaml) = serde_norway::from_str::<Value>(&content) else {
            complete = false;
            continue;
        };
        let Some(action_base) = action_dir
            .strip_prefix(repo_root)
            .ok()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
        else {
            complete = false;
            continue;
        };
        complete &= action_yml_runtime_paths_complete(&yaml, &action_base);
        let entrypoints = action_yml_entrypoint_paths(&yaml, &action_base)
            .into_iter()
            .chain(action_yml_helper_paths(&yaml, &action_base))
            .chain(
                action_yml_dockerfile_path(&yaml, &action_base)
                    .map(|p| (p, SourceFileKind::Dockerfile)),
            );
        for (entrypoint, kind) in entrypoints {
            let path = repo_root.join(&entrypoint);
            let Some(relative) = path.strip_prefix(repo_root).ok() else {
                complete = false;
                continue;
            };
            match workflow::open_child_file_path(repo_root, relative) {
                Ok(Some(_)) => push_unique_local_source_target(targets, path, kind),
                Ok(None) | Err(_) => complete = false,
            }
        }
    }
    complete
}

fn action_yml_entrypoint_paths(yaml: &Value, base: &str) -> Vec<(String, SourceFileKind)> {
    let Some(runs) = yaml.get("runs").and_then(|r| r.as_mapping()) else {
        return Vec::new();
    };
    let kind = match runs.get("using").and_then(|v| v.as_str()) {
        Some(using) if using.starts_with("node") => SourceFileKind::JavaScript,
        _ => return Vec::new(),
    };

    ["main", "pre", "post"]
        .into_iter()
        .filter_map(|key| runs.get(key).and_then(|v| v.as_str()))
        .filter_map(|path| normalize_action_entrypoint_path(base, path))
        .map(|path| (path, kind))
        .collect()
}

fn action_yml_runtime_paths_complete(yaml: &Value, base: &str) -> bool {
    let Some(runs) = yaml.get("runs").and_then(|runs| runs.as_mapping()) else {
        return false;
    };
    let Some(using) = runs.get("using").and_then(|value| value.as_str()) else {
        return false;
    };
    if using.starts_with("node") {
        for key in ["main", "pre", "post"] {
            match runs.get(key) {
                Some(value) => {
                    let Some(path) = value.as_str() else {
                        return false;
                    };
                    if normalize_action_entrypoint_path(base, path).is_none() {
                        return false;
                    }
                }
                None if key == "main" => return false,
                None => {}
            }
        }
        true
    } else if using.eq_ignore_ascii_case("docker") {
        let Some(image) = runs.get("image").and_then(|value| value.as_str()) else {
            return false;
        };
        image.starts_with("docker://") || normalize_action_entrypoint_path(base, image).is_some()
    } else if using.eq_ignore_ascii_case("composite") {
        runs.get("steps")
            .is_some_and(|steps| steps.as_sequence().is_some())
            && action_yml_helper_references(yaml).iter().all(|relative| {
                executable_source_kind(relative).is_some()
                    && normalize_action_entrypoint_path(base, relative).is_some()
            })
    } else {
        false
    }
}

fn action_yml_helper_paths(yaml: &Value, base: &str) -> Vec<(String, SourceFileKind)> {
    action_yml_helper_references(yaml)
        .into_iter()
        .filter_map(|relative| {
            let kind = executable_source_kind(&relative)?;
            let path = normalize_action_entrypoint_path(base, &relative)?;
            Some((path, kind))
        })
        .collect()
}

fn action_yml_helper_references(yaml: &Value) -> Vec<String> {
    let Some(steps) = yaml.get("runs").and_then(|runs| runs.get("steps")) else {
        return Vec::new();
    };
    let mut helpers = Vec::new();
    for (run, working_directory) in collect_step_run_contexts(steps) {
        for prefix in [
            "$GITHUB_ACTION_PATH/",
            "${GITHUB_ACTION_PATH}/",
            "${{ github.action_path }}/",
            "$PSScriptRoot/",
            "$PSScriptRoot\\",
        ] {
            let mut remaining = run;
            while let Some(index) = remaining.find(prefix) {
                let tail = &remaining[index + prefix.len()..];
                let end = tail
                    .find(|c: char| {
                        c.is_whitespace()
                            || matches!(c, '\'' | '"' | '`' | ';' | '|' | '&' | '(' | ')')
                    })
                    .unwrap_or(tail.len());
                let relative = tail[..end].replace('\\', "/");
                if !relative.is_empty() && !helpers.contains(&relative) {
                    helpers.push(relative);
                }
                remaining = &tail[end..];
            }
        }
        let mut action_cwd = working_directory.and_then(action_path_working_directory);
        if working_directory.is_some() && action_cwd.is_none() {
            helpers.push("$unresolved-action-cwd".to_string());
        }
        let mut directory_stack = Vec::new();
        for raw_command in split_shell_commands_unquoted(run) {
            let raw_command = raw_command.trim();
            let normalized_directory_command = normalize_directory_command(raw_command);
            let command = normalized_directory_command
                .as_deref()
                .unwrap_or(raw_command);
            if command == "cd" || command == "pushd" {
                helpers.push("$unresolved-action-cwd".to_string());
                action_cwd = None;
                continue;
            }
            if command.starts_with("cd ")
                || command.starts_with("cd\t")
                || command.starts_with("pushd ")
                || command.starts_with("pushd\t")
            {
                if command.starts_with("pushd") {
                    directory_stack.push(action_cwd.clone());
                }
                action_cwd = action_path_working_directory(command).or_else(|| {
                    action_cwd.as_deref().and_then(|base| {
                        directory_command_argument(command)
                            .and_then(|relative| normalize_action_entrypoint_path(base, relative))
                    })
                });
                if action_cwd.is_none() {
                    helpers.push("$unresolved-action-cwd".to_string());
                }
                continue;
            }
            if command == "popd" || command.starts_with("popd ") || command.starts_with("popd\t") {
                if command != "popd" {
                    helpers.push("$unresolved-action-cwd".to_string());
                    action_cwd = None;
                    continue;
                }
                action_cwd = directory_stack.pop().flatten();
                if action_cwd.is_none() {
                    helpers.push("$unresolved-action-cwd".to_string());
                }
                continue;
            }
            let Some(base) = action_cwd.as_deref() else {
                continue;
            };
            for captures in ACTION_CWD_EXEC_RE.captures_iter(command) {
                let Some(path) = captures.name("path") else {
                    continue;
                };
                let path = path.as_str().replace('\\', "/");
                let relative = normalize_action_entrypoint_path(base, &path)
                    .unwrap_or_else(|| "$unresolved-action-cwd".to_string());
                if !helpers.contains(&relative) {
                    helpers.push(relative);
                }
            }
        }
    }
    helpers
}

fn normalize_directory_command(command: &str) -> Option<String> {
    let words = shell_words(command);
    let mut index = 0;
    while words.get(index).is_some_and(|word| shell_assignment(word)) {
        index += 1;
    }
    if words.get(index).map(String::as_str) == Some("command") {
        index += 1;
        if words.get(index).map(String::as_str) == Some("-p") {
            index += 1;
        }
        if words.get(index).map(String::as_str) == Some("--") {
            index += 1;
        }
    } else if words.get(index).map(String::as_str) == Some("builtin") {
        index += 1;
        if words.get(index).map(String::as_str) == Some("--") {
            index += 1;
        }
    }
    matches!(
        words.get(index).map(String::as_str),
        Some("cd" | "pushd" | "popd")
    )
    .then(|| words[index..].join(" "))
}

fn shell_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn directory_command_argument(command: &str) -> Option<&str> {
    let mut arguments = command.split_whitespace();
    arguments.next()?;
    let first = arguments.next()?;
    let argument = if first == "--" {
        arguments.next()?
    } else if first.starts_with('-') {
        return None;
    } else {
        first
    };
    if arguments.next().is_some() {
        return None;
    }
    let argument = argument.trim_matches(['\'', '"']);
    let directory_stack_index = argument
        .strip_prefix('+')
        .or_else(|| argument.strip_prefix('-'))
        .is_some_and(|index| {
            !index.is_empty() && index.chars().all(|character| character.is_ascii_digit())
        });
    (!argument.is_empty()
        && !argument.starts_with('/')
        && !argument.contains(['$', '`', '\\'])
        && !directory_stack_index)
        .then_some(argument)
}

fn action_path_working_directory(value: &str) -> Option<String> {
    let command;
    let trimmed = value.trim_start();
    let is_directory_command = ["cd", "pushd"].iter().any(|command| {
        trimmed
            .strip_prefix(command)
            .and_then(|remaining| remaining.chars().next())
            .is_some_and(char::is_whitespace)
    });
    let value = if is_directory_command {
        value
    } else {
        command = format!("cd {}", value.trim());
        &command
    };
    ACTION_PATH_CD_RE.captures(value).map(|captures| {
        captures
            .name("suffix")
            .map_or("", |suffix| suffix.as_str())
            .trim_start_matches('/')
            .to_string()
    })
}

fn collect_step_run_contexts(steps: &Value) -> Vec<(&str, Option<&str>)> {
    fn collect<'a>(steps: &'a Value, runs: &mut Vec<(&'a str, Option<&'a str>)>) {
        let Some(sequence) = steps.as_sequence() else {
            return;
        };
        for step in sequence {
            let Some(mapping) = step.as_mapping() else {
                continue;
            };
            if let Some(run) = mapping.get("run").and_then(Value::as_str) {
                runs.push((
                    run,
                    mapping.get("working-directory").and_then(Value::as_str),
                ));
            }
            if let Some(parallel) = mapping.get("parallel") {
                collect(parallel, runs);
            }
        }
    }
    let mut runs = Vec::new();
    collect(steps, &mut runs);
    runs
}

fn split_shell_commands_unquoted(line: &str) -> Vec<&str> {
    let mut commands = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut characters = line.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote != Some('\'') {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            quote = if quote == Some(character) {
                None
            } else if quote.is_none() {
                Some(character)
            } else {
                quote
            };
        } else if quote.is_none()
            && (character == ';'
                || matches!(character, '&' | '|')
                    && characters
                        .peek()
                        .is_some_and(|(_, next)| *next == character))
        {
            let command = line[start..index].trim();
            if !command.is_empty() {
                commands.push(command);
            }
            if character != ';' {
                characters.next();
            }
            start = characters
                .peek()
                .map_or(line.len(), |(next_index, _)| *next_index);
        }
    }
    let command = line[start..].trim();
    if !command.is_empty() {
        commands.push(command);
    }
    commands
}

fn executable_source_kind(path: &str) -> Option<SourceFileKind> {
    if is_javascript_source(path) {
        Some(SourceFileKind::JavaScript)
    } else if path.ends_with(".py") {
        Some(SourceFileKind::Python)
    } else if is_shell_source(path) {
        Some(SourceFileKind::Shell)
    } else {
        None
    }
}

/// The Dockerfile a container action builds from, when its metadata names one.
///
/// A repository may carry Dockerfiles that no action references (test
/// fixtures, examples, its own CI images). Those never run for a consumer, so
/// reachability comes from `runs.image` rather than from a file being named
/// `Dockerfile`. A `docker://` image is a registry reference, not a path in
/// this repository, and the container-ref rules cover it instead.
fn action_yml_dockerfile_path(yaml: &Value, base: &str) -> Option<String> {
    let runs = yaml.get("runs").and_then(|r| r.as_mapping())?;
    if !runs
        .get("using")
        .and_then(|v| v.as_str())
        .is_some_and(|using| using.eq_ignore_ascii_case("docker"))
    {
        return None;
    }
    let image = runs.get("image").and_then(|v| v.as_str())?;
    if image.starts_with("docker://") {
        return None;
    }
    normalize_action_entrypoint_path(base, image)
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
    for component in Path::new(base).components().chain(rel.components()) {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?.to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            _ => return None,
        }
    }
    if parts.is_empty() {
        return None;
    }

    Some(parts.join("/"))
}

fn push_unique_source_target(
    targets: &mut Vec<(String, SourceFileKind)>,
    path: String,
    kind: SourceFileKind,
) {
    if let Some((_, existing_kind)) = targets.iter_mut().find(|(existing, _)| existing == &path) {
        *existing_kind = kind;
    } else {
        targets.push((path, kind));
    }
}

fn push_unique_local_source_target(
    targets: &mut Vec<(PathBuf, SourceFileKind)>,
    path: PathBuf,
    kind: SourceFileKind,
) {
    if let Some((_, existing_kind)) = targets.iter_mut().find(|(existing, _)| existing == &path) {
        *existing_kind = kind;
    } else {
        targets.push((path, kind));
    }
}

fn read_local_source_file(repo_root: &Path, path: &Path) -> Result<Option<String>> {
    let relative = path
        .strip_prefix(repo_root)
        .with_context(|| format!("{} is outside the repository", path.display()))?;
    let Some(mut file) = workflow::open_child_file_path(repo_root, relative)? else {
        return Ok(None);
    };
    if file.metadata()?.len() > MAX_SOURCE_FILE_BYTES as u64 {
        anyhow::bail!(
            "{} exceeds the {} byte source-file limit",
            path.display(),
            MAX_SOURCE_FILE_BYTES
        );
    }
    let mut content = String::new();
    file.by_ref()
        .take(MAX_SOURCE_FILE_BYTES as u64 + 1)
        .read_to_string(&mut content)
        .with_context(|| format!("reading {}", path.display()))?;
    if content.len() > MAX_SOURCE_FILE_BYTES {
        anyhow::bail!(
            "{} exceeds the {} byte source-file limit",
            path.display(),
            MAX_SOURCE_FILE_BYTES
        );
    }
    Ok(Some(content))
}

async fn fetch_remote_source_files(
    client: &GitHubClient,
    action: &ActionRef,
    targets: &[(String, SourceFileKind)],
    max_total_bytes: usize,
) -> (Vec<Option<Result<String>>>, bool, usize) {
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
    let mut total_bytes = 0usize;
    while let Some(joined) = fetches.join_next().await {
        match joined {
            Ok((index, Ok(content))) => {
                if content.len() > MAX_SOURCE_FILE_BYTES {
                    complete = false;
                    continue;
                }
                let Some(next_total) = total_bytes.checked_add(content.len()) else {
                    complete = false;
                    fetches.abort_all();
                    break;
                };
                if next_total > max_total_bytes {
                    complete = false;
                    fetches.abort_all();
                    break;
                }
                total_bytes = next_total;
                contents[index] = Some(Ok(content));
            }
            Ok((index, Err(error))) => {
                complete = false;
                contents[index] = Some(Err(error));
            }
            Err(_) => {
                complete = false;
            }
        }
    }

    (contents, complete, total_bytes)
}

fn collect_local_source_files(action_dir: &Path) -> Result<LocalSourceCollection> {
    fn visit(
        dir: &Path,
        base: &Path,
        targets: &mut Vec<(PathBuf, SourceFileKind)>,
        available: &mut Vec<PathBuf>,
        complete: &mut bool,
    ) -> Result<()> {
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
            if file_type.is_symlink() {
                *complete = false;
                continue;
            }
            if file_type.is_dir() {
                if is_nonruntime_support_path(&relative) {
                    continue;
                }
                visit(&path, base, targets, available, complete)?;
            } else if file_type.is_file() {
                available.push(path.clone());
                if let Some(kind) = source_file_kind(&relative) {
                    if targets.len() == MAX_SOURCE_FILES {
                        *complete = false;
                    } else if targets.len() < MAX_SOURCE_FILES {
                        targets.push((path, kind));
                    }
                }
            }
        }
        Ok(())
    }

    let mut targets = Vec::new();
    let mut available = Vec::new();
    let mut complete = true;
    visit(
        action_dir,
        action_dir,
        &mut targets,
        &mut available,
        &mut complete,
    )?;
    Ok((targets, available, complete))
}

fn source_file_kind(relative: &str) -> Option<SourceFileKind> {
    if relative == "action.yml" || relative == "action.yaml" {
        Some(SourceFileKind::ActionYml)
    } else {
        None
    }
}

fn is_shell_source(path: &str) -> bool {
    path.ends_with(".sh")
        || path.ends_with(".bash")
        || path.ends_with(".zsh")
        || path.ends_with(".ps1")
}

fn is_reusable_workflow(path: &str) -> bool {
    (path.ends_with(".yml") || path.ends_with(".yaml")) && path.contains("/.github/workflows/")
        || path.starts_with(".github/workflows/")
}

fn is_javascript_source(path: &str) -> bool {
    path.ends_with(".js")
        || path.ends_with(".ts")
        || path.ends_with(".mjs")
        || path.ends_with(".cjs")
        || path.ends_with(".mts")
        || path.ends_with(".cts")
}

fn force_include_remote_source_dependencies(
    tree: &[crate::github::TreeEntry],
    action_base: &str,
    targets: &mut Vec<(String, SourceFileKind)>,
    contents: &[Option<Result<String>>],
) -> bool {
    let available: HashSet<&str> = tree
        .iter()
        .filter(|entry| entry.entry_type == "blob")
        .map(|entry| entry.path.as_str())
        .collect();
    let sources: Vec<(String, SourceFileKind, String)> = targets
        .iter()
        .zip(contents)
        .filter_map(|((path, kind), content)| {
            content
                .as_ref()
                .and_then(|content| content.as_ref().ok())
                .map(|content| (path.clone(), *kind, content.clone()))
        })
        .collect();
    let mut complete = true;

    for (path, kind, content) in sources {
        match kind {
            SourceFileKind::JavaScript => {
                let code = strip_javascript_comments(&content);
                for captures in JS_LOCAL_DEPENDENCY_RE.captures_iter(&code) {
                    let Some(dependency) = captures.name("path") else {
                        complete = false;
                        continue;
                    };
                    complete &= include_remote_javascript_dependency(
                        &available,
                        targets,
                        &path,
                        dependency.as_str(),
                    );
                }
                for captures in JS_LOADER_CALL_RE.captures_iter(&code) {
                    if captures.get(0).is_some_and(|matched| {
                        crate::audit::javascript_position_is_quoted(&code, matched.start())
                    }) {
                        continue;
                    }
                    let Some(argument) = captures.name("argument") else {
                        complete = false;
                        continue;
                    };
                    let argument = argument.as_str().trim();
                    if let Some(dependency) = exact_javascript_loader_specifier(argument) {
                        if dependency.starts_with("./") || dependency.starts_with("../") {
                            complete &= include_remote_javascript_dependency(
                                &available, targets, &path, dependency,
                            );
                        }
                    } else if !argument.chars().all(|character| character.is_ascii_digit()) {
                        complete = false;
                    }
                }
                let (executed_strings, executed_strings_complete) =
                    executed_javascript_string_literals(&code);
                complete &= executed_strings_complete;
                for executed in executed_strings {
                    for captures in JS_LOADER_CALL_RE.captures_iter(executed) {
                        let Some(argument) = captures.name("argument") else {
                            complete = false;
                            continue;
                        };
                        let argument = argument.as_str().trim();
                        if let Some(dependency) = exact_javascript_loader_specifier(argument) {
                            if dependency.starts_with("./") || dependency.starts_with("../") {
                                complete &= include_remote_javascript_dependency(
                                    &available, targets, &path, dependency,
                                );
                            }
                        } else if !argument.chars().all(|character| character.is_ascii_digit()) {
                            complete = false;
                        }
                    }
                }
            }
            SourceFileKind::Python => {
                for captures in PYTHON_RELATIVE_IMPORT_RE.captures_iter(&content) {
                    let Some(module) = captures.name("module") else {
                        complete = false;
                        continue;
                    };
                    complete &= include_remote_python_dependency(
                        &available,
                        targets,
                        &path,
                        module.as_str(),
                    );
                }
            }
            SourceFileKind::Shell => {
                for captures in SHELL_LOCAL_SOURCE_RE.captures_iter(&content) {
                    let Some(dependency) = captures.name("path") else {
                        complete = false;
                        continue;
                    };
                    complete &= include_remote_exact_dependency(
                        &available,
                        targets,
                        path_parent(&path),
                        dependency.as_str(),
                        SourceFileKind::Shell,
                    );
                }
                for captures in SHELL_ACTION_SOURCE_RE.captures_iter(&content) {
                    let Some(dependency) = captures.name("path") else {
                        complete = false;
                        continue;
                    };
                    complete &= include_remote_exact_dependency(
                        &available,
                        targets,
                        action_base,
                        dependency.as_str(),
                        SourceFileKind::Shell,
                    );
                }
            }
            SourceFileKind::Dockerfile => {
                let (sources, parsed) = docker_local_source_paths(&content);
                complete &= parsed;
                for source in sources {
                    complete &=
                        include_remote_docker_dependency(&available, targets, action_base, &source);
                }
            }
            SourceFileKind::ActionYml | SourceFileKind::WorkflowYml => {}
        }
    }
    complete
}

fn exact_javascript_loader_specifier(argument: &str) -> Option<&str> {
    let quote = argument.chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') {
        return None;
    }
    let body = &argument[quote.len_utf8()..];
    let end = body.rfind(quote)?;
    if !body[end + quote.len_utf8()..].trim().is_empty()
        || quote == '`' && body[..end].contains("${")
    {
        return None;
    }
    Some(&body[..end])
}

fn executed_javascript_string_literals(code: &str) -> (Vec<&str>, bool) {
    let mut literals = Vec::new();
    let mut complete = true;
    for marker in ["eval", "Function", "setTimeout", "setInterval"] {
        for (index, _) in code.match_indices(marker) {
            let before = code[..index].chars().next_back();
            let after = code[index + marker.len()..].chars().next();
            if crate::audit::javascript_position_is_quoted(code, index)
                || before.is_some_and(|character| {
                    character == '_' || character == '$' || character.is_ascii_alphanumeric()
                })
                || after.is_some_and(|character| {
                    character == '_' || character == '$' || character.is_ascii_alphanumeric()
                })
            {
                continue;
            }
            let remaining = code[index + marker.len()..].trim_start();
            let mut method_call = false;
            let mut bound_argument = None;
            let mut call_like = remaining.starts_with('(') || remaining.starts_with("?.(");
            let call = if remaining.starts_with('(') {
                Some(remaining)
            } else if let Some(optional) = remaining.strip_prefix("?.") {
                let optional = optional.trim_start();
                if optional.starts_with('(') {
                    Some(optional)
                } else if optional.starts_with('[') {
                    if matches!(marker, "eval" | "Function") {
                        complete = false;
                    }
                    continue;
                } else if let Some(call_tail) = optional.strip_prefix("call") {
                    method_call = true;
                    call_like = true;
                    Some(call_tail.trim_start())
                } else if optional.starts_with("apply") {
                    complete = false;
                    continue;
                } else if let Some(bind_tail) = optional.strip_prefix("bind") {
                    match immediate_bound_javascript_argument(marker, bind_tail) {
                        Ok(Some(argument)) => bound_argument = Some(argument),
                        Ok(None) if marker == "eval" => complete = false,
                        Ok(None) => {}
                        Err(()) => complete = false,
                    }
                    None
                } else {
                    if matches!(marker, "eval" | "Function")
                        && has_escaped_javascript_method_call(optional)
                    {
                        complete = false;
                    }
                    None
                }
            } else if remaining.starts_with('[') {
                if matches!(marker, "eval" | "Function") {
                    complete = false;
                }
                continue;
            } else if let Some(call_tail) = remaining.strip_prefix(".call") {
                method_call = true;
                call_like = true;
                Some(call_tail.trim_start())
            } else if remaining.starts_with(".apply") {
                complete = false;
                continue;
            } else if let Some(bind_tail) = remaining.strip_prefix(".bind") {
                match immediate_bound_javascript_argument(marker, bind_tail) {
                    Ok(Some(argument)) => bound_argument = Some(argument),
                    Ok(None) if marker == "eval" => complete = false,
                    Ok(None) => {}
                    Err(()) => complete = false,
                }
                None
            } else if matches!(marker, "eval" | "Function")
                && remaining.starts_with('.')
                && has_escaped_javascript_method_call(remaining)
            {
                complete = false;
                continue;
            } else {
                let mut tail = remaining;
                let mut closing_parentheses = 0;
                while let Some(after_close) = tail.strip_prefix(')') {
                    closing_parentheses += 1;
                    tail = after_close.trim_start();
                }
                if closing_parentheses > 0 {
                    let optional_tail = tail.strip_prefix("?.").map(str::trim_start);
                    tail = optional_tail.unwrap_or(tail);
                    if tail.starts_with('(') {
                        call_like = true;
                        Some(tail)
                    } else if tail.starts_with('[') {
                        if matches!(marker, "eval" | "Function") {
                            complete = false;
                        }
                        None
                    } else if let Some(call_tail) = tail.strip_prefix(".call").or_else(|| {
                        optional_tail.and_then(|optional| optional.strip_prefix("call"))
                    }) {
                        method_call = true;
                        call_like = true;
                        Some(call_tail.trim_start())
                    } else if tail.starts_with(".apply")
                        || optional_tail.is_some_and(|optional| optional.starts_with("apply"))
                    {
                        complete = false;
                        None
                    } else if let Some(bind_tail) = tail.strip_prefix(".bind").or_else(|| {
                        optional_tail.and_then(|optional| optional.strip_prefix("bind"))
                    }) {
                        match immediate_bound_javascript_argument(marker, bind_tail) {
                            Ok(Some(argument)) => bound_argument = Some(argument),
                            Ok(None) if marker == "eval" => complete = false,
                            Ok(None) => {}
                            Err(()) => complete = false,
                        }
                        None
                    } else {
                        if matches!(marker, "eval" | "Function")
                            && has_escaped_javascript_method_call(tail)
                        {
                            complete = false;
                        }
                        None
                    }
                } else {
                    None
                }
            };
            let argument = if bound_argument.is_some() {
                bound_argument
            } else if let Some(arguments) = call.and_then(javascript_call_arguments) {
                let arguments = split_javascript_arguments(arguments);
                if marker == "Function" {
                    arguments.last().copied()
                } else if method_call {
                    arguments.get(1).copied()
                } else {
                    arguments.first().copied()
                }
            } else {
                if call_like && matches!(marker, "eval" | "Function") {
                    complete = false;
                }
                continue;
            };
            let Some(argument) = argument else {
                continue;
            };
            let string_argument = argument
                .trim_start()
                .chars()
                .next()
                .is_some_and(|character| matches!(character, '\'' | '"' | '`'));
            let Some(literal) = exact_javascript_string_literal(argument) else {
                if matches!(marker, "eval" | "Function") || string_argument {
                    complete = false;
                }
                continue;
            };
            if literal.contains('\\') {
                complete = false;
            } else {
                literals.push(literal);
            }
        }
    }
    (literals, complete)
}

fn has_escaped_javascript_method_call(value: &str) -> bool {
    value
        .split_once('(')
        .is_some_and(|(property, _)| property.contains('\\'))
}

fn immediate_bound_javascript_argument<'a>(
    marker: &str,
    bind_tail: &'a str,
) -> Result<Option<&'a str>, ()> {
    if !bind_tail.trim_start().starts_with('(') {
        return Ok(None);
    }
    let Some((bound, after_bind)) = javascript_call_parts(bind_tail) else {
        return Err(());
    };
    let after_bind = after_bind.trim_start();
    let invocation = after_bind.strip_prefix("?.").unwrap_or(after_bind);
    let Some((invoked, _)) = javascript_call_parts(invocation) else {
        return Ok(None);
    };
    let bound = split_javascript_arguments(bound);
    let invoked = split_javascript_arguments(invoked);
    Ok(if marker == "Function" {
        invoked.last().copied().or_else(|| {
            bound
                .get(1..)
                .and_then(|arguments| arguments.last().copied())
        })
    } else {
        bound.get(1).copied().or_else(|| invoked.first().copied())
    })
}

fn javascript_call_parts(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    let body = value.strip_prefix('(')?;
    let mut depth = 1usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in body.char_indices() {
        if escaped {
            escaped = false;
        } else if quote.is_some() && character == '\\' {
            escaped = true;
        } else if matches!(character, '\'' | '"' | '`') {
            quote = if quote == Some(character) {
                None
            } else {
                quote.or(Some(character))
            };
        } else if quote.is_none() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((&body[..index], &body[index + 1..]));
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn javascript_call_arguments(value: &str) -> Option<&str> {
    javascript_call_parts(value).map(|(arguments, _)| arguments)
}

fn split_javascript_arguments(arguments: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in arguments.char_indices() {
        if escaped {
            escaped = false;
        } else if quote.is_some() && character == '\\' {
            escaped = true;
        } else if matches!(character, '\'' | '"' | '`') {
            quote = if quote == Some(character) {
                None
            } else {
                quote.or(Some(character))
            };
        } else if quote.is_none() {
            match character {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    result.push(arguments[start..index].trim());
                    start = index + 1;
                }
                _ => {}
            }
        }
    }
    let argument = arguments[start..].trim();
    if !argument.is_empty() {
        result.push(argument);
    }
    result
}

fn exact_javascript_string_literal(value: &str) -> Option<&str> {
    let value = value.trim();
    let quote = value
        .chars()
        .next()
        .filter(|quote| matches!(quote, '\'' | '"' | '`'))?;
    let body = &value[quote.len_utf8()..];
    let mut escaped = false;
    for (end, character) in body.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == quote {
            let literal = &body[..end];
            let trailing = body[end + quote.len_utf8()..].trim();
            if trailing.is_empty() && !(quote == '`' && literal.contains("${")) {
                return Some(literal);
            }
            return None;
        }
    }
    None
}

fn include_remote_javascript_dependency(
    available: &HashSet<&str>,
    targets: &mut Vec<(String, SourceFileKind)>,
    source: &str,
    dependency: &str,
) -> bool {
    let Some(path) = normalize_action_entrypoint_path(path_parent(source), dependency) else {
        return false;
    };
    if available.contains(path.as_str()) {
        if let Some(kind) = executable_source_kind(&path) {
            push_unique_source_target(targets, path, kind);
        } else if Path::new(&path).extension().is_none() {
            push_unique_source_target(targets, path, SourceFileKind::JavaScript);
        } else if !is_nonexecutable_data_path(&path) {
            return false;
        }
        return true;
    }
    if Path::new(&path).extension().is_some() {
        return false;
    }
    ["js", "mjs", "cjs", "ts"]
        .into_iter()
        .map(|extension| format!("{path}.{extension}"))
        .chain(
            ["js", "mjs", "cjs", "ts"]
                .into_iter()
                .map(|extension| format!("{path}/index.{extension}")),
        )
        .find(|candidate| available.contains(candidate.as_str()))
        .is_some_and(|candidate| {
            push_unique_source_target(targets, candidate, SourceFileKind::JavaScript);
            true
        })
}

fn is_nonexecutable_data_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "json"
                    | "jsonl"
                    | "ndjson"
                    | "yaml"
                    | "yml"
                    | "toml"
                    | "csv"
                    | "tsv"
                    | "xml"
                    | "txt"
                    | "md"
                    | "rst"
            )
        })
}

fn include_remote_python_dependency(
    available: &HashSet<&str>,
    targets: &mut Vec<(String, SourceFileKind)>,
    source: &str,
    module: &str,
) -> bool {
    let parent_levels = module
        .chars()
        .take_while(|character| *character == '.')
        .count();
    let module = module[parent_levels..].replace('.', "/");
    if module.is_empty() {
        return false;
    }
    let mut relative = "../".repeat(parent_levels.saturating_sub(1));
    relative.push_str(&module);
    let Some(path) = normalize_action_entrypoint_path(path_parent(source), &relative) else {
        return false;
    };
    [format!("{path}.py"), format!("{path}/__init__.py")]
        .into_iter()
        .find(|candidate| available.contains(candidate.as_str()))
        .is_some_and(|candidate| {
            push_unique_source_target(targets, candidate, SourceFileKind::Python);
            true
        })
}

fn include_remote_exact_dependency(
    available: &HashSet<&str>,
    targets: &mut Vec<(String, SourceFileKind)>,
    base: &str,
    dependency: &str,
    kind: SourceFileKind,
) -> bool {
    let Some(path) = normalize_action_entrypoint_path(base, dependency) else {
        return false;
    };
    if !available.contains(path.as_str()) {
        return false;
    }
    push_unique_source_target(targets, path, kind);
    true
}

fn include_remote_docker_dependency(
    available: &HashSet<&str>,
    targets: &mut Vec<(String, SourceFileKind)>,
    action_base: &str,
    source: &str,
) -> bool {
    if source.starts_with("http://") || source.starts_with("https://") {
        return true;
    }
    if source.contains(['$', '`']) {
        return false;
    }
    let normalized = if source == "." {
        Some(action_base.to_string())
    } else {
        normalize_action_entrypoint_path(action_base, source)
    };
    let Some(path) = normalized else {
        return false;
    };

    if path.contains(['*', '?', '[']) {
        let mut matched = false;
        for candidate in available {
            if wildcard_path_matches(&path, candidate) {
                matched = true;
                if let Some(kind) = executable_source_kind(candidate) {
                    push_unique_source_target(targets, (*candidate).to_string(), kind);
                }
            }
        }
        return matched;
    }
    if available.contains(path.as_str()) {
        if let Some(kind) = executable_source_kind(&path) {
            push_unique_source_target(targets, path, kind);
        }
        return true;
    }

    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("{path}/")
    };
    let mut matched = false;
    for candidate in available {
        if candidate.starts_with(&prefix) {
            matched = true;
            if let Some(kind) = executable_source_kind(candidate) {
                push_unique_source_target(targets, (*candidate).to_string(), kind);
            }
        }
    }
    matched
}

fn docker_local_source_paths(content: &str) -> (Vec<String>, bool) {
    let mut sources = Vec::new();
    let mut complete = true;
    for line in content.lines() {
        let line = line.trim_start();
        let Some((instruction, mut arguments)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if !instruction.eq_ignore_ascii_case("COPY") && !instruction.eq_ignore_ascii_case("ADD") {
            continue;
        }
        arguments = arguments.trim_start();
        if arguments
            .split_whitespace()
            .any(|word| word == "--from" || word.starts_with("--from="))
        {
            continue;
        }
        while arguments.starts_with("--") {
            let Some((_, rest)) = arguments.split_once(char::is_whitespace) else {
                complete = false;
                break;
            };
            arguments = rest.trim_start();
        }
        if arguments.is_empty() {
            continue;
        }
        let values = if arguments.starts_with('[') {
            match serde_json::from_str::<Vec<String>>(arguments) {
                Ok(values) => values,
                Err(_) => {
                    complete = false;
                    continue;
                }
            }
        } else {
            arguments
                .split_whitespace()
                .map(|value| value.trim_matches(['\'', '"']).to_string())
                .collect()
        };
        if values.len() < 2 {
            complete = false;
            continue;
        }
        let source_count = values.len() - 1;
        sources.extend(values.into_iter().take(source_count));
    }
    (sources, complete)
}

fn path_parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn wildcard_path_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut matches = vec![false; value.len() + 1];
    matches[0] = true;
    for token in pattern {
        let mut next = vec![false; value.len() + 1];
        if *token == b'*' {
            next[0] = matches[0];
            for index in 1..=value.len() {
                next[index] = matches[index] || next[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                next[index] = matches[index - 1] && (*token == b'?' || *token == value[index - 1]);
            }
        }
        matches = next;
    }
    matches[value.len()]
}

fn strip_javascript_comments(content: &str) -> String {
    let mut output = String::with_capacity(content.len());
    let mut characters = content.chars().peekable();
    let mut quote = None;
    let mut escaped = false;
    let mut block_comment = false;
    let mut line_comment = false;

    while let Some(character) = characters.next() {
        if line_comment {
            if character == '\n' {
                output.push(character);
                line_comment = false;
            }
            continue;
        }
        if block_comment {
            if character == '*' && characters.peek() == Some(&'/') {
                characters.next();
                block_comment = false;
            } else if character == '\n' {
                output.push(character);
            }
            continue;
        }
        if let Some(delimiter) = quote {
            output.push(character);
            if character == '\n' {
                quote = None;
                escaped = false;
            } else if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
            output.push(character);
        } else if character == '/' && characters.peek() == Some(&'/') {
            characters.next();
            line_comment = true;
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            block_comment = true;
        } else {
            output.push(character);
        }
    }
    output
}

fn force_include_local_source_dependencies(
    repo_root: &Path,
    action_dir: &Path,
    available: &[PathBuf],
    targets: &mut Vec<(PathBuf, SourceFileKind)>,
) -> bool {
    let Some(action_base) = action_dir
        .strip_prefix(repo_root)
        .ok()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
    else {
        return false;
    };
    let tree: Vec<crate::github::TreeEntry> = available
        .iter()
        .filter_map(|path| {
            path.strip_prefix(repo_root)
                .ok()
                .map(|path| crate::github::TreeEntry {
                    path: path.to_string_lossy().replace('\\', "/"),
                    entry_type: "blob".to_string(),
                })
        })
        .collect();
    let mut string_targets = Vec::with_capacity(targets.len());
    let mut contents = Vec::with_capacity(targets.len());
    let mut complete = true;
    for (path, kind) in targets.iter() {
        let Some(relative) = path.strip_prefix(repo_root).ok() else {
            complete = false;
            continue;
        };
        string_targets.push((relative.to_string_lossy().replace('\\', "/"), *kind));
        match read_local_source_file(repo_root, path) {
            Ok(Some(content)) => contents.push(Some(Ok(content))),
            Ok(None) | Err(_) => {
                complete = false;
                contents.push(None);
            }
        }
    }
    if string_targets.len() != targets.len() {
        return false;
    }

    let before = string_targets.len();
    complete &= force_include_remote_source_dependencies(
        &tree,
        &action_base,
        &mut string_targets,
        &contents,
    );
    for (relative, kind) in string_targets.into_iter().skip(before) {
        let path = repo_root.join(&relative);
        match workflow::open_child_file_path(repo_root, Path::new(&relative)) {
            Ok(Some(_)) => push_unique_local_source_target(targets, path, kind),
            Ok(None) | Err(_) => complete = false,
        }
    }
    complete
}

fn local_action_dir(repo_root: &Path, action: &LocalActionRef) -> Result<PathBuf> {
    let Some(rel) = action
        .path
        .strip_prefix("./")
        .or_else(|| action.path.strip_prefix("$/"))
    else {
        anyhow::bail!("local action path must start with ./ or $/");
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

#[cfg(test)]
pub(crate) fn scan_local_action_source(
    repo_root: &Path,
    action: &LocalActionRef,
    collector: &mut AuditCollector,
    config: &Config,
) -> Result<ActionScanStatus> {
    let (status, nested_remote) =
        scan_local_action_source_graph(repo_root, action, collector, config)?;
    Ok(if nested_remote.is_empty() {
        status
    } else {
        ActionScanStatus::Incomplete
    })
}

pub(crate) fn scan_local_action_source_graph(
    repo_root: &Path,
    action: &LocalActionRef,
    collector: &mut AuditCollector,
    config: &Config,
) -> Result<(ActionScanStatus, Vec<ActionRef>)> {
    let action_dir = local_action_dir(repo_root, action)?;
    let (mut targets, mut available, mut complete) = collect_local_source_files(&action_dir)?;
    let initial_len = targets.len();
    complete &= force_include_local_action_entrypoints(repo_root, &action_dir, &mut targets);
    if cap_targets_prioritizing_entrypoints(&mut targets, initial_len).is_some() {
        complete = false;
    }
    for (path, _) in &targets {
        if !available.contains(path) {
            available.push(path.clone());
        }
    }
    loop {
        let before = targets.len();
        complete &= force_include_local_source_dependencies(
            repo_root,
            &action_dir,
            &available,
            &mut targets,
        );
        if targets.len() > MAX_SOURCE_FILES {
            targets.truncate(MAX_SOURCE_FILES);
            complete = false;
        }
        if targets.len() == before {
            break;
        }
    }
    if targets.is_empty() {
        return Ok((ActionScanStatus::Complete, Vec::new()));
    }

    let mut total_bytes = 0usize;
    let mut nested_remote = Vec::new();
    for (path, kind) in targets {
        let content = match read_local_source_file(repo_root, &path) {
            Ok(Some(content)) => content,
            Ok(None) | Err(_) => {
                complete = false;
                continue;
            }
        };
        total_bytes = total_bytes.saturating_add(content.len());
        if total_bytes > MAX_TOTAL_SOURCE_BYTES {
            complete = false;
            continue;
        }
        let relative = path
            .strip_prefix(&action_dir)
            .or_else(|_| path.strip_prefix(repo_root))
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let source_label = format!("{} ({relative})", action.path);
        match kind {
            SourceFileKind::ActionYml => match serde_norway::from_str::<Value>(&content) {
                Ok(yaml) => {
                    let nested =
                        scan_action_yml_runs(&yaml, &source_label, &action.path, collector, config);
                    complete &= nested.complete
                        && nested
                            .remote
                            .iter()
                            .all(|action| action.ref_type == workflow::RefType::Sha)
                        && nested.local.is_empty();
                    nested_remote.extend(nested.remote.into_iter().map(|mut remote| {
                        remote.line_number = action.line_number;
                        remote
                    }));
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
            SourceFileKind::Shell => {
                scan_shell_content(&content, &source_label, 0, &action.path, collector, config);
            }
            SourceFileKind::WorkflowYml => {
                complete = false;
            }
            SourceFileKind::Dockerfile => {
                scan_dockerfile_content(&content, &source_label, &action.path, collector, config);
            }
        }
    }

    Ok((ActionScanStatus::from_complete(complete), nested_remote))
}

pub(crate) async fn scan_action_source(
    client: &GitHubClient,
    action: &ActionRef,
    collector: &mut AuditCollector,
    config: &Config,
) -> Result<ActionScanStatus> {
    let mut queue = VecDeque::from([(action.clone(), 0usize)]);
    let mut visited = HashSet::new();
    let mut complete = true;
    let mut remaining_bytes = MAX_ACTION_GRAPH_SOURCE_BYTES;

    while let Some((current, depth)) = queue.pop_front() {
        let key = remote_action_scan_key(&current);
        if !visited.insert(key) {
            continue;
        }
        if visited.len() > MAX_ACTION_GRAPH_NODES {
            complete = false;
            break;
        }

        let (status, nested) =
            scan_one_action_source(client, &current, collector, config, &mut remaining_bytes)
                .await?;
        complete &= status == ActionScanStatus::Complete && nested.complete;

        for child in nested.remote {
            if child.ref_type != workflow::RefType::Sha {
                complete = false;
                continue;
            }
            if depth == MAX_ACTION_GRAPH_DEPTH {
                complete = false;
            } else {
                queue.push_back((child, depth + 1));
            }
        }
        for local in nested.local {
            let Some(child) = nested_local_action(&current, &local) else {
                complete = false;
                continue;
            };
            if depth == MAX_ACTION_GRAPH_DEPTH {
                complete = false;
            } else {
                queue.push_back((child, depth + 1));
            }
        }
    }

    Ok(ActionScanStatus::from_complete(complete))
}

async fn scan_one_action_source(
    client: &GitHubClient,
    action: &ActionRef,
    collector: &mut AuditCollector,
    config: &Config,
    remaining_graph_bytes: &mut usize,
) -> Result<(ActionScanStatus, NestedUses)> {
    let action_name = format!("{}@{}", action.full_name(), short_sha(&action.ref_string));
    let tree = client
        .fetch_tree(&action.owner, &action.repo, &action.ref_string)
        .await?;

    let base = action.subpath.as_deref().unwrap_or("");
    let mut targets = select_source_files(&tree.entries, base);
    let mut complete = true;
    if targets.len() > MAX_SOURCE_FILES {
        targets.truncate(MAX_SOURCE_FILES);
        complete = false;
    }
    if targets.is_empty() {
        return Ok((
            ActionScanStatus::from_complete(!tree.truncated),
            NestedUses::complete(),
        ));
    }

    // Fetch concurrently, then scan in tree order so findings are
    // deterministic regardless of which fetch lands first. A failed fetch
    // makes the scan incomplete, so the caller will not cache a clean verdict.
    let initial_budget = (*remaining_graph_bytes).min(MAX_TOTAL_SOURCE_BYTES);
    if initial_budget == 0 {
        return Ok((ActionScanStatus::Incomplete, NestedUses::complete()));
    }
    let (mut contents, fetched_complete, initial_bytes) =
        fetch_remote_source_files(client, action, &targets, initial_budget).await;
    *remaining_graph_bytes = remaining_graph_bytes.saturating_sub(initial_bytes);
    complete &= fetched_complete;
    let mut action_bytes = initial_bytes;
    let mut initial_len = targets.len();
    complete &= force_include_remote_action_entrypoints(&mut targets, &contents);
    if let Some(keep_initial) = cap_targets_prioritizing_entrypoints(&mut targets, initial_len) {
        complete = false;
        contents.truncate(keep_initial);
        initial_len = keep_initial;
    }
    if targets.len() > initial_len {
        let added_budget =
            (*remaining_graph_bytes).min(MAX_TOTAL_SOURCE_BYTES.saturating_sub(action_bytes));
        if added_budget == 0 {
            complete = false;
        } else {
            let (new_contents, new_complete, added_bytes) =
                fetch_remote_source_files(client, action, &targets[initial_len..], added_budget)
                    .await;
            *remaining_graph_bytes = remaining_graph_bytes.saturating_sub(added_bytes);
            contents.extend(new_contents);
            complete &= new_complete;
            action_bytes = action_bytes.saturating_add(added_bytes);
        }
    }

    loop {
        let fetched_len = targets.len();
        complete &=
            force_include_remote_source_dependencies(&tree.entries, base, &mut targets, &contents);
        if targets.len() == fetched_len {
            break;
        }
        if targets.len() > MAX_SOURCE_FILES {
            targets.truncate(MAX_SOURCE_FILES);
            complete = false;
        }
        if targets.len() == fetched_len {
            break;
        }
        let added_budget =
            (*remaining_graph_bytes).min(MAX_TOTAL_SOURCE_BYTES.saturating_sub(action_bytes));
        if added_budget == 0 {
            complete = false;
            break;
        }
        let (new_contents, new_complete, added_bytes) =
            fetch_remote_source_files(client, action, &targets[fetched_len..], added_budget).await;
        *remaining_graph_bytes = remaining_graph_bytes.saturating_sub(added_bytes);
        contents.extend(new_contents);
        complete &= new_complete;
        action_bytes = action_bytes.saturating_add(added_bytes);
    }

    let mut nested_uses = NestedUses::complete();
    for ((path, kind), content) in targets.iter().zip(contents) {
        let content = match content {
            Some(Ok(content)) => content,
            _ => continue,
        };
        let source_label = format!("{} ({path})", action.full_name());
        match kind {
            SourceFileKind::ActionYml => match serde_norway::from_str::<Value>(&content) {
                Ok(yaml) => {
                    let nested =
                        scan_action_yml_runs(&yaml, &source_label, &action_name, collector, config);
                    nested_uses.complete &= nested.complete;
                    nested_uses.remote.extend(nested.remote);
                    nested_uses.local.extend(nested.local);
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
            SourceFileKind::Shell => {
                scan_shell_content(&content, &source_label, 0, &action_name, collector, config);
            }
            SourceFileKind::WorkflowYml => {
                let nested = scan_reusable_workflow(
                    &content,
                    &source_label,
                    &action_name,
                    collector,
                    config,
                );
                nested_uses.complete &= nested.complete;
                nested_uses.remote.extend(nested.remote);
                nested_uses.local.extend(nested.local);
            }
            SourceFileKind::Dockerfile => {
                scan_dockerfile_content(&content, &source_label, &action_name, collector, config);
            }
        }
    }

    Ok((ActionScanStatus::from_complete(complete), nested_uses))
}

fn nested_local_action(parent: &ActionRef, reference: &str) -> Option<ActionRef> {
    let relative = reference.strip_prefix("$/")?;
    let components: Option<Vec<&str>> = Path::new(relative)
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect();
    let relative = components?.join("/");
    if relative.is_empty() {
        return None;
    }
    Some(ActionRef {
        owner: parent.owner.clone(),
        repo: parent.repo.clone(),
        subpath: Some(relative),
        ref_string: parent.ref_string.clone(),
        ref_type: parent.ref_type.clone(),
        tag_comment: None,
        line_number: 0,
        raw_line: format!("uses: {reference}"),
        value_start: 0,
        value_end: 0,
        block_style: true,
    })
}

fn scan_action_yml_runs(
    yaml: &Value,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) -> NestedUses {
    let mut nested = NestedUses::complete();
    // runs.steps[].run (composite actions), including nested parallel groups.
    // base_line 0: positions are block-relative — the block is never located
    // inside the fetched file.
    if let Some(steps) = yaml.get("runs").and_then(|r| r.get("steps")) {
        let mut shell_state = ShellScanState::default();
        for (run, working_directory) in collect_step_run_blocks_with_directory(steps, None) {
            scan_shell_content_with_state_at(
                run,
                source_file,
                0,
                action_name,
                collector,
                config,
                working_directory,
                &mut shell_state,
            );
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

    if let Some(image) = yaml
        .get("runs")
        .and_then(|runs| runs.get("image"))
        .and_then(|image| image.as_str())
        .and_then(|image| image.strip_prefix("docker://"))
    {
        push_docker_ref_result(
            &workflow::DockerRef {
                image: image.to_string(),
                pin: workflow::classify_docker_image(image),
                line_number: 0,
                raw_line: format!("runs.image: docker://{image}"),
            },
            source_file,
            collector,
        );
    }

    if let Some(steps) = yaml.get("runs").and_then(|runs| runs.get("steps")) {
        for uses in collect_step_uses(steps) {
            if let Some(image) = uses.strip_prefix("docker://") {
                push_docker_ref_result(
                    &workflow::DockerRef {
                        image: image.to_string(),
                        pin: workflow::classify_docker_image(image),
                        line_number: 0,
                        raw_line: format!("uses: {uses}"),
                    },
                    source_file,
                    collector,
                );
            } else {
                if let Some(action) = workflow::parse_external_action_reference(uses) {
                    nested.remote.push(action);
                } else if nested_local_action_reference(uses) {
                    nested.local.push(uses.to_string());
                } else {
                    nested.complete = false;
                }
            }
        }
    }
    nested
}

fn nested_local_action_reference(reference: &str) -> bool {
    let Some(relative) = reference
        .strip_prefix("./")
        .or_else(|| reference.strip_prefix("$/"))
    else {
        return false;
    };
    !relative.is_empty()
        && Path::new(relative)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn collect_step_uses(steps: &Value) -> Vec<&str> {
    fn collect<'a>(value: &'a Value, uses: &mut Vec<&'a str>) {
        if let Some(sequence) = value.as_sequence() {
            for item in sequence {
                collect(item, uses);
            }
        } else if let Some(mapping) = value.as_mapping() {
            for (key, value) in mapping {
                if key.as_str() == Some("uses") {
                    if let Some(reference) = value.as_str() {
                        uses.push(reference);
                    }
                } else if key.as_str() == Some("parallel") {
                    collect(value, uses);
                }
            }
        }
    }
    let mut uses = Vec::new();
    collect(steps, &mut uses);
    uses
}

fn scan_reusable_workflow(
    content: &str,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) -> NestedUses {
    let mut nested = NestedUses::complete();
    let Ok(jobs) = extract_job_run_blocks(Path::new(source_file), content) else {
        nested.complete = false;
        return nested;
    };
    for blocks in jobs {
        let mut shell_state = ShellScanState::default();
        for block in blocks {
            scan_shell_content_with_state_at(
                &block.content,
                source_file,
                block.line,
                action_name,
                collector,
                config,
                block.working_directory.as_deref(),
                &mut shell_state,
            );
        }
    }
    for docker in workflow::scan_docker_refs(content) {
        push_docker_ref_result(&docker, source_file, collector);
    }
    nested.remote = workflow::scan_content(content);
    nested.local = workflow::scan_local_actions(content)
        .into_iter()
        .map(|action| repository_bound_reusable_workflow(&action.path))
        .collect();
    nested.complete = workflow::scan_unsupported_uses(content).is_empty();
    nested
}

fn repository_bound_reusable_workflow(reference: &str) -> String {
    let Some(relative) = reference.strip_prefix("./") else {
        return reference.to_string();
    };
    if [
        ".github/workflows/",
        ".forgejo/workflows/",
        ".gitea/workflows/",
    ]
    .iter()
    .any(|root| relative.starts_with(root))
    {
        format!("$/{relative}")
    } else {
        reference.to_string()
    }
}

pub(crate) fn short_sha(sha: &str) -> &str {
    match sha.char_indices().nth(7) {
        Some((end, _)) => &sha[..end],
        None => sha,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static DEFAULT_CONFIG: LazyLock<Config> = LazyLock::new(Config::default);

    #[test]
    fn dependency_detection_ignores_comments_and_absolute_python_imports() {
        let javascript = strip_javascript_comments(
            "/* import './comment.js' */\n// import './also-commented.js'\nimport './runtime.js';",
        );
        let dependencies: Vec<_> = JS_LOCAL_DEPENDENCY_RE
            .captures_iter(&javascript)
            .filter_map(|captures| captures.name("path").map(|path| path.as_str()))
            .collect();
        assert_eq!(dependencies, vec!["./runtime.js"]);
        assert!(!PYTHON_RELATIVE_IMPORT_RE.is_match("import os\nfrom pathlib import Path"));
        assert!(PYTHON_RELATIVE_IMPORT_RE.is_match("from .helper import run"));
    }

    #[test]
    fn javascript_loader_detection_fails_closed_without_matching_strings() {
        let tree = vec![
            tree_entry("action/index.js", "blob"),
            tree_entry("action/addon.node", "blob"),
            tree_entry("shared/helper.js", "blob"),
        ];
        for source in [
            "require('./addon.node');",
            "require('../../shared/' + 'helper.js');",
            "require(loaderPath);",
        ] {
            let mut targets = vec![("action/index.js".to_string(), SourceFileKind::JavaScript)];
            assert!(!force_include_remote_source_dependencies(
                &tree,
                "action",
                &mut targets,
                &[Some(Ok(source.to_string()))]
            ));
        }

        let mut targets = vec![("action/index.js".to_string(), SourceFileKind::JavaScript)];
        assert!(force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut targets,
            &[Some(Ok(
                "console.log(\"use require(loaderPath) here\"); const text = `require(loaderPath)`; require(42);"
                    .to_string()
            ))]
        ));

        let mut template_targets =
            vec![("action/index.js".to_string(), SourceFileKind::JavaScript)];
        assert!(force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut template_targets,
            &[Some(Ok(
                "const loaded = `${require('../shared/helper.js')}`;".to_string()
            ))]
        ));
        assert!(
            template_targets
                .contains(&("shared/helper.js".to_string(), SourceFileKind::JavaScript))
        );

        let mut evaluated_targets = vec![(
            "action/dist/index.js".to_string(),
            SourceFileKind::JavaScript,
        )];
        assert!(force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut evaluated_targets,
            &[Some(Ok(
                "eval(\"require('../../shared/helper.js')\")".to_string()
            ))]
        ));
        assert!(
            evaluated_targets
                .contains(&("shared/helper.js".to_string(), SourceFileKind::JavaScript))
        );

        let mut template_targets = vec![(
            "action/dist/index.js".to_string(),
            SourceFileKind::JavaScript,
        )];
        assert!(force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut template_targets,
            &[Some(Ok(
                "eval(`require('../../shared/helper.js')`)".to_string()
            ))]
        ));
        assert!(
            template_targets
                .contains(&("shared/helper.js".to_string(), SourceFileKind::JavaScript))
        );

        let mut inert_targets = vec![("action/index.js".to_string(), SourceFileKind::JavaScript)];
        assert!(force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut inert_targets,
            &[Some(Ok(
                "const docs = `eval(\"require('./missing.js')\")`;".to_string()
            ))]
        ));
        assert_eq!(inert_targets.len(), 1);

        let mut interpolated_targets = vec![(
            "action/dist/index.js".to_string(),
            SourceFileKind::JavaScript,
        )];
        assert!(!force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut interpolated_targets,
            &[Some(Ok(
                "eval(`require('../../shared/${name}.js')`)".to_string()
            ))]
        ));

        let mut concatenated_targets = vec![(
            "action/dist/index.js".to_string(),
            SourceFileKind::JavaScript,
        )];
        assert!(!force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut concatenated_targets,
            &[Some(Ok(
                "eval(`require('../../shared/` + name + `.js')`)".to_string()
            ))]
        ));

        let mut function_targets = vec![(
            "action/dist/index.js".to_string(),
            SourceFileKind::JavaScript,
        )];
        assert!(force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut function_targets,
            &[Some(Ok(
                "Function('name', \"require('../../shared/helper.js')\")()".to_string()
            ))]
        ));
        assert!(
            function_targets
                .contains(&("shared/helper.js".to_string(), SourceFileKind::JavaScript))
        );

        for source in [
            "(eval)(\"require('../../shared/helper.js')\")",
            "eval?.(\"require('../../shared/helper.js')\")",
            "(Function)(\"require('../../shared/helper.js')\")()",
            "(0, eval)(\"require('../../shared/helper.js')\")",
            "((eval))(\"require('../../shared/helper.js')\")",
            "eval.call(null, \"require('../../shared/helper.js')\")",
            "eval?.call(null, \"require('../../shared/helper.js')\")",
            "(eval).call(null, \"require('../../shared/helper.js')\")",
            "(eval)?.call(null, \"require('../../shared/helper.js')\")",
            "eval.bind(null)(\"require('../../shared/helper.js')\")",
            "eval?.bind(null)(\"require('../../shared/helper.js')\")",
            "(eval).bind(null)(\"require('../../shared/helper.js')\")",
            "(eval)?.bind(null)(\"require('../../shared/helper.js')\")",
        ] {
            let mut indirect_targets = vec![(
                "action/dist/index.js".to_string(),
                SourceFileKind::JavaScript,
            )];
            assert!(force_include_remote_source_dependencies(
                &tree,
                "action",
                &mut indirect_targets,
                &[Some(Ok(source.to_string()))]
            ));
            assert!(
                indirect_targets
                    .contains(&("shared/helper.js".to_string(), SourceFileKind::JavaScript)),
                "source: {source}"
            );
        }

        for source in [
            "eval.apply(null, [\"require('../../shared/helper.js')\"])",
            "eval?.apply(null, [\"require('../../shared/helper.js')\"])",
            "(eval).apply(null, [\"require('../../shared/helper.js')\"])",
            "(eval)?.apply(null, [\"require('../../shared/helper.js')\"])",
            "eval[\"call\"](null, \"require('../../shared/helper.js')\")",
            "eval?.[\"bind\"](null)(\"require('../../shared/helper.js')\")",
            "(eval)[\"call\"](null, \"require('../../shared/helper.js')\")",
            "(eval)?.[\"apply\"](null, [\"require('../../shared/helper.js')\"])",
            r#"eval.c\u0061ll(null, "require('../../shared/helper.js')")"#,
            r#"(eval)?.c\u0061ll(null, "require('../../shared/helper.js')")"#,
        ] {
            let mut indirect_targets = vec![(
                "action/dist/index.js".to_string(),
                SourceFileKind::JavaScript,
            )];
            assert!(!force_include_remote_source_dependencies(
                &tree,
                "action",
                &mut indirect_targets,
                &[Some(Ok(source.to_string()))]
            ));
        }

        let mut function_bind_alias = vec![(
            "action/dist/index.js".to_string(),
            SourceFileKind::JavaScript,
        )];
        assert!(force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut function_bind_alias,
            &[Some(Ok("const bind = Function.bind;".to_string()))]
        ));
    }

    #[test]
    fn remote_dependencies_are_resolved_against_the_tree() {
        let tree = vec![
            tree_entry("action/dist/index.js", "blob"),
            tree_entry("shared/helper.js", "blob"),
        ];
        let mut targets = vec![(
            "action/dist/index.js".to_string(),
            SourceFileKind::JavaScript,
        )];
        let contents = vec![Some(Ok(
            "require('../../shared/helper'); /* require('../../missing.js') */".to_string(),
        ))];

        assert!(force_include_remote_source_dependencies(
            &tree,
            "action",
            &mut targets,
            &contents
        ));
        assert!(targets.contains(&("shared/helper.js".to_string(), SourceFileKind::JavaScript)));
    }

    #[test]
    fn remote_workspace_relative_action_is_not_mapped_to_parent_repository() {
        let parent = ActionRef {
            owner: "owner".into(),
            repo: "action".into(),
            subpath: None,
            ref_string: "0123456789abcdef0123456789abcdef01234567".into(),
            ref_type: workflow::RefType::Sha,
            tag_comment: None,
            line_number: 1,
            raw_line: String::new(),
            value_start: 0,
            value_end: 0,
            block_style: true,
        };

        assert!(nested_local_action(&parent, "./consumer-action").is_none());
        assert_eq!(
            nested_local_action(&parent, "$/repository-action").and_then(|action| action.subpath),
            Some("repository-action".to_string())
        );
        assert_eq!(
            nested_local_action(&parent, "$/repository-action/").and_then(|action| action.subpath),
            Some("repository-action".to_string())
        );
        assert!(nested_local_action(&parent, "$//repository-action").is_none());
    }

    #[test]
    fn reusable_workflow_local_children_are_repository_bound() {
        let mut collector = AuditCollector::new(false);
        let nested = scan_reusable_workflow(
            "jobs:\n  child:\n    uses: ./.github/workflows/child.yml\n",
            ".github/workflows/parent.yml",
            "owner/repo",
            &mut collector,
            &DEFAULT_CONFIG,
        );
        assert!(nested.complete);
        assert_eq!(
            nested.local,
            vec!["$/.github/workflows/child.yml".to_string()]
        );
    }

    #[test]
    fn docker_copy_sources_preserve_local_inputs() {
        let (sources, complete) = docker_local_source_paths(
            "COPY entrypoint.sh /entrypoint.sh\nCOPY [\"src/tool.py\", \"/tool.py\"]\nCOPY --from=builder /bin/tool /bin/tool\n",
        );
        assert!(complete);
        assert_eq!(sources, vec!["entrypoint.sh", "src/tool.py"]);
    }

    #[test]
    fn extensionless_composite_helper_fails_closed() {
        let yaml: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: $GITHUB_ACTION_PATH/helper\n",
        )
        .unwrap();
        assert!(!action_yml_runtime_paths_complete(&yaml, "action"));
    }

    #[test]
    fn composite_helpers_follow_action_path_working_directories() {
        for yaml in [
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      working-directory: ${{ github.action_path }}\n      run: ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: pushd \"$GITHUB_ACTION_PATH\" && ./install.sh\n",
        ] {
            let yaml: Value = serde_norway::from_str(yaml).unwrap();
            assert_eq!(
                action_yml_helper_references(&yaml),
                vec!["install.sh".to_string()]
            );
            assert!(action_yml_runtime_paths_complete(&yaml, "action"));
        }

        let relative: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && cd scripts && ./install.sh\n",
        )
        .unwrap();
        assert_eq!(
            action_yml_helper_references(&relative),
            vec!["scripts/install.sh".to_string()]
        );

        let option_terminated: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && cd -- scripts && ./install.sh\n",
        )
        .unwrap();
        assert_eq!(
            action_yml_helper_references(&option_terminated),
            vec!["scripts/install.sh".to_string()]
        );

        for unresolved in [
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && pushd scripts && popd +1 && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && pushd && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && pushd +1 && ./install.sh\n",
        ] {
            let unresolved: Value = serde_norway::from_str(unresolved).unwrap();
            assert!(!action_yml_runtime_paths_complete(&unresolved, "action"));
        }

        for prefixed in [
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && command cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && builtin cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=test command cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=\"test value\" command cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=$(printf test) command cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=$(printf test) builtin cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=`printf test` command cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=`printf test` builtin cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=${UNSET:-test value} command cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=${UNSET:-test value} builtin cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=<(printf test) command cd scripts && ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && MODE=<(printf test) builtin cd scripts && ./install.sh\n",
        ] {
            let prefixed: Value = serde_norway::from_str(prefixed).unwrap();
            assert_eq!(
                action_yml_helper_references(&prefixed),
                vec!["scripts/install.sh".to_string()]
            );
        }

        let powershell: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - shell: pwsh\n      working-directory: ${{ github.action_path }}\n      run: '& .\\install.ps1'\n",
        )
        .unwrap();
        assert_eq!(
            action_yml_helper_references(&powershell),
            vec!["install.ps1".to_string()]
        );
    }

    #[test]
    fn source_cap_prioritizes_metadata_entrypoints() {
        let mut targets: Vec<usize> = (0..MAX_SOURCE_FILES).collect();
        targets.push(usize::MAX);
        assert_eq!(
            cap_targets_prioritizing_entrypoints(&mut targets, MAX_SOURCE_FILES),
            Some(MAX_SOURCE_FILES - 1)
        );
        assert_eq!(targets.len(), MAX_SOURCE_FILES);
        assert_eq!(targets.last(), Some(&usize::MAX));
    }

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
    fn scan_action_yml_composite_steps_share_runtime_material_state() {
        let yaml: serde_norway::Value = serde_norway::from_str(
            r#"
runs:
  using: composite
  steps:
    - run: curl -o tool.sig https://example.com/v1.2.3/tool.sig
    - run: |
        curl -o tool https://example.com/tool
        gpg --verify tool.sig tool
"#,
        )
        .unwrap();
        let mut c = AuditCollector::new(false);

        scan_action_yml_runs(&yaml, "action.yml", "test-action", &mut c, &DEFAULT_CONFIG);

        assert_eq!(c.findings.len(), 1);
        assert_eq!(
            c.findings[0].pattern_matched,
            "curl -o tool https://example.com/tool"
        );
    }

    #[test]
    fn scan_action_yml_composite_steps_track_inline_directory_changes() {
        let yaml: serde_norway::Value = serde_norway::from_str(
            r#"
runs:
  using: composite
  steps:
    - run: mkdir -p dl && cd dl && curl -o tool.sig https://example.com/v1.2.3/tool.sig
    - run: |
        curl -o tool https://example.com/tool
        gpg --verify dl/tool.sig tool
"#,
        )
        .unwrap();
        let mut c = AuditCollector::new(false);

        scan_action_yml_runs(&yaml, "action.yml", "test-action", &mut c, &DEFAULT_CONFIG);

        assert_eq!(c.findings.len(), 1);
        assert_eq!(
            c.findings[0].pattern_matched,
            "curl -o tool https://example.com/tool"
        );
    }

    #[test]
    fn reusable_workflow_jobs_track_inline_directory_changes() {
        let workflow = r#"
on: workflow_call
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: mkdir -p dl && cd dl && curl -o tool.sig https://example.com/v1.2.3/tool.sig
      - run: |
          curl -o tool https://example.com/tool
          gpg --verify dl/tool.sig tool
"#;
        let mut c = AuditCollector::new(false);

        scan_reusable_workflow(
            workflow,
            ".github/workflows/reusable.yml",
            "test-action",
            &mut c,
            &DEFAULT_CONFIG,
        );

        assert_eq!(c.findings.len(), 1);
        assert_eq!(
            c.findings[0].pattern_matched,
            "curl -o tool https://example.com/tool"
        );
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
    - {cmd: "curl -L https://example.com/unversioned.sh | sh"}
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
    fn short_sha_handles_multibyte_refs() {
        assert_eq!(short_sha("🦀🦀"), "🦀🦀");
        assert_eq!(short_sha("aaaa🦀bb"), "aaaa🦀bb");
        assert_eq!(short_sha("abcdef1234🦀"), "abcdef1");
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
            value_start: 0,
            value_end: 0,
            block_style: true,
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
    fn action_yml_entrypoint_paths_normalize_within_repository() {
        let yaml: serde_norway::Value = serde_norway::from_str(
            r#"
runs:
  using: node20
  pre: ./preload
  main: dist/runner
  post: ../lib/post.js
"#,
        )
        .unwrap();

        assert_eq!(
            action_yml_entrypoint_paths(&yaml, "actions/sub"),
            vec![
                (
                    "actions/sub/dist/runner".to_string(),
                    SourceFileKind::JavaScript
                ),
                (
                    "actions/sub/preload".to_string(),
                    SourceFileKind::JavaScript
                ),
                (
                    "actions/lib/post.js".to_string(),
                    SourceFileKind::JavaScript
                )
            ]
        );
        assert!(normalize_action_entrypoint_path("", "/tmp/runner").is_none());
        assert!(normalize_action_entrypoint_path("", r"dist\\runner").is_none());
        assert!(normalize_action_entrypoint_path("", ".").is_none());
        assert!(normalize_action_entrypoint_path("actions/sub", "../../../outside.js").is_none());

        let no_runs: Value = serde_norway::from_str("name: test\n").unwrap();
        assert!(action_yml_entrypoint_paths(&no_runs, "").is_empty());
    }

    #[test]
    fn action_yml_helper_paths_only_include_declared_runtime_helpers() {
        let yaml: Value = serde_norway::from_str(
            r#"
runs:
  using: composite
  steps:
    - run: bash "$GITHUB_ACTION_PATH/scripts/install.sh"
      shell: bash
    - run: python "${{ github.action_path }}/scripts/check.py"
      shell: bash
    - run: '& "$PSScriptRoot/cleanup.ps1"'
      shell: pwsh
"#,
        )
        .unwrap();
        assert_eq!(
            action_yml_helper_paths(&yaml, "actions/sub"),
            vec![
                (
                    "actions/sub/scripts/install.sh".to_string(),
                    SourceFileKind::Shell
                ),
                (
                    "actions/sub/scripts/check.py".to_string(),
                    SourceFileKind::Python
                ),
                ("actions/sub/cleanup.ps1".to_string(), SourceFileKind::Shell),
            ]
        );
    }

    #[test]
    fn action_yml_helper_paths_follow_action_cwd_in_command_order() {
        let yaml: Value = serde_norway::from_str(
            r#"
runs:
  using: composite
  steps:
    - run: ./consumer.sh; cd "$GITHUB_ACTION_PATH/subdir" && echo "cd /tmp; ignored" && ./install.sh
      shell: bash
"#,
        )
        .unwrap();
        assert_eq!(
            action_yml_helper_paths(&yaml, "actions/local"),
            vec![(
                "actions/local/subdir/install.sh".to_string(),
                SourceFileKind::Shell
            )]
        );

        let unresolved: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - run: 'cd \"$GITHUB_ACTION_PATH/$SUBDIR\" && ./install.sh'\n",
        )
        .unwrap();
        assert!(!action_yml_runtime_paths_complete(
            &unresolved,
            "actions/local"
        ));
    }

    #[test]
    fn force_include_remote_entrypoints_ignores_unavailable_metadata() {
        for content in [None, Some(Ok("runs: [".to_string()))] {
            let mut targets = vec![("action.yml".to_string(), SourceFileKind::ActionYml)];
            assert!(!force_include_remote_action_entrypoints(
                &mut targets,
                &[content]
            ));
            assert_eq!(targets.len(), 1);
        }
    }

    #[test]
    fn force_include_local_entrypoints_ignores_unavailable_metadata() {
        let repo = tempfile::TempDir::new().unwrap();
        let action_dir = repo.path().join("action");
        std::fs::create_dir(&action_dir).unwrap();

        let missing = action_dir.join("missing.yml");
        let mut targets = vec![(missing, SourceFileKind::ActionYml)];
        assert!(!force_include_local_action_entrypoints(
            repo.path(),
            &action_dir,
            &mut targets
        ));
        assert_eq!(targets.len(), 1);

        let malformed = action_dir.join("action.yml");
        std::fs::write(&malformed, "runs: [").unwrap();
        let mut targets = vec![(malformed, SourceFileKind::ActionYml)];
        assert!(!force_include_local_action_entrypoints(
            repo.path(),
            &action_dir,
            &mut targets
        ));
        assert_eq!(targets.len(), 1);

        let metadata = repo.path().join("metadata.yml");
        std::fs::write(&metadata, "runs:\n  using: node20\n  main: runner\n").unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        let mut targets = vec![(metadata, SourceFileKind::ActionYml)];
        assert!(!force_include_local_action_entrypoints(
            repo.path(),
            outside.path(),
            &mut targets
        ));
        assert_eq!(targets.len(), 1);
    }

    #[test]
    fn dockerfile_path_comes_from_action_metadata() {
        let docker: Value =
            serde_norway::from_str("runs:\n  using: docker\n  image: Dockerfile\n").unwrap();
        assert_eq!(
            action_yml_dockerfile_path(&docker, ""),
            Some("Dockerfile".to_string())
        );
        assert_eq!(
            action_yml_dockerfile_path(&docker, "actions/sub"),
            Some("actions/sub/Dockerfile".to_string())
        );

        // A registry image is not a path in this repository; the container-ref
        // rules cover it instead.
        let registry: Value =
            serde_norway::from_str("runs:\n  using: docker\n  image: docker://alpine:3.20\n")
                .unwrap();
        assert!(action_yml_dockerfile_path(&registry, "").is_none());

        // A JavaScript action never builds an image, even in a repo that
        // happens to contain Dockerfiles.
        let js: Value =
            serde_norway::from_str("runs:\n  using: node20\n  main: dist/index.js\n").unwrap();
        assert!(action_yml_dockerfile_path(&js, "").is_none());
        let js_with_image: Value =
            serde_norway::from_str("runs:\n  using: node20\n  image: Dockerfile\n").unwrap();
        assert!(action_yml_dockerfile_path(&js_with_image, "").is_none());

        let no_image: Value = serde_norway::from_str("runs:\n  using: docker\n").unwrap();
        assert!(action_yml_dockerfile_path(&no_image, "").is_none());
    }

    #[test]
    fn referenced_dockerfile_is_force_included_unreferenced_is_not() {
        let targets_for = |image: &str| {
            let mut targets = vec![("action.yml".to_string(), SourceFileKind::ActionYml)];
            let contents = vec![Some(Ok(format!(
                "runs:\n  using: docker\n  image: {image}\n"
            )))];
            assert!(force_include_remote_action_entrypoints(
                &mut targets,
                &contents
            ));
            targets
        };
        // `runs.image` names it, so the consumer builds it: scanned.
        assert!(
            targets_for("test/Dockerfile")
                .contains(&("test/Dockerfile".to_string(), SourceFileKind::Dockerfile))
        );
        // Nothing references `test/Dockerfile`, so it stays out.
        assert!(
            !targets_for("docker://alpine:3.20")
                .iter()
                .any(|(_, kind)| *kind == SourceFileKind::Dockerfile)
        );
    }

    #[test]
    fn javascript_source_extensions_cover_typescript_module_variants() {
        for path in [
            "main.js", "main.ts", "main.mjs", "main.cjs", "main.mts", "main.cts",
        ] {
            assert!(is_javascript_source(path), "{path}");
        }
        assert!(!is_javascript_source("main.js.map"));
        assert!(!is_javascript_source("main.tsx"));
    }

    #[test]
    fn select_source_files_classifies_and_filters_in_order() {
        let tree = vec![
            tree_entry("action.yml", "blob"),
            tree_entry("sub/action.yaml", "blob"),
            tree_entry("dist/index.js", "blob"),
            tree_entry("dist/index.mjs", "blob"),
            tree_entry("src/main.cjs", "blob"),
            tree_entry("src/main.ts", "blob"),
            tree_entry("setup.py", "blob"),
            // Dockerfiles are never selected by name, at any depth. A nested
            // one no action metadata points at (a test
            // fixture, an example image) is not reachable, and neither is a
            // root one in a repository whose action is not a container action.
            // `force_include_remote_action_entrypoints` adds the ones that
            // `runs.image` actually names.
            tree_entry("Dockerfile", "blob"),
            tree_entry("sub/Dockerfile", "blob"),
            tree_entry("test/Dockerfile", "blob"),
            tree_entry("README.md", "blob"), // not scannable
            tree_entry("node_modules/dep/i.js", "blob"), // vendored — skipped
            tree_entry("src", "tree"),       // directory entry — skipped
        ];
        let got = select_source_files(&tree, "");
        assert_eq!(
            got,
            vec![("action.yml".to_string(), SourceFileKind::ActionYml)]
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
            vec![("action-a/action.yml".to_string(), SourceFileKind::ActionYml)]
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
            vec![("action-a/action.yml".to_string(), SourceFileKind::ActionYml)]
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
            action_dir.join("setup.py"),
            "requests.get('https://example.com/x')",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("node_modules/dep/index.js"),
            "fetch('https://evil.example/x')",
        )
        .unwrap();

        let (got, available, complete) = collect_local_source_files(&action_dir).unwrap();
        assert!(complete);
        let paths: Vec<_> = got
            .iter()
            .map(|(path, _)| {
                path.strip_prefix(&action_dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(paths, vec!["action.yml"]);
        assert_eq!(available.len(), 5);
    }

    #[test]
    fn read_local_source_file_returns_none_for_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(
            read_local_source_file(dir.path(), &dir.path().join("missing.js"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn read_local_source_file_rejects_oversized_input() {
        let dir = tempfile::TempDir::new().unwrap();
        let source = dir.path().join("large.js");
        std::fs::write(&source, vec![b'a'; MAX_SOURCE_FILE_BYTES + 1]).unwrap();
        let error = read_local_source_file(dir.path(), &source).unwrap_err();
        assert!(error.to_string().contains("source-file limit"));
    }

    #[test]
    fn scan_local_action_source_handles_empty_and_malformed_actions() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join("empty");
        std::fs::create_dir(&action_dir).unwrap();
        let action = LocalActionRef {
            path: "./empty".to_string(),
            line_number: 1,
        };
        let mut collector = AuditCollector::new(false);

        assert_eq!(
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap(),
            ActionScanStatus::Complete
        );

        std::fs::write(action_dir.join("action.yml"), "runs: [").unwrap();
        assert_eq!(
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap(),
            ActionScanStatus::Incomplete
        );
        assert!(collector.findings.is_empty());
    }

    #[test]
    fn scan_local_action_source_scans_python() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join("python-action");
        std::fs::create_dir(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("setup.py"),
            "requests.get('https://example.com/install')\n",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "runs:\n  using: composite\n  steps:\n    - run: python \"$GITHUB_ACTION_PATH/setup.py\"\n      shell: bash\n",
        )
        .unwrap();
        let action = LocalActionRef {
            path: "./python-action".to_string(),
            line_number: 1,
        };
        let mut collector = AuditCollector::new(false);

        assert_eq!(
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap(),
            ActionScanStatus::Complete
        );
        assert_eq!(collector.findings.len(), 1);
        assert_eq!(
            collector.findings[0].source_file,
            "./python-action (setup.py)"
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
    fn scan_local_action_source_scans_in_tree_imports_without_losing_completeness() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join(".github/actions/local");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "runs:\n  using: node20\n  main: index.js\n",
        )
        .unwrap();
        std::fs::write(action_dir.join("index.js"), "require('./helper.js');\n").unwrap();
        std::fs::write(
            action_dir.join("helper.js"),
            "fetch('https://example.com/latest/tool');\n",
        )
        .unwrap();

        let action = LocalActionRef {
            path: "./.github/actions/local".to_string(),
            line_number: 1,
        };
        let mut collector = AuditCollector::new(false);
        let status =
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert!(!collector.findings.is_empty());
        assert!(
            collector
                .findings
                .iter()
                .all(|finding| finding.source_file.ends_with("(helper.js)"))
        );
    }

    #[test]
    fn scan_local_action_source_accepts_common_in_tree_runtime_shapes() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join(".github/actions/local");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "runs:\n  using: docker\n  image: Dockerfile\n",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("Dockerfile"),
            "FROM alpine:3.20\nCOPY entrypoint.sh /entrypoint.sh\n",
        )
        .unwrap();
        std::fs::write(action_dir.join("entrypoint.sh"), "source ./helper.sh\n").unwrap();
        std::fs::write(action_dir.join("helper.sh"), "echo safe\n").unwrap();
        std::fs::write(action_dir.join("helper.py"), "import os\n").unwrap();

        let action = LocalActionRef {
            path: "./.github/actions/local".to_string(),
            line_number: 1,
        };
        let mut collector = AuditCollector::new(false);
        let status =
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
    }

    #[test]
    fn scan_local_action_source_exposes_sha_pinned_nested_action_for_scanning() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join(".github/actions/local");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n",
        )
        .unwrap();

        let action = LocalActionRef {
            path: "./.github/actions/local".to_string(),
            line_number: 1,
        };
        let mut collector = AuditCollector::new(false);
        let (status, nested) =
            scan_local_action_source_graph(dir.path(), &action, &mut collector, &DEFAULT_CONFIG)
                .unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].owner_repo(), "actions/checkout");
        assert_eq!(
            scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap(),
            ActionScanStatus::Incomplete
        );
        assert!(collector.findings.is_empty());
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
    fn scan_local_action_source_rejects_invalid_or_missing_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut collector = AuditCollector::new(false);

        for (path, expected) in [
            ("local", "local action path must start with ./"),
            ("./missing", "is not a directory"),
        ] {
            let action = LocalActionRef {
                path: path.to_string(),
                line_number: 1,
            };
            let err =
                scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG)
                    .unwrap_err();
            assert!(err.to_string().contains(expected), "path: {path}: {err}");
        }
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

    #[cfg(unix)]
    #[test]
    fn scan_local_action_source_rejects_symlinked_entrypoint_component() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        std::fs::write(
            outside.path().join("leak.js"),
            r#"fetch("https://example.com/OUT_OF_REPO_SECRET")"#,
        )
        .unwrap();

        let action_dir = dir.path().join(".github/actions/local");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "name: local\nruns:\n  using: node20\n  main: sub/leak.js\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), action_dir.join("sub")).unwrap();

        let action = LocalActionRef {
            path: "./.github/actions/local".to_string(),
            line_number: 1,
        };
        let mut collector = AuditCollector::new(false);
        scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG).unwrap();

        assert!(collector.findings.is_empty());
    }

    #[tokio::test]
    async fn scan_action_source_accepts_truncated_tree_with_exact_metadata() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/o/r/git/trees/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [{ "path": "action.yml", "type": "blob" }],
                "truncated": true
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/action.yml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("runs:\n  using: composite\n  steps: []\n"),
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
            value_start: 0,
            value_end: 0,
            block_style: true,
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert!(collector.findings.is_empty());
    }

    #[tokio::test]
    async fn scan_action_source_follows_sha_pinned_nested_action() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let root_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let child_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        Mock::given(method("GET"))
            .and(path(format!("/repos/o/root/git/trees/{root_sha}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [{ "path": "action.yml", "type": "blob" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/root/contents/action.yml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "runs:\n  using: composite\n  steps:\n    - uses: x/child@{child_sha}\n"
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/x/child/git/trees/{child_sha}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [{ "path": "action.yml", "type": "blob" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/x/child/contents/action.yml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "runs:\n  using: composite\n  steps:\n    - run: curl https://example.com/install | bash\n      shell: bash\n",
            ))
            .mount(&server)
            .await;

        let client = GitHubClient::with_base("t".into(), server.uri());
        let action = ActionRef {
            owner: "o".into(),
            repo: "root".into(),
            subpath: None,
            ref_string: root_sha.into(),
            ref_type: workflow::RefType::Sha,
            tag_comment: Some("v1.0.0".into()),
            line_number: 1,
            raw_line: String::new(),
            value_start: 0,
            value_end: 0,
            block_style: true,
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(collector.findings.len(), 1);
        assert_eq!(collector.findings[0].source_file, "x/child (action.yml)");
    }

    #[tokio::test]
    async fn scan_action_source_rejects_mutable_nested_action_ref() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let root_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        Mock::given(method("GET"))
            .and(path(format!("/repos/o/root/git/trees/{root_sha}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [{ "path": "action.yml", "type": "blob" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/root/contents/action.yml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n",
            ))
            .mount(&server)
            .await;

        let client = GitHubClient::with_base("t".into(), server.uri());
        let action = ActionRef {
            owner: "o".into(),
            repo: "root".into(),
            subpath: None,
            ref_string: root_sha.into(),
            ref_type: workflow::RefType::Sha,
            tag_comment: None,
            line_number: 1,
            raw_line: String::new(),
            value_start: 0,
            value_end: 0,
            block_style: true,
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Incomplete);
        assert!(collector.findings.is_empty());
    }

    #[tokio::test]
    async fn scan_action_source_reports_incomplete_when_truncated_tree_has_no_targets() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/o/r/git/trees/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [{ "path": "README.md", "type": "blob" }],
                "truncated": true
            })))
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
            value_start: 0,
            value_end: 0,
            block_style: true,
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Incomplete);
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
            value_start: 0,
            value_end: 0,
            block_style: true,
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
            value_start: 0,
            value_end: 0,
            block_style: true,
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
    async fn root_action_scan_routes_only_its_reachable_python() {
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
                    { "path": "sub/action.yml", "type": "blob" },
                    { "path": "setup.py", "type": "blob" },
                    { "path": "sub/Dockerfile", "type": "blob" }
                ]
            })))
            .mount(&server)
            .await;
        for (source_path, content) in [
            (
                "action.yml",
                "runs:\n  using: composite\n  steps:\n    - run: python \"$GITHUB_ACTION_PATH/setup.py\"\n      shell: bash\n",
            ),
            (
                "sub/action.yml",
                "runs:\n  using: docker\n  image: Dockerfile\n",
            ),
            ("setup.py", "requests.get('https://example.com/install')\n"),
            (
                "sub/Dockerfile",
                "FROM alpine:3.20\nRUN curl https://example.com/install -o tool\n",
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/repos/o/r/contents/{source_path}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(content))
                .mount(&server)
                .await;
        }

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
            value_start: 0,
            value_end: 0,
            block_style: true,
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(collector.findings.len(), 1);
        assert!(
            collector
                .findings
                .iter()
                .any(|finding| finding.source_file == "o/r (setup.py)")
        );
        assert!(
            !collector
                .findings
                .iter()
                .any(|finding| finding.source_file == "o/r (sub/Dockerfile)")
        );
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
                    { "path": "lib/runner", "type": "blob" }
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/sub/action.yml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("runs:\n  using: node20\n  main: ../lib/runner\n"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/lib/runner"))
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
            subpath: Some("sub".into()),
            ref_string: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ref_type: workflow::RefType::Sha,
            tag_comment: Some("v1.0.0".into()),
            line_number: 1,
            raw_line: String::new(),
            value_start: 0,
            value_end: 0,
            block_style: true,
        };
        let mut collector = AuditCollector::new(false);

        let status = scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
            .await
            .unwrap();

        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(collector.findings.len(), 1);
        assert_eq!(collector.findings[0].source_file, "o/r/sub (lib/runner)");
    }
}
