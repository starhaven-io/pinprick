//! Shell tokenizer and target-extraction layer for the audit scanners.
//!
//! Splits shell text into logical lines, pipelines, and commands, then
//! answers the questions the pattern layer asks of that structure: where a
//! fetch writes its output, whether a checksum command verifies that target,
//! whether a `git clone` is bound to a SHA checkout, and whether a fetch is
//! piped into `jq`.

use crate::audit_patterns::{git_clone_has_pinned_ref, has_checksum_verify};
use regex::Regex;
use std::sync::LazyLock;

static INLINE_DIGEST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:[0-9a-f]{64}|[0-9a-f]{128})$").unwrap());
static POWERSHELL_FILE_HASH_LITERAL_COMPARE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?ix)\(\s*Get-FileHash(?:\s+-(?:Literal)?Path)?\s+"#,
        r#"(?P<target>"[^\"]+"|'[^']+'|[^\s)]+)"#,
        r#"(?:\s+-Algorithm\s+[A-Za-z0-9-]+)?\s*\)\.Hash\s*"#,
        r#"-(?:c)?(?:eq|ne)\s+["']?(?:[0-9a-f]{64}|[0-9a-f]{128})["']?"#,
    ))
    .unwrap()
});

pub(crate) const UNKNOWN_FETCH_OUTPUT: &str = "<unknown runtime fetch output>";

/// Whether a shell source line is a pure comment and thus never executed.
/// Trailing comments on a command line are not covered — stripping an
/// unquoted `#` would require full shell tokenization and risks hiding a
/// real payload embedded in a quoted string.
pub(crate) fn is_shell_comment_line(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// Join shell lines ending in `\` into a single logical line, anchored at the
/// 0-based index of the first physical line.
pub(crate) fn join_continuations(content: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (i, raw) in content.lines().enumerate() {
        let trimmed_end = raw.trim_end();
        // A comment never continues onto the next line — a trailing backslash
        // is just comment text, so the next line is a new command. Joining it
        // into the comment would hide it from the scan.
        let backslash_continuation = trimmed_end.ends_with('\\');
        let operator_continuation = ends_with_pipeline_operator(trimmed_end);
        let is_continuation = (backslash_continuation || operator_continuation)
            && !(pending.is_none() && is_shell_comment_line(raw));
        let body = if backslash_continuation {
            &trimmed_end[..trimmed_end.len() - 1]
        } else {
            raw
        };
        match pending.as_mut() {
            Some((_, buf)) => {
                buf.push(' ');
                buf.push_str(body.trim());
            }
            None => {
                pending = Some((i, body.to_string()));
            }
        }
        if !is_continuation && let Some((start, buf)) = pending.take() {
            out.push((start, buf));
        }
    }
    if let Some(p) = pending {
        out.push(p);
    }
    out
}

fn ends_with_pipeline_operator(line: &str) -> bool {
    line.ends_with('|') || line.ends_with("&&") || line.ends_with("||")
}

#[derive(Debug, Clone)]
struct ShellCommand {
    text: String,
    stages: Vec<ShellStage>,
    following_control: Option<ShellControl>,
}

#[derive(Debug, Clone)]
struct ShellStage {
    text: String,
    words: Vec<String>,
}

#[derive(Debug, Clone)]
struct GitCloneCommand {
    dir: String,
    command_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellControl {
    And,
    Or,
    Sequence,
    Background,
}

fn parse_shell_line(line: &str) -> Vec<ShellCommand> {
    split_shell_control_parts(line)
        .into_iter()
        .filter_map(|(command, following_control)| {
            let stages: Vec<ShellStage> = split_shell_pipeline(&command)
                .into_iter()
                .map(|stage| ShellStage {
                    words: shell_words(&stage),
                    text: stage,
                })
                .collect();
            if stages.is_empty() {
                None
            } else {
                Some(ShellCommand {
                    text: command,
                    stages,
                    following_control,
                })
            }
        })
        .collect()
}

#[cfg(test)]
fn split_shell_control(line: &str) -> Vec<String> {
    split_shell_control_parts(line)
        .into_iter()
        .map(|(command, _)| command)
        .collect()
}

fn split_shell_control_parts(line: &str) -> Vec<(String, Option<ShellControl>)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            current.push(ch);
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            current.push(ch);
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            current.push(ch);
            continue;
        }

        let control = match ch {
            ';' => Some(ShellControl::Sequence),
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                Some(ShellControl::And)
            }
            '|' if chars.peek() == Some(&'|') => {
                chars.next();
                Some(ShellControl::Or)
            }
            '&' if chars.peek() != Some(&'>') && !current.trim_end().ends_with('>') => {
                Some(ShellControl::Background)
            }
            _ => None,
        };
        if let Some(control) = control {
            let part = current.trim();
            if !part.is_empty() {
                out.push((part.to_string(), Some(control)));
            }
            current.clear();
        } else {
            current.push(ch);
        }
    }

    let part = current.trim();
    if !part.is_empty() {
        out.push((part.to_string(), None));
    }
    out
}

fn split_shell_pipeline(line: &str) -> Vec<String> {
    split_shell(line, SplitMode::Pipeline)
}

enum SplitMode {
    Pipeline,
}

fn split_shell(line: &str, mode: SplitMode) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            current.push(ch);
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            current.push(ch);
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            current.push(ch);
            continue;
        }

        match mode {
            SplitMode::Pipeline if ch == '|' && chars.peek() != Some(&'|') => {
                push_shell_part(&mut out, &mut current);
            }
            _ => current.push(ch),
        }
    }

    push_shell_part(&mut out, &mut current);
    out
}

fn push_shell_part(out: &mut Vec<String>, current: &mut String) {
    let part = current.trim();
    if !part.is_empty() {
        out.push(part.to_string());
    }
    current.clear();
}

pub(crate) fn shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut substitution_delimiters = Vec::new();

    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if matches!(ch, '$' | '<' | '>')
            && let Some((opening, closing)) = chars.peek().and_then(|next| match (ch, *next) {
                ('<' | '>', '(') => Some(('(', ')')),
                ('<' | '>', _) => None,
                ('$', '(') => Some(('(', ')')),
                ('$', '{') => Some(('{', '}')),
                ('$', '[') => Some(('[', ']')),
                _ => None,
            })
        {
            chars.next();
            current.push(ch);
            current.push(opening);
            substitution_delimiters.push(closing);
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if let Some(closing) = substitution_delimiters.last().copied() {
            if ch == closing {
                substitution_delimiters.pop();
            } else if let Some(nested_closing) = match ch {
                '(' => Some(')'),
                '{' => Some('}'),
                '[' => Some(']'),
                _ => None,
            } {
                substitution_delimiters.push(nested_closing);
            }
            current.push(ch);
            continue;
        }
        if ch.is_whitespace() {
            push_shell_word(&mut words, &mut current);
            continue;
        }
        if ch == '>' {
            push_shell_word(&mut words, &mut current);
            if chars.peek() == Some(&'>') {
                chars.next();
                words.push(">>".to_string());
            } else {
                words.push(">".to_string());
            }
            continue;
        }
        current.push(ch);
    }

    push_shell_word(&mut words, &mut current);
    words
}

fn push_shell_word(words: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        words.push(std::mem::take(current));
    }
}

pub(crate) fn url_piped_to_jq(line: &str, url: &str) -> bool {
    parse_shell_line(line).into_iter().any(|command| {
        let Some(fetch_stage) = command
            .stages
            .iter()
            .position(|stage| stage.text.contains(url))
        else {
            return false;
        };
        command
            .stages
            .iter()
            .skip(fetch_stage + 1)
            .any(stage_invokes_jq)
    })
}

fn stage_invokes_jq(stage: &ShellStage) -> bool {
    command_word_index(&stage.words).is_some_and(|idx| stage.words[idx] == "jq")
}

fn command_word_index(words: &[String]) -> Option<usize> {
    words
        .iter()
        .position(|word| !word.contains('=') || word.starts_with('-'))
}

pub(crate) fn fetch_output_targets(line: &str) -> Vec<String> {
    fetch_output_targets_with_config(line, false, false)
}

pub(crate) fn fetch_output_targets_with_config(
    line: &str,
    wget_configured: bool,
    curl_configured: bool,
) -> Vec<String> {
    let mut targets = Vec::new();
    for command in parse_shell_line(line) {
        for stage in command.stages {
            for target in fetch_output_targets_for_stage(&stage, wget_configured, curl_configured) {
                if !targets.contains(&target) {
                    targets.push(target);
                }
            }
        }
    }
    targets
}

pub(crate) fn mutates_wget_config(line: &str) -> bool {
    mutates_wget_config_file(line) || mutates_wget_environment(line)
}

pub(crate) fn mutates_wget_config_file(line: &str) -> bool {
    mutates_named_fetch_config(line, &[".wgetrc", ".netrc"])
}

fn mutates_wget_environment(line: &str) -> bool {
    parse_shell_line(line).into_iter().any(|command| {
        command.stages.into_iter().any(|stage| {
            let literal_mutation = stage.words.iter().any(|word| {
                word == "WGETRC"
                    || word.starts_with("WGETRC+=")
                    || word
                        .strip_prefix("WGETRC=")
                        .is_some_and(|value| !value.is_empty())
            });
            let dynamic_named_assignment = stage
                .words
                .iter()
                .any(|word| word.starts_with('$') && word.contains('='));
            let has_dynamic_name = stage.words.iter().any(|word| word.starts_with('$'));
            let indirect_variable_mutation = has_dynamic_name
                && (stage
                    .words
                    .iter()
                    .any(|word| matches!(word.as_str(), "export" | "declare" | "typeset"))
                    || (stage.words.iter().any(|word| word == "printf")
                        && stage.words.iter().any(|word| word == "-v")));
            literal_mutation || dynamic_named_assignment || indirect_variable_mutation
        })
    })
}

pub(crate) fn mutates_curl_config(line: &str) -> bool {
    mutates_named_fetch_config(line, &[".curlrc", ".netrc"])
}

fn mutates_named_fetch_config(line: &str, config_names: &[&str]) -> bool {
    parse_shell_line(line).into_iter().any(|command| {
        command
            .stages
            .into_iter()
            .any(|stage| stage_mutates_named_config(&stage, config_names))
    })
}

fn stage_mutates_named_config(stage: &ShellStage, config_names: &[&str]) -> bool {
    let is_config_path = |word: &str| {
        let normalized = normalize_path_token(word);
        config_names.iter().any(|name| normalized.ends_with(name))
    };
    if stage
        .words
        .windows(2)
        .any(|pair| matches!(pair[0].as_str(), ">" | ">>") && is_config_path(&pair[1]))
    {
        return true;
    }
    if !stage.words.iter().any(|word| is_config_path(word)) {
        return false;
    }

    let Some(command_index) = command_word_index(&stage.words) else {
        return false;
    };
    let executable = stage.words[command_index]
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default();
    match executable {
        "cp" | "mv" | "ln" | "install" | "tee" | "touch" | "truncate" | "dd" | "curl"
        | "curl.exe" | "wget" | "wget.exe" => true,
        "sed" => stage.words[command_index + 1..]
            .iter()
            .any(|word| word == "-i" || word.starts_with("-i") || word == "--in-place"),
        "perl" => stage.words[command_index + 1..]
            .iter()
            .any(|word| word.starts_with('-') && word.contains('i')),
        _ => false,
    }
}

pub(crate) enum FileArtifactEvent {
    ChangeDirectory(String),
    UnresolvedDirectory,
    Download(String),
    Transfer { source: String, destination: String },
    RuntimeGpgImport(String),
    Verification,
}

pub(crate) fn file_artifact_events(
    line: &str,
    wget_configured: bool,
    curl_configured: bool,
) -> Vec<FileArtifactEvent> {
    let mut events = Vec::new();
    for command in parse_shell_line(line) {
        if command_has_unresolved_directory_scope(&command.text) {
            events.push(FileArtifactEvent::UnresolvedDirectory);
        }
        let imports_gpg_key = command.stages.iter().any(stage_is_gpg_import);
        let piped = command.stages.len() > 1;
        for stage in command.stages {
            if control_flow_stage_changes_directory(&stage) {
                events.push(FileArtifactEvent::UnresolvedDirectory);
            }
            if let Some(event) = directory_event_for_stage(&stage, piped) {
                events.push(event);
            }
            for (source, destination) in file_artifact_transfers_for_stage(&stage) {
                events.push(FileArtifactEvent::Transfer {
                    source,
                    destination,
                });
            }
            for target in fetch_output_targets_for_stage(&stage, wget_configured, curl_configured) {
                events.push(FileArtifactEvent::Download(target));
            }
            if has_checksum_verify(&stage.text) {
                events.push(FileArtifactEvent::Verification);
            }
        }
        if imports_gpg_key {
            events.push(FileArtifactEvent::RuntimeGpgImport(command.text));
        }
    }
    events
}

fn command_has_unresolved_directory_scope(command: &str) -> bool {
    matches!(command.trim_start().chars().next(), Some('(' | '{'))
}

fn control_flow_stage_changes_directory(stage: &ShellStage) -> bool {
    let Some(command_index) = command_word_index(&stage.words) else {
        return false;
    };
    let control = stage.words[command_index].to_ascii_lowercase();
    matches!(
        control.as_str(),
        "!" | "if"
            | "then"
            | "elif"
            | "else"
            | "while"
            | "until"
            | "for"
            | "select"
            | "case"
            | "do"
    ) && stage
        .words
        .get(command_index + 1)
        .is_some_and(|word| is_directory_command(word))
}

fn is_directory_command(word: &str) -> bool {
    matches!(
        word.rsplit(['/', '\\'])
            .next()
            .unwrap_or(word)
            .to_ascii_lowercase()
            .as_str(),
        "cd" | "chdir" | "set-location" | "pushd" | "popd" | "push-location" | "pop-location"
    )
}

fn directory_event_for_stage(stage: &ShellStage, piped: bool) -> Option<FileArtifactEvent> {
    let command = normalize_directory_command(&stage.text)?;
    let name = command.split_whitespace().next()?.to_ascii_lowercase();
    if piped
        || matches!(
            name.as_str(),
            "pushd" | "popd" | "push-location" | "pop-location"
        )
    {
        return Some(FileArtifactEvent::UnresolvedDirectory);
    }
    let Some(directory) = runtime_directory_command_argument(&command) else {
        return Some(FileArtifactEvent::UnresolvedDirectory);
    };
    Some(FileArtifactEvent::ChangeDirectory(directory.to_string()))
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
    words
        .get(index)
        .is_some_and(|word| is_directory_command(word))
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

fn runtime_directory_command_argument(command: &str) -> Option<&str> {
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
    let directory_stack_index = argument
        .strip_prefix('+')
        .or_else(|| argument.strip_prefix('-'))
        .is_some_and(|index| {
            !index.is_empty() && index.chars().all(|character| character.is_ascii_digit())
        });
    (!argument.is_empty()
        && !argument.contains(['$', '`', '\\', '*', '?', '['])
        && !argument.starts_with('~')
        && !directory_stack_index)
        .then_some(argument)
}

#[cfg(test)]
fn file_artifact_transfers(line: &str) -> Vec<(String, String)> {
    file_artifact_events(line, false, false)
        .into_iter()
        .filter_map(|event| match event {
            FileArtifactEvent::Transfer {
                source,
                destination,
            } => Some((source, destination)),
            FileArtifactEvent::ChangeDirectory(_)
            | FileArtifactEvent::UnresolvedDirectory
            | FileArtifactEvent::Download(_)
            | FileArtifactEvent::RuntimeGpgImport(_)
            | FileArtifactEvent::Verification => None,
        })
        .collect()
}

fn file_artifact_transfers_for_stage(stage: &ShellStage) -> Vec<(String, String)> {
    let Some(command_index) = file_transfer_command_index(&stage.words) else {
        return Vec::new();
    };
    let operands: Vec<&String> = stage.words[command_index + 1..]
        .iter()
        .filter(|word| !word.starts_with('-'))
        .collect();
    let Some(destination) = operands.last() else {
        return Vec::new();
    };
    if operands.len() < 2 {
        return Vec::new();
    }
    operands[..operands.len() - 1]
        .iter()
        .map(|source| ((*source).clone(), (*destination).clone()))
        .collect()
}

fn file_transfer_command_index(words: &[String]) -> Option<usize> {
    let index = wrapped_command_word_index(words)?;
    words.get(index).and_then(|word| {
        word.rsplit(['/', '\\'])
            .next()
            .filter(|executable| matches!(*executable, "cp" | "mv" | "install" | "ln"))
            .map(|_| index)
    })
}

fn wrapped_command_word_index(words: &[String]) -> Option<usize> {
    let mut index = command_word_index(words)?;
    loop {
        match words.get(index).map(String::as_str)? {
            "command" => {
                index += 1;
                while matches!(words.get(index).map(String::as_str), Some("-p" | "--")) {
                    index += 1;
                }
                if matches!(words.get(index).map(String::as_str), Some("-v" | "-V")) {
                    return None;
                }
            }
            "builtin" => {
                index += 1;
                if words.get(index).map(String::as_str) == Some("--") {
                    index += 1;
                }
            }
            "env" => {
                index += 1;
                while let Some(word) = words.get(index) {
                    if word == "--" {
                        index += 1;
                        break;
                    }
                    if shell_assignment(word) {
                        index += 1;
                    } else if matches!(word.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
                        index += 2;
                    } else if matches!(word.as_str(), "-S" | "--split-string") {
                        return None;
                    } else if word.starts_with('-') {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            _ => return Some(index),
        }
    }
}

pub(crate) fn docker_unpinned_images(line: &str) -> Vec<String> {
    let mut images = Vec::new();
    for command in parse_shell_line(line) {
        for stage in command.stages {
            let Some(image) = docker_pull_or_run_image(&stage.words) else {
                continue;
            };
            if docker_image_is_unpinned(&image) && !images.contains(&image) {
                images.push(image);
            }
        }
    }
    images
}

fn docker_pull_or_run_image(words: &[String]) -> Option<String> {
    let docker = docker_command_index(words)?;
    let mut i = docker + 1;
    let subcommand = words.get(i)?.as_str();
    let subcommand = match subcommand {
        "image" | "container" => {
            i += 1;
            words.get(i)?.as_str()
        }
        other => other,
    };
    i += 1;
    match subcommand {
        "pull" => docker_image_after_options(&words[i..], &["--platform"]),
        "run" => docker_image_after_options(
            &words[i..],
            &[
                "--add-host",
                "--cidfile",
                "--cpus",
                "--entrypoint",
                "--env",
                "--env-file",
                "--hostname",
                "--label",
                "--memory",
                "--mount",
                "--name",
                "--network",
                "--platform",
                "--publish",
                "--pull",
                "--user",
                "--volume",
                "--workdir",
            ],
        ),
        _ => None,
    }
}

fn docker_command_index(words: &[String]) -> Option<usize> {
    let mut idx = command_word_index(words)?;
    loop {
        match words.get(idx)?.as_str() {
            "sudo" | "command" => idx += 1,
            "env" => {
                idx += 1;
                while words.get(idx).is_some_and(|word| word.contains('=')) {
                    idx += 1;
                }
            }
            "docker" => return Some(idx),
            _ => return None,
        }
    }
}

fn docker_image_after_options(args: &[String], value_flags: &[&str]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let word = args[i].as_str();
        if word == "--" {
            return args.get(i + 1).cloned();
        }
        if !word.starts_with('-') {
            return Some(word.to_string());
        }
        if docker_option_consumes_value(word, value_flags) {
            i += if docker_option_has_attached_value(word) {
                1
            } else {
                2
            };
        } else {
            i += 1;
        }
    }
    None
}

fn docker_option_consumes_value(word: &str, value_flags: &[&str]) -> bool {
    if let Some((flag, _)) = word.split_once('=') {
        return value_flags.contains(&flag);
    }
    if value_flags.contains(&word) {
        return true;
    }
    let Some(short) = word.strip_prefix('-') else {
        return false;
    };
    if short.starts_with('-') {
        return false;
    }
    matches!(
        short.chars().next(),
        Some('e' | 'h' | 'l' | 'm' | 'p' | 'u' | 'v' | 'w')
    )
}

fn docker_option_has_attached_value(word: &str) -> bool {
    if word.starts_with("--") {
        return word.contains('=');
    }
    word.len() > 2
}

fn docker_image_is_unpinned(image: &str) -> bool {
    if image.contains('$') || image.contains('@') {
        return false;
    }
    let last_segment = image.rsplit('/').next().unwrap_or(image);
    match last_segment.rsplit_once(':') {
        Some((_, tag)) => tag.eq_ignore_ascii_case("latest"),
        None => true,
    }
}

fn fetch_output_targets_for_stage(
    stage: &ShellStage,
    wget_configured: bool,
    curl_configured: bool,
) -> Vec<String> {
    let fetch_index = stage
        .words
        .iter()
        .position(|word| fetch_program(word).is_some());
    let Some(fetch_index) = fetch_index else {
        return Vec::new();
    };
    let option_targets = match fetch_program(&stage.words[fetch_index]) {
        Some("curl") => {
            let words = &stage.words[fetch_index + 1..];
            let reads_default_config =
                !matches!(words.first().map(String::as_str), Some("-q" | "--disable"));
            curl_output_targets(words, curl_configured && reads_default_config)
        }
        Some("wget") => wget_output_targets(
            &stage.words[fetch_index + 1..],
            wget_configured
                || stage.words[..fetch_index]
                    .iter()
                    .any(|word| word.starts_with("WGETRC=")),
        ),
        _ => Vec::new(),
    };
    let mut targets: Vec<String> = if option_targets.is_empty() {
        redirect_output_target(&stage.words).into_iter().collect()
    } else {
        option_targets
    };
    if stage.words.windows(2).any(|pair| {
        matches!(pair[0].as_str(), ">" | ">>") && literal_fetch_target(&pair[1]).is_none()
    }) && !targets.iter().any(|target| target == UNKNOWN_FETCH_OUTPUT)
    {
        targets.push(UNKNOWN_FETCH_OUTPUT.to_string());
    }
    targets
}

fn fetch_program(word: &str) -> Option<&'static str> {
    match word.rsplit(['/', '\\']).next().unwrap_or(word) {
        "curl" | "curl.exe" => Some("curl"),
        "wget" | "wget.exe" => Some("wget"),
        _ => None,
    }
}

fn curl_output_targets(words: &[String], configured: bool) -> Vec<String> {
    let mut targets = Vec::new();
    let mut remote_names = false;
    let mut remote_header_name = false;
    let mut output_dir = None;
    let mut output_dir_unknown = false;
    let mut unknown_output = configured || curl_uses_explicit_config(words);
    let mut i = 0;
    while i < words.len() {
        let word = words[i].as_str();
        if matches!(word, "-o" | "--output") {
            match words
                .get(i + 1)
                .and_then(|target| literal_fetch_target(target))
            {
                Some(target) => targets.push(target),
                None => unknown_output = true,
            }
            i += 2;
            continue;
        }
        if let Some(target) = word.strip_prefix("--output=") {
            match literal_fetch_target(target) {
                Some(target) => targets.push(target),
                None => unknown_output = true,
            }
        }
        if word == "-O"
            || word == "--remote-name"
            || word == "--remote-name-all"
            || short_flag_has_remote_name(word)
        {
            remote_names = true;
        }
        if word == "--remote-header-name" || short_flag_has_remote_header_name(word) {
            remote_header_name = true;
        }
        if word == "--output-dir" {
            match words
                .get(i + 1)
                .and_then(|directory| literal_fetch_target(directory))
            {
                Some(directory) => output_dir = Some(directory),
                None => {
                    unknown_output = true;
                    output_dir_unknown = true;
                }
            }
            i += 2;
            continue;
        }
        if let Some(directory) = word.strip_prefix("--output-dir=") {
            match literal_fetch_target(directory) {
                Some(directory) => output_dir = Some(directory),
                None => {
                    unknown_output = true;
                    output_dir_unknown = true;
                }
            }
        }
        if short_flag_uses_output(word) {
            match words
                .get(i + 1)
                .and_then(|target| literal_fetch_target(target))
            {
                Some(target) => targets.push(target),
                None => unknown_output = true,
            }
            i += 2;
            continue;
        }
        if let Some(target) = curl_attached_output(word) {
            match literal_fetch_target(target) {
                Some(target) => targets.push(target),
                None => unknown_output = true,
            }
        }
        i += 1;
    }
    if remote_names {
        if remote_header_name || words.iter().any(|word| word.contains(['$', '`'])) {
            unknown_output = true;
        }
        if !remote_header_name {
            let remote_targets: Vec<String> = words
                .iter()
                .filter(|word| !word.starts_with('-'))
                .filter_map(|url| {
                    (url.starts_with("http://") || url.starts_with("https://"))
                        .then(|| url_basename(url))
                        .flatten()
                })
                .collect();
            if remote_targets.is_empty() {
                unknown_output = true;
            } else {
                targets.extend(remote_targets);
            }
        }
    }
    if output_dir_unknown {
        targets.clear();
    }
    if unknown_output {
        targets.push(UNKNOWN_FETCH_OUTPUT.to_string());
    }
    if let Some(directory) = output_dir {
        for target in &mut targets {
            if target != UNKNOWN_FETCH_OUTPUT && !target.starts_with('/') {
                *target = format!("{directory}/{target}");
            }
        }
    }
    targets
}

fn curl_uses_explicit_config(words: &[String]) -> bool {
    words.iter().any(|word| {
        word == "-K"
            || word == "--config"
            || word.starts_with("--config=")
            || word
                .strip_prefix('-')
                .is_some_and(|flags| !flags.starts_with('-') && flags.contains('K'))
    })
}

fn curl_attached_output(word: &str) -> Option<&str> {
    let flags = word.strip_prefix('-')?;
    if flags.starts_with('-') {
        return None;
    }
    let pos = flags.find('o')?;
    let target = &flags[pos + 1..];
    (!target.is_empty()).then_some(target)
}

fn short_flag_uses_output(word: &str) -> bool {
    let Some(flags) = word.strip_prefix('-') else {
        return false;
    };
    !flags.starts_with('-') && flags.ends_with('o')
}

fn short_flag_has_remote_name(word: &str) -> bool {
    let Some(flags) = word.strip_prefix('-') else {
        return false;
    };
    !flags.starts_with('-') && flags.contains('O')
}

fn short_flag_has_remote_header_name(word: &str) -> bool {
    let Some(flags) = word.strip_prefix('-') else {
        return false;
    };
    !flags.starts_with('-') && flags.contains('J')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WgetShortValue {
    Output,
    Directory,
    Execute,
    Other,
}

fn wget_short_options(word: &str) -> (bool, Option<(WgetShortValue, &str)>) {
    let Some(flags) = word.strip_prefix('-') else {
        return (false, None);
    };
    if flags.starts_with('-') || flags.is_empty() {
        return (false, None);
    }
    let bytes = flags.as_bytes();
    let mut response_selects_name = false;
    let mut index = 0;
    while index < bytes.len() {
        let flag = bytes[index] as char;
        if flag == 'n'
            && bytes
                .get(index + 1)
                .is_some_and(|next| matches!(*next as char, 'd' | 'H' | 'c' | 'v' | 'p'))
        {
            index += 2;
            continue;
        }
        if matches!(flag, 'r' | 'm' | 'E' | 'p' | 'x') {
            response_selects_name = true;
        }
        let value = match flag {
            'O' => Some(WgetShortValue::Output),
            'P' => Some(WgetShortValue::Directory),
            'e' => Some(WgetShortValue::Execute),
            'a' | 'A' | 'B' | 'D' | 'i' | 'l' | 'o' | 'Q' | 'R' | 't' | 'T' | 'U' | 'w' | 'X'
            | 'Y' => Some(WgetShortValue::Other),
            _ => None,
        };
        if let Some(value) = value {
            return (response_selects_name, Some((value, &flags[index + 1..])));
        }
        index += 1;
    }
    (response_selects_name, None)
}

fn wget_output_targets(words: &[String], configured: bool) -> Vec<String> {
    let mut response_selects_name = configured;
    let mut directory_prefix = None;
    let mut directory_prefix_unknown = false;
    let mut i = 0;
    while i < words.len() {
        let word = words[i].as_str();
        if word == "--output-document" {
            return match words
                .get(i + 1)
                .and_then(|target| literal_fetch_target(target))
            {
                Some(target) => vec![target],
                None => vec![UNKNOWN_FETCH_OUTPUT.to_string()],
            };
        }
        if let Some(target) = word.strip_prefix("--output-document=") {
            return literal_fetch_target(target).map_or_else(
                || vec![UNKNOWN_FETCH_OUTPUT.to_string()],
                |target| vec![target],
            );
        }
        if word == "--directory-prefix" {
            match words
                .get(i + 1)
                .and_then(|directory| literal_fetch_target(directory))
            {
                Some(directory) => directory_prefix = Some(directory),
                None => directory_prefix_unknown = true,
            }
            i += 2;
            continue;
        }
        if let Some(directory) = word.strip_prefix("--directory-prefix=") {
            match literal_fetch_target(directory) {
                Some(directory) => directory_prefix = Some(directory),
                None => directory_prefix_unknown = true,
            }
        }
        if matches!(
            word,
            "--content-disposition"
                | "--trust-server-names"
                | "--force-directories"
                | "--protocol-directories"
                | "--no-host-directories"
                | "--recursive"
                | "--mirror"
                | "--adjust-extension"
                | "--page-requisites"
                | "--restrict-file-names"
                | "--cut-dirs"
                | "--execute"
                | "--config"
        ) || word.starts_with("--cut-dirs=")
            || word.starts_with("--restrict-file-names=")
            || word.starts_with("--execute=")
            || word.starts_with("--config=")
        {
            response_selects_name = true;
        }
        let (short_selects_name, short_value) = wget_short_options(word);
        response_selects_name |= short_selects_name;
        if let Some((kind, attached)) = short_value {
            let value = if attached.is_empty() {
                i += 1;
                words.get(i).map(String::as_str)
            } else {
                Some(attached)
            };
            match kind {
                WgetShortValue::Output => {
                    return value.and_then(literal_fetch_target).map_or_else(
                        || vec![UNKNOWN_FETCH_OUTPUT.to_string()],
                        |target| vec![target],
                    );
                }
                WgetShortValue::Directory => match value.and_then(literal_fetch_target) {
                    Some(directory) => directory_prefix = Some(directory),
                    None => directory_prefix_unknown = true,
                },
                WgetShortValue::Execute => response_selects_name = true,
                WgetShortValue::Other => {}
            }
        }
        i += 1;
    }
    if response_selects_name || directory_prefix_unknown {
        return vec![UNKNOWN_FETCH_OUTPUT.to_string()];
    }
    let mut inferred: Vec<String> = words
        .iter()
        .filter(|word| word.starts_with("http://") || word.starts_with("https://"))
        .filter_map(|url| url_basename(url))
        .collect();
    if let Some(directory) = directory_prefix {
        for target in &mut inferred {
            *target = format!("{directory}/{target}");
        }
    }
    if inferred.is_empty()
        && words
            .iter()
            .any(|word| !word.starts_with('-') && word != "-")
    {
        vec![UNKNOWN_FETCH_OUTPUT.to_string()]
    } else {
        inferred
    }
}

fn redirect_output_target(words: &[String]) -> Option<String> {
    words.windows(2).find_map(|pair| {
        if pair[0] == ">" || pair[0] == ">>" {
            literal_fetch_target(&pair[1])
        } else {
            None
        }
    })
}

fn usable_target(target: &str) -> Option<String> {
    let target = normalize_path_token(target);
    (!target.is_empty() && target != "-" && !target.starts_with('&')).then_some(target)
}

fn literal_fetch_target(target: &str) -> Option<String> {
    let target = usable_target(target)?;
    (!target.contains(['$', '`'])).then_some(target)
}

fn url_basename(url: &str) -> Option<String> {
    let clean = url.split(['?', '#']).next().unwrap_or(url);
    let name = clean.rsplit('/').next().unwrap_or_default();
    usable_target(name)
}

#[cfg(test)]
pub(crate) fn checksum_verifies_target(line: &str, target: &str) -> bool {
    checksum_verifies_target_with_material(line, target, &[])
}

#[cfg(test)]
pub(crate) fn checksum_verifies_target_with_material(
    line: &str,
    target: &str,
    runtime_downloads: &[String],
) -> bool {
    checksum_verifies_target_with_material_policy(line, target, runtime_downloads, true, Some(""))
}

#[cfg(test)]
pub(crate) fn checksum_verifies_target_with_material_policy(
    line: &str,
    target: &str,
    runtime_downloads: &[String],
    trust_gpg_verification: bool,
    working_directory: Option<&str>,
) -> bool {
    let verification_count = parse_shell_line(line)
        .iter()
        .flat_map(|command| &command.stages)
        .filter(|stage| has_checksum_verify(&stage.text))
        .count();
    let working_directories = vec![working_directory.map(str::to_string); verification_count];
    checksum_verifies_target_with_material_policy_at(
        line,
        target,
        runtime_downloads,
        trust_gpg_verification,
        &working_directories,
    )
}

pub(crate) fn checksum_verifies_target_with_material_policy_at(
    line: &str,
    target: &str,
    runtime_downloads: &[String],
    trust_gpg_verification: bool,
    verification_working_directories: &[Option<String>],
) -> bool {
    if line.contains("||")
        || target == UNKNOWN_FETCH_OUTPUT
        || runtime_downloads
            .iter()
            .any(|path| path == UNKNOWN_FETCH_OUTPUT)
    {
        return false;
    }
    let commands = parse_shell_line(line);
    let mut verification_index = 0;
    for (command_index, command) in commands.iter().enumerate() {
        let failure_is_preserved = commands[command_index..].iter().all(|command| {
            command.following_control.is_none()
                || command.following_control == Some(ShellControl::And)
        });
        for (checksum_stage, stage) in command.stages.iter().enumerate() {
            if !has_checksum_verify(&stage.text) {
                continue;
            }
            let working_directory = verification_working_directories
                .get(verification_index)
                .and_then(Option::as_deref);
            verification_index += 1;
            if !failure_is_preserved
                || checksum_stage + 1 != command.stages.len()
                || working_directory.is_none()
                || !trust_gpg_verification && stage_is_gpg_verification(stage)
                || stage_has_dynamic_verification_input(stage)
            {
                continue;
            }
            let downloaded_verification_material = runtime_downloads.iter().any(|download| {
                !same_shell_path(download, target)
                    && stage.words.iter().any(|word| {
                        checksum_word_matches_download_at(word, download, working_directory)
                    })
            });
            if !downloaded_verification_material
                && (checksum_stage_verifies_named_target(stage, target, working_directory)
                    || checksum_stage_reads_manifest_stdin(stage)
                        && command.stages[..checksum_stage].iter().any(|stage| {
                            stage_supplies_inline_checksum_manifest(
                                stage,
                                target,
                                working_directory,
                            )
                        }))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
pub(crate) fn imports_runtime_gpg_key(line: &str, runtime_downloads: &[String]) -> bool {
    imports_runtime_gpg_key_at(line, runtime_downloads, Some(""))
}

pub(crate) fn imports_runtime_gpg_key_at(
    line: &str,
    runtime_downloads: &[String],
    working_directory: Option<&str>,
) -> bool {
    parse_shell_line(line).into_iter().any(|command| {
        command
            .stages
            .iter()
            .enumerate()
            .any(|(stage_index, stage)| {
                let Some(command_index) = wrapped_command_word_index(&stage.words) else {
                    return false;
                };
                if !stage_is_gpg_import(stage) {
                    return false;
                }
                let dynamic_import = stage.words[command_index + 1..]
                    .iter()
                    .any(|word| shell_word_is_dynamic(word));
                let imported_download = runtime_downloads.iter().any(|download| {
                    download != UNKNOWN_FETCH_OUTPUT
                        && stage.words[command_index + 1..].iter().any(|word| {
                            checksum_word_matches_download_at(word, download, working_directory)
                        })
                });
                let streamed_download = command.stages[..stage_index].iter().any(|source| {
                    source
                        .words
                        .iter()
                        .any(|word| fetch_program(word).is_some())
                }) || stage.text.match_indices("<(").any(|(index, _)| {
                    let command = stage.text[index + 2..].trim_start();
                    command
                        .split_whitespace()
                        .next()
                        .is_some_and(|word| fetch_program(word).is_some())
                });
                imported_download
                    || streamed_download
                    || dynamic_import && !runtime_downloads.is_empty()
            })
    })
}

#[cfg(test)]
pub(crate) fn is_gpg_verification(line: &str) -> bool {
    parse_shell_line(line)
        .into_iter()
        .any(|command| command.stages.iter().any(stage_is_gpg_verification))
}

fn stage_is_gpg_verification(stage: &ShellStage) -> bool {
    let Some(command_index) = wrapped_command_word_index(&stage.words) else {
        return false;
    };
    stage.words[command_index]
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|executable| matches!(executable, "gpg" | "gpg.exe"))
        && stage.words[command_index + 1..]
            .iter()
            .any(|word| word == "--verify")
}

fn stage_is_gpg_import(stage: &ShellStage) -> bool {
    let Some(command_index) = wrapped_command_word_index(&stage.words) else {
        return false;
    };
    stage.words[command_index]
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|executable| matches!(executable, "gpg" | "gpg.exe"))
        && stage.words[command_index + 1..]
            .iter()
            .any(|word| word == "--import" || word == "-import")
}

fn stage_has_dynamic_verification_input(stage: &ShellStage) -> bool {
    stage_is_negated(stage)
        || stage.text.contains("<(")
        || stage.text.contains(">(")
        || wrapped_command_word_index(&stage.words).is_some_and(|command_index| {
            stage.words[command_index + 1..]
                .iter()
                .any(|word| shell_word_is_dynamic(word) || shell_word_is_input_redirection(word))
        })
}

fn stage_is_negated(stage: &ShellStage) -> bool {
    command_word_index(&stage.words)
        .and_then(|index| stage.words.get(index))
        .is_some_and(|word| word == "!")
}

fn shell_word_is_input_redirection(word: &str) -> bool {
    word.trim_start_matches(|character: char| character.is_ascii_digit())
        .starts_with('<')
}

fn shell_word_is_dynamic(word: &str) -> bool {
    word.contains(['$', '`'])
}

fn checksum_stage_verifies_named_target(
    stage: &ShellStage,
    target: &str,
    working_directory: Option<&str>,
) -> bool {
    if checksum_stage_reads_named_manifest(stage) {
        return false;
    }
    let names_target = stage
        .words
        .iter()
        .any(|word| checksum_word_matches_download_at(word, target, working_directory));
    if !names_target || !stage.text.to_ascii_lowercase().contains("get-filehash") {
        return names_target;
    }

    POWERSHELL_FILE_HASH_LITERAL_COMPARE_RE
        .captures_iter(&stage.text)
        .any(|captures| {
            captures.name("target").is_some_and(|value| {
                checksum_word_matches_download_at(value.as_str(), target, working_directory)
            })
        })
}

fn checksum_stage_reads_named_manifest(stage: &ShellStage) -> bool {
    let Some(command_index) = wrapped_command_word_index(&stage.words) else {
        return false;
    };
    let checksum_command = stage.words[command_index]
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|command| {
            matches!(
                command.to_ascii_lowercase().as_str(),
                "sha256sum" | "sha512sum" | "shasum"
            )
        });
    checksum_command
        && stage.words[command_index + 1..]
            .iter()
            .any(|word| matches!(word.as_str(), "-c" | "--check"))
}

fn checksum_stage_reads_manifest_stdin(stage: &ShellStage) -> bool {
    stage.words.iter().any(|word| word == "-")
}

fn stage_supplies_inline_checksum_manifest(
    stage: &ShellStage,
    target: &str,
    working_directory: Option<&str>,
) -> bool {
    let Some(command_index) = command_word_index(&stage.words) else {
        return false;
    };
    let trusted_inline_command = stage
        .words
        .get(command_index)
        .and_then(|word| word.rsplit('/').next())
        .is_some_and(|command| matches!(command, "echo" | "printf" | "Write-Output"));
    if !trusted_inline_command {
        return false;
    }

    let arguments = &stage.words[command_index + 1..];
    arguments
        .iter()
        .any(|word| inline_manifest_record_matches(word, target, working_directory))
        || arguments.windows(2).any(|pair| {
            is_full_inline_digest(&pair[0])
                && checksum_word_matches_download_at(&pair[1], target, working_directory)
        })
}

fn inline_manifest_record_matches(
    word: &str,
    target: &str,
    working_directory: Option<&str>,
) -> bool {
    word.split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| {
            is_full_inline_digest(pair[0])
                && checksum_word_matches_download_at(pair[1], target, working_directory)
        })
}

fn is_full_inline_digest(word: &str) -> bool {
    let word = word.trim_matches(|c| matches!(c, '"' | '\'' | ',' | ';' | '(' | ')' | '{' | '}'));
    INLINE_DIGEST_RE.is_match(word)
}

fn checksum_word_matches_download_at(
    word: &str,
    target: &str,
    working_directory: Option<&str>,
) -> bool {
    let target = normalize_path_token(target);
    word.split_whitespace().any(|word| {
        let word = word.strip_prefix('*').unwrap_or(word);
        let Some(word) = resolve_shell_path(word, working_directory) else {
            return false;
        };
        word == target
            || word
                .strip_prefix(&target)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(").Hash"))
    })
}

fn resolve_shell_path(path: &str, working_directory: Option<&str>) -> Option<String> {
    if shell_word_is_dynamic(path) {
        return None;
    }
    let path = normalize_path_token(path);
    if path.starts_with('/') {
        return Some(path);
    }
    let directory = working_directory?;
    Some(if directory.is_empty() {
        path
    } else {
        normalize_path_token(&format!("{directory}/{path}"))
    })
}

pub(crate) fn git_clone_has_bound_sha_checkout(logical: &[(usize, String)], li: usize) -> bool {
    let clones = unpinned_git_clones(&logical[li].1);
    !clones.is_empty()
        && clones
            .iter()
            .all(|clone| clone_has_bound_sha_checkout(logical, li, clone))
}

fn unpinned_git_clones(line: &str) -> Vec<GitCloneCommand> {
    parse_shell_line(line)
        .into_iter()
        .enumerate()
        .filter_map(|(command_index, command)| {
            if command.stages.iter().any(stage_has_git_clone)
                && !git_clone_has_pinned_ref(&command.text)
            {
                git_clone_dir(&command).map(|dir| GitCloneCommand { dir, command_index })
            } else {
                None
            }
        })
        .collect()
}

fn stage_has_git_clone(stage: &ShellStage) -> bool {
    git_word_index(&stage.words)
        .is_some_and(|idx| stage.words.get(idx + 1).is_some_and(|w| w == "clone"))
}

fn git_clone_dir(command: &ShellCommand) -> Option<String> {
    let stage = command
        .stages
        .iter()
        .find(|stage| stage_has_git_clone(stage))?;
    let git = git_word_index(&stage.words)?;
    let args = &stage.words[git + 2..];
    let mut positionals = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let word = args[i].as_str();
        if git_clone_option_takes_value(word) {
            i += 2;
            continue;
        }
        if let Some(flag) = word.split_once('=').map(|(flag, _)| flag)
            && git_clone_option_takes_value(flag)
        {
            i += 1;
            continue;
        }
        if word.starts_with('-') {
            i += 1;
            continue;
        }
        positionals.push(word);
        i += 1;
    }

    if let Some(dir) = positionals.get(1) {
        usable_target(dir)
    } else {
        positionals.first().and_then(|url| clone_default_dir(url))
    }
}

fn git_clone_option_takes_value(flag: &str) -> bool {
    matches!(
        flag,
        "-b" | "--branch"
            | "-c"
            | "--config"
            | "--depth"
            | "--origin"
            | "-o"
            | "--template"
            | "--reference"
            | "--reference-if-able"
            | "--separate-git-dir"
            | "--jobs"
            | "-j"
    )
}

fn clone_default_dir(url: &str) -> Option<String> {
    let clean = url.trim_end_matches('/').trim_end_matches(".git");
    usable_target(clean.rsplit(['/', ':']).next().unwrap_or(clean))
}

fn clone_has_bound_sha_checkout(
    logical: &[(usize, String)],
    clone_line: usize,
    clone: &GitCloneCommand,
) -> bool {
    let mut current_dir: Option<String> = None;
    for offset in 0..=3 {
        let Some((_, line)) = logical.get(clone_line + offset) else {
            break;
        };
        let commands = parse_shell_line(line);
        for (command_index, command) in commands.iter().enumerate() {
            if offset == 0 && command_index <= clone.command_index {
                continue;
            }
            if let Some(dir) = command_cd_dir(command) {
                current_dir = Some(dir);
                continue;
            }
            if command_has_bound_checkout(command, &clone.dir, current_dir.as_deref()) {
                return true;
            }
        }
    }
    false
}

fn command_cd_dir(command: &ShellCommand) -> Option<String> {
    let stage = command.stages.first()?;
    let idx = command_word_index(&stage.words)?;
    if stage.words[idx] == "cd" {
        stage.words.get(idx + 1).and_then(|dir| usable_target(dir))
    } else {
        None
    }
}

fn command_has_bound_checkout(
    command: &ShellCommand,
    clone_dir: &str,
    current_dir: Option<&str>,
) -> bool {
    command.stages.iter().any(|stage| {
        git_checkout_sha_dir(stage).is_some_and(|checkout_dir| match checkout_dir {
            Some(dir) => same_shell_path(&dir, clone_dir),
            None => current_dir.is_some_and(|dir| same_shell_path(dir, clone_dir)),
        })
    })
}

fn git_checkout_sha_dir(stage: &ShellStage) -> Option<Option<String>> {
    let git = git_word_index(&stage.words)?;
    let mut checkout_dir = None;
    let mut i = git + 1;
    while i < stage.words.len() {
        let word = stage.words[i].as_str();
        if word == "-C" {
            checkout_dir = stage.words.get(i + 1).and_then(|dir| usable_target(dir));
            i += 2;
            continue;
        }
        if let Some(dir) = word.strip_prefix("-C")
            && !dir.is_empty()
        {
            checkout_dir = usable_target(dir);
            i += 1;
            continue;
        }
        if word == "checkout" && stage.words.get(i + 1).is_some_and(|sha| is_full_sha(sha)) {
            return Some(checkout_dir);
        }
        i += 1;
    }
    None
}

fn git_word_index(words: &[String]) -> Option<usize> {
    words.iter().position(|word| word == "git")
}

fn is_full_sha(word: &str) -> bool {
    word.len() == 40 && word.chars().all(|c| c.is_ascii_hexdigit())
}

fn same_shell_path(left: &str, right: &str) -> bool {
    normalize_path_token(left) == normalize_path_token(right)
}

fn normalize_path_token(path: &str) -> String {
    let path = path
        .trim_matches(|c| matches!(c, '"' | '\'' | ')' | '(' | ',' | ';'))
        .trim()
        .replace('\\', "/");
    let absolute = path.starts_with('/');
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." if components.last().is_some_and(|part| *part != "..") => {
                components.pop();
            }
            ".." if !absolute => components.push(component),
            ".." => {}
            _ => components.push(component),
        }
    }
    let normalized = components.join("/");
    if absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_shell_comment_line_detects_leading_hash() {
        assert!(is_shell_comment_line("# comment"));
        assert!(is_shell_comment_line("    # indented comment"));
        assert!(is_shell_comment_line("\t# tab indent"));
    }

    #[test]
    fn piped_checksum_manifest_verifies_named_target() {
        assert!(checksum_verifies_target(
            "echo \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tool\" | shasum -a 256 -c -",
            "tool"
        ));
    }

    #[test]
    fn downloaded_or_short_checksum_manifest_is_not_trusted() {
        assert!(!checksum_verifies_target(
            "sha256sum -c tool.sha256",
            "tool"
        ));
        assert!(!checksum_verifies_target(
            "echo \"abcdef  tool\" | shasum -a 256 -c -",
            "tool"
        ));
        assert!(!checksum_verifies_target(
            "cat tool.sha256 | shasum -a 256 -c -",
            "tool"
        ));
        assert!(!checksum_verifies_target_with_material(
            "gpg --verify tool.sig tool",
            "tool",
            &["tool".to_string(), "tool.sig".to_string()]
        ));
        assert!(!checksum_verifies_target_with_material(
            "gpg --verify tool.sig tool",
            "tool",
            &[UNKNOWN_FETCH_OUTPUT.to_string()]
        ));
        assert!(!checksum_verifies_target_with_material(
            "gpg --verify tool.sig tool",
            "tool",
            &["tool".to_string(), "tmp/../tool.sig".to_string()]
        ));
        assert!(!checksum_verifies_target_with_material(
            "gpg --verify \"$PWD/tool.sig\" tool",
            "tool",
            &["tool".to_string(), "tool.sig".to_string()]
        ));
        assert!(imports_runtime_gpg_key(
            "gpg --import keys/../key.asc",
            &["key.asc".to_string()]
        ));
        assert!(imports_runtime_gpg_key(
            "curl https://example.com/v1.2.3/key.asc | gpg --import",
            &[]
        ));
        assert!(imports_runtime_gpg_key(
            "gpg --import <(curl https://example.com/v1.2.3/key.asc)",
            &[]
        ));
        assert!(imports_runtime_gpg_key(
            "gpg --import <(/usr/bin/curl https://example.com/v1.2.3/key.asc)",
            &[]
        ));
        assert!(imports_runtime_gpg_key_at(
            "gpg --import \"$PWD/key.asc\"",
            &["key.asc".to_string()],
            Some("")
        ));
        assert!(is_gpg_verification("/usr/bin/gpg --verify tool.sig tool"));
        assert!(!is_gpg_verification("gpg --import key.asc"));
    }

    #[test]
    fn powershell_literal_digest_must_compare_the_downloaded_target() {
        let digest = "a".repeat(64);
        assert!(checksum_verifies_target(
            &format!("if ((Get-FileHash tool).Hash -ne '{digest}') {{ throw 'mismatch' }}"),
            "tool"
        ));
        assert!(!checksum_verifies_target(
            &format!(
                "if ((Get-FileHash tool).Hash -ne $EXPECTED -and $guard -eq '{digest}') {{ throw 'mismatch' }}"
            ),
            "tool"
        ));
    }

    #[test]
    fn unrelated_pipeline_target_does_not_bind_checksum() {
        assert!(!checksum_verifies_target(
            "curl -o tool https://example.com/tool | sha256sum unrelated.txt",
            "tool"
        ));
        assert!(!checksum_verifies_target(
            "echo tool && sha256sum unrelated.txt",
            "tool"
        ));
        assert!(!checksum_verifies_target(
            "echo \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other\" tool | sha256sum -c -",
            "tool"
        ));
    }

    #[test]
    fn masked_checksum_failure_does_not_verify_target() {
        assert!(!checksum_verifies_target(
            "sha256sum -c tool.sha256 || true",
            "tool"
        ));
        assert!(!checksum_verifies_target(
            "echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tool' | sha256sum -c -; true",
            "tool"
        ));
        assert!(!checksum_verifies_target(
            "echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tool' | sha256sum -c - &",
            "tool"
        ));
        assert!(checksum_verifies_target(
            "echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tool' | sha256sum -c - && echo verified",
            "tool"
        ));
    }

    #[test]
    fn is_shell_comment_line_rejects_trailing_hash() {
        // Trailing comments aren't covered — an unquoted `#` can't be
        // distinguished from one inside a string without real shell parsing.
        assert!(!is_shell_comment_line("echo hello  # note"));
        assert!(!is_shell_comment_line("foo=\"# not a comment\""));
    }

    #[test]
    fn join_continuations_merges_trailing_backslash() {
        let joined = join_continuations("curl https://x.example/s.sh \\\n  | sh\n");
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].0, 0);
        assert_eq!(joined[0].1, "curl https://x.example/s.sh  | sh");
    }

    #[test]
    fn join_continuations_merges_trailing_pipeline_operators() {
        let joined = join_continuations(
            "curl https://x.example/s.sh |\n  sh\necho ok &&\n  true\necho no ||\n  false\n",
        );
        assert_eq!(
            joined,
            vec![
                (0, "curl https://x.example/s.sh | sh".into()),
                (2, "echo ok && true".into()),
                (4, "echo no || false".into()),
            ]
        );
    }

    #[test]
    fn join_continuations_leaves_unbroken_lines_alone() {
        let joined = join_continuations("echo one\necho two\n");
        assert_eq!(joined, vec![(0, "echo one".into()), (1, "echo two".into())]);
    }

    #[test]
    fn join_continuations_handles_multiple_breaks() {
        let joined = join_continuations("curl \\\n  -L \\\n  https://x.example/s.sh | sh\n");
        assert_eq!(joined.len(), 1);
        assert!(joined[0].1.contains("curl"));
        assert!(joined[0].1.contains("| sh"));
    }

    #[test]
    fn join_continuations_keeps_dangling_continuation() {
        assert_eq!(
            join_continuations("echo unfinished \\"),
            vec![(0, "echo unfinished ".into())]
        );
    }

    #[test]
    fn shell_split_handles_escaped_controls_and_or_operator() {
        assert_eq!(
            split_shell_control(r#"printf one\;two || printf 'three;four'"#),
            vec![r#"printf one\;two"#, "printf 'three;four'"]
        );
    }

    #[test]
    fn shell_words_handles_escaped_whitespace_and_append_redirect() {
        assert_eq!(
            shell_words(r#"curl -o tool\ file https://example.com/tool >> download.log"#),
            vec![
                "curl",
                "-o",
                "tool file",
                "https://example.com/tool",
                ">>",
                "download.log",
            ]
        );
        assert_eq!(
            shell_words("MODE=$(printf test) command cd scripts"),
            vec!["MODE=$(printf test)", "command", "cd", "scripts"]
        );
        assert_eq!(
            shell_words("MODE=`printf test` builtin cd scripts"),
            vec!["MODE=printf test", "builtin", "cd", "scripts"]
        );
        assert_eq!(
            shell_words("MODE=${UNSET:-test value} command cd scripts"),
            vec!["MODE=${UNSET:-test value}", "command", "cd", "scripts"]
        );
        assert_eq!(
            shell_words("MODE=<(printf test) builtin cd scripts"),
            vec!["MODE=<(printf test)", "builtin", "cd", "scripts"]
        );
    }

    #[test]
    fn docker_image_extraction_handles_cli_prefixes_and_options() {
        for (line, expected) in [
            ("docker image pull alpine", vec!["alpine"]),
            (
                "env DOCKER_HOST=local docker container run --platform=linux alpine",
                vec!["alpine"],
            ),
            ("docker run -e MODE=test alpine", vec!["alpine"]),
            ("docker run -- alpine", vec!["alpine"]),
            ("docker pull --platform", vec![]),
        ] {
            assert_eq!(docker_unpinned_images(line), expected, "line: {line}");
        }
    }

    #[test]
    fn fetch_output_targets_handles_option_and_redirect_forms() {
        for (line, expected) in [
            ("curl --output=tool https://example.com/tool", vec!["tool"]),
            ("curl -sLo tool https://example.com/tool", vec!["tool"]),
            (
                "curl --compressed -otool https://example.com/tool",
                vec!["tool"],
            ),
            (
                "wget --output-document=tool https://example.com/tool",
                vec!["tool"],
            ),
            ("wget -Otool https://example.com/tool", vec!["tool"]),
            (
                "wget -O \"$SIG\" https://example.com/tool",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget --content-disposition https://example.com/v1/tool.sig",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget https://example.com/v1/tool https://example.com/v1/tool.sig",
                vec!["tool", "tool.sig"],
            ),
            ("wget \"$SIG_URL\"", vec![UNKNOWN_FETCH_OUTPUT]),
            (
                "curl -O https://example.com/v1/tool -O https://example.com/v1/tool.sig",
                vec!["tool", "tool.sig"],
            ),
            ("curl -O \"$SIG_URL\"", vec![UNKNOWN_FETCH_OUTPUT]),
            (
                "curl -OJ https://example.com/v1/tool.sig",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "curl --output-dir downloads -O https://example.com/v1/tool.sig",
                vec!["downloads/tool.sig"],
            ),
            (
                "curl --output-dir=\"$DIR\" -O https://example.com/v1/tool.sig",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "curl -O https://example.com/v1/tool -O \"$SIG_URL\"",
                vec!["tool", UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "curl -o \"$SIG\" https://example.com/v1/tool.sig",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "curl https://example.com/v1/tool > \"$OUTPUT\"",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            ("curl https://example.com/tool >> tool", vec!["tool"]),
            (
                "/usr/bin/curl -o tool.sig https://example.com/v1/tool.sig",
                vec!["tool.sig"],
            ),
            (
                "/usr/local/bin/wget -P downloads https://example.com/v1/tool.sig",
                vec!["downloads/tool.sig"],
            ),
            (
                "wget --directory-prefix=downloads https://example.com/v1/tool.sig",
                vec!["downloads/tool.sig"],
            ),
            (
                "wget -P \"$DIR\" https://example.com/v1/tool.sig",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget --trust-server-names https://example.com/v1/download",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget -x https://example.com/v1/tool.sig",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget -r https://example.com/v1/signatures/",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget -nvE https://example.com/v1/tool.sig",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget --restrict-file-names=lowercase https://example.com/v1/TOOL.SIG",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget -Ptmp https://example.com/v1/tool.sig",
                vec!["tmp/tool.sig"],
            ),
            (
                "wget -e restrict_file_names=lowercase https://example.com/v1/TOOL.SIG",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "wget --execute=restrict_file_names=lowercase https://example.com/v1/TOOL.SIG",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
            (
                "WGETRC=./wgetrc wget https://example.com/v1/TOOL.SIG",
                vec![UNKNOWN_FETCH_OUTPUT],
            ),
        ] {
            assert_eq!(fetch_output_targets(line), expected, "line: {line}");
        }
    }

    #[test]
    fn fetch_output_targets_fail_closed_for_curl_configuration() {
        assert_eq!(
            fetch_output_targets("curl -K ./curl.conf https://example.com/v1/tool.sig"),
            vec![UNKNOWN_FETCH_OUTPUT]
        );
        assert_eq!(
            fetch_output_targets(
                "curl --config=./curl.conf -o tool.sig https://example.com/v1/tool.sig"
            ),
            vec!["tool.sig", UNKNOWN_FETCH_OUTPUT]
        );
        assert_eq!(
            fetch_output_targets_with_config(
                "curl -o tool.sig https://example.com/v1/tool.sig",
                false,
                true,
            ),
            vec!["tool.sig", UNKNOWN_FETCH_OUTPUT]
        );
        assert_eq!(
            fetch_output_targets_with_config(
                "curl -q -o tool.sig https://example.com/v1/tool.sig",
                false,
                true,
            ),
            vec!["tool.sig"]
        );
    }

    #[test]
    fn fetch_config_file_mutations_are_detected() {
        for line in [
            r#"echo "output_document = tool.sig" >> ~/.wgetrc"#,
            "printf '%s\\n' config | tee /tmp/.wgetrc",
            "cp committed-wgetrc ~/.wgetrc",
            "ln -sf attacker-wgetrc ~/.wgetrc",
            "sed -i 's/a/b/' ~/.wgetrc",
            "wget -O ~/.wgetrc https://example.com/v1/config",
        ] {
            assert!(mutates_wget_config(line), "line: {line}");
        }
        for line in [
            r#"echo "output = tool.sig" >> ~/.curlrc"#,
            "printf '%s\\n' config | tee /tmp/.curlrc",
            "mv generated-curlrc ~/.curlrc",
            "ln -sf attacker-curlrc ~/.curlrc",
            "curl -o ~/.curlrc https://example.com/v1/config",
        ] {
            assert!(mutates_curl_config(line), "line: {line}");
        }
        assert!(mutates_wget_config("touch ~/.netrc"));
        assert!(mutates_curl_config("touch ~/.netrc"));
        assert!(!mutates_wget_config("cat ~/.wgetrc"));
        assert!(!mutates_curl_config("cat ~/.curlrc"));
    }

    #[test]
    fn file_artifact_transfers_track_common_copy_and_rename_commands() {
        for (line, expected) in [
            (
                "mv downloaded.sig trusted.sig",
                ("downloaded.sig", "trusted.sig"),
            ),
            (
                "cp -f downloaded.sig trusted.sig",
                ("downloaded.sig", "trusted.sig"),
            ),
            (
                "command install -m 0644 downloaded.sig trusted.sig",
                ("downloaded.sig", "trusted.sig"),
            ),
            (
                "ln -sf downloaded.sig trusted.sig",
                ("downloaded.sig", "trusted.sig"),
            ),
        ] {
            assert!(
                file_artifact_transfers(line)
                    .iter()
                    .any(|(source, destination)| source == expected.0 && destination == expected.1),
                "line: {line}"
            );
        }
    }

    #[test]
    fn file_artifact_events_track_literal_and_unresolved_directory_changes() {
        let events = file_artifact_events(
            "cd -- dl && curl -o tool.sig https://example.com/v1.2.3/tool.sig",
            false,
            false,
        );
        assert!(matches!(
            events.first(),
            Some(FileArtifactEvent::ChangeDirectory(directory)) if directory == "dl"
        ));
        assert!(matches!(
            events.get(1),
            Some(FileArtifactEvent::Download(target)) if target == "tool.sig"
        ));

        for line in [
            "cd \"$DIR\" && curl -o tool.sig https://example.com/v1.2.3/tool.sig",
            "(cd dl && curl -o tool.sig https://example.com/v1.2.3/tool.sig)",
            "pushd dl && curl -o tool.sig https://example.com/v1.2.3/tool.sig",
            "cd dl | curl -o tool.sig https://example.com/v1.2.3/tool.sig",
        ] {
            assert!(
                file_artifact_events(line, false, false)
                    .iter()
                    .any(|event| matches!(event, FileArtifactEvent::UnresolvedDirectory)),
                "line: {line}"
            );
        }
    }

    #[test]
    fn file_artifact_events_fail_closed_on_control_flow_and_powershell_directories() {
        let powershell = file_artifact_events(
            "Set-Location dl; curl -o tool.sig https://example.com/v1.2.3/tool.sig",
            false,
            false,
        );
        assert!(matches!(
            powershell.first(),
            Some(FileArtifactEvent::ChangeDirectory(directory)) if directory == "dl"
        ));

        for line in [
            "if cd dl; then curl -o tool.sig https://example.com/v1.2.3/tool.sig; fi",
            "Push-Location dl; curl -o tool.sig https://example.com/v1.2.3/tool.sig",
            "Pop-Location; curl -o tool.sig https://example.com/v1.2.3/tool.sig",
        ] {
            assert!(
                file_artifact_events(line, false, false)
                    .iter()
                    .any(|event| matches!(event, FileArtifactEvent::UnresolvedDirectory)),
                "line: {line}"
            );
        }

        assert!(
            !file_artifact_events("if test \"$MODE\" = cd; then true; fi", false, false)
                .iter()
                .any(|event| matches!(event, FileArtifactEvent::UnresolvedDirectory))
        );
    }

    #[test]
    fn unsafe_verification_syntax_never_suppresses_a_fetch() {
        for line in [
            "gpg --verify <(curl https://example.com/v1.2.3/tool.sig) tool",
            "gpg --verify /dev/stdin tool <tool.sig",
            "! gpg --verify trusted.sig tool",
            "sha256sum -c tool",
        ] {
            assert!(!checksum_verifies_target(line, "tool"), "line: {line}");
        }
    }

    #[test]
    fn wrapped_gpg_imports_taint_later_verification() {
        for line in [
            "command gpg --import key.asc",
            "builtin gpg --import key.asc",
            "env MODE=strict gpg --import key.asc",
            "env -u MODE gpg --import key.asc",
            "env --chdir /tmp gpg --import key.asc",
        ] {
            assert!(
                imports_runtime_gpg_key(line, &["key.asc".to_string()]),
                "line: {line}"
            );
        }
    }

    #[test]
    fn checksum_binding_uses_the_verification_directory() {
        assert!(checksum_verifies_target_with_material_policy(
            "gpg --verify ../trusted.sig tool",
            "dl/tool",
            &["dl/tool".to_string()],
            true,
            Some("dl")
        ));
        assert!(!checksum_verifies_target_with_material_policy(
            "gpg --verify trusted.sig tool",
            "tool",
            &["tool".to_string()],
            true,
            Some("dl")
        ));
    }

    #[test]
    fn git_clone_parses_equals_flags_and_attached_checkout_directory() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let script = format!(
            "git clone --depth=1 --quiet https://example.com/o/r.git\ngit -C././r checkout {sha}\n"
        );
        let logical = join_continuations(&script);

        assert!(git_clone_has_bound_sha_checkout(&logical, 0));
    }

    #[test]
    fn git_command_without_checkout_does_not_bind_clone() {
        let logical = join_continuations(
            "git clone --depth=1 --quiet https://example.com/o/r.git\ngit -C r status\n",
        );

        assert!(!git_clone_has_bound_sha_checkout(&logical, 0));
    }
}
