//! Shell tokenizer and target-extraction layer for the audit scanners.
//!
//! Splits shell text into logical lines, pipelines, and commands, then
//! answers the questions the pattern layer asks of that structure: where a
//! fetch writes its output, whether a checksum command verifies that target,
//! whether a `git clone` is bound to a SHA checkout, and whether a fetch is
//! piped into `jq`.

use crate::audit_patterns::{git_clone_has_pinned_ref, has_checksum_verify};

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

fn parse_shell_line(line: &str) -> Vec<ShellCommand> {
    split_shell_control(line)
        .into_iter()
        .filter_map(|command| {
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
                })
            }
        })
        .collect()
}

fn split_shell_control(line: &str) -> Vec<String> {
    split_shell(line, SplitMode::Control)
}

fn split_shell_pipeline(line: &str) -> Vec<String> {
    split_shell(line, SplitMode::Pipeline)
}

enum SplitMode {
    Control,
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
            SplitMode::Control if ch == ';' => {
                push_shell_part(&mut out, &mut current);
            }
            SplitMode::Control if ch == '&' && chars.peek() == Some(&'&') => {
                chars.next();
                push_shell_part(&mut out, &mut current);
            }
            SplitMode::Control if ch == '|' && chars.peek() == Some(&'|') => {
                chars.next();
                push_shell_part(&mut out, &mut current);
            }
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

fn shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

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
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
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
    let mut targets = Vec::new();
    for command in parse_shell_line(line) {
        for stage in command.stages {
            if let Some(target) = fetch_output_target(&stage)
                && !targets.contains(&target)
            {
                targets.push(target);
            }
        }
    }
    targets
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

fn fetch_output_target(stage: &ShellStage) -> Option<String> {
    let fetch_index = stage
        .words
        .iter()
        .position(|word| word == "curl" || word == "wget")?;
    let fetch = stage.words[fetch_index].as_str();
    let option_target = match fetch {
        "curl" => curl_output_target(&stage.words[fetch_index + 1..]),
        "wget" => wget_output_target(&stage.words[fetch_index + 1..]),
        _ => None,
    };
    option_target.or_else(|| redirect_output_target(&stage.words))
}

fn curl_output_target(words: &[String]) -> Option<String> {
    let mut urls = words
        .iter()
        .filter(|word| word.starts_with("http://") || word.starts_with("https://"));
    let mut i = 0;
    while i < words.len() {
        let word = words[i].as_str();
        if matches!(word, "-o" | "--output") {
            return words.get(i + 1).and_then(|target| usable_target(target));
        }
        if let Some(target) = word.strip_prefix("--output=") {
            return usable_target(target);
        }
        if word == "-O" || word == "--remote-name" || short_flag_has_remote_name(word) {
            return urls.next().and_then(|url| url_basename(url));
        }
        if short_flag_uses_output(word) {
            return words.get(i + 1).and_then(|target| usable_target(target));
        }
        if let Some(target) = curl_attached_output(word) {
            return usable_target(target);
        }
        i += 1;
    }
    None
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

fn wget_output_target(words: &[String]) -> Option<String> {
    let mut i = 0;
    while i < words.len() {
        let word = words[i].as_str();
        if matches!(word, "-O" | "--output-document") {
            return words.get(i + 1).and_then(|target| usable_target(target));
        }
        if let Some(target) = word.strip_prefix("--output-document=") {
            return usable_target(target);
        }
        if let Some(target) = word.strip_prefix("-O")
            && !target.is_empty()
        {
            return usable_target(target);
        }
        i += 1;
    }
    None
}

fn redirect_output_target(words: &[String]) -> Option<String> {
    words.windows(2).find_map(|pair| {
        if pair[0] == ">" || pair[0] == ">>" {
            usable_target(&pair[1])
        } else {
            None
        }
    })
}

fn usable_target(target: &str) -> Option<String> {
    let target = normalize_path_token(target);
    (!target.is_empty() && target != "-" && !target.starts_with('&')).then_some(target)
}

fn url_basename(url: &str) -> Option<String> {
    let clean = url.split(['?', '#']).next().unwrap_or(url);
    let name = clean.rsplit('/').next().unwrap_or_default();
    usable_target(name)
}

pub(crate) fn checksum_verifies_target(line: &str, target: &str) -> bool {
    parse_shell_line(line).into_iter().any(|command| {
        command
            .stages
            .iter()
            .any(|stage| checksum_stage_verifies_target(stage, target))
    })
}

fn checksum_stage_verifies_target(stage: &ShellStage, target: &str) -> bool {
    has_checksum_verify(&stage.text)
        && stage
            .words
            .iter()
            .any(|word| checksum_word_matches_target(word, target))
}

fn checksum_word_matches_target(word: &str, target: &str) -> bool {
    let word = normalize_path_token(word);
    let target = normalize_path_token(target);
    word == target
        || word
            .strip_prefix(&target)
            .is_some_and(|suffix| matches!(suffix, ".sha256" | ".sha512" | ".sha1" | ".sig"))
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
    let mut path = path
        .trim_matches(|c| matches!(c, '"' | '\'' | ')' | '(' | ',' | ';'))
        .trim()
        .to_string();
    while let Some(rest) = path.strip_prefix("./") {
        path = rest.to_string();
    }
    path
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
}
