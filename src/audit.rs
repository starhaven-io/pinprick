use anyhow::{Context, Result};
use serde_yml::Value;
use std::collections::HashSet;
use std::path::Path;
use std::process::ExitCode;

use crate::audit_patterns::{
    self, DOCKER_PATTERNS, JS_PATTERNS, JS_URL_PATTERNS, PY_PATTERNS, PY_URL_PATTERNS, Pattern,
    SH_GH_RELEASE_LATEST, SHELL_PATTERNS, SHELL_URL_PATTERNS, category_str, extract_url,
    gh_release_has_tag, has_checksum_verify, url_has_version,
};
use crate::audited_actions::AuditedActions;
use crate::auth;
use crate::config::Config;
use crate::github::GitHubClient;
use crate::output::{self, AuditFinding, AuditReport};
use crate::workflow::{self, ActionRef};

pub async fn run(repo_root: &Path, json: bool, config: &Config) -> Result<ExitCode> {
    let token = auth::resolve_token().await;
    let client = token.as_ref().map(|t| GitHubClient::new(t.clone()));
    let had_token = client.is_some();

    let files = workflow::find_workflows(repo_root)?;
    let mut findings: Vec<AuditFinding> = Vec::new();
    let mut scanned_actions: HashSet<String> = HashSet::new();
    let mut audited = AuditedActions::new(config.fetch_remote);

    for file in &files {
        let display_name = workflow::display_path(file, repo_root);
        if !json {
            eprint!("Scanning {display_name}...");
        }

        let run_blocks = extract_run_blocks(file)?;
        for (line_offset, content) in &run_blocks {
            scan_shell_content(content, &display_name, *line_offset, "", &mut findings);
        }

        if !json {
            eprintln!(" done");
        }

        if let Some(client) = &client {
            let actions = workflow::scan_workflow(file)?;
            for action in &actions {
                let key = format!("{}@{}", action.owner_repo(), action.ref_string);
                if !scanned_actions.insert(key) {
                    continue;
                }

                if config.is_action_ignored(&action.owner_repo()) {
                    if !json {
                        eprintln!(
                            "  {}@{} ignored",
                            action.full_name(),
                            short_sha(&action.ref_string)
                        );
                    }
                    continue;
                }

                if audited
                    .check(&action.owner, &action.repo, &action.ref_string)
                    .await
                {
                    if !json {
                        eprintln!(
                            "  {}@{} audited",
                            action.full_name(),
                            short_sha(&action.ref_string)
                        );
                    }
                    continue;
                }

                if !json {
                    eprint!(
                        "  Fetching {}@{}...",
                        action.full_name(),
                        short_sha(&action.ref_string)
                    );
                }

                let findings_before = findings.len();
                match scan_action_source(client, action, &mut findings).await {
                    Ok(()) => {
                        if !json {
                            eprintln!(" done");
                        }
                        if findings.len() == findings_before
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
                        if !json {
                            eprintln!(" failed");
                        }
                        eprintln!("warning: could not scan {}: {e}", action.full_name());
                    }
                }
            }
        }
    }

    if !json && !files.is_empty() {
        eprintln!();
    }

    findings.retain(|f| {
        config.meets_severity(&f.severity) && !config.is_pattern_ignored(&f.description)
    });

    findings.sort_by_key(|f| match f.severity.as_str() {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    });

    let has_findings = !findings.is_empty();
    let report = AuditReport {
        actions_scanned: scanned_actions.len(),
        findings,
        had_token,
    };

    if json {
        report.print_json();
    } else {
        report.print_human();
    }

    if has_findings {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn extract_run_blocks(path: &Path) -> Result<Vec<(usize, String)>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let yaml: Value =
        serde_yml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let mut blocks = Vec::new();

    // Walk jobs.*.steps[].run
    if let Some(jobs) = yaml.get("jobs").and_then(|j| j.as_mapping()) {
        for (_job_name, job) in jobs {
            if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                for step in steps {
                    if let Some(run) = step.get("run").and_then(|r| r.as_str()) {
                        let line = find_run_line(&content, run).unwrap_or(0);
                        blocks.push((line, run.to_string()));
                    }
                }
            }
        }
    }

    Ok(blocks)
}

fn find_run_line(file_content: &str, run_content: &str) -> Option<usize> {
    let first_line = run_content.lines().next()?;
    let trimmed = first_line.trim();
    if trimmed.is_empty() {
        return None;
    }
    for (i, line) in file_content.lines().enumerate() {
        if line.contains(trimmed) {
            return Some(i + 1);
        }
    }
    None
}

fn scan_shell_content(
    content: &str,
    source_file: &str,
    base_line: usize,
    action_name: &str,
    findings: &mut Vec<AuditFinding>,
) {
    let lines: Vec<&str> = content.lines().collect();
    let findings_before = findings.len();

    for (i, line) in lines.iter().enumerate() {
        let line_num = base_line + i;

        check_patterns(
            &SHELL_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            findings,
        );

        check_url_patterns(
            &SHELL_URL_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            findings,
        );

        if SH_GH_RELEASE_LATEST.is_match(line) && !gh_release_has_tag(line) {
            findings.push(AuditFinding {
                severity: output::severity_str(&audit_patterns::Severity::Medium).to_string(),
                category: category_str(&audit_patterns::Category::ShellFetch).to_string(),
                action: action_name.to_string(),
                source_file: source_file.to_string(),
                line: Some(line_num),
                pattern_matched: line.trim().to_string(),
                description: "gh release download without pinned version".to_string(),
            });
        }
    }

    // Downgrade severity for findings followed by checksum verification
    for finding in findings.iter_mut().skip(findings_before) {
        if let Some(finding_line) = finding.line {
            let rel = finding_line.saturating_sub(base_line);
            for offset in 1..=3 {
                if rel + offset < lines.len() && has_checksum_verify(lines[rel + offset]) {
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
    findings: &mut Vec<AuditFinding>,
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
                    findings,
                );
                check_url_patterns(
                    &JS_URL_PATTERNS,
                    segment,
                    source_file,
                    line_num,
                    action_name,
                    findings,
                );
            }
        } else {
            check_patterns(
                &JS_PATTERNS,
                line,
                source_file,
                line_num,
                action_name,
                findings,
            );
            check_url_patterns(
                &JS_URL_PATTERNS,
                line,
                source_file,
                line_num,
                action_name,
                findings,
            );
        }
    }
}

fn scan_py_content(
    content: &str,
    source_file: &str,
    action_name: &str,
    findings: &mut Vec<AuditFinding>,
) {
    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;

        check_patterns(
            &PY_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            findings,
        );
        check_url_patterns(
            &PY_URL_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            findings,
        );
    }
}

fn scan_dockerfile_content(
    content: &str,
    source_file: &str,
    action_name: &str,
    findings: &mut Vec<AuditFinding>,
) {
    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;

        if audit_patterns::DOCKER_FROM_DIGEST.is_match(line) {
            continue;
        }

        check_patterns(
            &DOCKER_PATTERNS,
            line,
            source_file,
            line_num,
            action_name,
            findings,
        );
    }
}

fn check_url_patterns(
    patterns: &[Pattern],
    line: &str,
    source_file: &str,
    line_num: usize,
    action_name: &str,
    findings: &mut Vec<AuditFinding>,
) {
    for pattern in patterns {
        if pattern.regex.is_match(line)
            && let Some(url) = extract_url(line)
            && !url_has_version(url)
        {
            findings.push(AuditFinding {
                severity: output::severity_str(&pattern.severity).to_string(),
                category: category_str(&pattern.category).to_string(),
                action: action_name.to_string(),
                source_file: source_file.to_string(),
                line: Some(line_num),
                pattern_matched: line.trim().to_string(),
                description: pattern.description.to_string(),
            });
        }
    }
}

fn check_patterns(
    patterns: &[Pattern],
    line: &str,
    source_file: &str,
    line_num: usize,
    action_name: &str,
    findings: &mut Vec<AuditFinding>,
) {
    for pattern in patterns {
        if pattern.regex.is_match(line) {
            findings.push(AuditFinding {
                severity: output::severity_str(&pattern.severity).to_string(),
                category: category_str(&pattern.category).to_string(),
                action: action_name.to_string(),
                source_file: source_file.to_string(),
                line: Some(line_num),
                pattern_matched: line.trim().to_string(),
                description: pattern.description.to_string(),
            });
        }
    }
}

async fn scan_action_source(
    client: &GitHubClient,
    action: &ActionRef,
    findings: &mut Vec<AuditFinding>,
) -> Result<()> {
    let action_name = format!("{}@{}", action.full_name(), short_sha(&action.ref_string));
    let tree = client
        .fetch_tree(&action.owner, &action.repo, &action.ref_string)
        .await?;

    let base = action.subpath.as_deref().unwrap_or("");

    for entry in &tree {
        if entry.entry_type != "blob" {
            continue;
        }

        let path = &entry.path;

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

        let is_action_yml = relative == "action.yml" || relative == "action.yaml";
        let is_js = path.ends_with(".js") || path.ends_with(".ts");
        let is_py = path.ends_with(".py");
        let is_dockerfile = relative == "Dockerfile" || path.ends_with(".dockerfile");

        if !is_action_yml && !is_js && !is_py && !is_dockerfile {
            continue;
        }

        let content = match client
            .fetch_file(&action.owner, &action.repo, path, &action.ref_string)
            .await
        {
            Ok(c) => c,
            Err(_) => continue,
        };

        let source_label = format!("{} ({path})", action.full_name());

        if is_action_yml {
            if let Ok(yaml) = serde_yml::from_str::<Value>(&content) {
                scan_action_yml_runs(&yaml, &source_label, &action_name, findings);
            }
        } else if is_js {
            scan_js_content(&content, &source_label, &action_name, findings);
        } else if is_py {
            scan_py_content(&content, &source_label, &action_name, findings);
        } else if is_dockerfile {
            scan_dockerfile_content(&content, &source_label, &action_name, findings);
        }
    }

    Ok(())
}

fn scan_action_yml_runs(
    yaml: &Value,
    source_file: &str,
    action_name: &str,
    findings: &mut Vec<AuditFinding>,
) {
    // runs.steps[].run (composite actions)
    if let Some(steps) = yaml
        .get("runs")
        .and_then(|r| r.get("steps"))
        .and_then(|s| s.as_sequence())
    {
        for step in steps {
            if let Some(run) = step.get("run").and_then(|r| r.as_str()) {
                scan_shell_content(run, source_file, 0, action_name, findings);
            }
        }
    }

    // runs.args (some actions use shell: bash with inline scripts)
    if let Some(args) = yaml
        .get("runs")
        .and_then(|r| r.get("args"))
        .and_then(|a| a.as_str())
    {
        scan_shell_content(args, source_file, 0, action_name, findings);
    }
}

fn short_sha(sha: &str) -> &str {
    if sha.len() >= 8 { &sha[..8] } else { sha }
}
