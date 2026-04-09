use anyhow::Result;
use std::path::Path;
use std::process::ExitCode;

use crate::auth;
use crate::github::GitHubClient;
use crate::output::{UpdateReport, UpdateResult};
use crate::workflow::{self, RefType};

pub async fn run(repo_root: &Path, apply: bool, json: bool) -> Result<ExitCode> {
    let token = auth::require_token().await?;
    let client = GitHubClient::new(token);

    let files = workflow::find_workflows(repo_root)?;
    let mut report = UpdateReport {
        updates: Vec::new(),
        up_to_date: 0,
        applied: apply,
    };

    for file in &files {
        let display_name = workflow::display_path(file, repo_root);
        if !json {
            eprintln!("Scanning {display_name}...");
        }

        let actions = workflow::scan_workflow(file)?;
        let mut replacements: Vec<(usize, String)> = Vec::new();

        for action in &actions {
            if action.ref_type != RefType::Sha {
                continue;
            }
            let current_tag = match &action.tag_comment {
                Some(t) => t.clone(),
                None => continue,
            };

            if !json {
                eprint!("  Checking {}@{}...", action.full_name(), current_tag);
            }

            let releases = match client.list_releases(&action.owner, &action.repo).await {
                Ok(r) => {
                    if !json {
                        eprintln!(" done");
                    }
                    r
                }
                Err(_) => {
                    if !json {
                        eprintln!(" failed");
                    }
                    continue;
                }
            };

            let latest = releases.iter().find(|r| !r.draft && !r.prerelease);

            let latest = match latest {
                Some(r) => r,
                None => {
                    report.up_to_date += 1;
                    continue;
                }
            };

            if latest.tag_name == current_tag {
                report.up_to_date += 1;
                continue;
            }

            if !is_newer(&current_tag, &latest.tag_name) {
                report.up_to_date += 1;
                continue;
            }

            let new_sha = match client
                .resolve_tag(&action.owner, &action.repo, &latest.tag_name)
                .await
            {
                Ok(sha) => sha,
                Err(_) => continue,
            };

            report.updates.push(UpdateResult {
                file: workflow::display_path(file, repo_root),
                action: action.full_name(),
                current_tag: current_tag.clone(),
                current_sha: action.ref_string.clone(),
                latest_tag: latest.tag_name.clone(),
                latest_sha: new_sha.clone(),
                line: action.line_number,
            });

            if apply
                && let Some(new_line) =
                    workflow::build_pinned_line(&action.raw_line, &new_sha, &latest.tag_name)
            {
                replacements.push((action.line_number, new_line));
            }
        }

        if apply && !replacements.is_empty() {
            workflow::rewrite_actions(file, &replacements)?;
        }
    }

    let has_updates = !report.updates.is_empty();

    if json {
        report.print_json();
    } else {
        report.print_human();
    }

    // Exit code 1 if there are pending updates (dry-run mode)
    if has_updates && !apply {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Simple version comparison: extract numeric components and compare.
fn is_newer(current: &str, candidate: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim_start_matches('v')
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect()
    };

    let cur = parse(current);
    let cand = parse(candidate);

    // Compare component by component
    for (c, n) in cur.iter().zip(cand.iter()) {
        if n > c {
            return true;
        }
        if n < c {
            return false;
        }
    }
    // If equal so far, longer version with more components is "newer"
    cand.len() > cur.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_patch() {
        assert!(is_newer("v1.2.3", "v1.2.4"));
    }

    #[test]
    fn newer_minor() {
        assert!(is_newer("v1.2.3", "v1.3.0"));
    }

    #[test]
    fn newer_major() {
        assert!(is_newer("v1.2.3", "v2.0.0"));
    }

    #[test]
    fn same_version() {
        assert!(!is_newer("v1.2.3", "v1.2.3"));
    }

    #[test]
    fn older_version() {
        assert!(!is_newer("v2.0.0", "v1.9.9"));
    }

    #[test]
    fn without_v_prefix() {
        assert!(is_newer("1.2.3", "1.2.4"));
    }

    #[test]
    fn mixed_prefixes() {
        assert!(is_newer("v1.0.0", "1.1.0"));
        assert!(is_newer("1.0.0", "v1.1.0"));
    }

    #[test]
    fn more_components_is_newer() {
        assert!(is_newer("v4", "v4.1"));
        assert!(is_newer("v4.1", "v4.1.1"));
    }

    #[test]
    fn fewer_components_not_newer() {
        assert!(!is_newer("v4.1", "v4"));
    }

    #[test]
    fn major_only() {
        assert!(is_newer("v3", "v4"));
        assert!(!is_newer("v4", "v3"));
    }
}
