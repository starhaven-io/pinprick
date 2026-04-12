use anyhow::Result;
use std::path::Path;
use std::process::ExitCode;

use crate::auth;
use crate::github::GitHubClient;
use crate::output::{PinReport, PinResult, PinSkip};
use crate::workflow::{self, RefType};

pub async fn run(repo_root: &Path, json: bool, apply: bool) -> Result<ExitCode> {
    let token = auth::require_token().await?;
    let client = GitHubClient::new(token);

    let files = workflow::find_workflows(repo_root)?;
    let mut report = PinReport {
        pinned: Vec::new(),
        skipped: Vec::new(),
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
            match action.ref_type {
                RefType::Sha => {}
                RefType::Branch => {
                    report.skipped.push(PinSkip {
                        file: workflow::display_path(file, repo_root),
                        action: format!("{}@{}", action.full_name(), action.ref_string),
                        reason: "branch ref — pin to a SHA manually".to_string(),
                        line: action.line_number,
                    });
                }
                RefType::SlidingTag | RefType::Tag => {
                    if !json {
                        eprint!(
                            "  Resolving {}@{}...",
                            action.full_name(),
                            action.ref_string
                        );
                    }
                    match client
                        .resolve_tag(&action.owner, &action.repo, &action.ref_string)
                        .await
                    {
                        Ok(sha) => {
                            let tag = client
                                .find_exact_tag(
                                    &action.owner,
                                    &action.repo,
                                    &sha,
                                    &action.ref_string,
                                )
                                .await;
                            if !json {
                                eprintln!(" done");
                            }
                            if action.ref_type == RefType::SlidingTag {
                                report.skipped.push(PinSkip {
                                    file: workflow::display_path(file, repo_root),
                                    action: format!("{}@{}", action.full_name(), action.ref_string),
                                    reason: format!("sliding tag, resolved to {tag}"),
                                    line: action.line_number,
                                });
                            }
                            if let Some(new_line) =
                                workflow::build_pinned_line(&action.raw_line, &sha, &tag)
                            {
                                replacements.push((action.line_number, new_line));
                                report.pinned.push(PinResult {
                                    file: workflow::display_path(file, repo_root),
                                    action: action.full_name(),
                                    old_ref: action.ref_string.clone(),
                                    sha,
                                    tag,
                                    line: action.line_number,
                                });
                            }
                        }
                        Err(e) => {
                            if !json {
                                eprintln!(" failed");
                            }
                            report.skipped.push(PinSkip {
                                file: workflow::display_path(file, repo_root),
                                action: format!("{}@{}", action.full_name(), action.ref_string),
                                reason: format!("{e}"),
                                line: action.line_number,
                            });
                        }
                    }
                }
            }
        }

        if apply && !replacements.is_empty() {
            workflow::rewrite_actions(file, &replacements)?;
        }
    }

    if json {
        report.print_json();
    } else {
        report.print_human();
    }

    if !apply && !report.pinned.is_empty() {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}
