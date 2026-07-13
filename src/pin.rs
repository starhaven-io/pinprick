use anyhow::Result;
use std::collections::HashMap;
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

    let mut resolve_cache: HashMap<String, (String, String)> = HashMap::new();

    // Actions that remain unpinned after the run: branch refs (which need a
    // manual pin) and refs whose resolution failed. A dry run must exit 1 for
    // these too — they are exactly what a CI gate exists to catch. Sliding-tag
    // skips are excluded: those are warnings attached to a successful pin.
    let mut unpinnable = 0usize;

    for file in &files {
        let display_name = workflow::display_path(file.path(), repo_root);
        if !json {
            eprintln!("Scanning {display_name}...");
        }

        let actions = workflow::scan_workflow(file)?;
        let mut replacements: Vec<(usize, String, String)> = Vec::new();

        for action in &actions {
            match action.ref_type {
                RefType::Sha => {}
                RefType::Branch => {
                    unpinnable += 1;
                    report.skipped.push(PinSkip {
                        file: workflow::display_path(file.path(), repo_root),
                        action: format!("{}@{}", action.full_name(), action.ref_string),
                        reason: "branch ref — pin to a SHA manually".to_string(),
                        line: action.line_number,
                    });
                }
                RefType::SlidingTag | RefType::Tag => {
                    let cache_key =
                        format!("{}/{}@{}", action.owner, action.repo, action.ref_string);

                    if !json {
                        eprint!(
                            "  Resolving {}@{}...",
                            action.full_name(),
                            action.ref_string
                        );
                    }

                    let resolved = if let Some(hit) = resolve_cache.get(&cache_key) {
                        if !json {
                            eprintln!(" cached");
                        }
                        Ok(hit.clone())
                    } else {
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
                                resolve_cache.insert(cache_key, (sha.clone(), tag.clone()));
                                Ok((sha, tag))
                            }
                            Err(e) => {
                                if !json {
                                    eprintln!(" failed");
                                }
                                Err(e)
                            }
                        }
                    };

                    match resolved {
                        Ok((sha, tag)) => {
                            if action.ref_type == RefType::SlidingTag {
                                report.skipped.push(PinSkip {
                                    file: workflow::display_path(file.path(), repo_root),
                                    action: format!("{}@{}", action.full_name(), action.ref_string),
                                    reason: format!("sliding tag, resolved to {tag}"),
                                    line: action.line_number,
                                });
                            }
                            if let Some(new_line) =
                                workflow::build_pinned_line(&action.raw_line, &sha, &tag)
                            {
                                replacements.push((
                                    action.line_number,
                                    action.raw_line.clone(),
                                    new_line,
                                ));
                                report.pinned.push(PinResult {
                                    file: workflow::display_path(file.path(), repo_root),
                                    action: action.full_name(),
                                    old_ref: action.ref_string.clone(),
                                    sha,
                                    tag,
                                    line: action.line_number,
                                });
                            }
                        }
                        Err(e) => {
                            unpinnable += 1;
                            report.skipped.push(PinSkip {
                                file: workflow::display_path(file.path(), repo_root),
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

    if !apply && (!report.pinned.is_empty() || unpinnable > 0) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}
