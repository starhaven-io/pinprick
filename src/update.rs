use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

use crate::auth;
use crate::github::{GitHubClient, Release};
use crate::output::{UpdateReport, UpdateResult};
use crate::workflow::{self, RefType};

pub async fn run(
    repo_root: &Path,
    apply: bool,
    json: bool,
    only: Option<&str>,
) -> Result<ExitCode> {
    let token = auth::require_token().await?;
    let client = GitHubClient::new(token);

    let files = workflow::find_workflows(repo_root)?;
    let mut report = UpdateReport {
        updates: Vec::new(),
        up_to_date: 0,
        applied: apply,
    };

    let mut releases_cache: HashMap<String, Vec<Release>> = HashMap::new();
    let mut releases_failed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut tag_sha_cache: HashMap<String, String> = HashMap::new();

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
            if let Some(pat) = only
                && !action.owner_repo().contains(pat)
            {
                continue;
            }
            let current_tag = match &action.tag_comment {
                Some(t) => leading_version_token(t),
                None => continue,
            };

            if !json {
                eprint!("  Checking {}@{}...", action.full_name(), current_tag);
            }

            let owner_repo = action.owner_repo();
            if releases_failed.contains(&owner_repo) {
                if !json {
                    eprintln!(" skipped");
                }
                continue;
            }

            let releases = if let Some(cached) = releases_cache.get(&owner_repo) {
                if !json {
                    eprintln!(" cached");
                }
                cached.clone()
            } else {
                match client.list_releases(&action.owner, &action.repo).await {
                    Ok(r) => {
                        if !json {
                            eprintln!(" done");
                        }
                        releases_cache.insert(owner_repo.clone(), r.clone());
                        r
                    }
                    Err(_) => {
                        if !json {
                            eprintln!(" failed");
                        }
                        releases_failed.insert(owner_repo);
                        continue;
                    }
                }
            };

            // Filter to tags that look like version numbers (rejects non-action
            // releases like codeql-bundle-*) and pick the highest version rather
            // than the most-recently-created release (handles backport releases
            // like v3.1.0-node20 published after v8.0.1).
            let latest = releases
                .iter()
                .filter(|r| {
                    !r.draft
                        && !r.prerelease
                        && r.tag_name
                            .strip_prefix('v')
                            .unwrap_or(&r.tag_name)
                            .starts_with(|c: char| c.is_ascii_digit())
                })
                .reduce(|best, r| {
                    if is_newer(&best.tag_name, &r.tag_name) {
                        r
                    } else {
                        best
                    }
                });

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

            let tag_key = format!("{}@{}", owner_repo, latest.tag_name);
            let new_sha = if let Some(cached) = tag_sha_cache.get(&tag_key) {
                cached.clone()
            } else {
                match client
                    .resolve_tag(&action.owner, &action.repo, &latest.tag_name)
                    .await
                {
                    Ok(sha) => {
                        tag_sha_cache.insert(tag_key, sha.clone());
                        sha
                    }
                    Err(_) => continue,
                }
            };

            report.updates.push(UpdateResult {
                file: workflow::display_path(file, repo_root),
                action: action.full_name(),
                current_tag: current_tag.clone(),
                current_sha: action.ref_string.clone(),
                latest_tag: latest.tag_name.clone(),
                latest_sha: new_sha.clone(),
                line: action.line_number,
                release_url: latest.html_url.clone(),
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

/// Extract the version token a `# comment` leads with. pin/update and the bots
/// write `# v1.2.3`, but humans annotate (`# v1.2.3 (pinned by renovate)`); the
/// trailing words would defeat the `latest == current` fast-path and feed the
/// lossy version parse. Take the leading `v?N…` token (up to the first space or
/// `(`), falling back to the whole comment when it doesn't start with a version.
fn leading_version_token(comment: &str) -> String {
    let trimmed = comment.trim();
    let rest = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if !rest.starts_with(|c: char| c.is_ascii_digit()) {
        return trimmed.to_string();
    }
    let end = trimmed
        .find(|c: char| c.is_whitespace() || c == '(')
        .unwrap_or(trimmed.len());
    trimmed[..end].to_string()
}

/// Simple version comparison: extract numeric components, then use the
/// presence of a pre-release suffix as a tie-breaker so that a stable release
/// sorts newer than a pre-release with the same numeric prefix.
fn is_newer(current: &str, candidate: &str) -> bool {
    let (cur, cur_pre) = parse_version(current);
    let (cand, cand_pre) = parse_version(candidate);

    // Compare component by component
    for (c, n) in cur.iter().zip(cand.iter()) {
        if n > c {
            return true;
        }
        if n < c {
            return false;
        }
    }
    // If numeric prefixes match up to the shorter length, the longer one wins —
    // except a pre-release tail like `-rc1` is not more components, it's less.
    if cand.len() != cur.len() {
        return cand.len() > cur.len();
    }
    // Exactly equal numerically: a stable release is newer than a pre-release.
    match (cur_pre, cand_pre) {
        (true, false) => true,
        (false, true) => false,
        _ => false,
    }
}

/// Parse a version string into (numeric components, has pre-release suffix).
/// Semver `-suffix` and `+build` tails are stripped before the numeric split.
fn parse_version(s: &str) -> (Vec<u64>, bool) {
    let s = s.trim_start_matches('v');
    let (head, has_suffix) = match s.split_once('-') {
        Some((before, _)) => (before, true),
        None => (s, false),
    };
    let head = head.split_once('+').map(|(b, _)| b).unwrap_or(head);
    let parts = head
        .split('.')
        .filter_map(|p| p.parse::<u64>().ok())
        .collect();
    (parts, has_suffix)
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

    #[test]
    fn prerelease_is_older_than_stable_same_numeric() {
        assert!(!is_newer("v1.2.3", "v1.2.3-rc1"));
        assert!(is_newer("v1.2.3-rc1", "v1.2.3"));
    }

    #[test]
    fn two_prereleases_same_numeric_are_equal() {
        // Conservative: we don't try to order rc1 vs rc2, so neither is newer.
        assert!(!is_newer("v1.2.3-rc1", "v1.2.3-rc2"));
        assert!(!is_newer("v1.2.3-rc2", "v1.2.3-rc1"));
    }

    #[test]
    fn numeric_bump_beats_prerelease_tail() {
        assert!(is_newer("v1.2.3-rc1", "v1.2.4"));
        assert!(!is_newer("v1.2.4", "v1.2.3-rc1"));
    }

    #[test]
    fn build_metadata_stripped() {
        assert!(!is_newer("v1.2.3+build.5", "v1.2.3+build.9"));
        assert!(is_newer("v1.2.3+build.9", "v1.2.4+build.1"));
    }

    #[test]
    fn leading_zeros() {
        assert!(is_newer("v01.02.03", "v01.02.04"));
    }

    #[test]
    fn empty_segments_skipped() {
        // "v1..3" splits into ["1", "", "3"], empty string fails parse → [1, 3]
        assert!(is_newer("v1.2", "v1.3"));
    }

    #[test]
    fn long_version() {
        assert!(is_newer("v1.2.3.4.5", "v1.2.3.4.6"));
        assert!(!is_newer("v1.2.3.4.6", "v1.2.3.4.5"));
    }

    #[test]
    fn both_empty_after_parse() {
        // No numeric components at all
        assert!(!is_newer("alpha", "beta"));
    }

    #[test]
    fn leading_version_token_extracts_version() {
        assert_eq!(leading_version_token("v6.0.2"), "v6.0.2");
        assert_eq!(leading_version_token("  v6.0.2  "), "v6.0.2");
        assert_eq!(
            leading_version_token("v6.0.2 (pinned by renovate)"),
            "v6.0.2"
        );
        assert_eq!(
            leading_version_token("v1.2.3-rc1 do not bump"),
            "v1.2.3-rc1"
        );
        assert_eq!(leading_version_token("1.2.3"), "1.2.3");
        // No leading version → fall back to the whole comment unchanged.
        assert_eq!(leading_version_token("pinned manually"), "pinned manually");
    }
}
