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
    run_with_client(repo_root, apply, json, only, &client).await
}

/// The command loop behind [`run`], with the GitHub client injected so tests
/// can point the resolve-and-rewrite path at a mock server.
async fn run_with_client(
    repo_root: &Path,
    apply: bool,
    json: bool,
    only: Option<&str>,
    client: &GitHubClient,
) -> Result<ExitCode> {
    let files = workflow::find_workflows(repo_root)?;
    let mut report = UpdateReport {
        updates: Vec::new(),
        up_to_date: 0,
        applied: apply,
    };

    let mut releases_cache: HashMap<String, Vec<Release>> = HashMap::new();
    let mut releases_failed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut tags_cache: HashMap<String, Vec<String>> = HashMap::new();
    let mut tag_sha_cache: HashMap<String, String> = HashMap::new();

    for file in &files {
        let display_name = workflow::display_path(file.path(), repo_root);
        if !json {
            eprintln!("Scanning {display_name}...");
        }

        let actions = workflow::scan_workflow(file)?;
        let mut replacements: Vec<(usize, String, String)> = Vec::new();

        for action in &actions {
            if action.ref_type != RefType::Sha {
                continue;
            }
            if let Some(pat) = only
                && !action.owner_repo().contains(pat)
            {
                continue;
            }
            // Prefer the `# tag` comment; for a bare SHA pin without one (or a
            // non-version annotation like `# pinned manually`), ask GitHub
            // which tag points at the SHA instead of silently skipping — or,
            // worse, comparing against the annotation text.
            let comment_tag = action
                .tag_comment
                .as_deref()
                .map(leading_version_token)
                .filter(|t| is_version_like(t));
            let current_tag = match comment_tag {
                Some(t) => t,
                None => match client
                    .sha_to_tag(&action.owner, &action.repo, &action.ref_string)
                    .await
                {
                    Ok(Some(tag)) => leading_version_token(&tag),
                    // Unknown SHA or fetch failure — nothing to compare against.
                    _ => continue,
                },
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

            // Fall back to tags when there's no usable release — some actions
            // tag versions but never cut a GitHub Release.
            let (latest_tag, release_url) = match pick_latest_release(&releases) {
                Some(r) => (r.tag_name.clone(), r.html_url.clone()),
                None => {
                    let tags = match tags_cache.get(&owner_repo) {
                        Some(cached) => cached.clone(),
                        None => match client.list_tags(&action.owner, &action.repo).await {
                            Ok(t) => {
                                tags_cache.insert(owner_repo.clone(), t.clone());
                                t
                            }
                            Err(_) => continue,
                        },
                    };
                    match pick_latest_tag(&tags) {
                        Some(t) => (t.clone(), None),
                        None => {
                            report.up_to_date += 1;
                            continue;
                        }
                    }
                }
            };

            if latest_tag == current_tag {
                report.up_to_date += 1;
                continue;
            }

            if !is_newer(&current_tag, &latest_tag) {
                report.up_to_date += 1;
                continue;
            }

            let tag_key = format!("{owner_repo}@{latest_tag}");
            let new_sha = if let Some(cached) = tag_sha_cache.get(&tag_key) {
                cached.clone()
            } else {
                match client
                    .resolve_tag(&action.owner, &action.repo, &latest_tag)
                    .await
                {
                    Ok(sha) => {
                        tag_sha_cache.insert(tag_key, sha.clone());
                        sha
                    }
                    Err(_) => continue,
                }
            };

            // The "newer" tag can resolve to the commit already pinned (e.g. a
            // sliding `# v4` comment next to the latest release's SHA) — that
            // is not an update, just a different name for the same content.
            if new_sha == action.ref_string {
                report.up_to_date += 1;
                continue;
            }

            report.updates.push(UpdateResult {
                file: workflow::display_path(file.path(), repo_root),
                action: action.full_name(),
                current_tag: current_tag.clone(),
                current_sha: action.ref_string.clone(),
                latest_tag: latest_tag.clone(),
                latest_sha: new_sha.clone(),
                line: action.line_number,
                release_url,
            });

            if apply
                && let Some(new_line) =
                    workflow::build_pinned_line(&action.raw_line, &new_sha, &latest_tag)
            {
                replacements.push((action.line_number, action.raw_line.clone(), new_line));
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

    if has_updates && !apply {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Pick the highest version-like release. Rejects drafts, prereleases, and
/// non-version tags (e.g. `codeql-bundle-*`), then takes the highest version
/// rather than the most-recently-created release — this handles backport
/// releases like `v3.1.0-node20` published after `v8.0.1`.
fn pick_latest_release(releases: &[Release]) -> Option<&Release> {
    releases
        .iter()
        .filter(|r| !r.draft && !r.prerelease && is_version_like(&r.tag_name))
        .reduce(|best, r| {
            if is_newer(&best.tag_name, &r.tag_name) {
                r
            } else {
                best
            }
        })
}

/// Pick the highest version-like tag name. The release-less fallback path.
/// Prefers stable tags — unlike releases, tags carry no `prerelease` flag, so
/// a bare `v2.1.0-rc1` would otherwise win over `v2.0.0` and propose an RC.
fn pick_latest_tag(tags: &[String]) -> Option<&String> {
    let pick = |stable_only: bool| {
        tags.iter()
            .filter(|t| is_version_like(t) && (!stable_only || parse_version(t).1.is_none()))
            .reduce(|best, t| if is_newer(best, t) { t } else { best })
    };
    pick(true).or_else(|| pick(false))
}

/// Whether a tag looks like a version (`v1.2.3`, `2.0`) rather than a moving
/// pointer or a non-version tag like `codeql-bundle-*`.
fn is_version_like(tag: &str) -> bool {
    tag.strip_prefix('v')
        .unwrap_or(tag)
        .starts_with(|c: char| c.is_ascii_digit())
}

/// The leading `v?N…` version token of a `# comment` (up to the first space or
/// `(`), so an annotation like `# v1.2.3 (pinned)` doesn't break the comparison.
/// Falls back to the whole comment when it doesn't start with a version.
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
    // Exactly equal numerically: a stable release is newer than a pre-release,
    // and two pre-releases order by semver identifier rules.
    match (cur_pre, cand_pre) {
        (Some(_), None) => true,
        (Some(cur), Some(cand)) => prerelease_newer(&cur, &cand),
        _ => false,
    }
}

/// Whether `candidate` is a newer pre-release than `current`, per semver
/// pre-release ordering (`rc.1` < `rc.2`, `beta` < `rc1`). Suffixes that
/// aren't valid semver pre-release identifiers stay conservative: neither
/// is newer.
fn prerelease_newer(current: &str, candidate: &str) -> bool {
    match (
        semver::Prerelease::new(current),
        semver::Prerelease::new(candidate),
    ) {
        (Ok(cur), Ok(cand)) => cand > cur,
        _ => false,
    }
}

/// Parse a version string into (numeric components, pre-release suffix).
/// The semver `+build` tail is stripped before the numeric split.
fn parse_version(s: &str) -> (Vec<u64>, Option<String>) {
    let s = s.trim_start_matches('v');
    let (head, pre) = match s.split_once('-') {
        Some((before, suffix)) => (before, Some(suffix.to_string())),
        None => (s, None),
    };
    let head = head.split_once('+').map(|(b, _)| b).unwrap_or(head);
    let parts = head
        .split('.')
        .filter_map(|p| p.parse::<u64>().ok())
        .collect();
    (parts, pre)
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
    fn two_prereleases_same_numeric_order_by_semver_rules() {
        assert!(is_newer("v1.2.3-rc1", "v1.2.3-rc2"));
        assert!(!is_newer("v1.2.3-rc2", "v1.2.3-rc1"));
        assert!(is_newer("v1.2.3-rc.1", "v1.2.3-rc.2"));
        assert!(is_newer("v1.2.3-beta", "v1.2.3-rc1"));
        assert!(!is_newer("v1.2.3-rc1", "v1.2.3-beta"));
        // Identical pre-releases: neither is newer.
        assert!(!is_newer("v1.2.3-rc1", "v1.2.3-rc1"));
    }

    #[test]
    fn invalid_prerelease_suffixes_stay_conservative() {
        // Not valid semver pre-release identifiers — don't guess an order.
        assert!(!is_newer("v1.2.3-r_c1", "v1.2.3-r_c2"));
        assert!(!is_newer("v1.2.3-r_c2", "v1.2.3-r_c1"));
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
        // "v1..3" splits into ["1", "", "3"]; the empty segment is dropped → [1, 3].
        assert!(is_newer("v1..2", "v1..3"));
    }

    #[test]
    fn long_version() {
        assert!(is_newer("v1.2.3.4.5", "v1.2.3.4.6"));
        assert!(!is_newer("v1.2.3.4.6", "v1.2.3.4.5"));
    }

    #[test]
    fn both_empty_after_parse() {
        assert!(!is_newer("alpha", "beta"));
    }

    #[test]
    fn pick_latest_tag_takes_highest_version() {
        let tags = vec![
            "v1".to_string(),
            "v1.0.0".to_string(),
            "v1.3.0".to_string(),
            "v1.2.0".to_string(),
            "nightly".to_string(),
        ];
        assert_eq!(pick_latest_tag(&tags).unwrap(), "v1.3.0");
    }

    #[test]
    fn pick_latest_tag_ignores_non_version_tags() {
        let tags = vec!["latest".to_string(), "stable".to_string()];
        assert_eq!(pick_latest_tag(&tags), None);
        assert_eq!(pick_latest_tag(&[]), None);
    }

    #[test]
    fn pick_latest_tag_prefers_stable_over_newer_prerelease() {
        let tags = vec!["v2.0.0".to_string(), "v2.1.0-rc1".to_string()];
        assert_eq!(pick_latest_tag(&tags).unwrap(), "v2.0.0");
    }

    #[test]
    fn pick_latest_tag_falls_back_to_prerelease_when_no_stable() {
        let tags = vec!["v0.1.0-beta".to_string(), "v0.2.0-rc1".to_string()];
        assert_eq!(pick_latest_tag(&tags).unwrap(), "v0.2.0-rc1");
    }

    #[test]
    fn pick_latest_release_skips_drafts_and_prereleases() {
        let rel = |tag: &str, draft: bool, prerelease: bool| Release {
            tag_name: tag.to_string(),
            draft,
            prerelease,
            html_url: None,
        };
        let releases = vec![
            rel("v2.0.0", false, false),
            rel("v3.0.0", true, false),           // draft, skipped
            rel("v2.5.0", false, true),           // prerelease, skipped
            rel("codeql-bundle-x", false, false), // non-version, skipped
        ];
        assert_eq!(pick_latest_release(&releases).unwrap().tag_name, "v2.0.0");
    }

    #[test]
    fn is_version_like_matches_digit_after_optional_v() {
        assert!(is_version_like("v1.2.3"));
        assert!(is_version_like("2.0"));
        assert!(!is_version_like("latest"));
        assert!(!is_version_like("codeql-bundle-v1"));
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

    mod command {
        use super::*;
        use crate::github::GitHubClient;
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const OLD_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
        const NEW_SHA: &str = "89abcdef0123456789abcdef0123456789abcdef";

        /// `ExitCode` exposes no accessor; its Debug form is the only stable
        /// way to compare against an expected status in-process.
        fn assert_code(code: ExitCode, expected: u8) {
            assert_eq!(
                format!("{code:?}"),
                format!("{:?}", ExitCode::from(expected))
            );
        }

        fn repo_with_workflow(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::TempDir::new().unwrap();
            let workflows = dir.path().join(".github").join("workflows");
            std::fs::create_dir_all(&workflows).unwrap();
            let file = workflows.join("ci.yml");
            std::fs::write(&file, content).unwrap();
            (dir, file)
        }

        fn client_for(server: &MockServer) -> GitHubClient {
            GitHubClient::with_base("test-token".into(), server.uri())
        }

        async fn mount_release(server: &MockServer, owner_repo: &str, tag: &str) {
            Mock::given(method("GET"))
                .and(path(format!("/repos/{owner_repo}/releases")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "tag_name": tag, "draft": false, "prerelease": false,
                      "html_url": format!("https://example.com/{tag}") }
                ])))
                .mount(server)
                .await;
        }

        async fn mount_tag_resolution(server: &MockServer, owner_repo: &str, tag: &str, sha: &str) {
            Mock::given(method("GET"))
                .and(path(format!("/repos/{owner_repo}/git/ref/tags/{tag}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "object": { "sha": sha, "type": "commit" }
                })))
                .mount(server)
                .await;
        }

        #[tokio::test]
        async fn newer_release_is_applied_to_the_workflow() {
            let server = MockServer::start().await;
            mount_release(&server, "actions/checkout", "v1.1.0").await;
            mount_tag_resolution(&server, "actions/checkout", "v1.1.0", NEW_SHA).await;

            let (dir, file) = repo_with_workflow(&format!(
                "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@{OLD_SHA} # v1.0.0\n"
            ));

            let code = run_with_client(dir.path(), true, true, None, &client_for(&server))
                .await
                .unwrap();

            assert_code(code, 0);
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                format!(
                    "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@{NEW_SHA} # v1.1.0\n"
                )
            );
        }

        #[tokio::test]
        async fn dry_run_reports_update_without_rewriting_and_exits_one() {
            let server = MockServer::start().await;
            mount_release(&server, "actions/checkout", "v1.1.0").await;
            mount_tag_resolution(&server, "actions/checkout", "v1.1.0", NEW_SHA).await;

            let original = format!(
                "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@{OLD_SHA} # v1.0.0\n"
            );
            let (dir, file) = repo_with_workflow(&original);

            let code = run_with_client(dir.path(), false, true, None, &client_for(&server))
                .await
                .unwrap();

            assert_code(code, 1);
            assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
        }

        #[tokio::test]
        async fn falls_back_to_tags_when_repo_has_no_releases() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/releases"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "name": "v2.0.0", "commit": { "sha": "unrelated" } }
                ])))
                .mount(&server)
                .await;
            mount_tag_resolution(&server, "o/r", "v2.0.0", NEW_SHA).await;

            let (dir, file) = repo_with_workflow(&format!(
                "jobs:\n  test:\n    steps:\n      - uses: o/r@{OLD_SHA} # v1.0.0\n"
            ));

            let code = run_with_client(dir.path(), true, true, None, &client_for(&server))
                .await
                .unwrap();

            assert_code(code, 0);
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                format!("jobs:\n  test:\n    steps:\n      - uses: o/r@{NEW_SHA} # v2.0.0\n")
            );
        }

        #[tokio::test]
        async fn newer_tag_name_for_the_same_commit_is_not_an_update() {
            // A "newer" tag that resolves to the already-pinned commit is just
            // a different name for the same content — up to date, exit 0.
            let server = MockServer::start().await;
            mount_release(&server, "o/r", "v1.1.0").await;
            mount_tag_resolution(&server, "o/r", "v1.1.0", OLD_SHA).await;

            let original =
                format!("jobs:\n  test:\n    steps:\n      - uses: o/r@{OLD_SHA} # v1.0.0\n");
            let (dir, file) = repo_with_workflow(&original);

            let code = run_with_client(dir.path(), false, true, None, &client_for(&server))
                .await
                .unwrap();

            assert_code(code, 0);
            assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
        }

        #[tokio::test]
        async fn only_filter_skips_non_matching_actions_entirely() {
            let server = MockServer::start().await;
            mount_release(&server, "actions/checkout", "v1.1.0").await;
            mount_tag_resolution(&server, "actions/checkout", "v1.1.0", NEW_SHA).await;

            let (dir, file) = repo_with_workflow(&format!(
                "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@{OLD_SHA} # v1.0.0\n      - uses: other/action@{OLD_SHA} # v0.1.0\n"
            ));

            let code = run_with_client(
                dir.path(),
                true,
                true,
                Some("checkout"),
                &client_for(&server),
            )
            .await
            .unwrap();

            assert_code(code, 0);
            // The matching action is updated; the filtered one is untouched.
            let rewritten = std::fs::read_to_string(&file).unwrap();
            assert!(rewritten.contains(&format!("actions/checkout@{NEW_SHA} # v1.1.0")));
            assert!(rewritten.contains(&format!("other/action@{OLD_SHA} # v0.1.0")));
            // And no request was ever made for the filtered repo.
            let requests = server.received_requests().await.unwrap();
            assert!(
                requests
                    .iter()
                    .all(|r| !r.url.path().starts_with("/repos/other/action")),
                "filtered action must not be queried"
            );
        }

        #[tokio::test]
        async fn bare_sha_pin_is_resolved_via_tag_lookup() {
            // No `# tag` comment: the current version comes from the tags
            // endpoint (which tag points at the pinned SHA?), then the release
            // comparison proceeds as usual.
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "name": "v1.0.0", "commit": { "sha": OLD_SHA } },
                    { "name": "v1.1.0", "commit": { "sha": NEW_SHA } }
                ])))
                .mount(&server)
                .await;
            mount_release(&server, "o/r", "v1.1.0").await;
            mount_tag_resolution(&server, "o/r", "v1.1.0", NEW_SHA).await;

            let (dir, file) = repo_with_workflow(&format!(
                "jobs:\n  test:\n    steps:\n      - uses: o/r@{OLD_SHA}\n"
            ));

            let code = run_with_client(dir.path(), true, true, None, &client_for(&server))
                .await
                .unwrap();

            assert_code(code, 0);
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                format!("jobs:\n  test:\n    steps:\n      - uses: o/r@{NEW_SHA} # v1.1.0\n")
            );
        }
    }
}
