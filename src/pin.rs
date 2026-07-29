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
    run_with_client(repo_root, json, apply, &client).await
}

/// The command loop behind [`run`], with the GitHub client injected so tests
/// can point the resolve-and-rewrite path at a mock server.
async fn run_with_client(
    repo_root: &Path,
    json: bool,
    apply: bool,
    client: &GitHubClient,
) -> Result<ExitCode> {
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

        let content = workflow::read_workflow(file)?;
        let actions = workflow::scan_content(&content);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    /// `ExitCode` exposes no accessor; its Debug form is the only stable way
    /// to compare against an expected status in-process.
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

    #[tokio::test]
    async fn sliding_tag_resolves_rewrites_and_keeps_most_specific_tag() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/actions/checkout/git/ref/tags/v4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": { "sha": SHA, "type": "commit" }
            })))
            .mount(&server)
            .await;
        // v4 and v4.2.1 both point at the release commit; the rewritten
        // comment must carry the most specific tag.
        Mock::given(method("GET"))
            .and(path("/repos/actions/checkout/git/matching-refs/tags/v4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                { "ref": "refs/tags/v4", "object": { "sha": SHA, "type": "commit" } },
                { "ref": "refs/tags/v4.2.1", "object": { "sha": SHA, "type": "commit" } }
            ])))
            .mount(&server)
            .await;

        let (dir, file) =
            repo_with_workflow("jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n");

        let code = run_with_client(dir.path(), true, true, &client_for(&server))
            .await
            .unwrap();

        assert_code(code, 0);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("jobs:\n  test:\n    steps:\n      - uses: actions/checkout@{SHA} # v4.2.1\n")
        );
    }

    #[tokio::test]
    async fn dry_run_reports_but_does_not_rewrite_and_exits_one() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/actions/checkout/git/ref/tags/v4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": { "sha": SHA, "type": "commit" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/actions/checkout/git/matching-refs/tags/v4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let original = "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n";
        let (dir, file) = repo_with_workflow(original);

        let code = run_with_client(dir.path(), true, false, &client_for(&server))
            .await
            .unwrap();

        assert_code(code, 1);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
    }

    #[tokio::test]
    async fn annotated_tag_double_dereferences_to_commit_sha() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/ref/tags/v1.2.3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": { "sha": "tagobjsha", "type": "tag" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/tags/tagobjsha"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": { "sha": SHA }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/matching-refs/tags/v1.2.3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let (dir, file) =
            repo_with_workflow("jobs:\n  test:\n    steps:\n      - uses: o/r@v1.2.3\n");

        let code = run_with_client(dir.path(), true, true, &client_for(&server))
            .await
            .unwrap();

        // The workflow must be pinned to the tag's target commit, never the
        // annotated tag object's own SHA.
        assert_code(code, 0);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("jobs:\n  test:\n    steps:\n      - uses: o/r@{SHA} # v1.2.3\n")
        );
    }

    #[tokio::test]
    async fn resolution_failure_is_skipped_and_fails_dry_run() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/ref/tags/v9"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let original = "jobs:\n  test:\n    steps:\n      - uses: o/r@v9\n";
        let (dir, file) = repo_with_workflow(original);

        let code = run_with_client(dir.path(), true, false, &client_for(&server))
            .await
            .unwrap();

        assert_code(code, 1);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
    }

    #[tokio::test]
    async fn rewrite_preserves_crlf_through_the_command() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/ref/tags/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": { "sha": SHA, "type": "commit" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/matching-refs/tags/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let (dir, file) =
            repo_with_workflow("jobs:\r\n  test:\r\n    steps:\r\n      - uses: o/r@v2\r\n");

        let code = run_with_client(dir.path(), true, true, &client_for(&server))
            .await
            .unwrap();

        assert_code(code, 0);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("jobs:\r\n  test:\r\n    steps:\r\n      - uses: o/r@{SHA} # v2\r\n")
        );
    }
}
