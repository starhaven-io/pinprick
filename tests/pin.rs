mod common;

use predicates::prelude::*;

#[test]
fn no_token_exits_two() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    common::pinprick_cmd()
        .arg("pin")
        .arg(dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("No GitHub token found"));
}

#[test]
fn no_token_human_error() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    common::pinprick_cmd()
        .arg("pin")
        .arg(dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("gh auth login"));
}

#[test]
fn branch_ref_dry_run_exits_one() {
    // A branch ref is an unpinned action `pin` can't fix automatically; a CI
    // gate must still fail on it. No network: the branch arm short-circuits
    // before any API call, so a dummy token is enough.
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_BRANCH_REF);
    common::pinprick_cmd()
        .env("GITHUB_TOKEN", "dummy")
        .arg("pin")
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("branch ref"));
}

#[test]
fn all_pinned_dry_run_exits_zero() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    common::pinprick_cmd()
        .env("GITHUB_TOKEN", "dummy")
        .arg("pin")
        .arg(dir.path())
        .assert()
        .code(0);
}

#[test]
fn no_token_json_error() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("pin")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("No GitHub token found")
    );
}
