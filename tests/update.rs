mod common;

use predicates::prelude::*;

#[test]
fn no_token_exits_two() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    common::pinprick_cmd()
        .arg("update")
        .arg(dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("No GitHub token found"));
}

#[test]
fn no_token_json_error() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("update")
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
