mod common;

use predicates::prelude::*;

const WORKFLOW_UNPINNED_SLIDING: &str = "\
name: sliding
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
";

const WORKFLOW_PERMISSIONS_WRITE_ALL: &str = "\
name: write-all
on: push
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
";

const WORKFLOW_PR_TARGET: &str = "\
name: pr-target
on:
  pull_request_target:
    branches: [main]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
";

#[test]
fn clean_repo_exits_zero() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Grade:  A"))
        .stdout(predicate::str::contains("100 / 100"));
}

#[test]
fn sliding_tag_exits_one() {
    let dir = common::repo_with_workflow("ci.yml", WORKFLOW_UNPINNED_SLIDING);
    common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("pin.sliding"));
}

#[test]
fn permissions_write_all_fires_workflow_rule() {
    let dir = common::repo_with_workflow("ci.yml", WORKFLOW_PERMISSIONS_WRITE_ALL);
    common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("workflow.permissions_write_all"));
}

#[test]
fn pull_request_target_fires_workflow_rule() {
    let dir = common::repo_with_workflow("ci.yml", WORKFLOW_PR_TARGET);
    common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("workflow.pull_request_target"));
}

#[test]
fn json_output_shape() {
    let dir = common::repo_with_workflow("ci.yml", WORKFLOW_UNPINNED_SLIDING);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("score")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(json["rubric_version"], "0.2.0");
    assert_eq!(json["grade"], "A");
    assert_eq!(json["score"], 95);
    assert_eq!(json["totals"]["findings"], 1);
    assert_eq!(json["totals"]["workflows_scanned"], 1);
    assert_eq!(json["findings"][0]["id"], "pin.sliding");
    assert_eq!(json["findings"][0]["points"], 5);
    assert_eq!(json["findings"][0]["category"], "pin");
    assert_eq!(json["findings"][0]["severity"], "medium");
    assert_eq!(json["findings"][0]["action_ref"], "actions/checkout@v4");
    assert_eq!(
        json["findings"][0]["occurrences"][0]["workflow"],
        ".github/workflows/ci.yml"
    );
}

#[test]
fn no_workflows_directory_errors() {
    // Temp dir with no .github/workflows/ — score should fail cleanly.
    let dir = tempfile::TempDir::new().unwrap();
    common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("No .github/workflows/"));
}

#[test]
fn html_output_contains_expected_markers() {
    let dir = common::repo_with_workflow("ci.yml", WORKFLOW_UNPINNED_SLIDING);
    let output = common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .arg("--html")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let html = String::from_utf8(output.stdout).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("<title>pinprick score report</title>"));
    assert!(html.contains("grade-A"));
    assert!(html.contains("95 / 100"));
    assert!(html.contains("pin.sliding"));
    assert!(html.contains("actions/checkout@v4"));
    assert!(html.contains("pinprick.rs"));
    assert!(html.ends_with("</html>\n"));
}
