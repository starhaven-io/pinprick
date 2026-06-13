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

// SHA-pinned (no pin.* finding) but from a publisher outside the trusted
// baseline — produces only the zero-point source.unverified note.
const WORKFLOW_UNVERIFIED_ONLY: &str = "\
name: unverified
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: some-vendor/tool@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v1.0.0
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
fn informational_only_findings_exit_zero() {
    // source.unverified is a zero-point informational note: it must appear
    // in the output without denting the score or failing the CI gate.
    let dir = common::repo_with_workflow("ci.yml", WORKFLOW_UNVERIFIED_ONLY);
    common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("source.unverified"))
        .stdout(predicate::str::contains("100 / 100"));
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

    assert_eq!(json["rubric_version"], "0.7.0");
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
    let dir = tempfile::TempDir::new().unwrap();
    common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("No .github/workflows/"));
}

#[test]
fn runtime_rules_fire_on_risky_run_block() {
    // A run-block with pipe-to-shell + wget-latest + git clone + pip install
    // should fire each runtime.* rule category.
    let workflow = "\
name: risky
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: |
          curl -fsSL https://example.com/install.sh | bash
          wget https://github.com/owner/repo/releases/latest/download/tool
          git clone https://github.com/other/thing
          pip install requests
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("score")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let ids: Vec<String> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&"runtime.pipe_to_shell".to_string()));
    assert!(ids.contains(&"runtime.fetch.high".to_string()));
    assert!(ids.contains(&"runtime.fetch.medium".to_string()));
    assert!(ids.contains(&"runtime.fetch.low".to_string()));
}

#[test]
fn ignore_patterns_suppresses_runtime_score_finding() {
    let workflow = "\
name: risky
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: curl -fsSL https://example.com/install.sh | bash
";
    // Without a suppression, the pipe-to-shell runtime finding fires (exit 1).
    let dir = common::repo_with_workflow("ci.yml", workflow);
    common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .assert()
        .code(1);

    // An explicit `ignore.patterns` entry removes it from the score, leaving
    // the repo clean (the severity display threshold would NOT do this).
    let dir2 = common::repo_with_config(
        "ci.yml",
        workflow,
        "[ignore]\npatterns = [\"piped to shell\"]\n",
    );
    common::pinprick_cmd()
        .arg("score")
        .arg(dir2.path())
        .assert()
        .success();
}

#[test]
fn repo_config_suppression_prints_notice_and_flag_restores() {
    let workflow = "\
name: risky
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: curl -fsSL https://example.com/install.sh | bash
";
    let dir = common::repo_with_config(
        "ci.yml",
        workflow,
        "[ignore]\npatterns = [\"piped to shell\"]\n",
    );

    // The scanned repo's own config shaped the score — a notice must say so.
    let output = common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("note: the scanned repo's .pinprick.toml affected the score"),
        "expected a repo-config notice on stderr, got: {stderr}"
    );
    assert!(stderr.contains("runtime findings suppressed: 1"));

    // --no-repo-config ignores the local file: finding returns, no notice.
    let output = common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .arg("--no-repo-config")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("note: the scanned repo's .pinprick.toml"));
}

#[test]
fn repo_config_trusted_owners_notice() {
    let workflow = "\
name: vendor
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: my-vendor/tool@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v1.0.0
      - run: echo ok
";
    let dir = common::repo_with_config("ci.yml", workflow, "trusted-owners = [\"my-vendor\"]\n");

    let output = common::pinprick_cmd()
        .arg("score")
        .arg(dir.path())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("actions exempted via trusted-owners: 1"),
        "expected a trusted-owners notice on stderr, got: {stderr}"
    );
}

#[test]
fn html_conflicts_with_json() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("score")
        .arg(dir.path())
        .arg("--html")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(json["error"].as_str().unwrap().contains("--html"));
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
