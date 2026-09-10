mod common;

use predicates::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

const COMMAND: &str = r#"curl --output "$OUTPUT" "$URL""#;
const DESCRIPTION: &str =
    "curl/wget downloads executable from non-literal source — cannot verify URL version";

fn workflow(extra: &str) -> String {
    format!(
        "name: scan\non: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {COMMAND}\n{extra}"
    )
}

fn acceptance(source: &str) -> String {
    format!(
        r#"[[accept-workflow-findings]]
workflow = ".github/workflows/scan.yml"
workflow-sha256 = "{:x}"
category = "shell_fetch"
severity = "low"
description = {DESCRIPTION:?}
command = {COMMAND:?}
reason = "Maintainer accepts this reviewed archive input; never execute its contents."
"#,
        Sha256::digest(source.as_bytes())
    )
}

fn audit(path: &std::path::Path, options: &[&str]) -> (i32, Value) {
    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(path)
        .args(options)
        .output()
        .unwrap();
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn reviewed_workflow_finding_remains_visible_in_every_format() {
    let source = workflow("");
    let dir = common::repo_with_config("scan.yml", &source, &acceptance(&source));
    let (status, report) = audit(dir.path(), &["--json"]);
    assert_eq!(status, 0);
    assert_eq!(report["coverage_complete"], true);
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(report["accepted"][0]["pattern_matched"], COMMAND);
    assert_eq!(report["accepted"][0]["description"], DESCRIPTION);
    assert!(
        report["accepted"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("Maintainer")
    );

    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "ACCEPTED  .github/workflows/scan.yml",
        ))
        .stdout(predicate::str::contains(
            "No unaccepted runtime fetch risks found; 1 explicitly accepted.",
        ))
        .stderr(predicate::str::contains("workflow findings accepted: 1"));
    let (status, sarif) = audit(dir.path(), &["--sarif"]);
    assert_eq!(status, 0);
    assert_eq!(
        sarif["runs"][0]["results"][0]["suppressions"][0]["kind"],
        "external"
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["suppressions"][0]["status"],
        "accepted"
    );
    assert_eq!(
        sarif["runs"][0]["properties"]["pinprickCoverageComplete"],
        true
    );

    let (status, report) = audit(dir.path(), &["--json", "--no-repo-config"]);
    assert_eq!(status, 1);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert!(report.get("accepted").is_none());
}

#[test]
fn every_identity_field_and_nonempty_reason_are_required() {
    let source = workflow("");
    let config = acceptance(&source);
    for (from, to) in [
        ("scan.yml", "other.yml"),
        ("shell_fetch", "python_fetch"),
        ("severity = \"low\"", "severity = \"medium\""),
        ("cannot verify URL version", "different description"),
        ("curl --output", "curl --silent --output"),
        (
            "Maintainer accepts this reviewed archive input; never execute its contents.",
            "  ",
        ),
    ] {
        let dir = common::repo_with_config("scan.yml", &source, &config.replace(from, to));
        let (status, report) = audit(dir.path(), &["--json"]);
        assert_eq!(status, 1, "changed {from}");
        assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn any_workflow_change_invalidates_acceptance_without_hiding_the_finding() {
    let source = workflow("");
    let dir = common::repo_with_config(
        "scan.yml",
        &format!("{source}# changed context\n"),
        &acceptance(&source),
    );
    let (status, report) = audit(dir.path(), &["--json"]);
    assert_eq!(status, 1);
    assert_eq!(report["coverage_complete"], true);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn acceptance_never_makes_missing_source_coverage_successful() {
    let source = workflow("      - uses: ./missing-action\n");
    let dir = common::repo_with_config("scan.yml", &source, &acceptance(&source));
    for format in ["--json", "--sarif"] {
        let (status, report) = audit(dir.path(), &[format]);
        assert_eq!(status, 2);
        if format == "--json" {
            assert_eq!(report["coverage_complete"], false);
            assert_eq!(report["accepted"].as_array().unwrap().len(), 1);
            assert!(!report["coverage_failures"].as_array().unwrap().is_empty());
        } else {
            assert_eq!(
                report["runs"][0]["properties"]["pinprickCoverageComplete"],
                false
            );
        }
    }
}

#[test]
fn sibling_workflow_findings_are_not_accepted() {
    let source = workflow("");
    let dir = common::repo_with_config("scan.yml", &source, &acceptance(&source));
    std::fs::write(dir.path().join(".github/workflows/other.yml"), &source).unwrap();
    let (status, report) = audit(dir.path(), &["--json"]);
    assert_eq!(status, 1);
    assert_eq!(report["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["findings"][0]["source_file"],
        ".github/workflows/other.yml"
    );
}

#[test]
fn global_configuration_cannot_accept_repository_workflow_findings() {
    let source = workflow("");
    let dir = common::repo_with_workflow("scan.yml", &source);
    let global = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(global.path().join("pinprick")).unwrap();
    std::fs::write(
        global.path().join("pinprick/config.toml"),
        acceptance(&source),
    )
    .unwrap();
    common::pinprick_cmd()
        .env("XDG_CONFIG_HOME", global.path())
        .arg("audit")
        .arg(dir.path())
        .arg("--json")
        .assert()
        .code(1)
        .stdout(predicate::str::contains(DESCRIPTION));
}
