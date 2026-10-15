mod common;

use predicates::prelude::*;
use serde_json::Value;
use std::fs;

const OLD_SHA: &str = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0";
const NEW_SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";
const COMMAND: &str = r#"curl --output "$OUTPUT" "$URL""#;
const DESCRIPTION: &str =
    "curl/wget downloads executable from non-literal source — cannot verify URL version";

fn workflow() -> String {
    format!(
        "name: scan\non: push\npermissions: {{}}\nenv:\n  URL: https://example.invalid/archive\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    environment: scanner\n    steps:\n      - uses: actions/checkout@{OLD_SHA} # v7.0.0\n        with:\n          persist-credentials: false\n      - run: {COMMAND}\n"
    )
}

fn fingerprint(root: &std::path::Path) -> Value {
    let output = common::pinprick_cmd()
        .args(["workflow-fingerprint", "--json"])
        .arg(root)
        .args([
            "--workflow",
            ".github/workflows/scan.yml",
            "--ignore-action-revision",
            "actions/checkout",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap()
}

fn acceptance(digest: &str) -> String {
    format!(
        r#"[[accept-workflow-findings]]
workflow = ".github/workflows/scan.yml"
workflow-context-sha256 = "{digest}"
ignore-action-revisions = ["actions/checkout"]
category = "shell_fetch"
severity = "low"
description = {DESCRIPTION:?}
command = {COMMAND:?}
reason = "Reviewed archive input for static scanning."
"#
    )
}

fn accepted_repo(source: &str) -> (tempfile::TempDir, String) {
    let dir = common::repo_with_workflow("scan.yml", source);
    let digest = fingerprint(dir.path())["workflow_context_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    fs::write(dir.path().join(".pinprick.toml"), acceptance(&digest)).unwrap();
    (dir, digest)
}

fn audit_with_stderr(root: &std::path::Path, options: &[&str]) -> (i32, Value, String) {
    let result = common::pinprick_cmd()
        .arg("audit")
        .arg(root)
        .args(options)
        .output()
        .unwrap();
    (
        result.status.code().unwrap(),
        serde_json::from_slice(&result.stdout).unwrap(),
        String::from_utf8(result.stderr).unwrap(),
    )
}

fn audit(root: &std::path::Path, options: &[&str]) -> (i32, Value) {
    let (status, report, _) = audit_with_stderr(root, options);
    (status, report)
}

const UNUSABLE: &str =
    "warning: accept-workflow-findings entry 1 (.github/workflows/scan.yml) accepts nothing: ";

#[test]
fn dependency_pin_updates_keep_acceptance_and_report_its_scope() {
    let source = workflow();
    let (dir, digest) = accepted_repo(&source);
    let updated = source
        .replace(OLD_SHA, NEW_SHA)
        .replace("# v7.0.0", "# v7.0.1");
    fs::write(dir.path().join(".github/workflows/scan.yml"), updated).unwrap();
    assert_eq!(fingerprint(dir.path())["workflow_context_sha256"], digest);
    let (status, report) = audit(dir.path(), &["--json"]);
    assert_eq!(status, 0);
    assert_eq!(report["coverage_complete"], true);
    assert_eq!(report["audited_bundled"], 1);
    assert_eq!(report["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(report["accepted"][0]["workflow_context_sha256"], digest);
    assert_eq!(
        report["accepted"][0]["ignore_action_revisions"],
        serde_json::json!(["actions/checkout"])
    );
    assert!(report["accepted"][0].get("workflow_sha256").is_none());
    let (status, sarif) = audit(dir.path(), &["--sarif"]);
    assert_eq!(status, 0);
    assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("workflow context SHA-256:"))
        .stdout(predicate::str::contains(
            "ignored action revisions: actions/checkout",
        ));
    let (status, report) = audit(dir.path(), &["--json", "--no-repo-config"]);
    assert_eq!(status, 1);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn changes_to_security_context_or_occurrences_invalidate_acceptance() {
    let source = workflow();
    let (dir, _) = accepted_repo(&source);
    let mutations = [
        source.replace("on: push", "on: pull_request_target"),
        source.replace("permissions: {}", "permissions: write-all"),
        source.replace("ubuntu-latest", "self-hosted"),
        source.replace("environment: scanner", "environment: production"),
        source.replace(
            "https://example.invalid/archive",
            "https://other.invalid/archive",
        ),
        source.replace("persist-credentials: false", "persist-credentials: true"),
        source.replace("      - run:", "      - if: always()\n        run:"),
        source.replace(COMMAND, &format!("{COMMAND} --insecure")),
        format!("{source}      - run: {COMMAND}\n"),
        source.replace("# v7.0.0", "# v7.0.0 security rationale"),
        source.replace(
            "      - run:",
            "      - run: echo validation removed\n      - run:",
        ),
        source.replace("steps:\n", &format!("steps:\n      - run: {COMMAND}\n")),
    ];
    for changed in mutations {
        fs::write(dir.path().join(".github/workflows/scan.yml"), &changed).unwrap();
        let (status, report) = audit(dir.path(), &["--json"]);
        assert_eq!(status, 1, "{changed}\n{report}");
        assert!(report.get("accepted").is_none(), "{changed}");
    }
}

#[test]
fn changed_identity_unpinned_reference_and_unknown_sha_never_pass() {
    let source = workflow();
    let (dir, _) = accepted_repo(&source);
    for (changed, problem) in [
        (
            source.replace("actions/checkout", "other/checkout"),
            "each ignored action must occur as a SHA-pinned step action",
        ),
        (
            source.replace("actions/checkout", "actions/checkout/subpath"),
            "each ignored action must occur as a SHA-pinned step action",
        ),
        (
            source.replace(OLD_SHA, "main"),
            "ignored action must use a full SHA pin",
        ),
        (
            source.replace(OLD_SHA, "v7"),
            "ignored action must use a full SHA pin",
        ),
        (
            source.replace(OLD_SHA, "abc123"),
            "ignored action must use a full SHA pin",
        ),
    ] {
        fs::write(dir.path().join(".github/workflows/scan.yml"), &changed).unwrap();
        let (status, report, stderr) = audit_with_stderr(dir.path(), &["--json"]);
        assert_ne!(status, 0);
        assert!(report.get("accepted").is_none());
        assert!(
            stderr.contains(&format!("{UNUSABLE}{problem}")),
            "{changed}\n{stderr}"
        );
    }
    fs::write(
        dir.path().join(".github/workflows/scan.yml"),
        source.replace(OLD_SHA, &"a".repeat(40)),
    )
    .unwrap();
    let (status, report) = audit(dir.path(), &["--json"]);
    assert_eq!(status, 2);
    assert_eq!(report["coverage_complete"], false);
    assert_eq!(report["accepted"].as_array().unwrap().len(), 1);
}

#[test]
fn local_action_findings_and_missing_coverage_remain_fatal() {
    let source = format!("{}      - uses: ./act\n", workflow());
    let (dir, _) = accepted_repo(&source);
    let (status, report) = audit(dir.path(), &["--json"]);
    assert_eq!(status, 2);
    assert_eq!(report["accepted"].as_array().unwrap().len(), 1);
    fs::create_dir(dir.path().join("act")).unwrap();
    fs::write(dir.path().join("act/action.yml"), "name: unsafe\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: curl https://example.invalid/install.sh | bash\n").unwrap();
    let (status, report) = audit(dir.path(), &["--json"]);
    assert_eq!(status, 1);
    assert_eq!(report["coverage_complete"], true);
    assert_eq!(report["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn ambiguous_or_broadened_config_accepts_nothing() {
    let (dir, digest) = accepted_repo(&workflow());
    let valid = acceptance(&digest);
    for (config, problem) in [
        (
            format!("{valid}workflow-sha256 = {:?}\n", "a".repeat(64)),
            Some("sets both workflow-sha256 and workflow-context-sha256"),
        ),
        (
            valid.replace(&format!("workflow-context-sha256 = \"{digest}\"\n"), ""),
            Some("sets neither workflow-sha256 nor workflow-context-sha256"),
        ),
        (
            valid.replace("workflow-context-sha256", "workflow-sha256"),
            Some("sets ignore-action-revisions without workflow-context-sha256"),
        ),
        (
            valid.replace(
                "ignore-action-revisions = [\"actions/checkout\"]",
                "ignore-action-revisions = []",
            ),
            Some("at least one action identity is required"),
        ),
        (
            valid.replace("actions/checkout", "actions/*"),
            Some("expected one literal owner/repo[/subpath] action identity"),
        ),
        (
            valid.replace("actions/checkout", "actions/../checkout"),
            Some("expected one literal owner/repo[/subpath] action identity"),
        ),
        (
            valid.replace(
                "[\"actions/checkout\"]",
                "[\"actions/checkout\", \"actions/checkout\"]",
            ),
            Some("duplicate action identity"),
        ),
        (
            valid.replace(
                "[\"actions/checkout\"]",
                "[\"actions/checkout\", \"actions/upload-artifact\"]",
            ),
            Some("each ignored action must occur as a SHA-pinned step action"),
        ),
        (valid.replace(&digest, &"0".repeat(64)), None),
    ] {
        fs::write(dir.path().join(".pinprick.toml"), &config).unwrap();
        let (status, report, stderr) = audit_with_stderr(dir.path(), &["--json"]);
        assert_eq!(status, 1, "{config}\n{stderr}");
        assert!(report.get("accepted").is_none(), "{config}");
        match problem {
            Some(problem) => assert!(
                stderr.contains(&format!("{UNUSABLE}{problem}\n")),
                "{config}\n{stderr}"
            ),
            None => assert!(!stderr.contains("accepts nothing"), "{config}\n{stderr}"),
        }
    }
}

#[test]
fn fingerprint_command_refuses_escape_and_symlinked_workflows() {
    let dir = common::repo_with_workflow("scan.yml", &workflow());
    for path in [
        "../scan.yml",
        ".github/workflows/../workflows/scan.yml",
        "/tmp/scan.yml",
    ] {
        common::pinprick_cmd()
            .arg("workflow-fingerprint")
            .arg(dir.path())
            .args([
                "--workflow",
                path,
                "--ignore-action-revision",
                "actions/checkout",
            ])
            .assert()
            .code(2);
    }
    fs::rename(
        dir.path().join(".github/workflows/scan.yml"),
        dir.path().join("source.yml"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../../source.yml",
        dir.path().join(".github/workflows/scan.yml"),
    )
    .unwrap();
    common::pinprick_cmd()
        .arg("workflow-fingerprint")
        .arg(dir.path())
        .args([
            "--workflow",
            ".github/workflows/scan.yml",
            "--ignore-action-revision",
            "actions/checkout",
        ])
        .assert()
        .code(2);
}
