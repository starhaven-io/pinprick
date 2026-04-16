mod common;

use predicates::prelude::*;

// ── Exit codes ──────────────────────────────────────────────────────────────

#[test]
fn clean_workflow_exits_zero() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .success();
}

#[test]
fn clean_workflow_human_output() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No runtime fetch risks found."));
}

#[test]
fn pipe_to_shell_exits_one() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_PIPE_TO_SHELL);
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .code(1);
}

#[test]
fn pipe_to_shell_json_fields() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_PIPE_TO_SHELL);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["severity"], "high");
    assert_eq!(findings[0]["category"], "shell_fetch");
    assert!(findings[0]["line"].is_number());
}

#[test]
fn curl_latest_finding() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CURL_LATEST);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["severity"], "high");
}

#[test]
fn versioned_url_is_clean() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_VERSIONED);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(findings.is_empty());
}

#[test]
fn data_format_exempt() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_DATA_FORMAT);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(findings.is_empty());
}

#[test]
fn checksum_downgrade() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CHECKSUM);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    // Still a finding, but severity should be downgraded from high to medium.
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["severity"], "medium");
    assert!(
        findings[0]["description"]
            .as_str()
            .unwrap()
            .contains("checksum verified")
    );
}

#[test]
fn multiple_findings() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_MULTI_FINDINGS);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.len() >= 2,
        "expected at least 2 findings, got {}",
        findings.len()
    );

    // Findings should be sorted high-first.
    let severities: Vec<&str> = findings
        .iter()
        .map(|f| f["severity"].as_str().unwrap())
        .collect();
    for window in severities.windows(2) {
        let order = |s: &str| match s {
            "high" => 0,
            "medium" => 1,
            _ => 2,
        };
        assert!(
            order(window[0]) <= order(window[1]),
            "findings not sorted by severity: {:?}",
            severities
        );
    }
}

#[test]
fn empty_workflow() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_EMPTY);
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .success();
}

#[test]
fn multiple_workflow_files() {
    let dir = common::repo_with_workflows(&[
        ("clean.yml", common::WORKFLOW_CLEAN),
        ("risky.yml", common::WORKFLOW_PIPE_TO_SHELL),
    ]);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
}

// ── Missing workflows directory ─────────────────────────────────────────────

#[test]
fn missing_workflows_dir_exits_two() {
    let dir = tempfile::TempDir::new().unwrap();
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "No .github/workflows/ directory found",
        ));
}

#[test]
fn missing_workflows_dir_json() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("No .github/workflows/ directory found")
    );
}

// ── Token status ────────────────────────────────────────────────────────────

#[test]
fn no_token_json_had_token_false() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["had_token"], false);
}

// ── SARIF output ────────────────────────────────────────────────────────────

#[test]
fn sarif_valid_structure() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    let output = common::pinprick_cmd()
        .arg("audit")
        .arg("--sarif")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert!(
        json["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0")
    );
    assert_eq!(json["version"], "2.1.0");

    let runs = json["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["tool"]["driver"]["name"], "pinprick");

    let rules = runs[0]["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(!rules.is_empty());
    for rule in rules {
        assert!(rule["id"].is_string());
        assert!(rule["name"].is_string());
        assert!(rule["shortDescription"]["text"].is_string());
        assert!(rule["fullDescription"]["text"].is_string());
    }
}

#[test]
fn sarif_findings_mapped() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_PIPE_TO_SHELL);
    let output = common::pinprick_cmd()
        .arg("audit")
        .arg("--sarif")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    let results = json["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty());
    for result in results {
        assert!(result["ruleId"].is_string());
        assert!(result["level"].is_string());
        assert!(result["message"]["text"].is_string());
        assert!(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].is_string());
        assert!(result["locations"][0]["physicalLocation"]["region"]["startLine"].is_number());
    }
}

#[test]
fn sarif_no_findings() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    let output = common::pinprick_cmd()
        .arg("audit")
        .arg("--sarif")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert!(results.is_empty());
}

#[test]
fn sarif_takes_precedence_over_json() {
    // When both --json and --sarif are passed, SARIF output wins.
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg("--sarif")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["version"], "2.1.0");
}

// ── Verbose output ──────────────────────────────────────────────────────────

#[test]
fn verbose_shows_allowed() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_VERSIONED);
    common::pinprick_cmd()
        .arg("audit")
        .arg("--verbose")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn verbose_json_includes_allowed() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_VERSIONED);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg("--verbose")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let allowed = json["allowed"].as_array().unwrap();
    assert!(
        !allowed.is_empty(),
        "expected allowed matches for versioned URL"
    );
}

// ── Config integration ──────────────────────────────────────────────────────

#[test]
fn config_severity_high_filters_lower() {
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_MULTI_FINDINGS,
        "severity = \"high\"\n",
    );

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.iter().all(|f| f["severity"] == "high"),
        "expected only high findings when severity=high"
    );
}

#[test]
fn config_ignore_patterns() {
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_PIPE_TO_SHELL,
        "[ignore]\npatterns = [\"piped to shell\"]\n",
    );

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.is_empty(),
        "expected finding to be suppressed by ignore.patterns"
    );
}

#[test]
fn config_trusted_hosts() {
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_TRUSTED_HOST,
        "trusted-hosts = [\"artifacts.internal.example.com\"]\n",
    );

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.is_empty(),
        "expected trusted host to suppress finding"
    );
}

#[test]
fn config_extra_data_formats() {
    let workflow = "\
name: proto
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: curl -L https://example.com/schema.proto -o schema.proto
";
    let dir = common::repo_with_config("ci.yml", workflow, "extra-data-formats = [\"proto\"]\n");

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.is_empty(),
        "expected .proto to be exempt via extra-data-formats"
    );
}

// ── git clone ─────────────────────────────────────────────────────────────

#[test]
fn git_clone_unpinned_finding() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_GIT_CLONE);

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["severity"], "medium");
    assert!(
        findings[0]["description"]
            .as_str()
            .unwrap()
            .contains("git clone")
    );
}

#[test]
fn git_clone_versioned_branch_clean() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_GIT_CLONE_VERSIONED);

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(findings.is_empty());
}
