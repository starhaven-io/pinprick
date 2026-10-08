mod common;

use serde_json::Value;

const ACTION: &str = "runs:\n  using: composite\n  steps:\n    - run: python3 \"$GITHUB_ACTION_PATH/main.py\"\n      shell: bash\n";
const FETCHING_HELPER: &str = "curl -fsSL https://example.com/latest/tool | sh\n";

#[test]
fn python_location_flow_never_clears_a_reachable_helper() {
    let fixtures: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/python_location_flow.json")).unwrap();
    assert_eq!(fixtures.len(), 67);
    assert_eq!(
        fixtures
            .iter()
            .filter(|fixture| fixture["executes_helper"] == true)
            .count(),
        59
    );

    let mut violations = Vec::new();
    for fixture in &fixtures {
        let name = fixture["name"].as_str().unwrap();
        let main = fixture["main"].as_str().unwrap();
        let executes_helper = fixture["executes_helper"].as_bool().unwrap();
        // Incomplete coverage is an acceptable cost for most safe cases, but a
        // scope-isolation case only proves anything if it stays clean.
        let expect_clean = fixture["expect_clean"].as_bool().unwrap_or(false);
        let mut files = vec![("main.py", main), ("install.sh", FETCHING_HELPER)];
        for (path, content) in fixture["extra"].as_object().unwrap() {
            files.push((path.as_str(), content.as_str().unwrap()));
        }
        let repo = common::repo_with_local_action(ACTION, &files);
        let output = common::pinprick_cmd()
            .args([
                "--json",
                "audit",
                "--no-repo-config",
                "--no-audited-catalog",
            ])
            .arg(repo.path())
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{name}: invalid report: {error}; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        let complete = report["coverage_complete"].as_bool().unwrap();
        let findings = report["findings"].as_array().unwrap();
        if executes_helper && complete && findings.is_empty() {
            violations.push(format!("{name}: executed action helper but audited clean"));
        } else if !executes_helper && !findings.is_empty() {
            violations.push(format!(
                "{name}: action helper did not run but audit found it"
            ));
        } else if expect_clean && !complete {
            violations.push(format!("{name}: expected a complete clean audit"));
        }
    }

    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn parameter_shadowing_keeps_a_later_local_location_assignment() {
    let source = "import os\nimport subprocess\npath = 'safe.sh'\ndef go(path):\n    path = os.path.join(os.path.dirname(__file__), 'install.sh')\n    subprocess.run(['bash', path])\ngo('safe.sh')\n";
    let repo = common::repo_with_local_action(
        ACTION,
        &[("main.py", source), ("install.sh", FETCHING_HELPER)],
    );
    let output = common::pinprick_cmd()
        .args([
            "--json",
            "audit",
            "--no-repo-config",
            "--no-audited-catalog",
        ])
        .arg(repo.path())
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn a_later_function_definition_does_not_shadow_an_earlier_subprocess_import() {
    let location = "os.path.join(os.path.dirname(__file__), 'install.sh')";
    for source in [
        format!(
            "import os\nfrom subprocess import run\nrun(['bash', {location}])\ndef run(p):\n    pass\n"
        ),
        format!(
            "import os\ndef run(p):\n    pass\nfrom subprocess import run\nrun(['bash', {location}])\n"
        ),
    ] {
        let repo = common::repo_with_local_action(
            ACTION,
            &[
                ("main.py", source.as_str()),
                ("install.sh", FETCHING_HELPER),
            ],
        );
        let output = common::pinprick_cmd()
            .args([
                "--json",
                "audit",
                "--no-repo-config",
                "--no-audited-catalog",
            ])
            .arg(repo.path())
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            !report["findings"].as_array().unwrap().is_empty()
                || !report["coverage_complete"].as_bool().unwrap(),
            "{source}"
        );
    }
}

#[test]
fn a_loop_rebinding_does_not_hide_a_located_execution() {
    let source = "import os\nimport subprocess\ndef run(argv):\n    pass\nos.chdir(os.path.dirname(__file__))\nfor run in [subprocess.run]:\n    run(['bash', 'install.sh'])\n";
    let repo = common::repo_with_local_action(
        ACTION,
        &[("main.py", source), ("install.sh", FETCHING_HELPER)],
    );
    let output = common::pinprick_cmd()
        .args([
            "--json",
            "audit",
            "--no-repo-config",
            "--no-audited-catalog",
        ])
        .arg(repo.path())
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        !report["findings"].as_array().unwrap().is_empty()
            || !report["coverage_complete"].as_bool().unwrap(),
        "rebound run() cannot clear a helper reached from __file__"
    );
}

#[test]
fn invalid_python_with_a_location_cannot_clear_coverage() {
    let repo = common::repo_with_local_action(
        ACTION,
        &[("main.py", "subprocess.run(['bash', __file__\n")],
    );
    let output = common::pinprick_cmd()
        .args([
            "--json",
            "audit",
            "--no-repo-config",
            "--no-audited-catalog",
        ])
        .arg(repo.path())
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report["coverage_complete"], false);
}

#[test]
fn reading_action_data_is_safe_until_it_selects_an_executed_script() {
    for (program, should_clear) in [
        ("subprocess.run(['echo', pin['path']])", true),
        ("subprocess.run(['bash', pin['path']])", false),
    ] {
        let source = format!(
            "import json\nimport os\nimport subprocess\npath = os.path.join(os.path.dirname(__file__), 'pin.json')\nwith open(path) as handle:\n    pin = json.load(handle)\nassert set(pin) == {{'path'}}\n{program}\n"
        );
        let repo = common::repo_with_local_action(
            ACTION,
            &[
                ("main.py", source.as_str()),
                ("pin.json", "{\"path\":\"install.sh\"}\n"),
                ("install.sh", FETCHING_HELPER),
            ],
        );
        let output = common::pinprick_cmd()
            .args([
                "--json",
                "audit",
                "--no-repo-config",
                "--no-audited-catalog",
            ])
            .arg(repo.path())
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let clear = report["coverage_complete"] == true
            && report["findings"].as_array().unwrap().is_empty();
        assert_eq!(clear, should_clear, "{program}");
    }
}

#[test]
fn returning_data_read_from_an_action_file_does_not_return_its_path() {
    let source = "import json, os, subprocess\ndef load_pin():\n    path = os.path.join(os.path.dirname(__file__), 'pin.json')\n    with open(path) as handle:\n        pin = json.load(handle)\n    return pin\npin = load_pin()\nsubprocess.run(['echo', pin['path']])\n";
    let repo = common::repo_with_local_action(
        ACTION,
        &[
            ("main.py", source),
            ("pin.json", "{\"path\":\"install.sh\"}\n"),
        ],
    );
    let output = common::pinprick_cmd()
        .args([
            "--json",
            "audit",
            "--no-repo-config",
            "--no-audited-catalog",
        ])
        .arg(repo.path())
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage_complete"], true);
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn scoped_python_calls_do_not_clear_reachable_helpers() {
    let location = "os.path.join(os.path.dirname(__file__), 'install.sh')";
    let cases = [
        (
            "two-step collision",
            "import os, subprocess\nbase = os.path.dirname(__file__)\nscript = os.path.join(base, 'install.sh')\ndef go(script):\n    subprocess.run(['bash', script])\ngo(script)\n".to_string(),
        ),
        (
            "annotated assignment",
            format!("import os, subprocess\np: str = {location}\ndef go(q):\n    subprocess.run(['bash', q])\ngo(p)\n"),
        ),
        (
            "helper chain",
            format!("import os, subprocess\ndef b(q):\n    subprocess.run(['bash', q])\ndef a(q):\n    b(q)\na({location})\n"),
        ),
        (
            "runner alias",
            format!("import os, subprocess\ndef go(q):\n    r = subprocess.run\n    r(['bash', q])\ngo({location})\n"),
        ),
        (
            "shadowed print",
            format!("import os, subprocess\ndef print(q):\n    subprocess.run(['bash', q])\nprint({location})\n"),
        ),
        (
            "shadowed open",
            format!("import os, subprocess\ndef open(q):\n    subprocess.run(['bash', q])\nopen({location})\n"),
        ),
        (
            "imported run comprehension",
            "import os\nfrom subprocess import run\n[run(['bash', p]) for p in [os.path.join(os.path.dirname(__file__), 'install.sh')]]\n".to_string(),
        ),
        (
            "return with separate resolved helper",
            format!("import os, subprocess\ndef choose():\n    return {location}\ndef go():\n    subprocess.run(['bash', choose()])\ngo()\nsubprocess.run(['bash', os.path.join(os.path.dirname(__file__), 'ok.sh')])\n"),
        ),
        (
            "comprehension with separate resolved helper",
            "import os, subprocess\n[subprocess.run(['bash', p]) for p in [os.path.join(os.path.dirname(__file__), 'install.sh')]]\nsubprocess.run(['bash', os.path.join(os.path.dirname(__file__), 'ok.sh')])\n".to_string(),
        ),
    ];
    let mut violations = Vec::new();
    for (name, source) in cases {
        let repo = common::repo_with_local_action(
            ACTION,
            &[
                ("main.py", source.as_str()),
                ("install.sh", FETCHING_HELPER),
                ("ok.sh", "echo harmless\n"),
            ],
        );
        let output = common::pinprick_cmd()
            .args([
                "--json",
                "audit",
                "--no-repo-config",
                "--no-audited-catalog",
            ])
            .arg(repo.path())
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        if report["findings"].as_array().unwrap().is_empty()
            && report["coverage_complete"].as_bool().unwrap()
        {
            violations.push(name);
        }
    }
    assert!(
        violations.is_empty(),
        "reachable helper audited clean: {violations:?}"
    );
}

#[test]
fn parser_and_scope_limit_failures_retain_known_findings() {
    let execution = "import os, subprocess\nsubprocess.run(['bash', os.path.join(os.path.dirname(__file__), 'install.sh')])\n";
    let large = (0..300)
        .map(|index| format!("def f{index}():\n    pass\n"))
        .collect::<String>();
    for (name, source) in [
        ("syntax failure", format!("print 'starting'\n{execution}")),
        ("scope limit", format!("{large}{execution}")),
    ] {
        let repo = common::repo_with_local_action(
            ACTION,
            &[
                ("main.py", source.as_str()),
                ("install.sh", FETCHING_HELPER),
            ],
        );
        let output = common::pinprick_cmd()
            .args([
                "--json",
                "audit",
                "--no-repo-config",
                "--no-audited-catalog",
            ])
            .arg(repo.path())
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["coverage_complete"], false, "{name}");
        assert!(
            !report["findings"].as_array().unwrap().is_empty(),
            "{name}: parser bailout lost a known finding"
        );
    }
}

#[test]
fn a_later_unresolved_execution_keeps_an_earlier_finding() {
    let source = "import os, subprocess, sys\nsubprocess.run(['bash', os.path.join(os.path.dirname(__file__), 'install.sh')])\nos.chdir(os.path.dirname(__file__))\nsubprocess.run(sys.argv[1:])\n";
    let repo = common::repo_with_local_action(
        ACTION,
        &[("main.py", source), ("install.sh", FETCHING_HELPER)],
    );
    let output = common::pinprick_cmd()
        .args([
            "--json",
            "audit",
            "--no-repo-config",
            "--no-audited-catalog",
        ])
        .arg(repo.path())
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["coverage_complete"], false);
    assert!(!report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn scope_uncertainty_does_not_hide_known_corpus_findings() {
    const CASES: [&str; 6] = [
        "collision_located",
        "collision_callback",
        "collision_decorator",
        "collision_returned_function",
        "collision_return_value",
        "executor_name_real",
    ];
    let fixtures: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/python_location_flow.json")).unwrap();
    let mut lost = Vec::new();
    for fixture in fixtures
        .iter()
        .filter(|fixture| CASES.contains(&fixture["name"].as_str().unwrap()))
    {
        let name = fixture["name"].as_str().unwrap();
        let main = fixture["main"].as_str().unwrap();
        let mut files = vec![("main.py", main), ("install.sh", FETCHING_HELPER)];
        for (path, content) in fixture["extra"].as_object().unwrap() {
            files.push((path.as_str(), content.as_str().unwrap()));
        }
        let repo = common::repo_with_local_action(ACTION, &files);
        let output = common::pinprick_cmd()
            .args([
                "--json",
                "audit",
                "--no-repo-config",
                "--no-audited-catalog",
            ])
            .arg(repo.path())
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        if report["findings"].as_array().unwrap().is_empty() {
            lost.push(name);
        }
    }
    assert!(lost.is_empty(), "known findings lost: {lost:?}");
}
