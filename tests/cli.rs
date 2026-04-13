mod common;

use predicates::prelude::*;

#[test]
fn version_flag() {
    common::pinprick_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("pinprick 0."));
}

#[test]
fn help_flag() {
    common::pinprick_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "GitHub Actions supply chain security",
        ));
}

#[test]
fn help_subcommand() {
    common::pinprick_cmd()
        .arg("help")
        .arg("audit")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Audit actions for runtime fetch risks",
        ));
}

#[test]
fn no_subcommand_exits_two() {
    // pinprick with no subcommand prints usage to stderr and exits 2.
    // Must build a command without `--color never` since there's no subcommand
    // to attach global flags to. clap treats this as an error.
    let mut cmd = assert_cmd::Command::cargo_bin("pinprick").unwrap();
    cmd.env("GITHUB_TOKEN", "");
    cmd.assert()
        .code(2)
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn unknown_subcommand_exits_two() {
    let mut cmd = assert_cmd::Command::cargo_bin("pinprick").unwrap();
    cmd.env("GITHUB_TOKEN", "");
    cmd.arg("bogus")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

#[test]
fn json_flag_is_global() {
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("clean")
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json.get("cleaned").is_some());
}

#[test]
fn color_never_flag() {
    common::pinprick_cmd().arg("clean").assert().success();
}
