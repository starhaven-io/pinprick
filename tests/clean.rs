mod common;

use predicates::prelude::*;

#[test]
fn human_output() {
    common::pinprick_cmd()
        .arg("clean")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Cache cleaned.")
                .or(predicate::str::contains("Nothing to clean.")),
        );
}

#[test]
fn json_output() {
    let output = common::pinprick_cmd()
        .arg("--json")
        .arg("clean")
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["cleaned"].is_boolean());
}

#[test]
fn always_exits_zero() {
    common::pinprick_cmd().arg("clean").assert().success();
}

#[test]
fn idempotent() {
    common::pinprick_cmd().arg("clean").assert().success();
    common::pinprick_cmd().arg("clean").assert().success();
}
