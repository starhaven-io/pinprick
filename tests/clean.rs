mod common;

use predicates::prelude::*;

#[test]
fn reports_nothing_to_clean_when_cache_absent() {
    // A fresh per-test HOME has no cache directory, so this is deterministic.
    common::pinprick_cmd()
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing to clean."));
}

#[test]
fn reports_cache_cleaned_when_present() {
    // Seed a cache directory under an isolated HOME, then clean it.
    let home = tempfile::TempDir::new().unwrap();
    let cache = home.path().join(".cache/pinprick/audited");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("actions.json"), "[]").unwrap();

    assert_cmd::Command::cargo_bin("pinprick")
        .unwrap()
        .env("GITHUB_TOKEN", "")
        .env("GH_TOKEN", "")
        .env("HOME", home.path())
        .arg("--color")
        .arg("never")
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cache cleaned."));
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
