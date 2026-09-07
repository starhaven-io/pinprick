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
    // Builds its own command (not pinprick_cmd) so the seeded HOME is the one cleaned.
    let home = tempfile::TempDir::new().unwrap();
    let cache = home.path().join(".cache/pinprick/audited");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("actions.json"), "[]").unwrap();

    assert_cmd::Command::cargo_bin("pinprick")
        .unwrap()
        .env("GITHUB_TOKEN", "")
        .env("GH_TOKEN", "")
        .env("HOME", home.path())
        .env_remove("XDG_CACHE_HOME")
        .arg("--color")
        .arg("never")
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cache cleaned."));
}

#[test]
fn xdg_cache_home_is_honored() {
    let home = tempfile::TempDir::new().unwrap();
    let xdg = tempfile::TempDir::new().unwrap();
    let cache = xdg.path().join("pinprick/audited");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("actions.json"), "[]").unwrap();

    assert_cmd::Command::cargo_bin("pinprick")
        .unwrap()
        .env("GITHUB_TOKEN", "")
        .env("GH_TOKEN", "")
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", xdg.path())
        .arg("--color")
        .arg("never")
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cache cleaned."));

    assert!(!cache.exists());
    // A relative XDG value is ignored per the spec — nothing to clean under
    // the fallback HOME.
    assert_cmd::Command::cargo_bin("pinprick")
        .unwrap()
        .env("GITHUB_TOKEN", "")
        .env("GH_TOKEN", "")
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", "relative/path")
        .arg("--color")
        .arg("never")
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing to clean."));
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
fn removal_error_exits_two_without_claiming_success() {
    let xdg = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(xdg.path().join("pinprick")).unwrap();
    let cache = xdg.path().join("pinprick/audited");
    std::fs::write(&cache, "unexpected file").unwrap();
    for json in [false, true] {
        let mut command = common::pinprick_cmd();
        command.env("XDG_CACHE_HOME", xdg.path());
        if json {
            command.arg("--json");
        }
        command
            .arg("clean")
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("Could not remove audit cache"));
    }
    assert_eq!(std::fs::read_to_string(cache).unwrap(), "unexpected file");
}

#[test]
fn idempotent() {
    let xdg = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(xdg.path().join("pinprick/audited")).unwrap();
    common::pinprick_cmd()
        .env("XDG_CACHE_HOME", xdg.path())
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cache cleaned."));
    common::pinprick_cmd()
        .env("XDG_CACHE_HOME", xdg.path())
        .arg("clean")
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing to clean."));
}
