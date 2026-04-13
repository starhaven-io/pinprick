mod common;

use predicates::prelude::*;

#[test]
fn bash() {
    common::pinprick_cmd()
        .arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("pinprick"));
}

#[test]
fn zsh() {
    common::pinprick_cmd()
        .arg("completions")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::str::contains("pinprick"));
}

#[test]
fn fish() {
    common::pinprick_cmd()
        .arg("completions")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::str::contains("pinprick"));
}

#[test]
fn powershell() {
    common::pinprick_cmd()
        .arg("completions")
        .arg("powershell")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn invalid_shell_exits_two() {
    common::pinprick_cmd()
        .arg("completions")
        .arg("invalid_shell")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid value"));
}
