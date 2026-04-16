#![allow(dead_code)]

use std::fs;
use tempfile::TempDir;

/// Create a temporary repo directory with one workflow file.
pub fn repo_with_workflow(filename: &str, content: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    let workflows = dir.path().join(".github").join("workflows");
    fs::create_dir_all(&workflows).unwrap();
    fs::write(workflows.join(filename), content).unwrap();
    dir
}

/// Create a temporary repo directory with multiple workflow files.
pub fn repo_with_workflows(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    let workflows = dir.path().join(".github").join("workflows");
    fs::create_dir_all(&workflows).unwrap();
    for (name, content) in files {
        fs::write(workflows.join(name), content).unwrap();
    }
    dir
}

/// Create a temporary repo directory with a workflow file and a `.pinprick.toml` config.
pub fn repo_with_config(filename: &str, workflow: &str, config: &str) -> TempDir {
    let dir = repo_with_workflow(filename, workflow);
    fs::write(dir.path().join(".pinprick.toml"), config).unwrap();
    dir
}

/// Build an `assert_cmd::Command` for pinprick with token stripped, colors off,
/// and HOME pointed at a temp location to avoid global config interference.
pub fn pinprick_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("pinprick").unwrap();
    cmd.env("GITHUB_TOKEN", "");
    cmd.env("GH_TOKEN", "");
    cmd.env("HOME", "/tmp/pinprick-test-home");
    cmd.env("XDG_CONFIG_HOME", "/tmp/pinprick-test-config");
    cmd.arg("--color").arg("never");
    cmd
}

// ── Workflow fixtures ───────────────────────────────────────────────────────

/// A clean workflow: SHA-pinned action, safe run block. Expect zero findings.
pub const WORKFLOW_CLEAN: &str = "\
name: clean
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: echo \"Hello World\"
";

/// Pipe-to-shell: curl piped to bash. Expect one high-severity finding.
pub const WORKFLOW_PIPE_TO_SHELL: &str = "\
name: risky
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: curl -fsSL https://example.com/install.sh | bash
";

/// Curl with /latest/ in URL. Expect one high-severity finding.
pub const WORKFLOW_CURL_LATEST: &str = "\
name: curl-latest
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: curl -L \"https://github.com/owner/repo/releases/latest/download/tool\" -o tool
";

/// Curl with versioned URL. Expect zero findings.
pub const WORKFLOW_VERSIONED: &str = "\
name: versioned
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: curl -L \"https://github.com/owner/repo/releases/download/v1.2.3/tool\" -o tool
";

/// Curl fetching a JSON file. Expect data-format exemption (no finding).
pub const WORKFLOW_DATA_FORMAT: &str = "\
name: data
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: curl -L https://example.com/api/data.json -o data.json
";

/// Multiple finding categories in one workflow.
pub const WORKFLOW_MULTI_FINDINGS: &str = "\
name: multi
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: |
          curl -fsSL https://example.com/install.sh | bash
          go install golang.org/x/tools/gopls@latest
          pip install requests
";

/// Curl with checksum verification on the next line.
pub const WORKFLOW_CHECKSUM: &str = "\
name: checksum
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: |
          curl -L \"https://github.com/owner/repo/releases/latest/download/tool\" -o tool
          sha256sum --check tool.sha256
";

/// Curl with unversioned URL hitting a trusted host.
pub const WORKFLOW_TRUSTED_HOST: &str = "\
name: trusted
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: curl -L https://artifacts.internal.example.com/tool -o tool
";

/// Empty steps list. Expect zero findings.
pub const WORKFLOW_EMPTY: &str = "\
name: empty
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
";

/// git clone without pinned ref. Expect one medium-severity finding.
pub const WORKFLOW_GIT_CLONE: &str = "\
name: git-clone
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: |
          git clone https://github.com/org/repo
          cd repo && make install
";

/// git clone with versioned --branch. Expect zero findings.
pub const WORKFLOW_GIT_CLONE_VERSIONED: &str = "\
name: git-clone-versioned
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: git clone --depth 1 --branch v1.2.3 https://github.com/org/repo
";
