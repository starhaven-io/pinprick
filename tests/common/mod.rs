#![allow(dead_code)]

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Build an `assert_cmd::Command` for pinprick with the token stripped, colors
/// off, and HOME pointed at a unique temp path per invocation. The per-call HOME
/// isolates the audit cache (`~/.cache/pinprick`) and global config
/// (`~/.config/pinprick`) so parallel test processes can't race on, or poison,
/// a shared directory.
pub fn pinprick_cmd() -> assert_cmd::Command {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut cmd = assert_cmd::Command::cargo_bin("pinprick").unwrap();
    cmd.env("GITHUB_TOKEN", "");
    cmd.env("GH_TOKEN", "");
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let home = std::env::temp_dir().join(format!("pinprick-test-{}-{n}", std::process::id()));
    cmd.env("HOME", &home);
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

/// Pipe-to-shell nested inside a `parallel:` step group (GitHub's parallel-
/// steps feature). Expect one high-severity finding from the nested run block,
/// proving run-block extraction descends into parallel groups.
pub const WORKFLOW_PARALLEL_PIPE_TO_SHELL: &str = "\
name: parallel
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - parallel:
          - name: Build frontend
            run: npm run build:frontend
          - name: Fetch installer
            run: curl -fsSL https://example.com/install.sh | bash
      - run: npm test
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

/// One branch-ref action next to a SHA-pinned one. `pin` skips the branch ref
/// without any network call, so this is usable with a dummy token.
pub const WORKFLOW_BRANCH_REF: &str = "\
name: branch-ref
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: owner/repo@main
      - run: echo \"Hello World\"
";
