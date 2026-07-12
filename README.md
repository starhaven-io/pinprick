# pinprick

<!-- fleet:block badges -->

[![CI](https://github.com/starhaven-io/pinprick/actions/workflows/ci.yml/badge.svg)](https://github.com/starhaven-io/pinprick/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)

<!-- fleet:end -->

A CLI tool for GitHub Actions supply chain security. Pins action references to full SHAs, checks for updates, audits runtime fetch patterns that bypass pinning, and scores repository posture.

The name: **pin** (SHA pinning) + **prick** (a small, sharp probe finding tiny holes in your supply chain).

## Why

For static analysis of your workflow files — template injection, excessive permissions, credential leaks — use [zizmor](https://github.com/zizmorcore/zizmor). It's excellent.

pinprick picks up where static analysis leaves off. SHA-pinning actions is table stakes, but even a pinned action can `curl` down `releases/latest` at runtime. pinprick pins your actions, keeps them updated, audits source code for unversioned runtime fetches in shell scripts, JavaScript, Python, and Dockerfiles, and gives you a single score to track over time.

## Installation

### Homebrew

```bash
brew install starhaven-io/tap/pinprick
```

### crates.io

```bash
cargo install pinprick
```

### From releases

Download a prebuilt binary from [GitHub Releases](https://github.com/starhaven-io/pinprick/releases).

### From git (unreleased HEAD)

To try unreleased changes from `main`:

```bash
cargo install --git https://github.com/starhaven-io/pinprick
```

### GitHub Action

For CI audit runs, use the shipped [`starhaven-io/pinprick-action`](https://github.com/starhaven-io/pinprick-action). It installs a pinned pinprick release, verifies the archive checksum, runs `pinprick audit`, and can upload SARIF:

```yaml
name: GitHub Actions supply chain audit

on:
  push:
    branches:
      - main
  workflow_dispatch:

permissions: {}

jobs:
  pinprick:
    runs-on: ubuntu-24.04
    permissions:
      security-events: write
      contents: read
      actions: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false

      - name: Run pinprick
        uses: starhaven-io/pinprick-action@a663b6d119c2e5f4ff239bfdf155f50143e67706 # v0.4.2
```

The action wraps `pinprick audit` only. Use the CLI directly for `pin`, `update`, and `score`. For console-mode pull request feedback, set `advanced-security: false`; see the action README for the full matrix.

## Usage

All commands default to the current directory. Pass a path to target a different repository root. Use `--json` for machine-readable output.

> **Forge support.** GitHub Actions is pinprick's first-class, fully supported target. Forgejo and Gitea run GitHub-compatible Actions, so workflows under `.forgejo/workflows/` and `.gitea/workflows/` are discovered and scanned alongside `.github/workflows/` (whichever exist are all scanned). That support is incidental to GHA compatibility and best-effort: we won't intentionally break it, but we also won't hold back a GitHub Actions improvement to preserve forge behavior. When the two conflict, GHA wins. Concretely today, `pin` and `update` resolve through the github.com API, so they handle github.com-hosted actions (the common case) but not actions hosted on a Forgejo or Gitea instance; `audit` and `score` need no network for their local rules.

```bash
# Pin action tags to full SHAs
pinprick pin

# Write changes to files
pinprick pin --write

# Check pinned actions for newer releases (dry-run)
pinprick update

# Write updates to files
pinprick update --write

# Only check a specific action or org
pinprick update --only actions/checkout

# Audit for runtime fetch patterns that bypass pinning
pinprick audit

# Target a specific repo
pinprick audit /path/to/repo

# Show every matched pattern, including allowed matches
pinprick audit --verbose

# Emit SARIF 2.1.0 for GitHub code scanning
pinprick audit --sarif > pinprick.sarif

# Score a repository's Actions supply chain posture
pinprick score

# Emit the full score report as JSON or a self-contained HTML report
pinprick --json score
pinprick score --html > report.html

# Clear locally cached audit results
pinprick clean

# Generate shell completions
pinprick completions zsh
```

### Pin

Resolve action tag references to full SHAs (dry-run by default):

```
$ pinprick pin
.github/workflows/ci.yml
  actions/checkout @v7 -> @9c091bb21b7c… # v7.0.0
  actions/upload-artifact @v7 -> @043fb46d1a93… # v7.0.1

  ! actions/checkout@v7 -- sliding tag, resolved to v7.0.0
  ! Homebrew/actions/setup-homebrew@main -- branch ref — pin to a SHA manually

Would pin 2 actions across 1 file (2 skipped)
Run with --write to apply.
```

Sliding tags like `@v7` are resolved to their exact version. Branch refs like `@main` are flagged.

### Update

Check pinned actions for newer releases (dry-run by default):

```
$ pinprick update
.github/workflows/ci.yml
  actions/checkout  v4.1.0 -> v7.0.0

1 update available. Run with --write to apply.
```

### Audit

Scan for runtime fetch patterns that bypass pinning:

```
$ pinprick audit
HIGH  .github/workflows/ci.yml:42
      action: some/action@abc123de
      curl -L "https://github.com/.../releases/latest/download/tool.tar.gz"
      curl fetching from a 'latest' URL — can change without notice

1 finding (1 high, 0 medium, 0 low)
```

Without a GitHub token, audit scans local workflow `run:` blocks and local actions referenced with `uses: ./...`. With a token (via `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth`), it also fetches and scans external action source code — JavaScript, Python, Dockerfiles, and composite action steps.

Pass `--sarif` to emit SARIF 2.1.0 for upload to [GitHub code scanning](https://docs.github.com/en/code-security/code-scanning). Pass `--verbose` to see every match, including ones that passed the version check or were downgraded to an allowed match by the trusted-host, data-format, jq-pipe, or checksum rules.

### Score

Compute a posture grade against the public, versioned rubric in [`docs/scoring.md`](docs/scoring.md):

```
$ pinprick score
pinprick score  v0.9.0 rubric

  Grade:  A   (95 / 100)

  Findings (1 unique, 1 occurrences):
    medium  -5    pin.sliding                       actions/checkout@v4

  3 workflows scanned, 8 unique actions.

  Run with --json for the full report.
```

`score` exits 1 only when at least one finding deducts points. Use `pinprick score --html > report.html` for a shareable static report.

### Configuration

A `.pinprick.toml` at the repo root (or `~/.config/pinprick/config.toml` globally) customizes behavior. All keys are optional:

```toml
# Minimum severity to report: "low" (default), "medium", or "high"
severity = "low"

# Fetch the audited-actions catalog from pinprick.rs instead of only using
# the bundle compiled into the binary. Useful in CI.
fetch-remote = false

# Hosts whose unversioned URL fetches are downgraded to allowed matches.
# Case-insensitive exact match. Only applies to the unversioned-URL rules.
trusted-hosts = ["crates.io"]

# Extra file extensions (beyond .json/.yaml/.toml/.csv/.tsv/.xml/.md/.rst/.txt)
# to treat as data formats for the unversioned-URL exemption.
extra-data-formats = ["proto"]

[ignore]
# Skip these actions entirely (prefix match on owner/repo).
actions = ["actions/checkout"]

# Suppress findings whose description contains any of these strings.
patterns = []
```

### Clean

Remove locally cached audit results (`~/.cache/pinprick/audited/`):

```
$ pinprick clean
Cache cleaned.
```

## What the audit detects

| Category      | Examples                                                                                           | Severity |
| ------------- | -------------------------------------------------------------------------------------------------- | -------- |
| Pipe-to-shell | `curl`/`wget` piped to `sh`/`bash`/`python` (any URL)                                              | High     |
| Pipe-to-shell | `bash <(curl ...)`, `bash -c "$(curl ...)"`, `eval "$(curl ...)"`                                  | High     |
| Pipe-to-shell | PowerShell `iex (iwr ...)` / `Invoke-Expression (... DownloadString ...)`                          | High     |
| Shell         | `curl`/`wget` to `/latest/` URLs                                                                   | High     |
| Shell         | `curl`/`wget` to unversioned URLs                                                                  | Medium   |
| Shell         | `gh release download` without a tag                                                                | Medium   |
| Shell         | `git clone` without a pinned `--branch` ref (unless a `git checkout <sha>` follows within 3 lines) | Medium   |
| Shell         | `go install @latest`, unpinned `pip`/`npm`/`cargo install`/`gem install`                           | Low      |
| PowerShell    | `Invoke-WebRequest`/`iwr`/`irm` to `/latest/` URLs                                                 | High     |
| PowerShell    | `Invoke-WebRequest`/`iwr`/`irm` to unversioned URLs                                                | Medium   |
| JavaScript    | `fetch()`/`axios`/`got` to `/latest/` URLs                                                         | High     |
| JavaScript    | `exec("curl ...")`, `child_process` curl                                                           | High     |
| Python        | `requests.get`/`urllib` to `/latest/` URLs                                                         | High     |
| Python        | `subprocess` shelling out to `curl`/`wget`                                                         | High     |
| Docker        | `FROM :latest` or untagged                                                                         | High     |
| Docker        | `RUN curl`/`wget` piped to a shell                                                                 | High     |
| Docker        | `curl`/`wget` in `RUN` instructions                                                                | Medium   |
| Docker        | `ADD` with an `http(s)://` URL source                                                              | Medium   |

Pipe-to-shell is flagged even when the URL is versioned — a piped payload is never written to disk, so it cannot be checksum-verified and the versioned path pins the URL but not the content.

Unversioned-URL rules don't fire when the URL's path ends in a data-format extension (`.json`, `.yaml`, `.toml`, `.csv`, etc.), or when the fetch is piped into `jq` — the payload is consumed as data, not executed. These matches are only visible under `--verbose`. (Pipe-to-shell takes precedence, so `curl … | jq … | bash` is still flagged.)

Findings followed within 3 lines by checksum verification (`sha256sum --check`, `gpg --verify`, etc.) are suppressed only when the command performs an actual comparison or signature check, does not mask failure with `||`, and names every downloaded target, a target-specific sidecar such as `tool.sha256`, or an inline manifest piped to the verifier. Merely calculating a hash, checking an unrelated file, or using a generic manifest whose contents cannot be inspected does not suppress findings. Verified matches are recorded as allowed under `--verbose`. Pipe-to-shell findings are exempt; the piped payload is never written to disk for a checksum to verify.

## Exit codes

| Code | Meaning                                                                                   |
| ---- | ----------------------------------------------------------------------------------------- |
| 0    | Clean — no findings, no pending updates                                                   |
| 1    | Findings present (audit), score deductions present, or updates available (update dry-run) |
| 2    | Error                                                                                     |

## Building

A [justfile](https://github.com/casey/just) provides common tasks:

```bash
just build          # Build the project
just build-release  # Build in release mode
just test           # Run tests
just clippy         # Run clippy
just fmt            # Format code
just typos          # Check for typos
just audit          # Audit GitHub Actions workflows
just check          # Run all checks (clippy, fmt, typos, zizmor, test, site)
just install-hooks  # Install git hooks: pre-push check + DCO sign-off (once per clone)
```

## Contributing

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/) format and include a DCO sign-off (`git commit -s`). Run `just install-hooks` once per clone to enable the git hooks (a pre-push `just check` and DCO sign-off enforcement).

<!-- fleet:block license-section -->

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (`AGPL-3.0-only`).

Copyright (C) 2026 Patrick Linnane

<!-- fleet:end -->
