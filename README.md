# pinprick

[![CI](https://github.com/p-linnane/pinprick/actions/workflows/ci.yml/badge.svg)](https://github.com/p-linnane/pinprick/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)

A CLI tool for GitHub Actions supply chain security. Pins action references to full SHAs, checks for updates, and audits pinned actions for runtime fetch patterns that bypass pinning.

The name: **pin** (SHA pinning) + **prick** (a small, sharp probe finding tiny holes in your supply chain).

## Why

For static analysis of your workflow files — template injection, excessive permissions, credential leaks — use [zizmor](https://github.com/zizmorcore/zizmor). It's excellent.

pinprick picks up where static analysis leaves off. SHA-pinning actions is table stakes, but even a pinned action can `curl` down `releases/latest` at runtime. pinprick pins your actions, keeps them updated, and audits their source code for unversioned runtime fetches in shell scripts, JavaScript, Python, and Dockerfiles.

## Installation

### Homebrew

```bash
brew install p-linnane/tap/pinprick
```

### From source

```bash
cargo install --git https://github.com/p-linnane/pinprick
```

### From releases

Download a prebuilt binary from [GitHub Releases](https://github.com/p-linnane/pinprick/releases).

## Usage

All commands default to the current directory. Pass a path to target a different repository root. Use `--json` for machine-readable output.

```bash
# Pin action tags to full SHAs
pinprick pin

# Check pinned actions for newer releases (dry-run)
pinprick update

# Apply updates
pinprick update --apply

# Audit for runtime fetch patterns that bypass pinning
pinprick audit

# Target a specific repo
pinprick audit /path/to/repo

# Generate shell completions
pinprick completions zsh
```

### Pin

Resolve action tag references to full SHAs:

```
$ pinprick pin
.github/workflows/ci.yml
  actions/checkout @v4 -> @de0fac2e…ce83dd # v6.0.2
  actions/upload-artifact @v4 -> @bbbca2dd…f024f # v7.0.0

  ! actions/checkout@v4 -- sliding tag, resolved to v6.0.2
  ! Homebrew/actions/setup-homebrew@main -- branch ref — pin to a SHA manually

Pinned 2 actions across 1 file (2 skipped)
```

Sliding tags like `@v4` are resolved to their exact version. Branch refs like `@main` are flagged.

### Update

Check pinned actions for newer releases:

```
$ pinprick update
.github/workflows/ci.yml
  actions/checkout  v4.1.0 -> v6.0.2

1 update available. Run with --apply to apply.
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

Without a GitHub token, audit scans local `run:` blocks only. With a token (via `GITHUB_TOKEN` or `gh auth`), it also fetches and scans action source code — JavaScript, Python, Dockerfiles, and composite action steps.

## What the audit detects

| Category | Examples | Severity |
|----------|----------|----------|
| Pipe-to-shell | `curl`/`wget` piped to `sh`/`bash`/`python` (any URL) | High |
| Pipe-to-shell | `bash <(curl ...)`, `bash -c "$(curl ...)"`, `eval "$(curl ...)"` | High |
| Pipe-to-shell | PowerShell `iex (iwr ...)` / `Invoke-Expression (... DownloadString ...)` | High |
| Shell | `curl`/`wget` to `/latest/` URLs | High |
| Shell | `curl`/`wget` to unversioned URLs | Medium |
| Shell | `go install @latest`, unpinned `pip`/`npm` | Low–Medium |
| PowerShell | `Invoke-WebRequest`/`iwr`/`irm` to `/latest/` URLs | High |
| PowerShell | `Invoke-WebRequest`/`iwr`/`irm` to unversioned URLs | Medium |
| JavaScript | `fetch()`/`axios`/`got` to `/latest/` URLs | High |
| JavaScript | `exec("curl ...")`, `child_process` curl | High |
| Python | `requests.get`/`urllib` to `/latest/` URLs | High |
| Python | `subprocess` shelling out to `curl`/`wget` | High |
| Docker | `FROM :latest` or untagged | High |
| Docker | `RUN curl`/`wget` piped to a shell | High |
| Docker | `curl`/`wget` in `RUN` instructions | Medium |
| Docker | `ADD` with an `http(s)://` URL source | Medium |

Pipe-to-shell is flagged even when the URL is versioned — a piped payload is never written to disk, so it cannot be checksum-verified and the versioned path pins the URL but not the content.

Unversioned-URL rules don't fire when the URL's path ends in a data-format extension (`.json`, `.yaml`, `.toml`, `.csv`, etc.) — the payload is consumed as data, not executed. These matches are only visible under `--verbose`.

Findings followed by checksum verification (`sha256sum`, `gpg --verify`, etc.) within 3 lines are downgraded one severity level. Pipe-to-shell findings are exempt.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings, no pending updates |
| 1 | Findings present (audit) or updates available (update dry-run) |
| 2 | Error |

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
```

## Contributing

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/) format and include a DCO sign-off (`git commit -s`).

## Acknowledgements

Built with [Claude Code](https://claude.ai/code).

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (`AGPL-3.0-only`).

Copyright (C) 2026 Patrick Linnane
