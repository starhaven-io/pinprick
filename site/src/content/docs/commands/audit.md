---
title: audit
description: Scan actions for runtime fetch patterns that bypass pinning.
---

Scan workflow `run:` blocks and action source code for runtime fetch patterns that bypass SHA pinning.

```bash
pinprick audit
pinprick audit /path/to/repo
```

## What it scans

- Shell commands in workflow `run:` blocks and composite `action.yml` steps
- JavaScript and TypeScript files (`.js`, `.ts`) inside each action's source tree, including minified bundles
- Python files (`.py`) inside each action's source tree
- `Dockerfile` and `*.dockerfile` files inside each action's source tree

For the full list of every rule, including examples and severity, see the [Detections reference](/reference/detections).

## Audited actions list

pinprick skips actions whose `owner/repo@sha` is already known to be clean. The check consults three sources, in order, and reports which one answered:

- `bundled` — ships with the pinprick binary from `audited-actions/` in the repo
- `local cache` — written to `~/.cache/pinprick/audited/` after a successful live scan on this machine
- `pinprick.rs` — fetched from the public audited-actions list (opt-in via `fetch-remote = true` in `.pinprick.toml`)

See [Audited Actions](/configuration/audited-actions) for details on how the list works and how to contribute.

## Without a token

When no GitHub token is available, audit scans only workflow `run:` blocks. Action source code is not fetched. This still catches the most common patterns (shell commands fetching unversioned resources) but misses JavaScript, Python, and Docker patterns inside actions.

## Output formats

- Default: colored human-readable output with severity buckets
- `--json`: machine-readable JSON for CI integration
- `--sarif`: SARIF 2.1.0 for upload to GitHub code scanning
- `--verbose`: also report _allowed_ matches (fetches that fired a rule but were dropped because the URL is versioned)

## Example

```
$ pinprick audit
Scanning .github/workflows/ci.yml... done
  actions/checkout@de0fac2e audited (bundled)
  actions/upload-artifact@bbbca2dd audited (bundled)
Scanning .github/workflows/release.yml... done
  actions/attest@59d89421 audited (bundled)
  rust-lang/crates-io-auth-action@bbd81622 audited (local cache)

No runtime fetch risks found.
```
