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

pinprick ships with a bundled list of popular actions that have been scanned and confirmed clean. These are skipped automatically during audit, avoiding redundant API calls.

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
  actions/checkout@de0fac2e audited
  actions/upload-artifact@bbbca2dd audited
Scanning .github/workflows/release.yml... done
  actions/attest@59d89421 audited

No runtime fetch risks found.
```
