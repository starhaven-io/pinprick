---
title: GitHub Action
description: Run pinprick audit in GitHub Actions.
---

[`starhaven-io/pinprick-action`](https://github.com/starhaven-io/pinprick-action) is the shipped composite action for CI audit runs. It installs a pinprick release, verifies the downloaded archive checksum and GitHub build provenance, runs `pinprick audit`, and optionally uploads SARIF to GitHub code scanning.

The action runs `audit` only. Use the CLI directly for `pin`, `update`, and `score`.

## Usage with GitHub Advanced Security

This is the default mode. The action emits SARIF and uploads findings to GitHub code scanning so they appear in the repository's Security tab.

In this mode, the action does not fail the workflow when pinprick reports findings unless `fail-on-findings: true` is set. Use GitHub rulesets if you want code scanning alerts to block merges.

Run SARIF upload on trusted events such as `push` or `workflow_dispatch`. Pull requests from forks receive a read-only token, so SARIF upload can fail there; use console mode for pull request feedback.

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
      contents: read # needed for checkout and private/internal repositories
      actions: read # needed for private/internal repositories
    steps:
      - name: Checkout repository
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false

      - name: Run pinprick
        uses: starhaven-io/pinprick-action@d1ad02330903473ce59ddb88b88ae36f4a4e0bf5 # v0.6.8
```

## Usage without GitHub Advanced Security

Set `advanced-security: false` to print results to the workflow log instead of uploading SARIF. This mode is suitable for pull requests from forks.

```yaml
name: GitHub Actions supply chain audit

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - '**'

permissions: {}

jobs:
  pinprick:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false

      - name: Run pinprick
        uses: starhaven-io/pinprick-action@d1ad02330903473ce59ddb88b88ae36f4a4e0bf5 # v0.6.8
        with:
          advanced-security: false
```

Each example pins `pinprick-action` to a full commit SHA with the release tag in a trailing comment, not a mutable tag. Bump the SHA when you adopt a newer release.

## Fail on findings

```yaml
- name: Run pinprick
  uses: starhaven-io/pinprick-action@d1ad02330903473ce59ddb88b88ae36f4a4e0bf5 # v0.6.8
  with:
    fail-on-findings: true
```

## Inputs

| Input               | Default    | Meaning                                                                                                                                                                                                                                                |
| ------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `version`           | `0.28.0`   | pinprick version to install. The `v0.6.8` action release pins this default for deterministic runs. Use `latest` for the newest pinprick release, or an exact version like `v0.28.0`.                                                                   |
| `path`              | `.`        | Repository path to scan.                                                                                                                                                                                                                               |
| `advanced-security` | `true`     | Upload SARIF results to GitHub code scanning. When `false`, the action prints normal console output.                                                                                                                                                   |
| `sarif-category`    | `pinprick` | Code scanning category for this upload. Set a unique value for each invocation in the same workflow.                                                                                                                                                   |
| `fail-on-findings`  | `false`    | Fail the workflow when `pinprick audit` reports findings. Without this, findings are emitted as a warning and the workflow continues.                                                                                                                  |
| `strict-provenance` | `false`    | Fail instead of warn when the release's provenance attestation cannot be checked, for example when `gh` is missing or too old, no GitHub token is available, or the pinprick release predates attestations.                                            |
| `no-repo-config`    | `true`     | Ignore the scanned repository's `.pinprick.toml` so pull requests cannot suppress their own findings. Set `false` only when repository policy is trusted, for example to apply [accepted findings](/configuration/config-file#accept-action-findings). |

## Outputs

| Output       | Meaning                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `exit-code`  | The `pinprick audit` exit code.                                                                  |
| `sarif-file` | Path to the generated SARIF file when `advanced-security` is enabled and the audit exits 0 or 1. |

## Permissions

Start workflows with `permissions: {}` and grant permissions only at the job that runs pinprick.

| Permission               | Required when                                                                 |
| ------------------------ | ----------------------------------------------------------------------------- |
| `security-events: write` | `advanced-security: true` uploads SARIF to code scanning.                     |
| `contents: read`         | Checking out the repository, and Advanced Security on private/internal repos. |
| `actions: read`          | Advanced Security on private/internal repos.                                  |

The action passes the workflow's `GITHUB_TOKEN` to pinprick so it can fetch and audit external action source when the job permissions allow it. Without a token, pinprick still scans local workflow `run:` blocks and local actions.

## Exit behavior

| Code | Meaning                      | Action behavior                                                |
| ---- | ---------------------------- | -------------------------------------------------------------- |
| `0`  | Clean                        | Succeeds.                                                      |
| `1`  | Findings present             | Succeeds by default; fails only with `fail-on-findings: true`. |
| `2+` | Error or incomplete coverage | Fails; no clean verdict was produced.                          |

In Advanced Security mode, SARIF upload happens before optional `fail-on-findings` failure so findings are still available in code scanning.

## Runner support

The action supports GitHub-hosted Linux x64, Linux ARM64, and macOS ARM64 runners. It rejects self-hosted runners. On Linux, it downloads the `gnu` release assets. Use a direct CLI install for self-hosted or musl/Alpine environments.

Windows and macOS x64 runners are not supported by the wrapper.
