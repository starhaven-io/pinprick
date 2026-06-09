---
title: score
description: Compute a posture grade for a repository's Actions supply chain.
---

Compute a single posture score (0–100, letter grade A–F) for a repository's GitHub Actions configuration. Implements the public [scoring rubric](https://github.com/starhaven-io/pinprick/blob/main/docs/scoring.md) — every point deducted maps to a named rule, so the grade can be re-derived by hand from the finding list.

```bash
pinprick score
pinprick score /path/to/repo
pinprick score --json
pinprick score --html > report.html
```

## Behavior

- Scans `.github/workflows/*.yml` and emits findings across four categories: `pin.*`, `workflow.*`, `source.*`, `runtime.*`
- Each finding has a fixed point deduction; the score is `max(0, 100 - sum(points))`
- Exits 1 when any findings exist (matches [audit](/commands/audit) for CI gating)
- Runs fully offline by default. `source.archived` and `source.advisory` activate only when a GitHub token is available

## Output formats

- Default: a compact human-readable summary with grade, finding counts by severity, and top remediations
- `--json`: the full finding list as JSON for CI integration or downstream processing
- `--html`: a self-contained HTML report (mutually exclusive with `--json`)
- `--no-repo-config`: ignore the scanned repository's `.pinprick.toml` and use the global config (or defaults)

## Rule catalog

The full catalog lives in [`docs/scoring.md`](https://github.com/starhaven-io/pinprick/blob/main/docs/scoring.md). Summary:

| Category   | Rule                                | Severity | Points |
| ---------- | ----------------------------------- | -------- | ------ |
| `pin`      | `pin.branch` (branch ref)           | high     | 15     |
| `pin`      | `pin.sliding` (sliding tag `@v4`)   | medium   | 5      |
| `pin`      | `pin.full_tag` (e.g. `@v4.2.1`)     | low      | 2      |
| `source`   | `source.archived`                   | high     | 10     |
| `source`   | `source.advisory` (GHSA match)      | high     | 15     |
| `source`   | `source.unverified` (untrusted org) | low      | 1      |
| `runtime`  | `runtime.pipe_to_shell`             | high     | 20     |
| `runtime`  | `runtime.fetch.high`                | high     | 15     |
| `runtime`  | `runtime.fetch.medium`              | medium   | 8      |
| `runtime`  | `runtime.fetch.low`                 | low      | 3      |
| `workflow` | `workflow.permissions_write_all`    | high     | 10     |
| `workflow` | `workflow.pull_request_target`      | high     | 5      |
| `workflow` | `workflow.workflow_run`             | medium   | 3      |

Grade bands: **A** 90–100, **B** 80–89, **C** 70–79, **D** 60–69, **F** 0–59.

## Trusted publishers

`source.unverified` fires when an action's `owner` is not in the baseline trusted set (`actions`, `github`). Extend the allowlist in `.pinprick.toml`:

```toml
trusted-owners = ["my-org", "vendor"]
```

Matching is exact owner, case-insensitive. See [Config File](/configuration/config-file) for the full set of options.

Because the scanned repository's own `.pinprick.toml` applies, a third-party repo can shape its own grade (`trusted-owners`, `ignore` rules). Whenever a repo-local config changes the score, pinprick prints a note to stderr saying what it changed; pass `--no-repo-config` to ignore the file entirely.

## Example

```
$ pinprick score
pinprick score  v0.5.0 rubric

  Grade:  C   (72 / 100)

  Findings (11 unique, 24 occurrences):
    high    2  pin.branch           actions/foo@main
    high    1  source.archived      bar/baz@abc1234
    medium  6  pin.sliding          7 actions
    low     2  pin.full_tag         2 actions

  Top remediations:
    1. Pin actions/foo@main to a full SHA             (-15)
    2. Replace bar/baz (archived) with a maintained action (-10)
    ...

  Run `pinprick score --json` for the full report.
```

## Versioning

The rubric is independently versioned from the pinprick binary (currently `v0.5.0`). Every scan records the rubric version so historical scores remain interpretable as the rubric evolves. Re-scoring against a newer rubric is always explicit — pinprick never silently re-grades a past scan.
