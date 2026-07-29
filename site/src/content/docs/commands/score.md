---
title: score
description: Compute a posture grade for a repository's Actions supply chain.
---

Compute a single posture score (0–100, letter grade A–F) for a repository's GitHub Actions configuration. Implements the public [scoring rubric](https://github.com/starhaven-io/pinprick/blob/main/docs/scoring.md) — every point deducted maps to a named rule, so the grade can be re-derived by hand from the finding list.

Workflows are discovered under `.github/workflows/`, `.forgejo/workflows/`, and `.gitea/workflows/` (whichever exist are all scanned). Forgejo and Gitea use GitHub-compatible workflow syntax.

```bash
pinprick score
pinprick score /path/to/repo
pinprick score --json
pinprick score --html > report.html
pinprick score --badge > badge.json
```

## Behavior

- Scans `.github/workflows/*.yml` and emits findings across four categories: `pin.*`, `workflow.*`, `source.*`, `runtime.*`
- Each finding has a fixed point deduction; the score is `max(0, 100 - sum(points))`
- Exits 1 when any finding deducts points
- Runs its workflow-owned rules offline. With a GitHub token, it also evaluates `source.archived`, `source.advisory`, and runtime findings in fetched remote action source
- Marks report coverage incomplete when token-gated checks do not run, remote source cannot be fetched completely, or configuration suppresses coverage

## Output formats

- Default: a compact human-readable summary with grade, finding count, prioritized rules, and targets
- `--json`: the full finding list and `coverage_complete` state as JSON for CI integration or downstream processing
- `--html`: a self-contained HTML report that displays incomplete-coverage reasons
- `--badge`: a [shields.io endpoint-badge](https://shields.io/badges/endpoint-badge) JSON document. Incomplete coverage produces a grey error badge instead of an unqualified grade
- `--no-repo-config`: ignore the scanned repository's `.pinprick.toml` and use the global config (or defaults)

`--json`, `--html`, and `--badge` are mutually exclusive.

## Rule catalog

The full catalog lives in [`docs/scoring.md`](https://github.com/starhaven-io/pinprick/blob/main/docs/scoring.md). Summary:

| Category   | Rule                              | Severity | Points |
| ---------- | --------------------------------- | -------- | ------ |
| `pin`      | `pin.branch` (branch ref)         | high     | 15     |
| `pin`      | `pin.sliding` (sliding tag `@v4`) | medium   | 5      |
| `pin`      | `pin.full_tag` (e.g. `@v4.2.1`)   | low      | 2      |
| `source`   | `source.archived`                 | high     | 10     |
| `source`   | `source.advisory` (GHSA match)    | high     | 15     |
| `runtime`  | `runtime.pipe_to_shell`           | high     | 20     |
| `runtime`  | `runtime.fetch.high`              | high     | 15     |
| `runtime`  | `runtime.fetch.medium`            | medium   | 8      |
| `runtime`  | `runtime.fetch.low`               | low      | 3      |
| `workflow` | `workflow.permissions_write_all`  | high     | 10     |
| `workflow` | `workflow.pull_request_target`    | high     | 5      |
| `workflow` | `workflow.workflow_run`           | medium   | 3      |

Grade bands: **A** 90–100, **B** 80–89, **C** 70–79, **D** 60–69, **F** 0–59.

Because the scanned repository's own `.pinprick.toml` applies, a third-party repo can shape its own grade (`trusted-hosts`, `extra-data-formats`, `ignore` rules). Whenever a repo-local config changes the score, pinprick prints a note to stderr saying what it changed; pass `--no-repo-config` to ignore the file entirely.

## Example

```
$ pinprick score
pinprick score  v0.10.0 rubric

  Grade:  A   (95 / 100)

  Findings (1 unique, 1 occurrences):
    medium  -5    pin.sliding                       actions/checkout@v4

  3 workflows scanned, 8 unique actions.

  Run with --json for the full report.
```

## Versioning

The rubric is independently versioned from the pinprick binary (currently `v0.10.0`). Every scan records the rubric version so historical scores remain interpretable as the rubric evolves. Re-scoring against a newer rubric is always explicit — pinprick never silently re-grades a past scan.
