# pinprick scoring rubric

**Status:** draft (rubric version `0.2.0`)

This document defines how pinprick computes a single score for a GitHub repository's Actions supply chain posture. It is the public specification that the `pinprick score` CLI subcommand implements against, and that any downstream tool wrapping the engine (dashboards, CI plugins, reporting pipelines) should implement against so scores stay portable and comparable.

Keeping this document public and versioned is deliberate: security scoring is only trustworthy if anyone can re-derive the score from the raw findings. Vendors that hide the rubric behind "proprietary algorithms" end up being distrusted by the security teams they want as customers.

## Design principles

1. **Transparent.** Every point deducted is tied to an explicit rule and finding. Given the raw findings, a third party can re-compute the score by hand.
2. **Actionable.** Every rule maps to a concrete remediation. The score is always accompanied by a prioritized fix list.
3. **Deterministic.** The same inputs always produce the same score. No stochastic inputs, no ML models, no "confidence-weighted" signals in v1.
4. **Versioned.** The rubric has a semantic version. Every scan records the rubric version used. Re-scoring is always explicit — we never silently mutate historical scores.
5. **Unique-finding basis.** Action-level rules (`pin.*`, `source.*`, `runtime.*`) fire once per unique `(rule, action_ref)` across the repo, with an `occurrences` list recording every `(workflow, line)` where the action is used. Workflow-level rules (`workflow.*`) fire once per `(rule, workflow_path)`. A repo with 20 workflows that all call `actions/checkout@main` has one fix to make, so the score reflects one finding.
6. **Absolute before relative.** v1 is an absolute rubric ("47/100"). Percentile scoring across a corpus is a later feature and needs real data first.

## Score formula

Each scan produces findings. Each finding has a severity that maps to a point deduction.

```
repo_score = max(0, 100 - sum(finding.points for finding in findings))
```

Grade bands (absolute):

| Grade | Range    |
|-------|----------|
| A     | 90 – 100 |
| B     | 80 – 89  |
| C     | 70 – 79  |
| D     | 60 – 69  |
| F     |  0 – 59  |

Rationale for the flat deduction model: it's trivial to explain, easy to audit, and composes cleanly across rules. Weighted-average models require calibrating weights against each other, which invites arguments that nobody can win. We can always move to a more nuanced formula later; we cannot retroactively earn back trust lost to an opaque one.

## Rule catalog

Each rule has an ID, a category, a severity, a point deduction, and a remediation hint. The **Status** column marks what is live in the current rubric version vs. reserved for a future release.

### Pinning rules (category: `pin`)

| ID            | Condition                                          | Severity | Points | Status | Remediation                                           |
|---------------|----------------------------------------------------|----------|--------|--------|-------------------------------------------------------|
| `pin.none`    | Action `uses:` has no `@ref` at all                | high     |   20   | reserved | Pin to a full 40-char SHA                           |
| `pin.branch`  | `@ref` is a branch name (`main`, `master`, custom) | high     |   15   | live   | Pin to a full 40-char SHA                             |
| `pin.sliding` | `@ref` is a sliding tag (e.g., `@v4`)              | medium   |    5   | live   | Pin to a full 40-char SHA; keep the tag as a comment  |
| `pin.full_tag`| `@ref` is a full version tag (e.g., `@v4.2.1`)     | low      |    2   | live   | Pin to a full 40-char SHA                             |

A SHA-pinned reference incurs no pinning deduction.

`pin.none` is catalogued for completeness but currently unreachable: pinprick's `uses:` parser rejects lines without an `@ref`, so no-ref references never reach the scorer. The rule id is reserved so future parser changes (or other tooling that implements this rubric) can emit it without colliding.

### Action-source rules (category: `source`)

These rules fire against properties of the referenced action itself. Most require a GitHub token; `source.unverified` is offline (allowlist-based).

| ID                    | Condition                                                    | Severity | Points | Status   | Remediation                                      |
|-----------------------|--------------------------------------------------------------|----------|--------|----------|--------------------------------------------------|
| `source.archived`     | Referenced repo is archived                                  | high     |   10   | planned  | Migrate to an actively maintained replacement    |
| `source.stale`        | Referenced SHA was committed >365 days ago and no newer tag  | medium   |    5   | planned  | Update to a newer maintained version             |
| `source.advisory`     | Referenced version has a published GHSA advisory             | high     |   15   | planned  | Update to a patched version                      |
| `source.unverified`   | Publisher is not in the baseline (`actions`, `github`) or the configured `trusted-owners` list | low | 1 | live | Confirm this publisher is trustworthy; add them to `trusted-owners` in `.pinprick.toml`, or fork the action into your own org and pin to that |

`source.unverified` is configurable. The built-in baseline of trusted publishers is `actions` and `github`. Extend with `trusted-owners = ["my-org", "vendor"]` in `.pinprick.toml`. Case-insensitive, exact owner match.

### Runtime-fetch rules (category: `runtime`) — **planned for v0.2.0**

These reuse findings from the existing `pinprick audit` pipeline. Severity comes straight from the audit finding. Not emitted in v0.1.0; the integration with the audit pipeline lands alongside these rules.

| ID                      | Condition                                          | Severity | Points | Remediation                                        |
|-------------------------|----------------------------------------------------|----------|--------|----------------------------------------------------|
| `runtime.pipe_to_shell` | `curl \| sh`, `bash <(curl …)`, `iex (iwr …)`, etc. | high     |   20   | Download, verify, then execute; never pipe         |
| `runtime.fetch.high`    | Audit finding, severity high                       | high     |   15   | Pin the fetched artifact; add checksum verification|
| `runtime.fetch.medium`  | Audit finding, severity medium                     | medium   |    8   | Pin or version-lock the fetched resource           |
| `runtime.fetch.low`     | Audit finding, severity low                        | low      |    3   | Review; often acceptable if the URL is versioned   |

Note: the audit pipeline already applies the `data format URL` and nearby-checksum adjustments. `runtime.*` scoring uses the post-adjustment severity, so double-counting doesn't happen.

### Workflow-level rules (category: `workflow`)

These fire once per workflow, not per action use.

| ID                          | Condition                                             | Severity | Points | Status | Remediation                                          |
|-----------------------------|-------------------------------------------------------|----------|--------|--------|------------------------------------------------------|
| `workflow.permissions_write_all` | Workflow declares `permissions: write-all`       | high     |   10   | live   | Declare minimal per-job `permissions:` blocks        |
| `workflow.pull_request_target` | Workflow uses the `pull_request_target` trigger     | high     |    5   | live   | Validate the checkout ref; avoid running PR code with elevated tokens |
| `workflow.workflow_run`     | Workflow uses the `workflow_run` trigger              | medium   |    3   | live   | Explicitly validate trigger provenance                |

The `pull_request_target` and `workflow_run` rules fire on trigger *presence* in v0.1.0. A future release may narrow to "without explicit guardrails" once the parser can recognize common safe patterns (e.g., validating the checkout ref).

### Future categories (not in v1)

- `secret.*` — detections of hard-coded secrets, improper `${{ secrets.* }}` exposure in logs, etc.
- `registry.*` — signals from the vetted-mirror layer once it exists (unvetted action used when a vetted equivalent is available).
- `sbom.*` — SBOM / provenance attestation coverage.

These are deliberately out of scope for v1 to keep the initial rubric defensible. Adding them bumps the rubric to `0.2.0`.

## Output

`pinprick score <path>` produces a stable JSON document. A static HTML report is generated from the same JSON.

### JSON schema (sketch)

```jsonc
{
  "rubric_version": "0.1.0",
  "pinprick_version": "…",
  "scanned_at": "2026-04-22T20:00:00Z",
  "target": { "kind": "repo", "path": "./" },
  "score": 72,
  "grade": "C",
  "totals": {
    "points_deducted": 28,
    "findings": 11,
    "workflows_scanned": 4,
    "unique_actions": 17
  },
  "findings": [
    {
      "id": "pin.sliding",
      "category": "pin",
      "severity": "medium",
      "points": 5,
      "action_ref": "actions/checkout@v4",
      "occurrences": [
        { "workflow": ".github/workflows/ci.yml", "line": 22 },
        { "workflow": ".github/workflows/release.yml", "line": 15 }
      ],
      "remediation": "Pin to a full 40-char SHA; keep the tag as a comment"
    }
    // …
  ]
}
```

### Terminal output (human-readable)

A compact summary:

```
pinprick score  v0.1.0 rubric

  Grade:  C   (72 / 100)

  Findings (11 unique, 24 occurrences):
    high    2  pin.branch           actions/foo@main
    high    1  source.archived      bar/baz@abc1234
    medium  6  pin.sliding          7 actions
    low     2  pin.full_tag         2 actions

  Top remediations:
    1. Pin actions/foo@main to a full SHA             (-15)
    2. Replace bar/baz (archived) with a maintained action (-10)
    …

  Run `pinprick score --json` for the full report.
```

### HTML report

A single self-contained HTML file with:

- Score + grade banner
- Per-category breakdown with expandable finding lists
- Per-workflow drill-down
- Prioritized remediation list (sorted by points recovered)

No JavaScript frameworks; plain HTML + a little CSS. The HTML report is shareable as a static artifact.

## Roll-ups

The CLI's natural scope is a single repo. Wrappers that scan across many repos (dashboards, org-wide scanners) roll findings up further; the roll-up semantics below are specified here so those implementations produce consistent numbers:

- **Workflow score**: `max(0, 100 - sum(points for findings in that workflow))`. Used for within-repo drill-down.
- **Org score**: weighted mean of repo scores, weighted by action-use count (so a single tiny repo with a bad score doesn't tank the whole org).
- **Time series**: every scan persists its full finding list plus rubric version; trend lines and scan-over-scan diffs are derived downstream.

The pinprick CLI does not implement the roll-ups; it scans a single repo and emits findings. Anything cross-repo belongs to a wrapper.

## Versioning

The rubric version is semver-ish:

- **Patch** (`0.1.0 → 0.1.1`): wording/remediation text changes; no score impact.
- **Minor** (`0.1.0 → 0.2.0`): new rules added, or point values adjusted. Existing repos may score differently; scans are re-labeled with the new version. Historical scans retain their original rubric version.
- **Major** (`0.x → 1.0`): structural change to the formula or output schema. Requires a migration note.

Re-scoring an existing scan against a newer rubric is always explicit in the UI. We never silently change a score.

## Worked example

A hypothetical small repo:

- 1 workflow (`ci.yml`) with:
  - `actions/checkout@v4` (sliding tag)
  - `actions/setup-node@v4.2.1` (full tag)
  - `some-org/custom-action@main` (branch ref)
  - A `run:` block that does `curl https://example.com/install.sh | sh`
  - `permissions: write-all` at workflow level

Findings:

| Rule                               | Points |
|------------------------------------|--------|
| `pin.sliding`                      |    5   |
| `pin.full_tag`                     |    2   |
| `pin.branch`                       |   15   |
| `source.unverified` (some-org)     |    1   |
| `runtime.pipe_to_shell` (planned)  |   20   |
| `workflow.permissions_write_all`   |   10   |

Total deducted in v0.2.0: **53**. Score: **47**. Grade: **F**.

Remediation priority (biggest point recovery first):
1. Remove the `curl | sh` (+20 — lands with the `runtime.*` rules in a later version)
2. Pin `some-org/custom-action` to a SHA (+15); if `some-org` is a trusted vendor, add to `trusted-owners` (+1 more)
3. Scope `permissions:` per-job (+10)
4. Pin `actions/checkout` to a SHA (+5)
5. Pin `actions/setup-node` to a SHA (+2)

Post-remediation score: **100**.
