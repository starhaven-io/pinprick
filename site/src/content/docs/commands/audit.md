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
Scanning .github/workflows/ci.yml
  actions/checkout@de0fac2e audited (bundled)
  actions/upload-artifact@bbbca2dd audited (bundled)
Scanning .github/workflows/release.yml
  actions/attest@59d89421 audited (bundled)
  rust-lang/crates-io-auth-action@bbd81622 audited (local cache)
  Fetching Homebrew/actions/setup-homebrew@main (unpinned)

No runtime fetch risks found.
Audited 4 actions: 3 bundled, 1 local cache.
1 branch ref scanned. Pin to a SHA manually.
```

If the workflow uses sliding tags like `@v4` instead of branch refs, the summary suggests the auto-fix:

```
1 sliding tag scanned. Run `pinprick pin` to resolve.
```

`pinprick pin` can auto-resolve sliding tags to exact SHAs. Branch refs (`@main`) require manual pinning because there's no version target to resolve to.

Per-action status is colored by semantic category, not by source, so a clean audit looks like a wall of uniform green with only the exceptions popping out:

- **`audited`** — green. Matched an entry in the bundled list, local cache, or `pinprick.rs` list. No network work needed.
- **`Fetching`** / **`scanned fresh`** — blue. pinprick fetched the action source over the network and scanned it fresh this run.
- **`(unpinned)`** / **`unpinned ref scanned`** — yellow. The ref is a branch (`@main`) or sliding tag (`@v4`) — pinprick scans the current tip but the trust does not carry across runs because the content can change.
- **`ignored`** — dimmed. Skipped per `ignore.actions` in `.pinprick.toml`.

The summary at the end is up to three lines: the audited total (durably trusted), a separate unpinned line if any branch/sliding-tag refs were scanned, and an ignored line if any config-driven skips were applied.
