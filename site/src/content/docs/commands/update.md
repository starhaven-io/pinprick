---
title: update
description: Check pinned actions for newer releases.
---

Check SHA-pinned actions for newer releases and optionally update them.

```bash
pinprick update                       # dry-run (show available updates)
pinprick update --write               # write updates to files
pinprick update --only actions/       # only check actions in the `actions/` org
pinprick update --only actions/checkout
pinprick update /path/to/repo
```

## Behavior

- Only checks actions that are already SHA-pinned with a tag comment (e.g., `@sha # v4.1.0`)
- Queries the GitHub Releases API for the latest non-draft, non-prerelease release
- Compares version numbers numerically — suggests the latest release regardless of major version
- Dry-run by default — shows what would change without writing files
- Each update is printed with a link to the release page for easy changelog review
- Exit code 1 when updates are available (useful in CI)

## Filtering with `--only`

`--only <pattern>` restricts the scan to actions whose `owner/repo` _contains_ the pattern as a substring. Useful in CI pipelines that bump one action at a time, or to scope an update to a single org:

```bash
pinprick update --only actions/checkout    # exactly this action
pinprick update --only actions/            # all actions/* repos
pinprick update --only aws                 # any repo with "aws" in owner/repo
```

Matching is case-sensitive. Matching is against `owner/repo` only — subpaths are not considered.

## Example

```
$ pinprick update
.github/workflows/ci.yml
  actions/checkout v4.1.0 -> v6.0.2
    https://github.com/actions/checkout/releases/tag/v6.0.2
  actions/setup-node v4.0.0 -> v6.3.0
    https://github.com/actions/setup-node/releases/tag/v6.3.0

2 updates available. Run with --write to apply.
```
