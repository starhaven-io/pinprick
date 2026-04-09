---
title: update
description: Check pinned actions for newer releases.
---

Check SHA-pinned actions for newer releases and optionally update them.

```bash
pinprick update            # dry-run (show available updates)
pinprick update --apply    # write updates to files
pinprick update /path/to/repo
```

## Behavior

- Only checks actions that are already SHA-pinned with a tag comment (e.g., `@sha # v4.1.0`)
- Queries the GitHub Releases API for the latest non-draft, non-prerelease release
- Compares version numbers numerically — suggests the latest release regardless of major version
- Dry-run by default — shows what would change without writing files
- Exit code 1 when updates are available (useful in CI)

## Example

```
$ pinprick update
.github/workflows/ci.yml
  actions/checkout  v4.1.0 -> v6.0.2
  actions/setup-node  v4.0.0 -> v6.3.0

2 updates available. Run with --apply to apply.
```
