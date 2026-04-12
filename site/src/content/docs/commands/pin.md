---
title: pin
description: Resolve action tag references to full SHAs.
---

Scan `.github/workflows/*.yml` files and resolve action tag references to full SHA-pinned references.

```bash
pinprick pin                # dry-run (show what would be pinned)
pinprick pin --write        # write changes to files
pinprick pin /path/to/repo
```

## Behavior

- Dry-run by default — shows what would change without writing files, exits 1 when there are unpinned actions (useful for CI gating)
- `--write` rewrites files in-place with `@sha # tag` format, preserving all comments and formatting
- Tag refs (e.g., `@v4.3.1`) are resolved to their commit SHA via the GitHub API
- Sliding tags (e.g., `@v4`) are resolved to the exact release version — `@v4` becomes `# v4.3.1`, not `# v4`
- Already-pinned refs (40-char hex SHAs) are skipped silently
- Branch refs (e.g., `@main`) are flagged — pin to a SHA manually
- Annotated tags are followed to their underlying commit SHA

## Example

```
$ pinprick pin
.github/workflows/ci.yml
  actions/checkout @v4 -> @de0fac2e…ce83dd # v4.3.1
  actions/upload-artifact @v4 -> @bbbca2dd…f024f # v7.0.0

  ! actions/checkout@v4 -- sliding tag, resolved to v4.3.1
  ! Homebrew/actions/setup-homebrew@main -- branch ref — pin to a SHA manually

Would pin 2 actions across 1 file (2 skipped)
Run with --write to apply.
```
