---
title: pin
description: Resolve action tag references to full SHAs.
---

Scan workflow files and resolve action tag references to full SHA-pinned references.

Workflows are discovered under `.github/workflows/`, `.forgejo/workflows/`, and `.gitea/workflows/`; whichever exist are all scanned. Forgejo and Gitea use GitHub-compatible workflow syntax, so the same pinning applies. The set of forge roots is fixed and cannot be changed by a repository's `.pinprick.toml`, so a scanned repo can never redirect the scan away from `.github`. Tag resolution goes through the github.com API, so refs to actions hosted on a Forgejo or Gitea instance cannot be resolved; only github.com-hosted actions (the common case) are pinned.

```bash
pinprick pin                # dry-run (show what would be pinned)
pinprick pin --write        # write changes to files
pinprick pin /path/to/repo
```

## Behavior

- Dry-run by default — shows what would change without writing files, exits 1 when there are unpinned actions (useful for CI gating)
- `--write` rewrites files in-place with `@sha # tag` format, preserving all comments and formatting
- Tag refs (e.g., `@v7.0.0`) are resolved to their commit SHA via the GitHub API
- Sliding tags (e.g., `@v7`) are resolved to the exact release version — `@v7` becomes `# v7.0.0`, not `# v7`
- Already-pinned refs (40-char hex SHAs) are skipped silently
- Branch refs (e.g., `@main`) are flagged — pin to a SHA manually
- Annotated tags are followed to their underlying commit SHA
- `docker://` container references are audited and scored separately; registry tags must be replaced with a reviewed `@sha256:` digest manually
- Only block-style, single-line `uses:` mappings are rewritten. Flow mappings, escaped YAML keys, and multiline values exit 2 and block all writes rather than risking a structurally ambiguous edit

## Example

```
$ pinprick pin
.github/workflows/ci.yml
  actions/checkout @v7 -> @9c091bb21b7c… # v7.0.0
  actions/upload-artifact @v7 -> @043fb46d1a93… # v7.0.1

  ! actions/checkout@v7 -- sliding tag, resolved to v7.0.0
  ! Homebrew/actions/setup-homebrew@main -- branch ref — pin to a SHA manually

Would pin 2 actions across 1 file (2 skipped)
Run with --write to apply.
```
