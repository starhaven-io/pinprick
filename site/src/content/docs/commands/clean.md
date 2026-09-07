---
title: clean
description: Remove locally cached audit results.
---

Remove the local audit cache at `$XDG_CACHE_HOME/pinprick/audited/` (default `~/.cache/pinprick/audited/`). This directory stores results from previous `pinprick audit` runs so that already-scanned action SHAs can be skipped on future runs.

```bash
pinprick clean
```

## When to use

- To discard local verdicts and repeat source scans. Entries from older scanner versions are already ignored automatically; `--no-audited-catalog` also bypasses bundled and remote verdicts for a single audit
- To reclaim disk space from accumulated cache entries
- To troubleshoot unexpected audit results

## Output

```
$ pinprick clean
Cache cleaned.
```

If there is nothing to clean:

```
$ pinprick clean
Nothing to clean.
```

A filesystem error exits 2 and is reported on stderr; a failed removal is never reported as a successful cleanup.
