---
title: clean
description: Remove locally cached audit results.
---

Remove the local audit cache at `$XDG_CACHE_HOME/pinprick/audited/` (default `~/.cache/pinprick/audited/`). This directory stores results from previous `pinprick audit` runs so that already-scanned action SHAs can be skipped on future runs.

```bash
pinprick clean
```

## When to use

- After updating pinprick to a version with new or changed detection rules — clearing the cache forces a fresh scan of all actions
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
