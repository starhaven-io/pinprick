---
title: audit
description: Scan actions for runtime fetch patterns that bypass pinning.
---

Fetch action source code at the pinned SHA and scan for unversioned runtime fetch patterns.

```bash
pinprick audit
pinprick audit /path/to/repo
```

## What it detects

### Shell (in `run:` blocks and `action.yml`)

| Pattern                                               | Severity |
| ----------------------------------------------------- | -------- |
| `curl`/`wget` piped to `sh`/`bash`/`python` (any URL) | High     |
| `bash <(curl ...)` process substitution               | High     |
| `bash -c "$(curl ...)"` / `eval "$(curl ...)"`        | High     |
| `curl`/`wget` to `/latest/` URLs                      | High     |
| `curl`/`wget` to unversioned URLs                     | Medium   |
| `gh release download` without a pinned tag            | Medium   |
| `go install @latest`                                  | Medium   |
| `pip install` without version pin                     | Low      |
| `npm install` without version pin                     | Low      |

### PowerShell (in `run:` blocks)

| Pattern                                                                 | Severity |
| ----------------------------------------------------------------------- | -------- |
| `iex`/`Invoke-Expression` on fetched content (`iex (iwr ...)`)          | High     |
| `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` to `/latest/` URLs  | High     |
| `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` to unversioned URLs | Medium   |

### JavaScript (in `.js`/`.ts` files)

| Pattern                                                | Severity |
| ------------------------------------------------------ | -------- |
| `fetch()`/`axios`/`got`/`http.get` to `/latest/` URLs  | High     |
| `exec()`/`child_process` shelling out to `curl`/`wget` | High     |
| `fetch()`/`axios` to unversioned URLs                  | Medium   |

Minified bundles (`dist/index.js`) are split on `;` and scanned statement-by-statement.

### Python (in `.py` files)

| Pattern                                                     | Severity |
| ----------------------------------------------------------- | -------- |
| `urllib.request.urlopen`/`requests.get` to `/latest/` URLs  | High     |
| `subprocess` shelling out to `curl`/`wget`                  | High     |
| `urllib.request.urlopen`/`requests.get` to unversioned URLs | Medium   |

### Docker (in Dockerfiles)

| Pattern                                | Severity                 |
| -------------------------------------- | ------------------------ |
| `FROM image:latest` or untagged `FROM` | High                     |
| `RUN curl`/`wget` piped to a shell     | High                     |
| `curl`/`wget` in `RUN` instructions    | Medium                   |
| `FROM image@sha256:...`                | Skipped (already pinned) |

### Checksum verification

Findings followed within 3 lines by a checksum verification command (`sha256sum`, `shasum`, `openssl dgst`, `gpg --verify`, `Get-FileHash`) are downgraded one severity level. The fetch is still flagged, but verified downloads are less risky.

Pipe-to-shell findings are **not** downgraded by a following checksum command — the piped payload is never written to disk, so a checksum line nearby cannot cover it.

## Audited actions list

pinprick ships with a bundled list of popular actions that have been scanned and confirmed clean. These are skipped automatically during audit, avoiding redundant API calls.

See [Audited Actions](/configuration/audited-actions) for details on how the list works and how to contribute.

## Without a token

When no GitHub token is available, audit scans only local `run:` blocks in workflow files. Action source code is not fetched. This still catches the most common patterns (shell commands fetching unversioned resources) but misses JavaScript, Python, and Docker patterns inside actions.

## Example

```
$ pinprick audit
Scanning .github/workflows/ci.yml... done
  actions/checkout@de0fac2e audited
  actions/upload-artifact@bbbca2dd audited
Scanning .github/workflows/release.yml... done
  actions/attest@59d89421 audited

No runtime fetch risks found.
```
