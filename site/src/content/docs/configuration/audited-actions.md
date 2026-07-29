---
title: Audited Actions
description: How pinprick's pre-audited action list works.
---

pinprick maintains a list of GitHub Actions that have been scanned and confirmed to have zero runtime fetch findings. When auditing, actions in this list are skipped — avoiding redundant API calls and scans.

## Lookup order

1. **Bundled** — compiled into the binary at build time. Same trust as the binary itself.
2. **Local cache** — `$XDG_CACHE_HOME/pinprick/audited/` (default `~/.cache/pinprick/audited/`). Populated automatically when you scan an action and it comes back clean.
3. **Remote** — `https://pinprick.rs/audited-actions/`. Opt-in via `fetch-remote = true` in your [config file](/configuration/config-file).
4. **GitHub API** — full source fetch and scan as last resort.

## Remote catalog signing

A remote catalog entry tells pinprick to _skip scanning_ a SHA, so its integrity matters more than TLS alone can guarantee — a compromised CDN must not be able to mark malicious SHAs as audited. Every catalog file is therefore signed with [minisign](https://jedisct1.github.io/minisign/): the signature is served next to the file (`….json.minisig`), and the pinprick binary verifies it against a public key embedded at build time before honoring any entry.

Verification is fail-closed. A missing or invalid signature — or a binary built without the public key — disables the remote layer entirely, and pinprick falls back to scanning via the GitHub API. Nothing is silently trusted.

## What "audited" means

Each SHA was scanned for **unversioned runtime fetch patterns**. Specifically:

- Shell: pipe-to-shell, `curl`/`wget` to `/latest/` or unversioned URLs, `gh release download` without a tag, unpinned `git clone`, `go install @latest`, and unpinned package installs
- PowerShell: pipe-to-shell equivalents, `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` to `/latest/` or unversioned URLs, and unpinned `Install-Module` / `Install-Script`
- JavaScript: `fetch()`/`axios`/`got`/`http.get` to `/latest/` or unversioned URLs, `exec()`/`child_process` shelling out to `curl`
- Python: `urllib.request.urlopen`/`requests.get` to `/latest/` or unversioned URLs, `subprocess` shelling out to `curl`/`wget`
- Docker: `FROM :latest` or untagged, `curl`/`wget` in `RUN` instructions, and remote `ADD` sources

A clean repository-level audit also covers actions exposed from subpaths at the same SHA. A clean subpath audit applies only to that subpath, not to sibling actions or the repository as a whole.

## What "audited" does NOT mean

This is not a full security review. An action listed as audited may still:

- Fetch resources from dynamically constructed URLs
- Execute code from inputs or environment variables
- Have vulnerabilities unrelated to runtime fetching
- Contain patterns in languages pinprick does not scan (Ruby, Go)

For static analysis of workflow files — permissions, template injection, credential handling — use [zizmor](https://github.com/zizmorcore/zizmor).

## Why the SHA is permanent

A SHA is a commit hash. If any file in the commit changes — including `dist/index.js` — the hash changes. So an audit result for a SHA is deterministic and permanent.

## Contributing

To add a new entry to the audited-actions list:

1. Run `pinprick audit` against a repository using the action at the SHA you want to add
2. Confirm zero findings
3. Add the SHA and tag to the appropriate JSON file in `audited-actions/{owner}/{repo}.json`
4. Open a PR

Each file is a JSON array:

```json
[{ "sha": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "tag": "v7.0.0" }]
```
