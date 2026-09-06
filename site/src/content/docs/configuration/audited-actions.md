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

Verification is fail-closed. The authenticated trusted comment binds both the signing timestamp and the exact action key, so a valid catalog response cannot be relocated to another action. A missing or invalid signature, missing or mismatched action identity, stale signed timestamp, or binary built without the public key disables the remote layer. With a GitHub token, pinprick falls back to a fresh API scan; without one, coverage is reported incomplete and no clean verdict is produced. Nothing is silently trusted.

## What "audited" means

Each SHA was scanned for **unversioned runtime fetch patterns**. Specifically:

- Shell: pipe-to-shell, `curl`/`wget` to `/latest/` or unversioned URLs, `gh release download` without a tag, unpinned `git clone`, `go install @latest`, and unpinned package installs
- PowerShell: pipe-to-shell equivalents, `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` to `/latest/` or unversioned URLs, and unpinned `Install-Module` / `Install-Script`
- JavaScript: `fetch()`/`axios`/`got`/`http.get` to `/latest/` or unversioned URLs, conservative unresolved-variable sinks in authored source, and `exec()`/`child_process` shelling out to `curl`
- Python: `urllib.request.urlopen`/`requests.get` to `/latest/` or unversioned URLs, `subprocess` shelling out to `curl`/`wget`
- Docker: mutable `runs.image` registry references, plus `FROM :latest` or untagged bases, `curl`/`wget` in `RUN`, and remote `ADD` sources in reachable Dockerfiles
- Action helpers: shell, Bash, Zsh, PowerShell, and Python files referenced from composite `run:` steps, plus entrypoints declared by action metadata

Catalog and cache identities are exact. A clean root action does not suppress scanning a subpath action at the same commit, and a clean subpath does not cover its parent or siblings.

## What "audited" does NOT mean

This is not a full security review. An action listed as audited may still:

- Fetch resources through dataflow too complex for pinprick's bounded literal propagation; these sinks are reported conservatively when recognized
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
3. Add the SHA and tag to the exact identity file: `audited-actions/{owner}/{repo}.json` for a root action or `audited-actions/{owner}/{repo}/{subpath}.json` for a subpath action
4. Open a PR

Each file is a JSON array:

```json
[{ "sha": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "tag": "v7.0.0" }]
```
