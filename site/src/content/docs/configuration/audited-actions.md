---
title: Audited Actions
description: How pinprick's pre-audited action list works.
---

pinprick maintains a list of GitHub Actions that have been scanned and confirmed to have zero runtime fetch findings. When auditing, actions in this list are skipped — avoiding redundant API calls and scans.

## Lookup order

1. **Bundled** — compiled into the binary at build time. Same trust as the binary itself.
2. **Local cache** — `~/.cache/pinprick/audited/`. Populated automatically when you scan an action and it comes back clean.
3. **Remote** — `https://pinprick.rs/audited-actions/`. Opt-in via `fetch-remote = true` in your [config file](/configuration/config-file).
4. **GitHub API** — full source fetch and scan as last resort.

## What "audited" means

Each SHA was scanned for **unversioned runtime fetch patterns**. Specifically:

- Shell: `curl`/`wget` to `/latest/` or unversioned URLs, `gh release download` without a tag, `go install @latest`, unpinned `pip`/`npm`
- PowerShell: `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` to `/latest/` or unversioned URLs
- JavaScript: `fetch()`/`axios`/`got`/`http.get` to `/latest/` or unversioned URLs, `exec()`/`child_process` shelling out to `curl`
- Python: `urllib.request.urlopen`/`requests.get` to `/latest/` or unversioned URLs, `subprocess` shelling out to `curl`/`wget`
- Docker: `FROM :latest` or untagged, `curl`/`wget` in `RUN` instructions

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
[{ "sha": "de0fac2e4500dabe0009e67214ff5f5447ce83dd", "tag": "v6.0.2" }]
```
