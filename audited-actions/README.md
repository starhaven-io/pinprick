# Audited Actions

This directory contains GitHub Actions that have been scanned by `pinprick audit` and returned zero findings at the listed SHAs.

## What "audited" means

Each SHA was scanned for **unversioned runtime fetch patterns** — code that downloads external resources without version pinning. Specifically, pinprick checks:

**Shell** (in `run:` blocks and `action.yml` composite steps):
- `curl`/`wget` fetching from `/latest/` URLs
- `curl`/`wget` fetching URLs with no version segment (e.g., `v1.2.3`)
- `gh release download` without a pinned tag
- `go install @latest`
- `pip install` / `npm install` without version pins

**PowerShell** (in `run:` blocks):
- `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` fetching from `/latest/` or unversioned URLs

**JavaScript** (in `.js`/`.ts` files, including minified bundles):
- `fetch()`/`axios`/`got`/`http.get` to `/latest/` or unversioned URLs
- `exec()`/`child_process` shelling out to `curl`/`wget`

**Python** (in `.py` files):
- `urllib.request.urlopen`/`requests.get` to `/latest/` or unversioned URLs
- `subprocess` shelling out to `curl`/`wget`

**Docker** (in Dockerfiles):
- `FROM image:latest` or untagged `FROM`
- `curl`/`wget` in `RUN` instructions

## What "audited" does NOT mean

This is not a full security review. An action listed here may still:

- Fetch resources from URLs constructed dynamically at runtime (variable interpolation, API responses)
- Execute code from inputs or environment variables
- Have vulnerabilities unrelated to runtime fetching (template injection, credential leaks, etc.)
- Contain patterns in languages pinprick does not scan (Ruby, Go)

For static analysis of workflow files themselves — permissions, template injection, credential handling — use [zizmor](https://github.com/zizmorcore/zizmor).

## File format

Each file is named `{owner}/{repo}.json` and contains an array of audited SHAs with their corresponding tags:

```json
[{ "sha": "de0fac2e4500dabe0009e67214ff5f5447ce83dd", "tag": "v6.0.2" }]
```

## Contributing

To add a new entry:

1. Run `pinprick audit` against a repository using the action at the SHA you want to add
2. Confirm zero findings for that action
3. Add the SHA and tag to the appropriate JSON file (or create a new one)
4. Open a PR
