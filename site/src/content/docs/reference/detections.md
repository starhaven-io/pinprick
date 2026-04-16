---
title: Detections
description: Every runtime fetch pattern pinprick audit looks for, with examples and rationale.
---

This is the canonical list of every rule `pinprick audit` checks. All rules emit findings under the `pinprick/shell_fetch`, `pinprick/javascript_fetch`, `pinprick/python_fetch`, or `pinprick/docker_unpinned` SARIF rule ids.

## Severity levels

- **High** — an attacker controlling the fetched resource gets arbitrary code execution in the job. Typical: `/latest/` URLs, piped-to-shell, missing Docker tags.
- **Medium** — an unversioned URL or unpinned download. Risk depends on what the URL points at.
- **Low** — unpinned package manager install (`pip install foo`, `npm install foo`). Usually a hygiene issue rather than an immediate exploit.

## How matches are scored

pinprick scans line by line. Each rule is an anchored regex, compiled once at startup.

- **Pipe-to-shell pre-empts other shell rules.** If a line matches a pipe-to-shell rule, no other shell or Docker rule fires on that line. So `curl ... | sh` produces a single high-severity finding instead of one medium (unversioned URL) plus one high (pipe-to-shell).
- **Versioned-URL downgrade.** Non-pipe shell, JavaScript, and Python fetch rules only fire if the URL is _unversioned_. A URL is versioned if any path segment matches `v?\d+(\.\d+)+` — e.g. `/v1.2.3/`, `/0.55.8/`. See [Versioned URL heuristic](#versioned-url-heuristic).
- **Trusted hosts exemption.** Unversioned-URL rules are downgraded to allowed matches when the URL host matches an entry in the user's [`trusted-hosts`](#trusted-hosts-exemption) list.
- **Data-format exemption.** If a fetch targets a URL whose path ends in a known data-format extension (`.json`, `.yaml`, `.toml`, etc.), it is treated as a data fetch, not a code fetch, and downgraded to an allowed match instead of a finding. See [Data-format exemption](#data-format-exemption).
- **Checksum downgrade.** A non-pipe finding followed within 3 lines by `sha256sum`, `shasum`, `openssl dgst`, `gpg --verify`, or `Get-FileHash` is downgraded one severity level (high → medium → low). The fetch is still reported.
- **Pipe-to-shell is never downgraded.** A piped payload is never written to disk, so no checksum command can verify it.

## Pipe-to-shell

Flagged in shell `run:` blocks, composite `action.yml` steps, and Dockerfile `RUN` lines. High severity regardless of URL versioning.

### curl or wget piped to a shell interpreter

**Severity:** High

Triggers on `curl` or `wget` piped into `sh`, `bash`, `zsh`, `dash`, `ash`, `ksh`, `fish`, or `python`/`python3`, optionally via `sudo`.

```bash
curl -sSL https://example.com/releases/download/v1.2.3/install.sh | sh
curl -fsSL https://example.com/install.sh | sudo bash
wget -qO- https://example.com/install.sh | sh -s -- --yes
curl https://example.com/get.py | python3
```

Not flagged:

```bash
curl https://example.com/file.sh | tee out.sh     # not an interpreter
curl https://api.example.com/data | jq .          # not an interpreter
```

The versioned URL in the first example pins the _path_, not the _bytes on the wire_: release tags can be recreated, S3 buckets can be overwritten, in-flight bytes can be swapped. Writing the script to disk and checking a signature is always cheap; piping to `sh` forfeits that option.

### Process substitution of a fetched script

**Severity:** High

Triggers on Bash process substitution where the inner command is a fetch.

```bash
bash <(curl -L https://example.com/install.sh)
sh <(wget -qO- https://example.com/install.sh)
```

Equivalent to piping to shell: the script is executed without ever being written to disk.

### Command substitution of fetched content

**Severity:** High

Triggers on `bash -c "$(…)"` or `eval "$(…)"` wrapping a fetch.

```bash
bash -c "$(curl -fsSL https://example.com/install.sh)"
eval "$(wget -qO- https://example.com/install.sh)"
```

Same risk: fetched bytes are handed straight to a shell.

### PowerShell Invoke-Expression on fetched content

**Severity:** High

Triggers on `iex` / `Invoke-Expression` combined with `iwr` / `Invoke-WebRequest` / `irm` / `Invoke-RestMethod` / `DownloadString`.

```powershell
iex (iwr https://example.com/install.ps1)
iex (Invoke-RestMethod -Uri https://example.com/install.ps1)
Invoke-Expression ((New-Object Net.WebClient).DownloadString("https://example.com/install.ps1"))
```

The PowerShell equivalent of `curl | sh`. Same risk, same high severity.

## Shell fetches

Flagged in shell `run:` blocks and composite `action.yml` steps.

### curl or wget to a `/latest/` URL

**Severity:** High

Triggers on `curl` or `wget` with a URL containing `/latest` or `=latest`.

```bash
curl -L "https://github.com/owner/repo/releases/latest/download/tool.tar.gz"
wget "https://example.com/releases/latest/tool.tar.gz"
```

Not flagged:

```bash
curl -L "https://github.com/owner/repo/releases/download/v1.2.3/tool.tar.gz"
```

`latest` is a mutable alias — whatever it resolves to today may be different tomorrow.

### curl or wget to an unversioned URL

**Severity:** Medium

Triggers on `curl` or `wget` fetching an `http://` or `https://` URL whose path contains no version segment.

```bash
curl -L https://example.com/install.sh -o install.sh
wget https://example.com/bin/tool
```

Not flagged:

- Any URL whose path contains a segment matching `v?\d+(\.\d+)+`, e.g. `https://example.com/releases/download/v1.2.3/tool`.
- Any URL whose host matches [`trusted-hosts`](#trusted-hosts-exemption) in `.pinprick.toml`.
- Any URL whose path ends in a data-format extension (`.json`, `.yaml`, `.toml`, `.csv`, etc.). See [Data-format exemption](#data-format-exemption).

### gh release download without a pinned tag

**Severity:** Medium

Triggers on `gh release download` without a version argument.

```bash
gh release download --pattern '*.tar.gz'
```

Not flagged:

```bash
gh release download v1.2.3 --pattern '*.tar.gz'
```

The `gh` CLI grabs the most recent release when no tag is given — same problem as a `/latest/` URL.

### go install @latest

**Severity:** Medium

Triggers on `go install …@latest`.

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

Not flagged:

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.0
```

### git clone without a pinned ref

**Severity:** Medium

Triggers on `git clone` without `--branch`/`-b` or with a branch name that doesn't look like a version tag.

```bash
git clone https://github.com/org/repo
git clone --branch main https://github.com/org/repo
git clone -b develop https://github.com/org/repo
```

Not flagged:

```bash
git clone --branch v1.2.3 https://github.com/org/repo
git clone -b 2.0.1 https://github.com/org/repo
git clone --depth 1 --branch v1.2.3 https://github.com/org/repo
```

A bare `git clone` defaults to HEAD of the default branch, which is mutable. Pinning to a version tag via `--branch` makes the clone deterministic (at least to the tag level).

**SHA checkout suppression:** if `git checkout <40-character-SHA>` appears within 3 lines after an unpinned `git clone`, the finding is fully suppressed (recorded as an allowed match visible under `--verbose`). The SHA checkout deterministically pins the repository content.

```bash
# This produces zero findings:
git clone https://github.com/org/repo
cd repo
git checkout abcdef1234567890abcdef1234567890abcdef12
```

Also flagged in Dockerfile `RUN` instructions under the `pinprick/docker_unpinned` rule.

### pip install without a version pin

**Severity:** Low

Triggers on `pip install <package>` where `<package>` has no `==`/`>=` specifier and is the last argument.

```bash
pip install requests
pip3 install flask
```

Not flagged:

```bash
pip install requests==2.31.0
pip install -r requirements.txt
```

### npm install without a version pin

**Severity:** Low

Triggers on `npm install <package>` where `<package>` has no `@version` specifier.

```bash
npm install typescript
npm install @babel/core
```

Not flagged:

```bash
npm install typescript@5.6.0
npm install    # no package argument — uses package-lock.json
```

### cargo install without a version pin

**Severity:** Low

Triggers on `cargo install <crate>` where `<crate>` has no `@version` specifier and no `--version` flag.

```bash
cargo install ripgrep
```

Not flagged:

```bash
cargo install ripgrep@14.0.0
cargo install ripgrep --version 14.0.0
cargo install    # no crate argument — uses Cargo.toml
```

### gem install without a version pin

**Severity:** Low

Triggers on `gem install <gem>` where `<gem>` has no `-v` version specifier.

```bash
gem install rubocop
```

Not flagged:

```bash
gem install rubocop -v 1.0.0
gem install    # no gem argument
```

## PowerShell fetches

Flagged in shell `run:` blocks that happen to be PowerShell.

### Invoke-WebRequest / iwr / Invoke-RestMethod / irm to a `/latest/` URL

**Severity:** High

```powershell
Invoke-WebRequest "https://example.com/releases/latest/tool"
irm "https://example.com/releases/latest/tool"
```

### Invoke-WebRequest / iwr / Invoke-RestMethod / irm to an unversioned URL

**Severity:** Medium

```powershell
Invoke-WebRequest "https://example.com/tool"
iwr https://example.com/tool -OutFile tool.exe
```

Not flagged:

```powershell
Invoke-WebRequest "https://example.com/releases/download/v1.2.3/tool"
```

## JavaScript / TypeScript fetches

Flagged in `.js` and `.ts` files inside an action's source tree. Minified bundles (lines longer than 500 characters) are split on `;` and each segment is scanned individually — this catches calls buried inside `dist/index.js`.

### fetch() / axios / got / http.get to a `/latest/` URL

**Severity:** High

```javascript
fetch('https://api.github.com/repos/owner/repo/releases/latest');
axios.get('https://example.com/releases/latest/tool');
got('https://example.com/releases/latest/tool');
https.get('https://example.com/releases/latest/tool', cb);
```

### exec / child_process shelling out to curl or wget

**Severity:** High

```javascript
exec('curl -L https://example.com/install.sh | sh');
child_process.execSync('wget https://example.com/tool');
```

A JavaScript action reaching for `curl` is almost always doing something that should be a signed release download instead.

### fetch() / axios to an unversioned URL

**Severity:** Medium

```javascript
const r = await fetch('https://example.com/api/data');
const r = await axios.get('https://example.com/api/data');
```

Not flagged:

- Versioned URL: `fetch('https://example.com/api/1.2.3/data')`
- Trusted host via [`trusted-hosts`](#trusted-hosts-exemption)
- Data-format URL: `fetch('https://example.com/config.json')` — see [Data-format exemption](#data-format-exemption).

## Python fetches

Flagged in `.py` files inside an action's source tree.

### urllib.request.urlopen / requests.get to a `/latest/` URL

**Severity:** High

```python
urllib.request.urlopen("https://example.com/releases/latest/tool")
requests.get("https://example.com/releases/latest/tool")
```

### subprocess shelling out to curl or wget

**Severity:** High

```python
subprocess.run(["curl", "-L", url])
subprocess.check_output(["wget", url])
```

### urllib.request.urlopen / requests.get to an unversioned URL

**Severity:** Medium

```python
requests.get("https://example.com/api/data")
urllib.request.urlopen("https://example.com/file")
```

Not flagged:

- Versioned URL: `requests.get("https://example.com/releases/download/v1.2.3/tool")`
- Trusted host via [`trusted-hosts`](#trusted-hosts-exemption)
- Data-format URL: `requests.get("https://example.com/data.json")` — see [Data-format exemption](#data-format-exemption).

## Dockerfile patterns

Flagged in `Dockerfile` and `*.dockerfile` files inside an action's source tree.

### FROM image:latest

**Severity:** High

```dockerfile
FROM ubuntu:latest
FROM node:latest AS builder
```

`:latest` is a mutable tag. Pin to a specific version or, better, a digest.

### FROM image without a tag

**Severity:** High

```dockerfile
FROM ubuntu
FROM node AS builder
```

An untagged `FROM` implicitly pulls `:latest`.

### FROM image@sha256:…

**Not flagged.** Digest-pinned images are immutable.

```dockerfile
FROM ubuntu@sha256:abc123def456...
```

### RUN curl or wget piped to a shell

**Severity:** High

Caught by the shared [pipe-to-shell rules](#curl-or-wget-piped-to-a-shell-interpreter). Escalated from the medium-severity generic `RUN curl` rule below.

```dockerfile
RUN curl -sSL https://example.com/install.sh | sh
RUN wget -qO- https://example.com/install.sh | sh
```

### RUN curl or wget (no pipe)

**Severity:** Medium

```dockerfile
RUN curl -L https://example.com/install.sh -o /usr/local/bin/install
RUN wget https://example.com/tool
```

Not flagged: a `curl` line followed within 3 lines by a checksum command, which is downgraded to low.

### ADD with a URL source

**Severity:** Medium

Dockerfile's `ADD` instruction accepts an `http://` or `https://` URL as its source, which is downloaded at build time. Unlike `COPY`, it can reach the network.

```dockerfile
ADD https://example.com/install.tar.gz /tmp/
ADD --chown=user:group https://example.com/tool.tgz /opt/
```

Not flagged:

- Versioned URL: `ADD https://example.com/releases/download/v1.2.3/install.tar.gz /tmp/`
- Trusted host via [`trusted-hosts`](#trusted-hosts-exemption)
- Data-format URL: `ADD https://example.com/config.json /etc/` — see [Data-format exemption](#data-format-exemption).
- Local source: `ADD ./local.tar.gz /tmp/`

## Versioned URL heuristic

A URL is considered _versioned_ if it contains a path segment matching `v?\d+(\.\d+)+` between `/` or `=` boundaries:

| URL                                                        | Versioned?                         |
| ---------------------------------------------------------- | ---------------------------------- |
| `https://example.com/releases/download/v1.2.3/tool.tar.gz` | yes                                |
| `https://example.com/releases/download/0.55.8/tool`        | yes                                |
| `https://example.com/releases/latest/download/tool.tar.gz` | no                                 |
| `https://api.example.com/data`                             | no                                 |
| `https://example.com/v4/resource`                          | no (single numeric component only) |

This is intentionally strict — `v4` alone is a sliding major-version alias, not a pinned release.

## Data-format exemption

Unversioned URL rules (`curl`/`wget` to an unversioned URL, `fetch()`/`axios` to an unversioned URL, `urllib`/`requests` to an unversioned URL) are **not** emitted as findings when the URL's path ends in a known data-format extension. Instead, the match is recorded as an _allowed_ match with reason `data format URL` and is only visible under `--verbose`.

Rationale: a workflow fetching JSON for `jq` or YAML for parsing is a different risk class from fetching an install script. The payload is consumed as data, never executed. Homebrew/core's `curl -s https://formulae.brew.sh/api/analytics/install/homebrew-core/30d.json` is a real example — the JSON is assigned to a shell variable and parsed, never run.

**Extensions considered data formats:**

| Category | Extensions                   |
| -------- | ---------------------------- |
| JSON     | `.json`, `.jsonl`, `.ndjson` |
| Config   | `.yaml`, `.yml`, `.toml`     |
| Tabular  | `.csv`, `.tsv`, `.xml`       |
| Text     | `.txt`, `.md`, `.rst`        |

Matching is case-insensitive. Query strings (`?foo=bar`) and fragments (`#section`) are stripped before the extension check. `.html` and `.svg` are intentionally excluded — both can carry embedded scripts.

The exemption applies only to the _unversioned-URL_ rules. `/latest/` URLs, pipe-to-shell, and `gh release download` without a tag still fire regardless of extension, because the risk there is about the _path_ being mutable, not about what the bytes decode to.

The list can be extended via `extra-data-formats` in [`.pinprick.toml`](/configuration/config-file#extra-data-formats) to add project-specific extensions (e.g., `.proto`, `.graphql`).

## Trusted hosts exemption

Unversioned-URL rules are downgraded to allowed matches when the URL host matches an entry in the user's [`trusted-hosts`](/configuration/config-file#trusted-hosts) list. Configured via `.pinprick.toml`:

```toml
trusted-hosts = ["artifacts.example.com"]
```

Matching is exact hostname, case-insensitive. `example.com` does _not_ trust `api.example.com` — each subdomain must be listed separately. Port numbers and paths are stripped before comparison.

The exemption applies only to the _unversioned-URL_ rules — the same scope as the data-format exemption. It does **not** cover:

- `/latest/` URLs — the risk is the path being mutable, regardless of who's serving it.
- Pipe-to-shell — the piped payload is never written to disk, so host trust doesn't change the safety profile.
- `gh release download` without a pinned tag.
- Package manager installs (`pip install foo`, `npm install foo`) — those go through package registries, not the HTTP host.

## Suppressing findings

When a finding is intentional and you want `pinprick audit` to stop flagging it, reach for the tightest mechanism that covers the case. Each mechanism lives in [`.pinprick.toml`](/configuration/config-file), is visible in code review, and applies across the whole repo.

There are two distinct outcomes to be aware of:

- **Allowed match** — the rule still matched, but the finding is recorded as allowed instead of emitted. Visible under `--verbose` with a reason, so a reviewer auditing the audit can still see what fired. Used by [`trusted-hosts`](#trusted-hosts), [`extra-data-formats`](#extra-data-formats), the [versioned-URL heuristic](#versioned-url-heuristic), the [data-format exemption](#data-format-exemption), and the [audited-actions list](/commands/audit#audited-actions-list).
- **Removed finding** — the finding is dropped from the report entirely and is not visible under `--verbose`. Used by [`ignore.patterns`](#ignorepatterns), [`ignore.actions`](#ignoreactions), and [`severity`](#severity-threshold).

Prefer _allowed match_ mechanisms when you can — they preserve the audit trail.

### `trusted-hosts`

Allowlist a URL host. Any `curl`/`wget`/`fetch` to that host becomes an allowed match instead of a finding.

```toml
trusted-hosts = ["artifacts.example.com"]
```

Use this when you operate an internal artifact server and control what lives at `https://artifacts.example.com/`. Covers the unversioned-URL rules for shell, JavaScript, Python, and Docker `ADD`. See [Trusted hosts exemption](#trusted-hosts-exemption) for what it does _not_ cover (pipe-to-shell, `/latest/` URLs, package-manager installs).

### `extra-data-formats`

Allowlist a file extension. Unversioned URL fetches ending in that extension become allowed matches.

```toml
extra-data-formats = ["proto", "graphql"]
```

Use this when you regularly fetch a schema, config, or data file format that isn't in [pinprick's built-in data-format list](#data-format-exemption). The fetched bytes have to be consumed as data, not executed — the exemption is wrong if you're fetching an `install.proto` that happens to be a shell script.

### `ignore.patterns`

Drop any finding whose description contains a given substring.

```toml
[ignore]
patterns = [
  "pip install without version pin",
]
```

Use this to silence a specific _rule_ across all actions. Matches by substring against the rule's description — so `"pip install"` silences the pip rule, `"unversioned URL"` silences every unversioned-URL rule. Findings matching a suppressed pattern are removed entirely, not visible under `--verbose`.

Prefer `extra-data-formats` or `trusted-hosts` when they fit — those keep the audit trail; this one doesn't.

### `ignore.actions`

Skip an action entirely. The action's source code is never fetched, never scanned, and never counted in the "audited" total — it shows up on its own as `ignored` in the per-line output and the summary.

```toml
[ignore]
actions = [
  "actions/checkout",
]
```

Matches by prefix against `owner/repo`, so `"actions/checkout"` matches every `actions/checkout@anything`. Use this when you've manually reviewed an action and decided it's out of scope — e.g. an action maintained by your own org that you already security-review separately. The blast radius is the entire action, so use sparingly.

### `severity` threshold

Raise the minimum severity that gets reported.

```toml
severity = "medium"
```

Accepts `"low"`, `"medium"`, or `"high"`. Findings below the threshold are removed from the report. Useful in CI when you want the audit to fail on real risks (high and medium) but not on hygiene issues (unpinned `pip install`, etc.). Not a targeted suppression — it silences _every_ finding below the bar.

### Why there's no inline comment syntax

pinprick deliberately does not read `# pinprick: ignore`-style inline comments. All suppression lives in `.pinprick.toml` so silencing is explicit, auditable in one place, and does not travel with copy-pasted code from another repo. If a specific line in a workflow needs to bypass a finding, your options are:

1. Rewrite the line to avoid the pattern (pin the URL to a version, add a checksum check, etc.).
2. Add a targeted allowlist entry in `.pinprick.toml` using the mechanisms above.
3. Raise the `severity` threshold if the finding is structurally low-value.

The trade-off is intentional: a little more friction for the edge case, in exchange for no per-line escape hatch that a malicious or careless commit could hide in a workflow.
