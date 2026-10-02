---
title: Config File
description: Configure pinprick behavior with .pinprick.toml.
---

pinprick reads configuration from TOML files in two locations:

1. **Global** — `$XDG_CONFIG_HOME/pinprick/config.toml` (default `~/.config/pinprick/config.toml`)
2. **Per-repo** — `.pinprick.toml` in the repository root

Per-repo config overrides global config as a whole file; fields are not merged. Both are optional — pinprick uses sensible defaults.

## Options

```toml
# Fetch audited-actions list from pinprick.rs (default: false)
fetch-remote = true

# Minimum severity to report: "low", "medium", or "high" (default: "low")
severity = "medium"

# Additional file extensions to treat as data formats, beyond the built-in set
# (see the Detections reference for the full built-in list). Case-insensitive;
# leading dots are optional.
extra-data-formats = ["proto", "graphql"]

# Hostnames to treat as trusted sources for unversioned fetches. A fetch whose
# URL host exactly matches an entry is downgraded from a finding to an allowed
# match. Case-insensitive.
trusted-hosts = ["artifacts.example.com"]

# Suppress specific findings
[ignore]
# Skip audit for these actions entirely
actions = [
  "actions/checkout",
]

# Suppress findings whose description contains these strings
patterns = [
  "pip install without version pin",
]
```

### `fetch-remote`

When enabled, pinprick fetches the community audited-actions list from `pinprick.rs` for actions not found in the bundled or local cache. This is off by default to minimize network calls.

### `severity`

Filter findings by minimum severity. Set to `"medium"` to hide low-severity findings like unpinned `pip install`, or `"high"` to only see the most critical patterns.

### `extra-data-formats`

A list of file extensions to append to pinprick's built-in [data-format exemption](/reference/detections#data-format-exemption) set. Useful if you regularly fetch protocol schemas (`.proto`, `.graphql`), infrastructure definitions (`.tf`, `.hcl`), or any other non-executable asset format that's not in the default list.

```toml
extra-data-formats = ["proto", "graphql", "tf", "hcl"]
```

Matching is case-insensitive. Leading dots are stripped (`".proto"` and `"proto"` behave identically). The configured extensions are _added_ to the built-in set, not replacing it.

### `trusted-hosts`

A list of hostnames that are trusted sources for unversioned fetches. Any fetch whose URL host exactly matches an entry is recorded as an allowed match (visible under `--verbose`) with reason `trusted host` instead of being emitted as a finding.

```toml
trusted-hosts = [
  "artifacts.example.com",
  "releases.internal.example.org",
]
```

**Matching is exact and case-insensitive.** `example.com` does _not_ trust `api.example.com` — each subdomain must be listed separately. This is deliberate: suffix-matching `example.com` would implicitly trust any subdomain including ones that don't exist yet, which is an easy way to accidentally widen the trust boundary.

**Scope.** `trusted-hosts` exempts the same rules as the [data-format exemption](/reference/detections#data-format-exemption): unversioned-URL rules only. It does **not** suppress:

- `/latest/` URL findings — the risk is about the path being mutable, regardless of who's serving it
- Pipe-to-shell findings — the risk is that the payload is never written to disk, regardless of trust
- `gh release download` without a pinned tag
- Package manager installs (`pip install foo`, `npm install foo`) — those are package registries, not HTTP hosts

To suppress a specific pattern that `trusted-hosts` doesn't cover, use [`ignore.patterns`](#ignorepatterns) instead.

### `accept-workflow-findings`

Accept a reviewed finding in a local workflow without skipping source coverage or hiding other findings. Each entry matches the exact repository-relative workflow path, SHA-256 of the complete workflow bytes, category, severity, description, and logical command from `pinprick audit --json`. A nonempty reason is required. Wildcards and substring matching are not supported.

```toml
[[accept-workflow-findings]]
workflow = ".github/workflows/scan.yml"
workflow-sha256 = "<SHA-256 of the reviewed workflow>"
category = "shell_fetch"
severity = "low"
description = "<exact finding description>"
command = '<exact pattern_matched from the audit JSON>'
reason = "<owner, justification, compensating controls, and review conditions>"
```

Only repository-local configuration can accept workflow findings. Entries do not apply to remote or local action findings (see [`accept-action-findings`](#accept-action-findings) for remote actions), do not skip any source reads, and do not make incomplete coverage successful. Any workflow byte change invalidates its acceptances; review the changed workflow before updating its hash. An invalid or stale entry accepts nothing. Use `shasum -a 256 .github/workflows/scan.yml` to compute the hash after review.

Accepted findings and their reasons remain visible in ordinary human output and the JSON `accepted` array. SARIF excludes accepted findings from its results so they do not become GitHub code-scanning alerts; GitHub's [supported SARIF properties](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support#result-object) do not include result suppressions. The audit exits zero only when coverage is complete and no unaccepted findings remain. `--no-repo-config` restores the findings, including in SARIF. Acceptance changes audit policy only: it does not improve posture scores or create reusable clean action catalog verdicts.

### `accept-action-findings`

Accept a reviewed finding in a remote action's source without skipping that action or hiding its other findings. Each entry matches the action's exact `owner/repo[/subpath]`, the file's path in that repository (shown in parentheses in the finding's `source_file`), and the finding's category, severity, description, and logical command from `pinprick audit --json`. Owner and repository names match case-insensitively; paths match exactly. A nonempty reason is required. Wildcards and substring matching are not supported.

```toml
[[accept-action-findings]]
action = "Homebrew/actions/setup-homebrew"
path = "setup-homebrew/main.sh"
category = "shell_fetch"
severity = "high"
description = "<exact finding description>"
command = '<exact pattern_matched from the audit JSON>'
reason = "<owner, justification, compensating controls, and review conditions>"
```

An entry applies at any revision of the action, so a release that keeps the reviewed line stays accepted, while a changed command, file, or finding is reported again. Each entry accepts one occurrence per revision, so a release that repeats the reviewed command reports the copy. Every other finding in the action is still reported, and an incomplete scan still fails. Only repository-local configuration can accept action findings, and entries never apply to local actions, whose source the repository controls. Accepted action findings appear with the accepted workflow findings, without a workflow hash, and an action with an accepted finding never receives a cached clean verdict.

### `ignore.actions`

Skip scanning specific actions entirely. Useful for actions you've reviewed manually or that produce known false positives. Entries match an action's `owner/repo`, case-insensitively and at path boundaries: `"actions/checkout"` skips every action in that repository at any SHA, while `"actions"` or `"actions/"` skips the owner. Partial repository names and subpaths do not match; to accept one finding in a subpath action, use [`accept-action-findings`](#accept-action-findings).

### `ignore.patterns`

Suppress individual findings by description substring. Useful for silencing specific pattern types across all actions. Empty entries match nothing.
