---
title: Config File
description: Configure pinprick behavior with .pinprick.toml.
---

pinprick reads configuration from TOML files in two locations:

1. **Global** — `~/.config/pinprick/config.toml`
2. **Per-repo** — `.pinprick.toml` in the repository root

Per-repo config overrides global config. Both are optional — pinprick uses sensible defaults.

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

### `ignore.actions`

Skip scanning specific actions entirely. Useful for actions you've reviewed manually or that produce known false positives. Matches by prefix — `"actions/checkout"` matches `actions/checkout` at any SHA.

### `ignore.patterns`

Suppress individual findings by description substring. Useful for silencing specific pattern types across all actions.
