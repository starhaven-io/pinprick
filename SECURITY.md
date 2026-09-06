# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately by emailing
[security@pinprick.rs](mailto:security@pinprick.rs) or using
[GitHub's private vulnerability reporting](https://github.com/starhaven-io/pinprick/security/advisories/new).
Do not open a public issue for an undisclosed vulnerability.

Include the affected component, version, or commit; reproduction steps; potential
impact; and any suggested mitigation. We will acknowledge the report,
investigate it, and coordinate disclosure with you.

Reports about unsafe runtime fetches performed by third-party GitHub Actions
should normally be sent to that action's maintainer; report them here when
pinprick fails to detect or accurately describe the behavior.

## Audited-actions catalog trust

pinprick ships a catalog of pre-audited action SHAs (`audited-actions/`)
whose clean verdicts suppress scanning. The catalog reaches users two ways,
with different trust anchors:

- **Bundled** — compiled into the binary at build time; trusted exactly as
  hard as the binary itself (releases carry build provenance attestations).
  Because a detection-rule improvement can invalidate a verdict recorded
  under older rules, CI re-verifies entries whenever the rules change and a
  scheduled workflow re-scans a rotating weekly shard until the full catalog
  has been covered (`scripts/verify-audited-actions.sh`).
- **Remote** (`https://pinprick.rs/audited-actions/`, opt-in via
  `fetch-remote = true`) — every served file is signed with
  [minisign](https://jedisct1.github.io/minisign/) during deploy, and the
  binary verifies the signature against the public key committed at
  `catalog-minisign.pub` and embedded at build time. Verification is
  fail-closed: an unsigned, tampered, legacy-format (non-prehashed),
  timestamp-less, or stale catalog is ignored with a warning and the action
  is scanned normally. Freshness is judged by minisign's signed `timestamp:`
  trusted comment — a catalog signed more than 30 days ago is rejected, so a
  compromised CDN cannot replay a superseded-but-validly-signed catalog
  indefinitely. Timestamps more than 10 minutes in the future are also
  rejected: legitimate runner and client clock drift is expected to stay
  within minutes, and a far-future timestamp would otherwise stay inside the
  staleness window until it plus 30 days — turning one signing-clock fault (or
  a compromised signer) into an extended replay horizon. TLS alone is
  deliberately not trusted.

### Signing key custody

The catalog signing key (`CATALOG_SIGNING_KEY`) must be stored as a
passwordless minisign secret key in the GitHub `cloudflare` environment.
Only `deploy-site.yml` reads it. Every build job is explicitly restricted to
`main`, including manual dispatches, and a weekly default-branch schedule
refreshes signatures before their 30-day expiry. Relevant pushes to `main`
also deploy immediately. The workflow writes a temporary runner copy and
removes it on step exit; maintainers must not retain additional copies. A
compromise of that workflow or environment is a catalog compromise. Signing the catalog offline
(committing `.minisig` files next to each JSON and serving them verbatim)
would take the key out of CI at the cost of maintainer friction on every
catalog change; that trade-off remains under consideration.

### Key rotation

To rotate the key (or respond to a suspected compromise):

1. Generate a new keypair: `minisign -G -p catalog-minisign.pub -s catalog.key -W`.
2. In a maintenance window, replace the `CATALOG_SIGNING_KEY` secret in the
   `cloudflare` environment with the new secret key.
3. Commit the matching `catalog-minisign.pub` and merge. That path triggers a
   deployment which re-signs every served catalog file and verifies a produced
   signature against the committed public key before publishing.
4. Confirm the deployment succeeded, then delete every local secret-key copy.
5. Cut a release. The public key is embedded at build time, so binaries built
   before the rotation reject the newly signed catalog — fail-closed: they
   warn and fall back to fresh scans until users upgrade.

A wrongly-vouched bundled entry follows the binary, not the site: removing
it from `audited-actions/` stops vouching in future builds and (within the
freshness window) in the remote layer, but already-shipped binaries keep
their bundled copy until upgraded.

## Supported versions

Only the latest released version of pinprick is supported with security fixes.
