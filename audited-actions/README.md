# Audited Actions

This directory contains GitHub Actions that have been scanned by `pinprick audit` and returned zero findings at the listed SHAs.

## What "audited" means

Each SHA was scanned for runtime fetch patterns covered by the current pinprick rules. The scan includes composite action steps, declared JavaScript and Python entrypoints, reachable container Dockerfiles, and non-vendored shell and PowerShell helpers. Specifically, pinprick checks:

**Shell** (in `run:` blocks and `action.yml` composite steps):
- `curl`/`wget` fetching from `/latest/` URLs
- `curl`/`wget` fetching URLs with no version segment (e.g., `v1.2.3`)
- `gh release download` without a pinned tag
- `go install @latest`
- unpinned package and tool installs, unpinned `git clone`, Deno URL execution, and mutable Docker CLI image pulls/runs

**PowerShell** (in `run:` blocks):
- `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` fetching from `/latest/` or unversioned URLs

**JavaScript** (in `.js`/`.ts` files, including minified bundles):
- `fetch()`/`axios`/`got`/`http.get` to `/latest/`, unversioned, or recognized unresolved dynamic URLs
- `exec()`/`child_process` shelling out to `curl`/`wget`

Literal URLs, including simple identifier bindings, still scan minified and generated bundles. Only the conservative unresolved-variable sink rule is limited to authored source because generic dynamic networking calls in bundled dependencies are not actionable evidence of an unpinned runtime fetch. Generated bundles are recognized from conventional `dist/` paths, `.min.js` names, and narrow bundler-runtime markers.

**Python** (in `.py` files):
- `urllib.request.urlopen`/`requests.get` to `/latest/` or unversioned URLs
- `subprocess` shelling out to `curl`/`wget`, including recognized unresolved dynamic URL sinks

**Docker** (in Dockerfiles):
- mutable `runs.image` registry references, `FROM image:latest` or untagged `FROM`
- `curl`/`wget` in `RUN` instructions and remote `ADD` sources

## What "audited" does NOT mean

This is not a full security review. An action listed here may still:

- Fetch resources through dataflow too complex for pinprick's bounded literal propagation; recognized unresolved sinks are reported conservatively
- Execute code from inputs or environment variables
- Have vulnerabilities unrelated to runtime fetching (template injection, credential leaks, etc.)
- Contain patterns in languages pinprick does not scan (Ruby, Go)

For static analysis of workflow files themselves — permissions, template injection, credential handling — use [zizmor](https://github.com/zizmorcore/zizmor).

## File format

Each file is named for the exact action identity and contains an array of audited SHAs with their corresponding tags: `owner/repo.json` for a root action and `owner/repo/subpath.json` for a subpath action. A root-action verdict never covers a subpath action at the same commit.

```json
[{ "sha": "de0fac2e4500dabe0009e67214ff5f5447ce83dd", "tag": "v6.0.2", "rules_version": 1 }]
```

`rules_version` records the detection semantics that produced that entry's clean verdict. It is earned from the current scanner's JSON report, not chosen manually. It changes only when detection or suppression semantics could invalidate existing verdicts, independently of the pinprick release version.

## Trust model

These files reach users two ways with different trust anchors:

- **Bundled**: compiled into the pinprick binary at build time — same trust as the binary itself (which ships with build provenance attestations). The build rejects unstamped source entries, and the running binary honors only entries stamped with its current detection-rules version.
- **Remote** (`https://pinprick.rs/audited-actions/`, opt-in): each served file is signed with [minisign](https://jedisct1.github.io/minisign/) during deploy, and the binary verifies the signature against a public key (`catalog-minisign.pub` at the repo root) embedded at build time. The authenticated trusted comment binds the exact action key and signing timestamp. Verification is fail-closed: a missing, invalid, identity-mismatched, timestamp-less, stale (signed more than 30 days ago), future-dated (more than 10 minutes ahead), unstamped, or rules-version-mismatched entry is ignored and the action is scanned normally. TLS alone is deliberately not trusted — a catalog entry suppresses scanning, so a compromised CDN must not be able to forge one, relocate it to another action, replay a superseded one indefinitely, or reuse a verdict issued under obsolete detection semantics.

See [SECURITY.md](../SECURITY.md) for key custody and rotation.

## Contributing

To add a new entry:

1. Run `just add-action owner/repo` from a Pinprick checkout (include the subpath when applicable).
2. The recipe resolves a full SHA and requires a fresh, complete scan with zero ignored actions under isolated default configuration. It stamps the entry with the detection-rules version reported by that scan.
3. Inspect the generated entry and build the current scanner with `cargo build --locked --release`, then run `scripts/verify-audited-actions.sh target/release/pinprick files <entry-file>` with a GitHub token.
4. Open a PR with the verification result.
