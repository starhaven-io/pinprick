# Agent Instructions for pinprick

Pinprick is a Rust CLI for GitHub Actions supply-chain pinning, updates, runtime-fetch auditing, and posture scoring. `site/` contains its Astro Starlight documentation and signed catalog endpoints. GitHub Actions is the supported target; Forgejo/Gitea workflow discovery is additive, best-effort compatibility. API resolution remains github.com-only.

## Sources of truth

- `src/main.rs` defines command flags and dispatch. Public command/configuration documentation lives in `site/src/content/docs/`.
- `src/workflow.rs` owns workflow discovery, read-only YAML extraction, and format-preserving pin edits; `pin.rs` and `update.rs` resolve their API results before writing.
- `src/audit.rs`, `audit_patterns.rs`, `audit_shell.rs`, and `audit_source.rs` own bounded source traversal and detection. `site/src/content/docs/reference/detections.md` documents the rules and heuristic limits.
- `src/audited_actions.rs` and `build.rs` own catalog lookup, verification, caching, and embedding. `audited-actions/README.md` defines exact action identities; `SECURITY.md` covers signing custody and rotation.
- `src/score.rs` implements the versioned public contract in `docs/scoring.md`.
- `src/config.rs`, `auth.rs`, `github.rs`, and `output.rs` own configuration, token resolution, API transport, and output boundaries.
- `Cargo.toml`, `Cargo.lock`, and `rust-toolchain.toml` define Rust requirements. `site/package.json`, its lockfile, and Wrangler config define the independent site root.

## Behavioral boundaries

1. Never execute fetched action code. Remote JavaScript, Python, shell, Dockerfiles, and metadata are untrusted inputs to static analysis.
2. Never round-trip workflow files through a YAML serializer for writes. Rewrite supported block-style, single-line `uses:` values while preserving comments and formatting. Unsupported syntax and required resolution failures block all pending pin/update writes. Best-effort tag comments and manual branch/container skips are separate; per-file write failures are not a cross-file transaction.
3. Scan every supported forge root. Repository configuration must not redirect discovery. Preserve directory-handle containment and symlink refusal for local reads and writes.
4. Keep action identities exact: a root action verdict does not cover subpaths or siblings. Local cache verdicts require the current scanner version and default runtime trust policy; configured host/data exemptions must not become reusable default-policy verdicts.
5. Repository config wholly replaces global config. Keep effective suppressions visible and preserve `--no-repo-config`. Canonical catalog verification must also isolate global config and disable all catalog reuse.
6. Incomplete audit coverage exits 2 in every output format. Score completeness is independent of deductions and must remain visible in human, JSON, HTML, and badge output. Retain findings already collected when a later API request fails.
7. Keep SARIF rule IDs stable. Change rubric versions deliberately when adjusting scoring semantics; document the contract alongside implementation.
8. Preserve pipe-to-shell precedence and the distinction between a detected finding, a heuristic allowed match, and missing source coverage. A nearby checksum command qualifies only when its target and independently trusted verification material can be bound.

Prefer flat modules and direct control flow. Use `LazyLock` for compiled patterns, typed errors for transport, and contextual command errors. Comments should explain constraints or non-obvious rationale; keep command lists and detection details in their public documentation.

## Local checks

Read the complete `justfile` before changing gates. Use focused tests while iterating, then run `just check` once the change is stable. It covers Rust clippy/format/tests, typos, dependency policy, workflow security analysis, and site format/build/deployment dry-run. Run `git diff --check` before handoff. A missing tool or failed gate is unverified, not a pass.

`rust-toolchain.toml` pins the reviewed Rust toolchain. Homebrew's standalone Rust does not honor it, so compare `rustc --version` with `channel`. Install site dependencies with `npm ci --strict-allow-scripts`; preserve package-level allowScripts decisions. Use local mocks for API regressions. No live catalog refresh, release, or deployment is implied by a code review.

## Ownership and release operation

Fleet-managed files, fenced blocks, and first-party reusable-workflow pins belong to `../dot_github/fleet`; never hand-edit consumer copies. Keep the always-reporting `conclusion` CI job. Repo-owned workflow orchestration stays here.

`release.yml` is a trusted-main manual workflow. It embeds the checked-in catalog, validates crate packaging, builds supported macOS/Linux artifacts, verifies macOS signing/notarization, attaches build provenance, publishes the crate, and opens distribution updates. `pinprick-action` is the separate released adapter: the engine release must open its bot-authored version bump with the existing action/README count assertions. Review and merge that bump to trigger the adapter release; never manually update those version references. The fleet consumes the released adapter, and the Homebrew cask bump must merge separately.

`deploy-site.yml` separates unprivileged build, canonical-byte validation/signing, and deployment. Preserve that credential boundary. Weekly catalog verification and cargo-deny workflows retain failures as tracking issues. Local tests do not prove hosted environment protections, signing credentials, Linux execution, or publication readiness.

<!-- fleet:block commit-and-pr-conventions -->

## Commit and PR conventions

- Conventional Commits: `type(scope): description`. Valid types: `feat`,
  `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.
  Mark a breaking change with `!` before the colon (`feat!:`,
  `feat(scope)!:`).
- Commits require DCO sign-off. Make all commits with `git commit -s` (enforced
  by the `.githooks/commit-msg` hook; run `just install-hooks` once per clone).
- Do not identify an AI tool or model as an author, co-author, committer, or
  signatory of a commit. Do not name an AI tool or model in `Co-authored-by`,
  `Assisted-by`, `Co-developed-by`, `Generated-by`, or similar trailers. Human
  `Co-authored-by` trailers are allowed.
- Never commit directly to `main`; create a feature branch and open a PR.
- PR descriptions should contain a concise summary of changes. Do not add a
  standalone test-plan section or checklists.
- When AI/LLM was used to generate or assist with a pull request, the initial
  PR description must end with exactly one unformatted line as the last line of
  the PR body: `AI disclosure: <model> with <how the output was verified>.`
  This is PR body text, not a commit trailer. Omit the line when no AI/LLM was
  used.
- Name the model as its vendor names it, for example `Claude Opus 5`. Do not
  also name a tool or harness unless the harness is the only identifier. Do not
  describe what the AI did.
- Do not format the disclosure as a heading, bullet, bold label, or horizontal
  rule, and do not add a promotional "generated with" footer.
- Keep each prose paragraph in a PR description on one source line. Do not
  hard-wrap PR body prose like a commit message; preserve intentional Markdown
  line breaks in lists, code blocks, and other structured content.
- Comments must earn their keep: a comment states a constraint or rationale the
  code cannot express. Never add comments that narrate what the code does,
  restate names, or explain a change to its reviewer.

<!-- fleet:end -->
