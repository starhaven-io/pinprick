# Agent Instructions for pinprick

pinprick is a CLI tool for GitHub Actions supply chain security. It pins action references to full SHAs, checks for updates, and audits pinned actions for runtime fetch patterns that bypass pinning (e.g., `curl ... latest`).

## Project overview

- **Language:** Rust (2024 edition)
- **Platform:** macOS, Linux
- **Architecture:** Single binary CLI with six subcommands (`audit`, `clean`, `completions`, `pin`, `score`, `update`)
- **License:** AGPL-3.0-only
- **Dependencies:** clap/clap_complete (CLI), tokio (async), reqwest (HTTP), serde/serde_norway (parsing), regex (pattern matching), colored (terminal output), toml (config parsing)

## Repository structure

```
pinprick/
├── Cargo.toml
├── build.rs                  # Embeds audited-actions/ into binary at compile time
├── src/
│   ├── main.rs              # Entry point, clap CLI definition, command dispatch
│   ├── audit.rs             # Audit command: scan workflows + action source for runtime fetches
│   ├── audit_patterns.rs    # Compiled regex patterns for shell/JS/Docker fetch detection
│   ├── audit_shell.rs       # Shell tokenizer + fetch-target extraction for the audit scanners
│   ├── audit_source.rs      # Action source selection and fetch (remote trees API, local ./ actions)
│   ├── audited_actions.rs   # Layered lookup: bundled → local cache → remote → GitHub API
│   ├── auth.rs              # GitHub token resolution (GITHUB_TOKEN/GH_TOKEN env → gh auth token fallback)
│   ├── config.rs            # TOML config file loading (.pinprick.toml, ~/.config/pinprick/)
│   ├── github.rs            # GitHub API client (tag→SHA, releases, file trees)
│   ├── output.rs            # Human-readable (colored) and --json output formatting
│   ├── pin.rs               # Pin command: resolve tags to SHAs, rewrite files
│   ├── score.rs             # Score command: compute a posture grade per docs/scoring.md
│   ├── update.rs            # Update command: check pinned actions for newer releases
│   └── workflow.rs           # Regex-based uses: line scanning, ActionRef types
├── audited-actions/          # Pre-audited action SHAs (bundled into binary)
├── docs/                     # Specs (scoring rubric, etc.) — source of truth for behaviors
├── scripts/                  # Helper scripts (release notes formatting)
├── site/                     # Astro Starlight docs site (pinprick.rs)
├── justfile                  # Task runner (build, test, lint, check)
├── rustfmt.toml              # Rustfmt configuration (2024 style edition)
├── .github/
│   ├── workflows/           # CI, CodeQL, zizmor, release, deploy-site, pinprick-audit, audit-actions
│   ├── dependabot.yml       # Dependabot for GitHub Actions, Cargo, and npm
│   └── FUNDING.yml
└── .gitignore
```

## Project-specific notes

### Commands

- `pinprick pin [PATH] [--write]` — Scan workflow files, resolve action tag refs to full SHAs via GitHub API. Dry-run by default (exits 1 when there are unpinned actions). `--write` rewrites files with `@sha # tag` format. Skips already-pinned (SHA) refs. Warns on branch refs (`@main`) and sliding tags (`@v4`), resolving sliding tags to exact versions.
- `pinprick update [PATH] [--write] [--only PATTERN]` — Check SHA-pinned actions for newer releases. Dry-run by default, `--write` to apply changes. `--only` restricts the check to actions whose `owner/repo` contains the given substring.
- `pinprick audit [PATH] [--verbose] [--sarif]` — Scan for runtime fetch patterns that bypass pinning. Without a GitHub token, scans local `run:` blocks and local actions referenced with `uses: ./...`. With a token, also fetches and scans remote action source code (JS/TS, Python, Dockerfiles, action.yml). `--verbose` shows allowed matches. `--sarif` outputs SARIF 2.1.0 for GitHub code scanning.
- `pinprick score [PATH] [--html]` — Compute a supply-chain posture score (0–100, letter grade A–F) for a repository's workflows. Implements the public rubric in `docs/scoring.md` (rubric v0.9.0). The offline rules (`pin.*`, `workflow.*`, `runtime.*`) need no token; with a token it additionally emits the token-gated `source.archived` and `source.advisory` rules. `runtime.*` rules reuse the `audit` shell pipeline against each workflow's `run:` blocks, distinguishing pipe-to-shell (-20) from severity-graded fetches (-15/-8/-3). Exits 1 when any finding deducts points (matches `audit` for CI gating); outputs JSON with `--json` or a self-contained HTML report with `--html` (mutually exclusive with `--json`).
- `pinprick clean` — Remove locally cached audit results (`~/.cache/pinprick/audited/`).
- `pinprick completions <SHELL>` — Generate shell completions for bash, zsh, fish, etc.

### Global flags

- `--json` — Output as JSON for CI integration
- `--color auto|always|never` — Control color output
- `--version` / `-V` — Print version

### YAML handling

**Critical design decision:** workflow files are never round-tripped through a YAML parser for writing. `uses:` lines have a rigid single-line format — regex capture groups replace the ref while preserving leading whitespace, indentation, and surrounding comments. `serde_norway` is only used for read-only extraction of `run:` block contents during audit.

That read-only `run:` extraction (`extract_run_blocks` for workflows and `scan_action_yml_runs` for composite actions) recurses into `parallel:` step groups. GitHub's parallel-steps feature models a `parallel:` step as a sequence of nested steps, so `run:` blocks inside a parallel group (including `parallel:` nested in `parallel:`) are scanned by both `audit` and `score`. A `background:`/`wait:`/`cancel:` step carries no nested `run:` and needs no special handling; line anchoring still walks blocks in document order.

### Workflow discovery

`workflow::find_workflows` scans every forge root in `DEFAULT_FORGE_ROOTS` (`.github`, `.forgejo`, `.gitea`) for a `workflows/` subdirectory. Forgejo and Gitea use GitHub-compatible workflow syntax. Discovery is **purely additive**: each root that exists is scanned and the files are unioned, so extra roots only widen coverage. The list is a compile-time constant and is deliberately *not* configurable via `.pinprick.toml`: a scanned repo (which may be hostile, hence `--no-repo-config`) must never be able to redirect the scan to a decoy directory while real workflows hide in `.github/workflows`. Every root goes through the same symlink-refusing `open_child_dir` path, so a symlinked forge root is refused, never followed. GitLab is out of scope: `.gitlab-ci.yml` is a single file with a different schema and no `uses:` references.

**Support tiers.** GitHub Actions is the first-class, fully supported target. Forgejo/Gitea support is incidental to GHA compatibility and best-effort: don't intentionally break it, but don't constrain a GitHub Actions improvement to preserve forge behavior either. When the two conflict, GHA wins. (Example: tag/release resolution is hardcoded to the github.com API, so `pin`/`update` only resolve github.com-hosted actions; that's an accepted limitation, not a bug to fix at GHA's expense.)

### GitHub auth

1. `GITHUB_TOKEN` environment variable (checked first)
2. `GH_TOKEN` environment variable (the variable the `gh` CLI itself honors)
3. `gh auth token` CLI fallback
4. Graceful degradation: `pin` and `update` require a token; `audit` works without one (reduced coverage)

Rate-limit handling: `github::get` retries once on network/5xx errors and sleeps through `x-ratelimit-reset` when the reset is within 60 s; longer waits bail with `RateLimit`.

### Configuration

A `.pinprick.toml` at the repo root (or `~/.config/pinprick/config.toml`) customizes behavior. Keys are all optional: `severity`, `fetch-remote`, `trusted-hosts`, `extra-data-formats`, `ignore.actions`, `ignore.patterns`. Per-repo wholly overrides global (no field-level merge). Because the scanned repo's own config applies, `audit`/`score` print a stderr notice whenever a repo-local config suppressed findings or extended runtime/data-format trust, and accept `--no-repo-config` to ignore the repo's file (for scanning repositories you don't control).

### Audit patterns

Six categories of runtime fetch detection:
- **Pipe-to-shell:** `curl`/`wget` piped into `sh`/`bash`/`python`, `bash <(curl …)` process substitution, `bash -c "$(curl …)"` / `eval "$(…)"` command substitution, PowerShell `iex (iwr …)` / `Invoke-Expression (… DownloadString …)`. Flagged high severity regardless of URL versioning.
- **Shell:** `curl`/`wget`/`gh release download` with unversioned URLs, non-literal `curl`/`wget` executable outputs, `deno run`/`install` from unversioned URLs, `git clone` without a pinned ref, `go install @latest`, unpinned `pip`/`pipx`/`npm`/`npx`/`cargo install`/`gem install`/`uv tool install`/`uvx` installs
- **PowerShell:** `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm`, `Start-BitsTransfer`, and `WebClient.DownloadFile` with unversioned URLs
- **JavaScript:** `fetch()`/`axios`/`got`/`http.get` with unversioned URLs, `exec()`/`child_process` shelling out to curl
- **Python:** `urllib.request.urlopen`/`requests.get` with unversioned URLs, `subprocess` shelling out to curl/wget
- **Docker:** `docker pull`/`docker run` with literal images using `:latest` or no tag in shell run blocks, `FROM :latest` or no tag, `curl`/`wget` in `RUN` instructions (escalated to high when piped to a shell), `ADD` with an `http(s)://` URL source (subject to versioning + data-format exemption via the URL-check path)

Pipe-to-shell pre-empts the other shell/Docker patterns so each line emits a single finding. It also reuses the existing `ShellFetch` SARIF category/rule id to keep downstream configs stable.

URL "versioned" heuristic: a URL is considered versioned if any path segment matches `v?\d+(\.\d+)+`; Deno-style `@v1.2.3` path pins count.

Data-format exemption: unversioned-URL rules (shell, JS, Python) do **not** fire when the URL's path ends in a data-format extension (`.json`/`.jsonl`/`.ndjson`, `.yaml`/`.yml`/`.toml`, `.csv`/`.tsv`/`.xml`, `.txt`/`.md`/`.rst`). Matches are recorded as allowed (visible under `--verbose`) with reason `data format URL`. Applies only to the unversioned-URL rules — `/latest/` URLs, pipe-to-shell, and `gh release download` without a tag still fire regardless of extension. `.html` and `.svg` are intentionally excluded because both can carry embedded scripts.

Piped-to-jq exemption: an unversioned-URL fetch whose line pipes into `jq` is recorded as allowed with reason `piped to jq` — the same data-not-code rationale as the data-format exemption, but for JSON API endpoints that carry no file extension (e.g. `curl …/api/v1/crates/<x> | jq …`). The `jq\b` match keeps `jqfoo` from qualifying. Pipe-to-shell matches and pre-empts the URL rules, so `curl … | jq … | bash` is flagged high, never exempted.

Checksum verification: findings followed within 3 lines by `sha256sum`, `shasum`, `openssl dgst`, `gpg --verify`, or `Get-FileHash` are suppressed only when the command performs an actual check or signature verification, does not mask failure with `||`, and names every downloaded target, a target-specific sidecar such as `tool.sha256`, or an inline manifest piped to the verifier. Merely calculating a hash, checking an unrelated file, or using a generic manifest whose contents cannot be inspected does not suppress the finding. Verified matches are recorded as allowed (visible under `--verbose`). Pipe-to-shell findings are exempt — the piped payload is never written to disk, so a nearby checksum command cannot verify it.

Git clone ref pinning: `git clone` without `--branch`/`-b` or with a branch name (main, develop, feature/foo) is flagged medium severity. `--branch v1.2.3` (version-like ref) suppresses the finding. A `git checkout <40-char-SHA>` within 3 lines fully suppresses the finding (recorded as allowed, visible under `--verbose`), since the SHA checkout deterministically pins the repo content.

### Exit codes

- `0` — clean (no findings, no pending updates)
- `1` — findings present (audit) or updates available (update dry-run)
- `2` — error

### CI workflows (`.github/workflows/`)

- **audit-actions.yml** — Weekly scan of tracked actions for new releases, automated PRs for clean entries
- **bump-cargo-tools.yml** — Weekly check for newer versions of the cargo-installed CI lint tools (typos, cargo-deny, cargo-nextest, cargo-llvm-cov); opens a PR bumping the pins in ci.yml
- **ci.yml** — Dynamic PR checks: conventional commits, clippy + rustfmt + typos, cargo test, coverage, site format + build, audited-actions verification, and a separate zizmor job with `security-events: write`
- **codeql.yml** — CodeQL security analysis (actions queries) on push to main
- **deploy-site.yml** — Build and deploy Astro site to Cloudflare Workers
- **link-check.yml** — Weekly lychee broken-link check across the built site and README
- **pinprick-audit.yml** — Run pinprick audit on its own workflows with SARIF upload
- **release.yml** — Manual dispatch: dry-run crate publishing, build cross-platform binaries (linux-amd64 and linux-arm64, each in glibc and static musl variants, plus darwin-arm64), create GitHub release with build provenance attestations, publish the crate to crates.io, open a pinprick-action default-version bump PR, and bump the Homebrew cask (glibc/macOS only)
- **zizmor.yml** — GitHub Actions security audit on push to main

## Safety / do-not-touch rules

1. Do not round-trip workflow files through a YAML parser when writing pins or
   updates; preserve the single-line `uses:` replacement model.
2. Keep repo-local config suppressions visible on stderr, and preserve
   `--no-repo-config` for scanning repositories the caller does not control.
3. Treat remote action source as untrusted input. Audit may inspect fetched
   JavaScript, Python, Docker, and action metadata, but it must not execute
   fetched action code.
4. Keep SARIF rule IDs stable when refining detections so downstream code
   scanning configuration keeps working.

## Required checks

`rust-toolchain.toml` pins CI and rustup-based workstations to the reviewed
stable toolchain. Homebrew's standalone Rust does not honor that file, so verify
`rustc --version` matches its `channel` before running the required checks.

- `cargo clippy` with zero warnings
- `cargo fmt` for formatting
- No unnecessary abstractions — flat module structure, no nested directories
- `thiserror` for typed errors in library code, `anyhow` for context-rich error propagation in commands
- `LazyLock` for compiled regex constants

<!-- fleet:block commit-and-pr-conventions -->

## Commit and PR conventions

- Conventional Commits: `type(scope): description`. Valid types: `feat`,
  `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.
- Sign off every commit with `git commit -s` for DCO (enforced by the
  `.githooks/commit-msg` hook; run `just install-hooks` once per clone to
  enable it).
- When authored with an AI coding agent, add a `Co-authored-by` trailer before
  `Signed-off-by` (git-native order: `git commit -s` appends the sign-off last),
  naming the agent and model. Current example:
  `Co-authored-by: Claude Opus 4.8 <noreply@anthropic.com>`. Bump the model
  version as newer ones ship.
- Never commit directly to `main`; create a feature branch and open a PR.
- PR descriptions should contain only a concise summary of changes. Do not add
  test-plan sections, bot attribution, or generated-with footers.
- Keep each prose paragraph in a PR description on one source line. Do not
  hard-wrap PR body prose like a commit message; preserve intentional Markdown
  line breaks in lists, code blocks, and other structured content.
- Comments must earn their keep: a comment states a constraint or rationale the
  code cannot express. Never add comments that narrate what the code does,
  restate names, or explain a change to its reviewer.

<!-- fleet:end -->
