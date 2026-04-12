# pinprick — Claude Project Context

pinprick is a CLI tool for GitHub Actions supply chain security. It pins action references to full SHAs, checks for updates, and audits pinned actions for runtime fetch patterns that bypass pinning (e.g., `curl ... latest`).

## Project overview

- **Language:** Rust (2024 edition)
- **Platform:** macOS, Linux
- **Architecture:** Single binary CLI with five subcommands (`audit`, `clean`, `completions`, `pin`, `update`)
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
│   ├── audited_actions.rs   # Layered lookup: bundled → local cache → remote → GitHub API
│   ├── auth.rs              # GitHub token resolution (GITHUB_TOKEN env → gh auth token fallback)
│   ├── config.rs            # TOML config file loading (.pinprick.toml, ~/.config/pinprick/)
│   ├── github.rs            # GitHub API client (tag→SHA, releases, file trees)
│   ├── output.rs            # Human-readable (colored) and --json output formatting
│   ├── pin.rs               # Pin command: resolve tags to SHAs, rewrite files
│   ├── update.rs            # Update command: check pinned actions for newer releases
│   └── workflow.rs           # Regex-based uses: line scanning, ActionRef types
├── audited-actions/          # Pre-audited action SHAs (bundled into binary)
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

## Architecture

### Commands

- `pinprick pin [PATH] [--write]` — Scan `.github/workflows/*.yml`, resolve action tag refs to full SHAs via GitHub API. Dry-run by default (exits 1 when there are unpinned actions). `--write` rewrites files with `@sha # tag` format. Skips already-pinned (SHA) refs. Warns on branch refs (`@main`) and sliding tags (`@v4`), resolving sliding tags to exact versions.
- `pinprick update [PATH] [--write] [--only PATTERN]` — Check SHA-pinned actions for newer releases. Dry-run by default, `--write` to apply changes. `--only` restricts the check to actions whose `owner/repo` contains the given substring.
- `pinprick audit [PATH] [--verbose] [--sarif]` — Scan for runtime fetch patterns that bypass pinning. Without a GitHub token, scans only local `run:` blocks. With a token, also fetches and scans action source code (JS/TS, Python, Dockerfiles, action.yml). `--verbose` shows allowed matches. `--sarif` outputs SARIF 2.1.0 for GitHub code scanning.
- `pinprick clean` — Remove locally cached audit results (`~/.cache/pinprick/audited/`).
- `pinprick completions <SHELL>` — Generate shell completions for bash, zsh, fish, etc.

### Global flags

- `--json` — Output as JSON for CI integration
- `--color auto|always|never` — Control color output
- `--version` / `-V` — Print version

### YAML handling

**Critical design decision:** workflow files are never round-tripped through a YAML parser for writing. `uses:` lines have a rigid single-line format — regex capture groups replace the ref while preserving leading whitespace, indentation, and surrounding comments. `serde_norway` is only used for read-only extraction of `run:` block contents during audit.

### GitHub auth

1. `GITHUB_TOKEN` environment variable (checked first)
2. `gh auth token` CLI fallback
3. Graceful degradation: `pin` and `update` require a token; `audit` works without one (reduced coverage)

### Audit patterns

Six categories of runtime fetch detection:
- **Pipe-to-shell:** `curl`/`wget` piped into `sh`/`bash`/`python`, `bash <(curl …)` process substitution, `bash -c "$(curl …)"` / `eval "$(…)"` command substitution, PowerShell `iex (iwr …)` / `Invoke-Expression (… DownloadString …)`. Flagged high severity regardless of URL versioning.
- **Shell:** `curl`/`wget`/`gh release download` with unversioned URLs, `go install @latest`, unpinned `pip`/`npm` installs
- **PowerShell:** `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm` with unversioned URLs
- **JavaScript:** `fetch()`/`axios`/`got`/`http.get` with unversioned URLs, `exec()`/`child_process` shelling out to curl
- **Python:** `urllib.request.urlopen`/`requests.get` with unversioned URLs, `subprocess` shelling out to curl/wget
- **Docker:** `FROM :latest` or no tag, `curl`/`wget` in `RUN` instructions (escalated to high when piped to a shell), `ADD` with an `http(s)://` URL source (subject to versioning + data-format exemption via the URL-check path)

Pipe-to-shell pre-empts the other shell/Docker patterns so each line emits a single finding. It also reuses the existing `ShellFetch` SARIF category/rule id to keep downstream configs stable.

URL "versioned" heuristic: a URL is considered versioned if any path segment matches `v?\d+(\.\d+)+`.

Data-format exemption: unversioned-URL rules (shell, JS, Python) do **not** fire when the URL's path ends in a data-format extension (`.json`/`.jsonl`/`.ndjson`, `.yaml`/`.yml`/`.toml`, `.csv`/`.tsv`/`.xml`, `.txt`/`.md`/`.rst`). Matches are recorded as allowed (visible under `--verbose`) with reason `data format URL`. Applies only to the unversioned-URL rules — `/latest/` URLs, pipe-to-shell, and `gh release download` without a tag still fire regardless of extension. `.html` and `.svg` are intentionally excluded because both can carry embedded scripts.

Checksum verification: findings followed within 3 lines by `sha256sum`, `shasum`, `openssl dgst`, `gpg --verify`, or `Get-FileHash` are downgraded one severity level. Pipe-to-shell findings are exempt — the piped payload is never written to disk, so a nearby checksum command cannot verify it.

### Exit codes

- `0` — clean (no findings, no pending updates)
- `1` — findings present (audit) or updates available (update dry-run)
- `2` — error

## Code style and conventions

- `cargo clippy` with zero warnings
- `cargo fmt` for formatting
- No unnecessary abstractions — flat module structure, no nested directories
- `thiserror` for typed errors in library code, `anyhow` for context-rich error propagation in commands
- `LazyLock` for compiled regex constants

## CI workflows (.github/workflows/)

- **audit-actions.yml** — Weekly scan of tracked actions for new releases, automated PRs for clean entries
- **ci.yml** — Dynamic matrix PR checks: conventional commits, clippy + rustfmt + typos, cargo test, site format + build, audited-actions verification, zizmor
- **codeql.yml** — CodeQL security analysis on push to main
- **deploy-site.yml** — Build and deploy Astro site to Cloudflare Workers
- **release.yml** — Manual dispatch: build cross-platform binaries (linux-amd64, linux-arm64, darwin-arm64), create GitHub release with build provenance attestations, publish the crate to crates.io
- **pinprick-audit.yml** — Run pinprick audit on its own workflows with SARIF upload
- **zizmor.yml** — GitHub Actions security audit on push to main

## Commit conventions

Conventional Commits format: `type(scope): description`

Common types: `feat`, `fix`, `refactor`, `docs`, `ci`, `chore`

All commits must:
- Use `git commit -s` for DCO sign-off
- Include a `Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>` trailer when authored with Claude

## Git workflow

- Never commit directly to main — always create a feature branch and open a PR
- PR descriptions should contain only a summary of the changes — no test plan sections, no bot attribution, no "Generated with Claude Code" footers
