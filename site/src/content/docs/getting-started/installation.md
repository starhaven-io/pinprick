---
title: Installation
description: How to install pinprick.
---

## Homebrew

```bash
brew install starhaven-io/tap/pinprick
```

## crates.io

```bash
cargo install pinprick
```

## From source (unreleased HEAD)

```bash
cargo install --git https://github.com/starhaven-io/pinprick
```

## From releases

Download a prebuilt binary from [GitHub Releases](https://github.com/starhaven-io/pinprick/releases). Binaries are available for:

- Linux (amd64)
- Linux (arm64)
- macOS (Apple Silicon)

## Shell completions

Generate completions for your shell:

```bash
pinprick completions zsh > ~/.zfunc/_pinprick
pinprick completions bash > /etc/bash_completion.d/pinprick
pinprick completions fish > ~/.config/fish/completions/pinprick.fish
```

## GitHub authentication

pinprick uses the GitHub API to resolve tags, check releases, and fetch action source code.

It looks for a token in this order:

1. `GITHUB_TOKEN` environment variable
2. `gh auth token` CLI fallback

The `pin` and `update` commands require a token. The `audit` command works without one but with reduced coverage — only local `run:` blocks are scanned.
