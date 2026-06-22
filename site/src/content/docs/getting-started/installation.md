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

- Linux amd64, glibc — `x86_64-unknown-linux-gnu`
- Linux arm64, glibc — `aarch64-unknown-linux-gnu`
- Linux amd64, musl (static) — `x86_64-unknown-linux-musl`
- Linux arm64, musl (static) — `aarch64-unknown-linux-musl`
- macOS Apple Silicon — `aarch64-apple-darwin`

The `gnu` builds link against the system glibc and suit most mainstream distributions (Debian, Ubuntu, Fedora, …). The `musl` builds are statically linked and run on musl-based distributions such as Alpine, as well as minimal or distroless containers.

:::note[musl binaries still need CA certificates]
The musl binaries are statically linked, but pinprick makes HTTPS calls to the GitHub API and reads the host's trusted CA certificates at runtime. On Alpine, install them with `apk add ca-certificates`.
:::

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
