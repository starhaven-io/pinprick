---
title: pinprick
description: GitHub Actions supply chain security. Pin actions to SHAs, audit them for runtime fetch patterns that bypass pinning, and score a repository's overall posture.
template: splash
editUrl: false
hero:
  title: GitHub Actions supply chain security
  tagline: SHA-pin your actions. Audit their source for runtime fetches that bypass pinning. Score the result.
  image:
    html: |
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="220" height="220" fill="none" aria-hidden="true">
        <circle cx="16" cy="8" r="5" fill="#dc2626"/>
        <line x1="16" y1="13" x2="16" y2="30" stroke="#dc2626" stroke-width="2.5" stroke-linecap="round"/>
        <line x1="16" y1="30" x2="14" y2="26" stroke="#dc2626" stroke-width="2" stroke-linecap="round"/>
        <line x1="16" y1="30" x2="18" y2="26" stroke="#dc2626" stroke-width="2" stroke-linecap="round"/>
      </svg>
  actions:
    - text: Get started
      link: /getting-started/introduction/
      icon: right-arrow
      variant: primary
    - text: View on GitHub
      link: https://github.com/starhaven-io/pinprick
      icon: external
      variant: minimal
---

## What it does

- **[`pin`](/commands/pin/)** — resolve action tag references (`actions/checkout@v4`) to full SHA-pinned references, preserving the tag as a comment.
- **[`update`](/commands/update/)** — check SHA-pinned actions for newer releases and update them.
- **[`audit`](/commands/audit/)** — scan workflow `run:` blocks and action source code for runtime fetch patterns that bypass pinning (shell, PowerShell, JavaScript, Python, Docker).
- **[`score`](/commands/score/)** — compute a single posture grade (0–100, A–F) against a [public, versioned rubric](https://github.com/starhaven-io/pinprick/blob/main/docs/scoring.md).

## Why

For static analysis of workflow files — template injection, excessive permissions, credential leaks — use [zizmor](https://github.com/zizmorcore/zizmor). It's excellent.

pinprick picks up where static analysis leaves off. SHA-pinning is table stakes, but a pinned action can still `curl` down `releases/latest` at runtime. pinprick keeps your pins fresh, audits the source code reachable through them, and gives you a single number to track over time.
