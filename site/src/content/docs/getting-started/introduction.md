---
title: Introduction
description: What pinprick does and why it exists.
---

pinprick is a CLI tool for GitHub Actions supply chain security — **pin** (SHA pinning) + **prick** (a small, sharp probe finding tiny holes in your supply chain). It does four things:

1. **Pin** — resolve action tag references (e.g., `actions/checkout@v7`) to full SHA-pinned references
2. **Update** — check pinned actions for newer releases and update them
3. **Audit** — fetch action source code and scan for unversioned runtime fetches that bypass pinning
4. **Score** — compute a reproducible posture grade against a public, versioned rubric

## Why

For static analysis of your workflow files — template injection, excessive permissions, credential leaks — use [zizmor](https://github.com/zizmorcore/zizmor). It's excellent.

pinprick picks up where static analysis leaves off. SHA-pinning actions is table stakes, but even a pinned action can `curl` down `releases/latest` at runtime. pinprick pins your actions, keeps them updated, audits their source code for unversioned runtime fetches in shell scripts, JavaScript, Python, and Dockerfiles, and gives you a single score to track over time.

For CI audit runs, the shipped [GitHub Action](/getting-started/github-action/) wraps `pinprick audit` and optional SARIF upload. Use the CLI directly for pinning, updates, and scoring.

## Exit codes

| Code | Meaning                                                                                   |
| ---- | ----------------------------------------------------------------------------------------- |
| 0    | Clean — no findings, no pending updates                                                   |
| 1    | Findings present (audit), score deductions present, or updates available (update dry-run) |
| 2    | Error                                                                                     |
