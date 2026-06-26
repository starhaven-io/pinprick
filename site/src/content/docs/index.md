---
title: pinprick
description: GitHub Actions supply chain security. Pin actions to SHAs, audit them for runtime fetch patterns that bypass pinning, and score a repository's overall posture.
template: splash
editUrl: false
head:
  - tag: title
    content: 'pinprick: GitHub Actions supply chain security'
hero:
  title: pinprick
  tagline: Pin GitHub Actions to immutable SHAs, audit what they fetch at runtime, and keep the score visible in CI.
  image:
    html: |
      <div class="pp-hero-visual" aria-hidden="true">
        <div class="pp-score-chip">
          <span>score</span>
          <strong>A</strong>
          <small>95 / 100</small>
        </div>
        <div class="pp-terminal pp-terminal--hero">
          <div class="pp-terminal-bar">
            <span></span>
            <span></span>
            <span></span>
            <b>pinprick audit</b>
          </div>
          <pre><code>$ pinprick audit&#10;Scanning .github/workflows/ci.yml&#10;  actions/checkout@9c091bb audited (bundled)&#10;  actions/upload-artifact@043fb46 audited (bundled)&#10;Scanning .github/workflows/release.yml&#10;  rust-lang/crates-io-auth-action@c6f97d4 audited (bundled)&#10;&#10;No runtime fetch risks found.&#10;Audited 3 actions: 3 bundled.</code></pre>
        </div>
      </div>
  actions:
    - text: Start hardening
      link: /getting-started/installation/
      icon: right-arrow
      variant: primary
    - text: Audit rules
      link: /reference/detections/
      icon: document
      variant: minimal
---

<div class="pp-home">
  <section class="pp-install-strip" aria-label="Install pinprick">
    <span class="pp-eyebrow">Install</span>
    <code>brew install starhaven-io/tap/pinprick</code>
    <a href="/getting-started/installation/">More options</a>
  </section>

  <section class="pp-workflow" aria-labelledby="workflow-title">
    <div>
      <p class="pp-eyebrow">Workflow</p>
      <h2 id="workflow-title">Make action pinning measurable, not ceremonial.</h2>
      <p>
        pinprick covers the part of Actions supply chain security that gets blurry after the YAML looks clean:
        mutable tags, runtime downloads, stale SHAs, and the drift between policy and reality.
      </p>
    </div>
    <ol class="pp-steps" aria-label="pinprick workflow">
      <li>
        <span>01</span>
        <strong>Pin</strong>
        Resolve tags to full commit SHAs while preserving the human-readable tag comment.
      </li>
      <li>
        <span>02</span>
        <strong>Audit</strong>
        Inspect workflow scripts and action source for fetches that escape SHA pinning.
      </li>
      <li>
        <span>03</span>
        <strong>Update</strong>
        Move pinned actions forward when newer releases are ready to review.
      </li>
      <li>
        <span>04</span>
        <strong>Score</strong>
        Turn the posture into a reproducible grade that can gate CI or trend over time.
      </li>
    </ol>
  </section>

  <section class="pp-command-grid" aria-label="Command overview">
    <a class="pp-command-card" href="/commands/pin/">
      <span class="pp-command-name">pin</span>
      <strong>Rewrite mutable action refs.</strong>
      <code>actions/checkout@v7 -> @9c091bb21b7c... # v7.0.0</code>
    </a>
    <a class="pp-command-card" href="/commands/audit/">
      <span class="pp-command-name">audit</span>
      <strong>Find runtime fetches.</strong>
      <code>curl .../latest/tool.tar.gz</code>
    </a>
    <a class="pp-command-card" href="/commands/update/">
      <span class="pp-command-name">update</span>
      <strong>Keep pinned actions fresh.</strong>
      <code>pinprick update --write</code>
    </a>
    <a class="pp-command-card" href="/commands/score/">
      <span class="pp-command-name">score</span>
      <strong>Report a posture grade.</strong>
      <code>Grade: A (95 / 100)</code>
    </a>
  </section>

  <section class="pp-split" aria-labelledby="runtime-title">
    <div>
      <p class="pp-eyebrow">Runtime audit</p>
      <h2 id="runtime-title">Pinned action, unpinned payload? That still shows up.</h2>
      <p>
        SHA pinning fixes the action checkout. It does not prove the action avoids mutable downloads once the job
        starts. pinprick follows the reachable source and flags shell, PowerShell, JavaScript, Python, and Docker
        fetch patterns that reintroduce drift.
      </p>
      <a class="pp-text-link" href="/reference/detections/">Review every detection rule</a>
    </div>
    <div class="pp-report-card" aria-label="Example runtime findings">
      <div class="pp-report-row pp-report-row--high">
        <span>high</span>
        <strong>pipe to shell</strong>
        <code>curl -fsSL ... | sh</code>
      </div>
      <div class="pp-report-row pp-report-row--medium">
        <span>medium</span>
        <strong>unversioned URL</strong>
        <code>wget https://example.com/tool</code>
      </div>
      <div class="pp-report-row pp-report-row--low">
        <span>low</span>
        <strong>unpinned install</strong>
        <code>npm install package</code>
      </div>
    </div>
  </section>

  <section class="pp-ci-band" aria-label="CI outputs">
    <div>
      <span class="pp-eyebrow">CI ready</span>
      <strong>Run the CLI locally, or drop starhaven-io/pinprick-action into CI for audit plus SARIF upload.</strong>
    </div>
    <a href="/getting-started/github-action/">Configure the action</a>
  </section>
</div>
