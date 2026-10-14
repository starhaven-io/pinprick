---
title: workflow-fingerprint
description: Compute a reviewed workflow fingerprint that permits named actions' SHA updates.
---

Generate the digest and action scope for a [workflow context acceptance](/configuration/config-file/#allowing-named-actions-revision-updates). This command is read-only and does not contact GitHub or accept findings.

```sh
pinprick workflow-fingerprint . \
  --workflow .github/workflows/scan.yml \
  --ignore-action-revision actions/checkout \
  --ignore-action-revision actions/upload-artifact
```

The repository path defaults to `.`. `--workflow` must name one discovered repository-relative workflow file. Repeat `--ignore-action-revision` for each exact `owner/repo[/subpath]` whose full SHA pin may change without renewing the acceptance. Every listed identity must occur in a workflow step; duplicates, wildcards, and unpinned references are rejected.

The default output is ready to copy into an `accept-workflow-findings` entry alongside its reviewed finding identity and reason. `--json` emits `workflow`, `workflow_context_sha256`, and `ignore_action_revisions`. Failure to read or safely fingerprint the workflow exits 2.

The fingerprint preserves action identities and every other workflow byte except the named actions' SHA tokens and full version-only comments. The auditor still checks updated action revisions independently. Review the workflow before adopting the output; computing a digest is not a security review.
