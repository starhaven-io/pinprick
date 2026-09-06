# pinprick.rs documentation site

This directory contains the Astro Starlight site published at [pinprick.rs](https://pinprick.rs). Command and configuration documentation lives in `src/content/docs/`; the public audited-actions catalog is generated from the repository-level `../audited-actions/` directory during the build.

Run from this directory:

```bash
npm ci --strict-allow-scripts
npm run format:check
npm run build
npm run deploy:dry
```

Use `npm run dev` for a local preview. The repository-level `just check` task runs the supported site checks alongside the Rust and workflow checks.

Production deployment is intentionally split across isolated jobs: an unprivileged job installs dependencies and builds the site, a fresh job verifies that generated catalog bytes exactly match the canonical repository files and signs them, and a final job deploys only the signed artifact.
