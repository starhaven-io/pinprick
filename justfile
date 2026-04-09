# Build

# Build the project
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Clean build artifacts
clean:
    cargo clean

# Test

# Run tests
test:
    cargo test

# Lint

# Audit GitHub Actions workflows
audit:
    zizmor .github/workflows/

# Run clippy
clippy:
    cargo clippy -- -D warnings

# Check formatting
fmt-check:
    cargo fmt -- --check

# Format code
fmt:
    cargo fmt

# Check for typos
typos:
    typos

# Site

# Build the site
site-build:
    cd site && npm run build

# Start the site dev server
site-dev:
    cd site && npm run dev

# Format site files with Prettier
site-format:
    cd site && npm run format

# Check site formatting
site-format-check:
    cd site && npm run format:check

# Install site dependencies
site-install:
    cd site && npm install

# Preview the built site
site-preview:
    cd site && npm run preview

# Check

# Run all checks
check:
    #!/usr/bin/env bash
    set -euo pipefail
    failed=0
    skipped=()
    run() {
        echo "--- $1 ---"
        if ! "$@"; then
            failed=1
        fi
    }
    skip() {
        echo "--- $1 --- skipped ($2 not found)"
        skipped+=("$2 (brew install $3)")
    }
    run cargo clippy -- -D warnings
    run cargo fmt -- --check
    if command -v typos &>/dev/null; then
        run typos
    else
        skip typos typos typos-cli
    fi
    if command -v zizmor &>/dev/null; then
        run zizmor .github/workflows/
    else
        skip audit zizmor zizmor
    fi
    run cargo test
    echo "--- site-format-check ---"
    (cd site && npm run format:check) || failed=1
    echo "--- site-build ---"
    (cd site && npm run build) || failed=1
    if [ ${#skipped[@]} -gt 0 ]; then
        echo ""
        echo "Checks skipped due to missing tools:"
        for tool in "${skipped[@]}"; do
            echo "  - $tool"
        done
        failed=1
    fi
    exit $failed
