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

# Audited Actions

# Add a new audited action by resolving its latest release and verifying it is clean
add-action owner_repo:
    #!/usr/bin/env bash
    set -euo pipefail
    OWNER_REPO="{{ owner_repo }}"
    if [[ "$OWNER_REPO" != */* ]]; then
        echo "error: expected OWNER/REPO, got '$OWNER_REPO'" >&2
        exit 2
    fi
    OWNER="${OWNER_REPO%/*}"
    REPO="${OWNER_REPO#*/}"

    echo "--- ${OWNER_REPO} ---"

    LATEST=$(gh api "repos/${OWNER}/${REPO}/releases/latest" --jq '.tag_name')
    if [[ -z "$LATEST" ]]; then
        echo "error: no releases found for ${OWNER_REPO}" >&2
        exit 1
    fi
    echo "  latest release: $LATEST"

    LATEST_SHA=$(gh api "repos/${OWNER}/${REPO}/git/ref/tags/${LATEST}" --jq '.object.sha')
    OBJ_TYPE=$(gh api "repos/${OWNER}/${REPO}/git/ref/tags/${LATEST}" --jq '.object.type')
    if [[ "$OBJ_TYPE" == "tag" ]]; then
        LATEST_SHA=$(gh api "repos/${OWNER}/${REPO}/git/tags/${LATEST_SHA}" --jq '.object.sha')
    fi
    echo "  resolved sha: ${LATEST_SHA:0:8}"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    mkdir -p "$TMPDIR/.github/workflows"
    cat > "$TMPDIR/.github/workflows/test.yml" <<YAML
    name: test
    on: push
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: ${OWNER}/${REPO}@${LATEST_SHA} # ${LATEST}
    YAML

    cargo run --release --quiet -- --json audit "$TMPDIR"

    FILE="audited-actions/${OWNER}/${REPO}.json"
    mkdir -p "$(dirname "$FILE")"
    [[ -f "$FILE" ]] || echo "[]" > "$FILE"
    jq -r --arg sha "$LATEST_SHA" --arg tag "$LATEST" '
      (if any(.[]; .sha == $sha) then . else [{sha: $sha, tag: $tag}] + . end) as $u |
      "[\n" + ([$u[] | "  { \"sha\": \"\(.sha)\", \"tag\": \"\(.tag)\" }"] | join(",\n")) + "\n]"
    ' "$FILE" > "$FILE.tmp"
    command mv "$FILE.tmp" "$FILE"
    echo "  wrote ${FILE}"

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
