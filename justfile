set positional-arguments := true

# Build

# Build the project
build:
    cargo build --locked

# Build in release mode
build-release:
    cargo build --locked --release

# Clean build artifacts
clean:
    cargo clean

# Test

# Run tests
test:
    cargo test --locked

# Check release tooling using local stubs
script-tests:
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py'

# Lint

# fleet:block audit
audit:
    zizmor --strict-collection --persona auditor .github/workflows/
# fleet:end

# Run clippy
clippy:
    cargo clippy --locked --all-targets -- -D warnings

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
add-action action_key:
    #!/usr/bin/env bash
    set -euo pipefail
    ACTION_KEY="$1"
    if [[ ! "${ACTION_KEY}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]; then
        echo "error: expected OWNER/REPO[/SUBPATH], got '${ACTION_KEY}'" >&2
        exit 2
    fi
    IFS='/' read -r -a PARTS <<< "${ACTION_KEY}"
    for PART in "${PARTS[@]}"; do
        if [[ "${PART}" == "." || "${PART}" == ".." ]]; then
            echo "error: action path cannot contain '${PART}'" >&2
            exit 2
        fi
    done
    OWNER="${PARTS[0]}"
    REPO="${PARTS[1]}"
    OWNER_REPO="${OWNER}/${REPO}"

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
    if [[ ! "${LATEST_SHA}" =~ ^[0-9a-fA-F]{40}$ ]]; then
        echo "error: release did not resolve to a full SHA" >&2
        exit 1
    fi
    echo "  resolved sha: ${LATEST_SHA:0:8}"

    SCAN_DIR=$(mktemp -d)
    trap 'rm -rf "$SCAN_DIR"' EXIT
    mkdir -p "$SCAN_DIR/.github/workflows"
    cat > "$SCAN_DIR/.github/workflows/test.yml" <<YAML
    name: test
    on: push
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: ${ACTION_KEY}@${LATEST_SHA} # ${LATEST}
    YAML

    AUDIT_JSON=$(XDG_CONFIG_HOME="${SCAN_DIR}/config" cargo run --locked --release --quiet -- --json audit --no-repo-config --no-audited-catalog "$SCAN_DIR")
    RULES_VERSION=$(jq -er '
      select(.scanned_fresh == 1 and .coverage_complete == true and .ignored == 0) |
      .rules_version |
      select(type == "number" and . >= 1 and . <= 4294967295 and . == floor)
    ' <<< "$AUDIT_JSON")

    FILE="audited-actions/${ACTION_KEY}.json"
    mkdir -p "$(dirname "$FILE")"
    [[ -f "$FILE" ]] || echo "[]" > "$FILE"
    jq -r --arg sha "$LATEST_SHA" --arg tag "$LATEST" --argjson rules_version "$RULES_VERSION" '
      ([{sha: $sha, tag: $tag, rules_version: $rules_version}] + [.[] | select(.sha != $sha)])
      | sort_by([(.tag | ltrimstr("v") | split(".") | map(tonumber? // 0)), .tag]) | reverse
      | "[\n" + ([.[] | "  { \"sha\": \(.sha | tojson), \"tag\": \(.tag | tojson), \"rules_version\": \(.rules_version) }"] | join(",\n")) + "\n]"
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
    cd site && npm ci --strict-allow-scripts

# fleet:block npm-policy
# Verify every dependency install script is denied or exactly approved
npm-policy:
    node scripts/check-npm-install-policy.mjs site
# fleet:end

# Preview the built site
site-preview:
    cd site && npm run preview

# Check for broken links in the built site and README
lychee: site-build
    lychee --config lychee.toml --root-dir "$(pwd)/site/dist/client" 'site/dist/client/**/*.html' README.md

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
    run node scripts/check-npm-install-policy.mjs site
    run cargo clippy --locked --all-targets -- -D warnings
    run cargo fmt -- --check
    if command -v typos &>/dev/null; then
        run typos
    else
        skip typos typos typos-cli
    fi
    if command -v cargo-deny &>/dev/null; then
        run cargo deny check
    else
        skip cargo-deny cargo-deny cargo-deny
    fi
    if command -v zizmor &>/dev/null; then
        run zizmor --strict-collection --persona auditor .github/workflows/
    else
        skip audit zizmor zizmor
    fi
    run cargo test --locked
    run env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py'
    echo "--- site-format-check ---"
    (cd site && npm run format:check) || failed=1
    echo "--- site-build ---"
    (cd site && npm run build) || failed=1
    echo "--- site-deploy-dry ---"
    (cd site && WRANGLER_SEND_METRICS=false npm run deploy:dry) || failed=1
    if [ ${#skipped[@]} -gt 0 ]; then
        echo ""
        echo "Checks skipped due to missing tools:"
        for tool in "${skipped[@]}"; do
            echo "  - $tool"
        done
        failed=1
    fi
    exit $failed

# fleet:block install-hooks
# Install git hooks (AI trailer guard + DCO sign-off + pre-push checks). Run once per clone.
install-hooks:
    git config core.hooksPath .githooks
# fleet:end
