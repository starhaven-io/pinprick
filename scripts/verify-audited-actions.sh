#!/usr/bin/env bash
# Re-scan audited-actions catalog entries with the current detection rules.
#
# Bundled clean verdicts suppress scanning for every pinprick user, so they
# are trusted exactly as hard as the binary itself — and a detection-rule
# improvement can invalidate a verdict recorded under older rules. This script
# is the single place that re-verification lives; ci.yml's verify-audited leg
# and the scheduled verify-audited-actions.yml both call it.
#
# Requires a GITHUB_TOKEN (public repo read): a fresh scan fetches action
# source through the GitHub API. Each entry costs one tree call plus one call
# per scanned source file, so scheduled runs use stable shards. Full-catalog
# mode is available for manual diagnosis but may exhaust the API budget.
#
# Usage:
#   verify-audited-actions.sh <pinprick-binary> all
#   verify-audited-actions.sh <pinprick-binary> latest
#   verify-audited-actions.sh <pinprick-binary> shard <k> <m>
#   verify-audited-actions.sh <pinprick-binary> files <catalog.json>...
#
#   all     every entry in every catalog file
#   latest  the newest entry of every catalog file (files are sorted
#           newest-first; ci.yml's sort-order check enforces that)
#   shard   entries whose stable hash lands in shard k of m (0 <= k < m)
#   files   every entry of the given catalog files
set -euo pipefail
# Without this an unmatched catalog glob expands to the pattern itself, which
# reads as one file that happens not to exist rather than as an empty catalog.
shopt -s globstar nullglob

BIN="${1:?usage: verify-audited-actions.sh <pinprick-binary> <all|latest|shard k m|files ...>}"
MODE="${2:?missing mode: all|latest|shard k m|files ...}"
shift 2

SHARD_K=0
SHARD_M=1
FILES=()
case "${MODE}" in
  all | latest)
    FILES=(audited-actions/**/*.json)
    ;;
  shard)
    SHARD_K="${1:?missing shard index}"
    SHARD_M="${2:?missing shard count}"
    # An out-of-range shard matches no entry, so it would "pass" having
    # verified nothing. Reject the arguments instead.
    if [[ ! "${SHARD_M}" =~ ^[0-9]+$ ]] || ((SHARD_M < 1)); then
      echo "shard count must be a positive integer, got '${SHARD_M}'" >&2
      exit 2
    fi
    if [[ ! "${SHARD_K}" =~ ^[0-9]+$ ]] || ((SHARD_K >= SHARD_M)); then
      echo "shard index must be in [0, ${SHARD_M}), got '${SHARD_K}'" >&2
      exit 2
    fi
    FILES=(audited-actions/**/*.json)
    ;;
  files)
    FILES=("$@")
    ;;
  *)
    echo "unknown mode '${MODE}'" >&2
    exit 2
    ;;
esac

if [[ ${#FILES[@]} -eq 0 ]]; then
  # `files` mode is handed an explicit list, and ci.yml legitimately passes an
  # empty one when a change only deletes catalog files. Every other mode globs
  # the catalog itself, so finding nothing means the catalog is missing, not
  # that there is nothing to verify.
  if [[ "${MODE}" == "files" ]]; then
    echo "no catalog files to verify" >&2
    exit 0
  fi
  echo "no catalog files found under audited-actions/" >&2
  exit 2
fi

SELECT='.[]'
if [[ "${MODE}" == "latest" ]]; then
  SELECT='.[0] // empty'
fi

FAILED=0
CHECKED=0
for JSON_FILE in "${FILES[@]}"; do
  ACTION_KEY="${JSON_FILE#audited-actions/}"
  ACTION_KEY="${ACTION_KEY%.json}"
  echo "--- ${ACTION_KEY} ---"

  # Parse before the loop: inside a process substitution a jq failure is
  # invisible to `set -e`, so malformed or unreadable JSON would drain to an
  # empty loop and report the file as verified.
  if ! ENTRIES=$(jq -c "${SELECT}" "${JSON_FILE}"); then
    echo "::error::${ACTION_KEY} could not be parsed; entries NOT verified"
    FAILED=1
    continue
  fi

  while IFS= read -r ENTRY; do
    [[ -n "${ENTRY}" ]] || continue
    SHA=$(jq -r '.sha' <<< "${ENTRY}")
    TAG=$(jq -r '.tag' <<< "${ENTRY}")
    if [[ ! "${SHA}" =~ ^[0-9a-fA-F]{40}$ ]]; then
      echo "::error::${ACTION_KEY} contains non-canonical SHA '${SHA}'"
      FAILED=1
      continue
    fi

    if [[ "${MODE}" == "shard" ]]; then
      # Stable per-entry assignment: adding entries never reshuffles the
      # existing ones across shards.
      HASH=$(cksum <<< "${ACTION_KEY}@${SHA}" | cut -d' ' -f1)
      if ((HASH % SHARD_M != SHARD_K)); then
        continue
      fi
    fi

    echo "  Verifying ${TAG} (${SHA:0:7})..."
    CHECKED=$((CHECKED + 1))

    SCAN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pinprick-audit.XXXXXX")
    mkdir -p "${SCAN_DIR}/.github/workflows"
    cat > "${SCAN_DIR}/.github/workflows/test.yml" <<YAML
name: test
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: ${ACTION_KEY}@${SHA} # ${TAG}
YAML

    set +e
    OUTPUT=$("${BIN}" --json audit --no-audited-catalog "${SCAN_DIR}")
    STATUS=$?
    set -e
    rm -rf "${SCAN_DIR}"

    if [[ "${STATUS}" -eq 1 ]]; then
      echo "::error::${ACTION_KEY}@${SHA} (${TAG}) has audit findings under the current rules"
      # Print what was actually found. Without this the run says only that a
      # verdict is stale, and reproducing it means re-running the scan by hand.
      jq -r '.findings[]? | "  finding: \(.severity) \(.source_file)\(.line // "" | if . == "" then "" else ":\(.)" end): \(.description)"' \
        <<< "${OUTPUT}" || echo "  finding: (could not parse findings from the scan output)"
      FAILED=1
    elif [[ "${STATUS}" -ne 0 ]] || [[ "$(jq -r '.scanned_fresh' <<< "${OUTPUT}")" != "1" ]] || [[ "$(jq -r '.coverage_complete' <<< "${OUTPUT}")" != "true" ]]; then
      # A pass only counts if the scan actually completed — otherwise a
      # missing token, a rate limit, or a network error would silently
      # "verify" everything.
      echo "::error::${ACTION_KEY}@${SHA} (${TAG}) could not be scanned (exit ${STATUS}); verdict NOT verified"
      FAILED=1
    fi
  done <<< "${ENTRIES}"
done

echo "Checked ${CHECKED} catalog entries."
exit "${FAILED}"
