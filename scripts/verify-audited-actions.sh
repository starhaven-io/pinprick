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
# per scanned source file, so scheduled runs use stable shards. A run larger
# than the hourly GITHUB_TOKEN budget waits for the budget to reset.
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

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
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

if ! command -v "${BIN}" >/dev/null 2>&1; then
  echo "catalog verifier binary is missing or not executable: ${BIN}" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "catalog verifier requires jq" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "catalog verifier requires python3" >&2
  exit 2
fi
NORMALIZER="${SCRIPT_DIR}/normalize-audit-json.py"
if [[ ! -r "${NORMALIZER}" ]]; then
  echo "catalog verifier helper is missing or unreadable: ${NORMALIZER}" >&2
  exit 2
fi

# A scan that exhausts the API budget part-way reports incomplete coverage, so
# wait for the reset before starting an entry the remaining budget may not
# cover. The reserve is well above the costliest entry measured. pinprick
# prefers GITHUB_TOKEN, so its budget is the one the scans spend; without it
# nothing waits. A scan that still runs out fails closed, so an unreadable
# budget only skips the wait.
#
# /rate_limit has reported an unspent budget while real responses showed it
# spent, so read the budget from a real response's headers. Revalidating the
# API root's ETag answers 304, which carries them without spending budget.
API_RESERVE=100
API_BUDGET_READABLE=1
API_ROOT_ETAG=""
api_header() {
  awk -v name="$2:" 'tolower($1) == name { value = $2 } END { print value }' <<< "$1"
}
wait_for_api_budget() {
  [[ -n "${GITHUB_TOKEN:-}" && "${API_BUDGET_READABLE}" -eq 1 ]] || return 0
  local REQUEST HEADERS REMAINING RESET ETAG DELAY
  # Headers travel on stdin to keep the token out of the process list.
  REQUEST="Authorization: Bearer ${GITHUB_TOKEN}"
  if [[ -n "${API_ROOT_ETAG}" ]]; then
    REQUEST+=$'\n'"If-None-Match: ${API_ROOT_ETAG}"
  fi
  HEADERS=$(curl -sS --max-time 30 -o /dev/null -D - -H @- https://api.github.com/ \
    <<< "${REQUEST}" | tr -d '\r') || HEADERS=""
  REMAINING=$(api_header "${HEADERS}" x-ratelimit-remaining)
  RESET=$(api_header "${HEADERS}" x-ratelimit-reset)
  if [[ ! "${REMAINING}" =~ ^[0-9]+$ || ! "${RESET}" =~ ^[0-9]+$ ]]; then
    echo "::warning::could not read the GitHub API budget; verifying without waiting for resets"
    API_BUDGET_READABLE=0
    return 0
  fi
  ETAG=$(api_header "${HEADERS}" etag)
  if [[ -n "${ETAG}" ]]; then
    API_ROOT_ETAG="${ETAG}"
  fi
  DELAY=$((RESET - $(date +%s) + 5))
  if ((REMAINING >= API_RESERVE || DELAY <= 0)); then
    return 0
  fi
  if ((DELAY > 3660)); then
    DELAY=3660
  fi
  echo "  API budget low (${REMAINING} requests left); waiting ${DELAY}s for its reset..."
  sleep "${DELAY}"
}

SELECT='.[]'
if [[ "${MODE}" == "latest" ]]; then
  SELECT='.[0] // empty'
fi

FAILED=0
CHECKED=0
CURRENT_RULES_VERSION=""
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
    if ! jq -e '
      type == "object" and
      (.sha | type == "string") and
      (.tag | type == "string") and
      (.rules_version |
        type == "number" and . >= 1 and . <= 4294967295 and . == floor)
    ' <<< "${ENTRY}" > /dev/null; then
      echo "::error::${ACTION_KEY} contains an invalid or unstamped catalog entry; verdict NOT verified"
      FAILED=1
      continue
    fi
    SHA=$(jq -r '.sha' <<< "${ENTRY}")
    TAG=$(jq -r '.tag' <<< "${ENTRY}")
    ENTRY_RULES_VERSION=$(jq -r '.rules_version' <<< "${ENTRY}")
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

    wait_for_api_budget
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

    OUTPUT_FILE="${SCAN_DIR}/audit-output.json"
    set +e
    XDG_CONFIG_HOME="${SCAN_DIR}/config" "${BIN}" --json audit --no-repo-config --no-audited-catalog "${SCAN_DIR}" > "${OUTPUT_FILE}"
    STATUS=$?
    set -e

    # jq normalizes invalid UTF-8 and duplicate object keys while parsing, so
    # reject ambiguous raw JSON before applying the typed report schema.
    if ! REPORT=$(
      python3 "${NORMALIZER}" "${OUTPUT_FILE}" 2>/dev/null |
        jq -c -e '
          if (type == "object" and
              (.findings | type == "array") and
              all(.findings[];
                  type == "object" and
                  (.severity | type == "string") and
                  (.source_file | type == "string") and
                  ((.line == null) or (.line | type == "number")) and
                  (.description | type == "string")) and
              (.scanned_fresh | type == "number") and
              (.rules_version |
                type == "number" and . >= 1 and . <= 4294967295 and . == floor) and
              (.coverage_complete | type == "boolean") and
              (if has("coverage_failures")
               then (.coverage_failures | type == "array") and
                    all(.coverage_failures[]; type == "string")
               else true
               end))
          then .
          else error("invalid audit report")
          end
        ' 2>/dev/null
    ); then
      rm -rf "${SCAN_DIR}"
      echo "::error::${ACTION_KEY}@${SHA} (${TAG}) returned malformed audit output (exit ${STATUS}); verdict NOT verified"
      FAILED=1
      continue
    fi
    rm -rf "${SCAN_DIR}"

    FINDING_COUNT=$(jq -r '.findings | length' <<< "${REPORT}")
    COVERAGE_FAILURE_COUNT=$(jq -r 'if has("coverage_failures") then .coverage_failures | length else 0 end' <<< "${REPORT}")
    SCANNED_FRESH=$(jq -r '.scanned_fresh' <<< "${REPORT}")
    REPORT_RULES_VERSION=$(jq -r '.rules_version' <<< "${REPORT}")
    COVERAGE_COMPLETE=$(jq -r '.coverage_complete' <<< "${REPORT}")

    if [[ -z "${CURRENT_RULES_VERSION}" ]]; then
      CURRENT_RULES_VERSION="${REPORT_RULES_VERSION}"
    elif [[ "${CURRENT_RULES_VERSION}" != "${REPORT_RULES_VERSION}" ]]; then
      echo "::error::${ACTION_KEY}@${SHA} (${TAG}) reported rules version ${REPORT_RULES_VERSION}, expected ${CURRENT_RULES_VERSION}; verdict NOT verified"
      FAILED=1
    fi

    if [[ "${REPORT_RULES_VERSION}" != "${ENTRY_RULES_VERSION}" ]]; then
      echo "::error::${ACTION_KEY}@${SHA} (${TAG}) was stamped with rules version ${ENTRY_RULES_VERSION}, but the scanner reports ${REPORT_RULES_VERSION}; verdict NOT verified"
    fi

    if [[ "${STATUS}" -eq 0 ]] && [[ "${FINDING_COUNT}" -eq 0 ]] && \
       [[ "${COVERAGE_FAILURE_COUNT}" -eq 0 ]] && [[ "${SCANNED_FRESH}" == "1" ]] && \
       [[ "${COVERAGE_COMPLETE}" == "true" ]] && \
       [[ "${REPORT_RULES_VERSION}" == "${ENTRY_RULES_VERSION}" ]]; then
      continue
    fi

    if [[ "${FINDING_COUNT}" -ne 0 ]]; then
      echo "::error::${ACTION_KEY}@${SHA} (${TAG}) has audit findings under the current rules"
      jq -r '
        def printable:
          [explode[] |
           if ((. != 9 and ((. < 32) or (. >= 127 and . <= 159))) or
               . == 8206 or . == 8207 or
               (. >= 8234 and . <= 8238) or
               (. >= 8294 and . <= 8297))
           then 65533
           else .
           end] | implode;
        # The legacy `##[...]` runner command parser matches anywhere in a
        # line, so unlike a modern `::` command it is not neutralized by the
        # two-space diagnostic prefix. Break the token itself.
        def inert: gsub("##\\["; "## [");
        .findings[] |
        ("  finding: \(.severity | printable) \(.source_file | printable)\(if .line == null then "" else ":\(.line)" end): \(.description | printable)" | inert)
      ' <<< "${REPORT}"
    fi

    if [[ "${STATUS}" -ne 0 && "${STATUS}" -ne 1 ]] || \
       [[ "${COVERAGE_FAILURE_COUNT}" -ne 0 ]] || [[ "${SCANNED_FRESH}" != "1" ]] || \
       [[ "${COVERAGE_COMPLETE}" != "true" ]]; then
      echo "::error::${ACTION_KEY}@${SHA} (${TAG}) could not be scanned (exit ${STATUS}); verdict NOT verified"
      jq -r '
        def printable:
          [explode[] |
           if ((. != 9 and ((. < 32) or (. >= 127 and . <= 159))) or
               . == 8206 or . == 8207 or
               (. >= 8234 and . <= 8238) or
               (. >= 8294 and . <= 8297))
           then 65533
           else .
           end] | implode;
        # The legacy `##[...]` runner command parser matches anywhere in a
        # line, so unlike a modern `::` command it is not neutralized by the
        # two-space diagnostic prefix. Break the token itself.
        def inert: gsub("##\\["; "## [");
        if has("coverage_failures")
        then .coverage_failures[] | ("  coverage: \(. | printable)" | inert)
        else empty
        end
      ' <<< "${REPORT}"
    fi

    if [[ "${STATUS}" -eq 0 && "${FINDING_COUNT}" -ne 0 ]] || \
       [[ "${STATUS}" -eq 1 && "${FINDING_COUNT}" -eq 0 ]]; then
      echo "::error::${ACTION_KEY}@${SHA} (${TAG}) returned an inconsistent audit status and report; verdict NOT verified"
    fi

    FAILED=1
  done <<< "${ENTRIES}"
done

if [[ -n "${CURRENT_RULES_VERSION}" ]]; then
  CATALOG_FILES=(audited-actions/**/*.json)
  if [[ ${#CATALOG_FILES[@]} -gt 0 ]]; then
    if ! INERT_COUNT=$(jq -s --argjson current "${CURRENT_RULES_VERSION}" \
      '[.[][] | select(.rules_version != $current)] | length' "${CATALOG_FILES[@]}"); then
      echo "::error::could not count catalog entries inert under rules version ${CURRENT_RULES_VERSION}"
      FAILED=1
    else
      echo "Catalog entries inert under rules version ${CURRENT_RULES_VERSION}: ${INERT_COUNT}."
    fi
  fi
fi
echo "Checked ${CHECKED} catalog entries."
exit "${FAILED}"
