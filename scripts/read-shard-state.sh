#!/usr/bin/env bash
# Read validated shard state from an audited-actions tracking issue body.
#
# The body mixes trusted workflow state with action-derived diagnostics: a
# scanned action controls its own file paths, so it can make a forged marker
# appear in the issue. Only an exact block at the very start of the body is
# authoritative. A block found further down could have been forged inside
# diagnostics retained from an older, unsanitized body, so position alone is
# what separates state from content here.
#
# Anything unrecognized yields all-pending, which is the safe direction: a
# shard has to pass again before it counts, and the worst case is that a
# tracking issue takes one extra cycle to close.
#
# Usage: read-shard-state.sh <body-file> <shard-count>
# Prints exactly <shard-count> lines, one state per shard.
set -euo pipefail

BODY="${1:?usage: read-shard-state.sh <body-file> <shard-count>}"
COUNT="${2:?missing shard count}"

if [[ ! "${COUNT}" =~ ^[0-9]+$ ]] || ((COUNT < 1)); then
  echo "shard count must be a positive integer, got '${COUNT}'" >&2
  exit 2
fi

all_pending() {
  local i
  for ((i = 0; i < COUNT; i++)); do
    echo pending
  done
}

if [[ ! -r "${BODY}" ]]; then
  all_pending
  exit 0
fi

# GitHub may hand back CRLF; normalizing keeps the exact line comparisons
# below from failing open-endedly on a body that is otherwise well formed.
mapfile -t LINES < <(tr -d '\r' < "${BODY}")

if [[ ${#LINES[@]} -lt $((COUNT + 2)) ]] ||
  [[ "${LINES[0]}" != "<!-- pinprick-state:begin -->" ]] ||
  [[ "${LINES[COUNT + 1]}" != "<!-- pinprick-state:end -->" ]]; then
  all_pending
  exit 0
fi

STATES=()
for ((I = 0; I < COUNT; I++)); do
  # Exact match on the whole line, in shard order. A marker that is merely
  # present somewhere is not state.
  case "${LINES[I + 1]}" in
    "<!-- pinprick-shard-${I}:passed -->") STATES+=(passed) ;;
    "<!-- pinprick-shard-${I}:failed -->") STATES+=(failed) ;;
    "<!-- pinprick-shard-${I}:pending -->") STATES+=(pending) ;;
    *)
      all_pending
      exit 0
      ;;
  esac
done

printf '%s\n' "${STATES[@]}"
