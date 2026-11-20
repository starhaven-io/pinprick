#!/usr/bin/env bash
set -euo pipefail

[[ "${EXPECTED_CHECKSUM}" =~ ^[0-9a-f]{64}$ ]] || { echo "::error::Missing verified crate checksum"; exit 1; }
response_dir=$(mktemp -d "${RUNNER_TEMP}/pinprick-crate.XXXXXX")
trap 'rm -f "${response_dir}/version.json"; rmdir "${response_dir}"' EXIT

# Exit 1 only for a definite absence. Every other failure preserves the draft for a retry.
registry_matches() {
    local status
    status=$(curl --silent --show-error --connect-timeout 10 --max-time 30 --retry 3 \
        --user-agent pinprick-release --output "${response_dir}/version.json" --write-out '%{http_code}' \
        "https://crates.io/api/v1/crates/pinprick/${VERSION}") || return 2
    case "${status}" in
        404) return 1 ;;
        200)
            if jq --exit-status --arg version "${VERSION}" --arg checksum "${EXPECTED_CHECKSUM}" \
                '.version | .crate == "pinprick" and .num == $version and .checksum == $checksum and .yanked == false' \
                "${response_dir}/version.json" > /dev/null; then
                return 0
            fi
            echo "::error::Published pinprick ${VERSION} does not match the verified package or is yanked" >&2
            ;;
        *) echo "::error::Registry lookup for pinprick ${VERSION} returned HTTP ${status}" >&2 ;;
    esac
    return 2
}

if registry_matches; then
    exit 0
elif (( $? != 1 )); then
    exit 1
fi

# Cargo packages again during publication. Check this checkout reproduces the verified archive first.
cargo package --locked --no-verify --registry crates-io
local_checksum=$(sha256sum "target/package/pinprick-${VERSION}.crate" | cut -d ' ' -f 1)
if [[ "${local_checksum}" != "${EXPECTED_CHECKSUM}" ]]; then
    echo "::error::Local crate does not reproduce the verified package" >&2
    exit 1
fi
if ! cargo publish --locked --no-verify --registry crates-io; then
    echo "::warning::Cargo reported a failure; checking whether the registry accepted the upload" >&2
fi
for attempt in 1 2 3 4 5; do
    if registry_matches; then
        exit 0
    elif (( $? != 1 )); then
        exit 1
    fi
    if (( attempt < 5 )); then sleep 5; fi
done
echo "::error::Registry publication of pinprick ${VERSION} is unconfirmed. Re-run failed jobs to resume from the draft." >&2
exit 1
