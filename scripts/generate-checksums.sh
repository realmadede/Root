#!/usr/bin/env bash
# Root — Release Artifact Checksum Generator
# Generates and self-verifies cryptographic SHA-256 checksums for all distribution artifacts.

set -euo pipefail
shopt -s nullglob

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"

if [[ ! -d "${DIST_DIR}" ]]; then
    echo "Error: distribution directory '${DIST_DIR}' does not exist." >&2
    exit 1
fi

cd "${DIST_DIR}"

DEB_FILES=(*.deb)
TAR_FILES=(*.tar.gz)

if [[ ${#DEB_FILES[@]} -eq 0 ]]; then
    echo "Error: no .deb package artifacts found in '${DIST_DIR}'." >&2
    exit 1
fi

if [[ ${#TAR_FILES[@]} -eq 0 ]]; then
    echo "Error: no .tar.gz archive artifacts found in '${DIST_DIR}'." >&2
    exit 1
fi

ARTIFACTS=("${DEB_FILES[@]}" "${TAR_FILES[@]}")
for artifact in "${ARTIFACTS[@]}"; do
    if [[ ! -s "${artifact}" ]]; then
        echo "Error: release artifact '${artifact}' is empty." >&2
        exit 1
    fi
done

echo "=== Generating SHA-256 Release Checksums ==="
rm -f SHA256SUMS

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${ARTIFACTS[@]}" > SHA256SUMS
    sha256sum -c SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${ARTIFACTS[@]}" > SHA256SUMS
    shasum -a 256 -c SHA256SUMS
else
    echo "Error: neither 'sha256sum' nor 'shasum' is available." >&2
    exit 1
fi

cat SHA256SUMS
echo "Checksum manifest verified and written to ${DIST_DIR}/SHA256SUMS"
