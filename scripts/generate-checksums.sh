#!/usr/bin/env bash
# Root — Release Artifact Checksum Generator
# Generates cryptographic SHA-256 checksums for all distribution artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"

if [[ ! -d "${DIST_DIR}" ]]; then
    echo "Distribution directory '${DIST_DIR}' does not exist."
    exit 1
fi

cd "${DIST_DIR}"

echo "=== Generating SHA-256 Release Checksums ==="
rm -f SHA256SUMS

shasum -a 256 *.deb *.tar.gz > SHA256SUMS 2>/dev/null || sha256sum *.deb *.tar.gz > SHA256SUMS

cat SHA256SUMS
echo "Checksum manifest written to ${DIST_DIR}/SHA256SUMS"
