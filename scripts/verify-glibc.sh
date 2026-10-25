#!/usr/bin/env bash
# Root — ELF Dynamic Linker & glibc Symbol Compatibility Verifier
# Audits compiled release binaries for:
# 1. Maximum required glibc symbol version in the ELF VERNEED (.gnu.version_r) table.
# 2. Strong vs. weak undefined glibc symbol version breakdown.
# 3. Strict headless dynamic library isolation for the CLI binary (zero GTK/network libs).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MAX_GLIBC="${MAX_GLIBC_VERSION:-2.39}"
CLI_BIN="${REPO_ROOT}/target/release/root"
GUI_BIN="${REPO_ROOT}/target/release/root-gui"
PRINT_MIN_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-glibc)
            MAX_GLIBC="$2"
            shift 2
            ;;
        --cli)
            CLI_BIN="$2"
            shift 2
            ;;
        --gui)
            GUI_BIN="$2"
            shift 2
            ;;
        --print-min-glibc)
            PRINT_MIN_ONLY=true
            shift 1
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--max-glibc <X.YY>] [--cli <path>] [--gui <path>] [--print-min-glibc]" >&2
            exit 1
            ;;
    esac
done

for cmd in readelf awk sort grep; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Error: required binary inspection tool '${cmd}' is not installed." >&2
        exit 1
    fi
done

if [[ ! -f "${CLI_BIN}" ]]; then
    echo "Error: CLI binary not found at '${CLI_BIN}'." >&2
    exit 1
fi

# Extract all GLIBC_X.Y[.Z] versions from the ELF VERNEED table of one or more binaries
extract_verneed_glibc_versions() {
    readelf -V "$@" 2>/dev/null \
        | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' \
        | sed 's/^GLIBC_//' \
        | sort -uV
}

# Extract all strong (GLOBAL DEFAULT UND) GLIBC versions from dynamic symbol table
extract_strong_glibc_versions() {
    readelf -s -W "$@" 2>/dev/null \
        | awk '/GLOBAL[[:space:]]+DEFAULT[[:space:]]+UND/ && /@GLIBC_/ {print $8}' \
        | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' \
        | sed 's/^GLIBC_//' \
        | sort -uV
}

# Compare two dotted version strings: returns 0 if $1 <= $2, 1 if $1 > $2
version_le() {
    local v1="$1"
    local v2="$2"
    local highest
    highest="$(printf '%s\n%s\n' "${v1}" "${v2}" | sort -V | tail -n 1)"
    [[ "${highest}" == "${v2}" ]]
}

BINS=("${CLI_BIN}")
if [[ -f "${GUI_BIN}" ]]; then
    BINS+=("${GUI_BIN}")
fi

ALL_VERNEED="$(extract_verneed_glibc_versions "${BINS[@]}")"
if [[ -z "${ALL_VERNEED}" ]]; then
    echo "Error: failed to extract GLIBC version requirements from ELF binaries." >&2
    exit 1
fi

HIGHEST_VERNEED="$(echo "${ALL_VERNEED}" | tail -n 1)"

if [[ "${PRINT_MIN_ONLY}" == "true" ]]; then
    echo "${HIGHEST_VERNEED}"
    exit 0
fi

echo "=== Root ELF Binary & glibc Compatibility Audit ==="
echo "Maximum allowed glibc baseline: GLIBC_${MAX_GLIBC}"

# 1. Verify CLI headless dynamic library isolation (Invariant 6 & 10)
echo ""
echo "--- Checking CLI Dynamic Library Isolation (${CLI_BIN}) ---"
CLI_NEEDED="$(readelf -d "${CLI_BIN}" | awk '/\(NEEDED\)/ {gsub(/\[|\]/, "", $5); print $5}')"

ALLOWED_CLI_LIBS="^(libc\.so\.6|libgcc_s\.so\.1|ld-linux-x86-64\.so\.2|libm\.so\.6|libpthread\.so\.0|libdl\.so\.2|librt\.so\.1)$"
for lib in ${CLI_NEEDED}; do
    echo "  NEEDED: ${lib}"
    if ! [[ "${lib}" =~ ${ALLOWED_CLI_LIBS} ]]; then
        echo "Error: CLI binary links against unauthorized shared library '${lib}'." >&2
        echo "The headless CLI must not link against GTK, desktop, or networking libraries." >&2
        exit 1
    fi
done
echo "  Result: PASSED (strictly standard C/GCC runtime libraries)"

# 2. Audit each binary's strong symbols and ELF VERNEED table
for bin in "${BINS[@]}"; do
    echo ""
    echo "--- Auditing glibc Symbols: ${bin} ---"
    STRONG_VERS="$(extract_strong_glibc_versions "${bin}")"
    MAX_STRONG="$(echo "${STRONG_VERS}" | tail -n 1)"
    BIN_VERNEED="$(extract_verneed_glibc_versions "${bin}")"
    MAX_BIN_VERNEED="$(echo "${BIN_VERNEED}" | tail -n 1)"

    echo "  Highest strong (GLOBAL UND) symbol: GLIBC_${MAX_STRONG}"
    echo "  Highest ELF VERNEED requirement:    GLIBC_${MAX_BIN_VERNEED}"

    # List any symbols referencing the highest VERNEED version if it exceeds MAX_STRONG
    if [[ "${MAX_BIN_VERNEED}" != "${MAX_STRONG}" ]]; then
        echo "  Symbols referencing GLIBC_${MAX_BIN_VERNEED}:"
        readelf -s -W "${bin}" \
            | awk -v ver="GLIBC_${MAX_BIN_VERNEED}" '$0 ~ ver && /UND/ {printf "    %-8s %s\n", $5, $8}' \
            | sort -u
    fi

    if ! version_le "${MAX_BIN_VERNEED}" "${MAX_GLIBC}"; then
        echo "Error: '${bin}' requires GLIBC_${MAX_BIN_VERNEED}, which exceeds the allowed baseline GLIBC_${MAX_GLIBC}." >&2
        exit 1
    fi
done

echo ""
echo "=== glibc Compatibility Audit PASSED (Required Debian dependency: libc6 (>= ${HIGHEST_VERNEED})) ==="
