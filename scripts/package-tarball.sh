#!/usr/bin/env bash
# Root — Portable Linux Tarball Builder
# Builds a standalone tar.gz archive for x86_64 Linux with user-level installation script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="0.1.0"
TARGET_TRIPLE="x86_64-unknown-linux-gnu"
ARCHIVE_NAME="root-v${VERSION}-${TARGET_TRIPLE}"
STAGE_DIR="${REPO_ROOT}/target/tarball/${ARCHIVE_NAME}"
DIST_DIR="${REPO_ROOT}/dist"

echo "=== Building Root Portable Linux Archive ==="
echo "Archive:      ${ARCHIVE_NAME}.tar.gz"
echo "Source root:  ${REPO_ROOT}"

# 1. Ensure release binaries are built
if [[ ! -f "${REPO_ROOT}/target/release/root" ]] || [[ ! -f "${REPO_ROOT}/target/release/root-gui" ]]; then
    echo "Release binaries not found. Building release binaries..."
    cargo build --release -p root-cli
    cargo build --release -p root-gui --features gtk
fi

# 2. Prepare staging tree
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}/bin"
mkdir -p "${STAGE_DIR}/share/applications"
mkdir -p "${STAGE_DIR}/share/metainfo"
mkdir -p "${STAGE_DIR}/share/icons/hicolor/scalable/apps"
mkdir -p "${STAGE_DIR}/share/man/man1"
mkdir -p "${STAGE_DIR}/doc"
mkdir -p "${DIST_DIR}"

# 3. Copy binaries
install -m 755 "${REPO_ROOT}/target/release/root" "${STAGE_DIR}/bin/root"
install -m 755 "${REPO_ROOT}/target/release/root-gui" "${STAGE_DIR}/bin/root-gui"

# 4. Copy assets
install -m 644 "${REPO_ROOT}/data/io.github.realmadede.Root.desktop" "${STAGE_DIR}/share/applications/io.github.realmadede.Root.desktop"
install -m 644 "${REPO_ROOT}/data/io.github.realmadede.Root.metainfo.xml" "${STAGE_DIR}/share/metainfo/io.github.realmadede.Root.metainfo.xml"
install -m 644 "${REPO_ROOT}/data/icons/io.github.realmadede.Root.svg" "${STAGE_DIR}/share/icons/hicolor/scalable/apps/io.github.realmadede.Root.svg"
install -m 644 "${REPO_ROOT}/data/man/root.1" "${STAGE_DIR}/share/man/man1/root.1"
install -m 644 "${REPO_ROOT}/data/man/root-gui.1" "${STAGE_DIR}/share/man/man1/root-gui.1"
install -m 644 "${REPO_ROOT}/LICENSE" "${STAGE_DIR}/doc/LICENSE"
install -m 644 "${REPO_ROOT}/README.md" "${STAGE_DIR}/doc/README.md"

# 5. Generate portable installer script
cat <<'EOF' > "${STAGE_DIR}/install.sh"
#!/usr/bin/env bash
# Root — Portable Distribution Installer
# Defaults to unprivileged user installation in ~/.local

set -euo pipefail

PREFIX="${PREFIX:-${HOME}/.local}"
BIN_DIR="${PREFIX}/bin"
DATA_DIR="${PREFIX}/share"

echo "=== Installing Root to ${PREFIX} ==="

mkdir -p "${BIN_DIR}"
mkdir -p "${DATA_DIR}/applications"
mkdir -p "${DATA_DIR}/metainfo"
mkdir -p "${DATA_DIR}/icons/hicolor/scalable/apps"
mkdir -p "${DATA_DIR}/man/man1"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -m 755 "${DIR}/bin/root" "${BIN_DIR}/root"
install -m 755 "${DIR}/bin/root-gui" "${BIN_DIR}/root-gui"

install -m 644 "${DIR}/share/applications/io.github.realmadede.Root.desktop" "${DATA_DIR}/applications/"
install -m 644 "${DIR}/share/metainfo/io.github.realmadede.Root.metainfo.xml" "${DATA_DIR}/metainfo/"
install -m 644 "${DIR}/share/icons/hicolor/scalable/apps/io.github.realmadede.Root.svg" "${DATA_DIR}/icons/hicolor/scalable/apps/"

install -m 644 "${DIR}/share/man/man1/root.1" "${DATA_DIR}/man/man1/"
install -m 644 "${DIR}/share/man/man1/root-gui.1" "${DATA_DIR}/man/man1/"

if which update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q "${DATA_DIR}/applications" || true
fi
if which gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f "${DATA_DIR}/icons/hicolor" || true
fi

echo "Root installed successfully."
echo "Binaries: ${BIN_DIR}/root, ${BIN_DIR}/root-gui"
echo "Ensure ${BIN_DIR} is in your PATH."
EOF
chmod 755 "${STAGE_DIR}/install.sh"

# 6. Generate uninstaller script
cat <<'EOF' > "${STAGE_DIR}/uninstall.sh"
#!/usr/bin/env bash
# Root — Portable Distribution Uninstaller
# Removes Root binaries and desktop integration from PREFIX (defaults to ~/.local)

set -euo pipefail

PREFIX="${PREFIX:-${HOME}/.local}"
BIN_DIR="${PREFIX}/bin"
DATA_DIR="${PREFIX}/share"

echo "=== Uninstalling Root from ${PREFIX} ==="

rm -f "${BIN_DIR}/root"
rm -f "${BIN_DIR}/root-gui"
rm -f "${DATA_DIR}/applications/io.github.realmadede.Root.desktop"
rm -f "${DATA_DIR}/metainfo/io.github.realmadede.Root.metainfo.xml"
rm -f "${DATA_DIR}/icons/hicolor/scalable/apps/io.github.realmadede.Root.svg"
rm -f "${DATA_DIR}/man/man1/root.1"
rm -f "${DATA_DIR}/man/man1/root-gui.1"

if which update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q "${DATA_DIR}/applications" || true
fi
if which gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f "${DATA_DIR}/icons/hicolor" || true
fi

echo "Root uninstalled successfully. User preferences and logs have been preserved."
EOF
chmod 755 "${STAGE_DIR}/uninstall.sh"

# 7. Create reproducible tarball
TARBALL_OUTPUT="${DIST_DIR}/${ARCHIVE_NAME}.tar.gz"
tar -czf "${TARBALL_OUTPUT}" -C "${REPO_ROOT}/target/tarball" "${ARCHIVE_NAME}"

echo "=== Tarball Built Successfully ==="
echo "Artifact: ${TARBALL_OUTPUT}"
ls -lh "${TARBALL_OUTPUT}"
