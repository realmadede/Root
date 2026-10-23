#!/usr/bin/env bash
# Root — Debian Package Builder (.deb)
# Builds a deterministic, production-grade Debian package containing Root CLI and GUI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="0.1.0"
DEB_REVISION="1"
PKG_VERSION="${VERSION}-${DEB_REVISION}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo "amd64")"
PKG_NAME="root"
BUILD_DIR="${REPO_ROOT}/target/debian/${PKG_NAME}_${PKG_VERSION}_${ARCH}"
DIST_DIR="${REPO_ROOT}/dist"

echo "=== Building Root Debian Package ==="
echo "Package:      ${PKG_NAME}"
echo "Version:      ${PKG_VERSION}"
echo "Architecture: ${ARCH}"
echo "Source root:  ${REPO_ROOT}"

# 1. Ensure release binaries are built
if [[ ! -f "${REPO_ROOT}/target/release/root" ]] || [[ ! -f "${REPO_ROOT}/target/release/root-gui" ]]; then
    echo "Release binaries not found. Building release binaries..."
    cargo build --release -p root-cli
    cargo build --release -p root-gui --features gtk
fi

# 2. Prepare clean staging hierarchy
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/bin"
mkdir -p "${BUILD_DIR}/usr/share/applications"
mkdir -p "${BUILD_DIR}/usr/share/metainfo"
mkdir -p "${BUILD_DIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${BUILD_DIR}/usr/share/man/man1"
mkdir -p "${BUILD_DIR}/usr/share/doc/${PKG_NAME}"
mkdir -p "${DIST_DIR}"

# 3. Copy binaries
install -m 755 "${REPO_ROOT}/target/release/root" "${BUILD_DIR}/usr/bin/root"
install -m 755 "${REPO_ROOT}/target/release/root-gui" "${BUILD_DIR}/usr/bin/root-gui"

# 4. Copy desktop integration assets
install -m 644 "${REPO_ROOT}/data/io.github.realmadede.Root.desktop" "${BUILD_DIR}/usr/share/applications/io.github.realmadede.Root.desktop"
install -m 644 "${REPO_ROOT}/data/io.github.realmadede.Root.metainfo.xml" "${BUILD_DIR}/usr/share/metainfo/io.github.realmadede.Root.metainfo.xml"
install -m 644 "${REPO_ROOT}/data/icons/io.github.realmadede.Root.svg" "${BUILD_DIR}/usr/share/icons/hicolor/scalable/apps/io.github.realmadede.Root.svg"

# 5. Compress and copy man pages (reproducible with -9 -n)
gzip -9 -n -c "${REPO_ROOT}/data/man/root.1" > "${BUILD_DIR}/usr/share/man/man1/root.1.gz"
chmod 644 "${BUILD_DIR}/usr/share/man/man1/root.1.gz"

gzip -9 -n -c "${REPO_ROOT}/data/man/root-gui.1" > "${BUILD_DIR}/usr/share/man/man1/root-gui.1.gz"
chmod 644 "${BUILD_DIR}/usr/share/man/man1/root-gui.1.gz"

# 6. Copy documentation and copyright
install -m 644 "${REPO_ROOT}/data/debian/copyright" "${BUILD_DIR}/usr/share/doc/${PKG_NAME}/copyright"
install -m 644 "${REPO_ROOT}/README.md" "${BUILD_DIR}/usr/share/doc/${PKG_NAME}/README.md"

gzip -9 -n -c "${REPO_ROOT}/data/debian/changelog" > "${BUILD_DIR}/usr/share/doc/${PKG_NAME}/changelog.Debian.gz"
chmod 644 "${BUILD_DIR}/usr/share/doc/${PKG_NAME}/changelog.Debian.gz"

# 7. Compute installed size in KiB
INSTALLED_SIZE="$(du -sk "${BUILD_DIR}/usr" | cut -f1)"

# 8. Generate DEBIAN/control
cat <<EOF > "${BUILD_DIR}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: Raphael Madede <bagomwaraphael@gmail.com>
Depends: libc6 (>= 2.34), libadwaita-1-0 (>= 1.4), libgtk-4-1 (>= 4.12), libglib2.0-0t64 | libglib2.0-0 (>= 2.76)
Homepage: https://github.com/realmadede/Root
Description: Deterministic resource inspection utility for agentic coding workflows
 Root is a deterministic, local-first system resource inspection utility engineered
 to help developers understand, audit, and safely inspect system resources accumulated
 through AI coding workflows.
 .
 Root operates under least-privilege principles, requiring zero elevated privileges
 and executing no destructive mutations in production.
EOF
chmod 644 "${BUILD_DIR}/DEBIAN/control"

# 9. Generate maintainer scripts
cat <<'EOF' > "${BUILD_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    if which update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if which gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
    fi
fi

exit 0
EOF
chmod 755 "${BUILD_DIR}/DEBIAN/postinst"

cat <<'EOF' > "${BUILD_DIR}/DEBIAN/postrm"
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if which update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if which gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
    fi
fi

exit 0
EOF
chmod 755 "${BUILD_DIR}/DEBIAN/postrm"

# 10. Build Debian package using dpkg-deb with root ownership
DEB_OUTPUT="${DIST_DIR}/${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "${BUILD_DIR}" "${DEB_OUTPUT}"

echo "=== Package Built Successfully ==="
echo "Artifact: ${DEB_OUTPUT}"
dpkg-deb -I "${DEB_OUTPUT}"
echo "Contents:"
dpkg-deb -c "${DEB_OUTPUT}"
