# Root — Phase 12 Validation Report
## End-to-End Packaging, Desktop Integration, and Runtime Verification

## 1. Overview

This report documents the empirical validation of Root's production release packages, desktop integration, runtime performance, and lifecycle scripts on Linux.

---

## 2. Test Environment

- **Operating System**: Kali GNU/Linux Rolling (x86_64)
- **Kernel Release**: `7.1.5+kali-amd64`
- **Desktop Environment**: GNOME 47 / Wayland (`WAYLAND_DISPLAY=wayland-0`, `DISPLAY=:0`)
- **Package Manager**: `dpkg` 1.22.11 / `apt` 2.9.21
- **Toolchain**: Rust 1.85.0 (stable-x86_64-unknown-linux-gnu), `cargo` 1.85.0

---

## 3. Package Generation & Artifact Validation

| Artifact Name | Format | Architecture | File Size | SHA-256 Checksum | Validation Status |
|---|---|---|---|---|---|
| `root_0.1.0-1_amd64.deb` | Debian Package (`.deb`) | `amd64` | 840,856 bytes (~821 KiB) | `f1e10cf596d4e9f66ca9b9bc96050225e575f5c1c06cd7ed6bfbaa400aeabe4f` | [VERIFIED] Valid control archive, permissions, file tree |
| `root-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` | Portable Tarball (`.tar.gz`) | `x86_64` | ~1.4 MiB | `0262664a51fdc88f9c187d4d81ac9b880019b2fa0c2a7c3ec2d9697027437ee1` | [VERIFIED] Valid gzip archive, installer script, uninstaller |
| `SHA256SUMS` | Checksum Manifest | Text | 179 bytes | Verified against generated files | [VERIFIED] 100% hash match |

---

## 4. Empirical Runtime Performance Measurements

All measurements were taken on the live host environment with native Wayland session active:

| Metric | Measured Value | Target / Assessment | Status |
|---|---|---|---|
| **CLI Cold Launch Latency** | **2.50 ms** | < 10 ms (Instantaneous execution) | [VERIFIED] Exceeds target |
| **CLI Warm Launch Latency** | **2.23 ms** | < 5 ms (Instantaneous execution) | [VERIFIED] Exceeds target |
| **GUI Cold Launch Latency** | **~500.51 ms** | < 750 ms (Initial Wayland window map) | [VERIFIED] Responsive startup |
| **GUI Steady-State Idle Memory (RSS)** | **126.94 MiB** | < 150 MiB (Standard Adwaita baseline) | [VERIFIED] Within budget |
| **GUI Steady-State Idle CPU** | **1.0%** | < 2% (Near-zero idle CPU consumption) | [VERIFIED] No runaway threads |
| **GUI Graceful Shutdown Latency** | **15.45 ms** | < 50 ms (Instantaneous window closure) | [VERIFIED] Clean shutdown |
| **CLI Scan Responsiveness (19 items)** | **3.18 ms** | < 10 ms (Rapid directory traversal) | [VERIFIED] High throughput |

---

## 5. Desktop Integration Validation

1. **Desktop Entry Specification**:
   - File: `data/io.github.realmadede.Root.desktop`.
   - Tool: `desktop-file-validate`.
   - Result: **0 errors, 0 warnings (100% compliant)**.
2. **Application Icon**:
   - File: `data/icons/io.github.realmadede.Root.svg`.
   - Verified installation path: `/usr/share/icons/hicolor/scalable/apps/io.github.realmadede.Root.svg`.
   - Format: Clean scalable vector geometry, GNOME squircle shape, zero emojis.
3. **AppStream Catalog Metadata**:
   - File: `data/io.github.realmadede.Root.metainfo.xml`.
   - Result: Valid XML schema specifying binary mapping to `root-gui` and desktop ID `io.github.realmadede.Root.desktop`.
4. **Manual Pages**:
   - Files: `data/man/root.1`, `data/man/root-gui.1`.
   - Tool: `man -l`.
   - Result: **0 syntax errors, clean troff formatting**.

---

## 6. Installation & Removal Lifecycle Validation

Tested using portable installer and uninstaller against an isolated target prefix (`/tmp/test-root-prefix`):
1. **Fresh Installation**:
   - Ran `install.sh`. Created `bin/root`, `bin/root-gui`, desktop file, icon, and man pages.
   - Verified `root doctor` and `root status` executed cleanly from the installed location.
2. **Explicit Target Selection**:
   - Ran `root scan` without `--path`. Verified it returned `RootError::InvalidPath` explaining that a path is required, rather than fabricating dummy synthetic fixtures.
   - Ran `root scan --path /tmp/test-root-prefix`. Audited all 19 installed files with middle-truncated formatting and zero host mutations.
3. **Live Monitoring**:
   - Ran `root monitor --path /tmp/test-root-prefix` for 2 seconds. Inotify watches established, stopped cleanly via signal.
4. **User-Level Scheduling State**:
   - Ran `root schedule status`. Verified state remains `[DISABLED by default]`.
5. **Uninstallation & State Preservation**:
   - Ran `uninstall.sh`. Verified all binaries and desktop integration assets were removed.
   - User configuration in XDG directories remained intact.
