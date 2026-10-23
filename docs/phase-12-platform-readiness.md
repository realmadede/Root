# Root — Phase 12 Platform Readiness Evaluation

This document details the readiness assessment across supported operating systems for Root v1.0.

---

## 1. Platform Readiness Tiers

Root defines three explicit levels of platform readiness:

- **Tier 1 — Validated Release**: Fully verified native release builds, package generation, desktop integration, runtime functionality, and uninstallation.
- **Tier 2 — Experimental Package**: Compiles and packages cleanly, but runtime behavior or platform-specific edge cases remain partially verified.
- **Tier 3 — Source Support Only**: Platform adapters exist and compile, but native installers, signing, and graphical desktop applications are not available.

---

## 2. Evaluation Matrix

| Platform / Environment | Readiness Classification | CLI Distribution | GUI Distribution | Scheduling Integration | Filesystem Monitoring | Packaging Formats |
|---|---|---|---|---|---|---|
| **Linux (Debian / Kali / Ubuntu)** | **Tier 1 — Validated Release** | [VERIFIED] Fully functional | [VERIFIED] GTK4 / Libadwaita | [VERIFIED] systemd user units | [VERIFIED] inotify + polling | `.deb` package, portable `.tar.gz` |
| **macOS (Darwin 12+)** | **Tier 3 — Source Support Only** | [VERIFIED] Compiles in CI | Unsupported | [VERIFIED] launchd user plists | [VERIFIED] kqueue / polling | Source build (`cargo build`) |
| **Windows (Win32 / NTFS)** | **Tier 3 — Source Support Only** | [VERIFIED] Compiles in CI | Unsupported | [VERIFIED] Task Scheduler XML | [VERIFIED] ReadDirectoryChangesW | Source build (`cargo build`) |

---

## 3. Detailed Platform Analysis

### Linux (Tier 1 — Reference Platform)
- **Host Testing Environment**: Kali GNU/Linux Rolling (Kernel 7.1.5+kali-amd64, Wayland display server, GNOME 47 desktop).
- **Runtime Dependencies**:
  - `root` (CLI): Depends strictly on `libc.so.6` and `libgcc_s.so.1`. Contains zero graphical dependencies and executes seamlessly in headless terminal sessions.
  - `root-gui` (GUI): Depends on standard GTK4 and Libadwaita desktop libraries (`libgtk-4-1`, `libadwaita-1-0`).
- **Packaging Verified**:
  - `dist/root_0.1.0-1_amd64.deb`: Built via `dpkg-deb`, validated with control archives and desktop triggers.
  - `dist/root-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`: Built with user-level installer and uninstaller.
- **Desktop Integration**:
  - Validated desktop launcher: `io.github.realmadede.Root.desktop`.
  - Scalable vector icon: `io.github.realmadede.Root.svg`.
  - AppStream catalog metadata: `io.github.realmadede.Root.metainfo.xml`.
  - Man pages: `man 1 root`, `man 1 root-gui`.

### macOS (Tier 3 — Source Support Only)
- **Status in Phase 12**: Platform inspection adapters (`crates/root-platform/src/macos/`) compile and execute unit tests in continuous integration (`macos-latest`).
- **Unverified Primitives**:
  - Native Cocoa / macOS GUI: Root GUI is written in GTK4/Libadwaita; native macOS GTK rendering requires Homebrew dependencies and is not bundled into a native `.app` bundle.
  - Apple Developer Code Signing and Notarization: Root maintains zero private signing keys in repository code; Apple Gatekeeper notarization has not been performed.
- **Release Posture**: macOS is documented as source-supported only. No pre-built `.dmg` or `.pkg` packages are published in v1.0.

### Windows (Tier 3 — Source Support Only)
- **Status in Phase 12**: Platform inspection adapters (`crates/root-platform/src/windows/`) compile and execute unit tests in continuous integration (`windows-latest`).
- **Unverified Primitives**:
  - Native Win32 / WinUI GUI: Root GUI does not compile natively for Windows without MSYS2/GTK4 runtime layers.
  - Authenticode Code Signing: Windows SmartScreen signing certificates are not embedded or configured.
  - Native Windows Installer: MSI or Inno Setup installers are not yet configured.
- **Release Posture**: Windows is documented as source-supported only. No pre-built `.msi` or `.exe` installers are published in v1.0.
