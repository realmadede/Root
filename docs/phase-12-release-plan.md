# Root — Phase 12 Release Plan
## Production Hardening, Packaging, and Public Distribution

## 1. Executive Summary

Phase 12 transitions Root from an internally verified research and inspection prototype into an installable, publicly distributable v1.0 release candidate.

Root's primary mission in v1.0 is to deliver a secure, deterministic, local-first resource inspection utility for Linux developer workstations running agentic workflows. All production mutation features remain permanently disabled.

---

## 2. Release Objectives & Scope

| Objective | Target Scope | Status |
|---|---|---|
| **Deterministic Release Profile** | Reproducible builds via `profile.release` (LTO, codegen-units=1, debuginfo strip) | [VERIFIED] Implemented |
| **Linux Native Packaging** | Debian package (`.deb`) with full desktop integration, icons, and AppStream metadata | [VERIFIED] Implemented |
| **Portable Linux Distribution** | Standalone tarball (`.tar.gz`) with user-level installer (`install.sh`) | [VERIFIED] Implemented |
| **Desktop Integration** | XDG `.desktop` file, scalable SVG icon, manual pages (`man 1 root`, `man 1 root-gui`) | [VERIFIED] Implemented |
| **Safe Target Selection** | Eliminate silent fallback to development repositories or synthetic fixture creation | [VERIFIED] Remediated |
| **Cryptographic Integrity** | SHA-256 release checksum manifest (`dist/SHA256SUMS`) | [VERIFIED] Implemented |
| **Automated Release CI** | Controlled workflow (`.github/workflows/release.yml`) gated by manual trigger/tag | [VERIFIED] Implemented |
| **Documentation Suite** | Installation, uninstallation, security review, and platform readiness documentation | [VERIFIED] Implemented |

---

## 3. Platform Distribution Strategy

Root categorizes target platforms into three strict operational tiers:

### Tier 1 — Validated Release Target: Linux (x86_64)
- **Target OS**: Debian, Kali Linux, Ubuntu, and Debian-derived desktop distributions.
- **Components**:
  - `root`: Headless CLI executable (depends only on `libc`).
  - `root-gui`: Desktop application (GTK4 + Libadwaita).
- **Packaging**: Official `.deb` package and portable `.tar.gz` distribution.
- **Verification**: End-to-end verified on Kali Linux with GNOME/Wayland.

### Tier 2 — Experimental Package Target: None in v1.0
- No platform is currently designated as Tier 2.

### Tier 3 — Source Support Only: macOS & Windows
- **macOS (Darwin)**: Source-supported platform adapter. Compiles and unit tests in CI; macOS GUI and signed `.app` bundle are deferred.
- **Windows (NTFS / Win32)**: Source-supported platform adapter. Compiles and unit tests in CI; native installer and Windows GUI are deferred.

---

## 4. Release Candidate Timeline and Phase Gates

1. **Gate 1: Core & Invariant Verification** (Completed)
   - 250 workspace tests pass cleanly.
   - 11 repository invariants pass with zero violations.
2. **Gate 2: Package Validation & Desktop Integration** (Completed)
   - `.deb` and `.tar.gz` packages generated and validated via `dpkg-deb`.
   - Desktop file passes `desktop-file-validate`.
   - Man pages pass `man -l` syntax validation.
3. **Gate 3: Performance & Responsiveness Baseline** (Completed)
   - CLI cold launch: < 5 ms.
   - GUI cold launch: ~500 ms on Wayland.
   - GUI idle RSS: ~127 MiB; steady-state idle CPU: ~1.0%.
4. **Gate 4: Human Review & Release Tagging** (Awaiting Review)
   - Author review of Phase 12 completion report and artifacts.
   - Authorized tag creation (`v0.1.0` or `v1.0.0-rc1`).
