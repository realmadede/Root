# Root — Release Candidate Readiness Report (`v0.1.0-rc.1`)

## Executive Summary

This report records the final integration, verification, artifact generation, and security sign-off for Root release candidate **`v0.1.0-rc.1`** on the `main` branch.

Root is a deterministic, local-first, non-AI system resource inspection and monitoring utility for agentic coding environments. All verified GTK4/libadwaita GUI navigation repairs, ELF glibc baseline verifications, and CI/CD release workflow supply-chain security improvements have been merged into `main` via a non-fast-forward merge commit (`739ba5b`) and validated against all workspace quality and safety gates.

---

## 1. Repository

- **Repository**: `realmadede/Root`
- **Current Branch**: `main`
- **Pre-Merge Main Commit**: `f2b5184` (`chore(release): complete phase 12 release candidate verification and reconcile versioning`)
- **Integrated Branch**: `fix/gui-sidebar-navigation`
  - `a7d39ad`: `fix(gui): restore functional page navigation with left sidebar`
  - `47daba4`: `docs(release): document final release gate verification for v0.1.0-rc.1`
  - `9fafa67`: `ci(release): enforce ELF glibc verification and harden workflow supply-chain security`
- **Merge Commit SHA**: `739ba5b` (`merge: integrate verified GUI navigation and release validation`)
- **Main HEAD Commit**: `main` (merge commit `739ba5b` plus this readiness report commit)
- **Working-Tree Status**: Clean (`git status --short` reports zero untracked or modified tracked files; `dist/` and `target/` remain gitignored).
- **Release Candidate Version**: `0.1.0-rc.1` (target Git tag: `v0.1.0-rc.1`; Debian package version: `0.1.0-rc.1-1`).

---

## 2. Verification

All required quality gates, test suites, ELF binary audits, and packaging pipelines were executed directly against the integrated `main` branch:

| Verification Gate | Command Executed | Result | Details |
|---|---|---|---|
| **Code Formatting** | `cargo fmt --check` | **[VERIFIED] PASSED** | Exit code `0`; zero formatting diffs across all 5 workspace crates. |
| **Workspace Compilation** | `cargo check --workspace --all-targets --all-features` | **[VERIFIED] PASSED** | Exit code `0`; clean compilation with all features enabled. |
| **Static Analysis (Clippy)** | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **[VERIFIED] PASSED** | Exit code `0`; zero warnings across all workspace targets and features. |
| **Workspace Test Suite** | `cargo test --workspace --all-targets` | **[VERIFIED] PASSED** | **253 passed**, `0` failed, `0` ignored across unit and integration suites. |
| **Native GTK GUI Tests** | `cargo test --features gtk -p root-gui` | **[VERIFIED] PASSED** | **30 passed**, `0` failed, `0` ignored (including native GTK widget and navigation tests). |
| **Documentation Build** | `cargo doc --workspace --no-deps` | **[VERIFIED] PASSED** | Exit code `0`; Rustdoc generated cleanly with zero broken intra-doc links. |
| **Security Invariants** | `python3 .github/scripts/check_invariants.py` | **[VERIFIED] PASSED** | **12 of 12 invariants passed** (zero emojis, confidential hygiene, headless isolation, CLI mutation prohibition, SHA-pinned workflows). |
| **Release Binary Builds** | `cargo build --release -p root-cli`<br>`cargo build --release -p root-gui --features gtk` | **[VERIFIED] PASSED** | Compiled with Thin LTO, `codegen-units = 1`, and debuginfo stripping. `root --version` -> `root 0.1.0-rc.1`; `root-gui --version` -> `root-gui 0.1.0-rc.1`. |
| **ELF & glibc Verification** | `./scripts/verify-glibc.sh` | **[VERIFIED] PASSED** | `root` links exclusively to `libc.so.6` and `libgcc_s.so.1`; ELF `VERNEED` floor verified at `GLIBC_2.39`. |
| **Package Builds** | `./scripts/package-deb.sh`<br>`./scripts/package-tarball.sh` | **[VERIFIED] PASSED** | Generated `.deb` (`root:root` ownership, `Depends: libc6 (>= 2.39)`) and portable `.tar.gz` archive. |
| **Checksum Verification** | `./scripts/generate-checksums.sh`<br>`(cd dist && sha256sum -c SHA256SUMS)` | **[VERIFIED] PASSED** | Both distribution archives verified (`OK`) against `dist/SHA256SUMS`. |

---

## 3. Distribution

### Generated Release Candidate Artifacts

| Artifact Path | Format | Size (Bytes) | SHA-256 Checksum |
|---|---|---|---|
| `dist/root_0.1.0-rc.1-1_amd64.deb` | Debian Binary Package (`amd64`) | `852,784` | `683e6413e6068d315986390ed6a714dc946fd35b6888a8023584c2d64bf36d25` |
| `dist/root-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz` | Portable Gzip Tarball (`x86_64`) | `1,397,170` | `7ab325de4b99e9dd721b458e0f0057d78462822aa3c2cbaf06c0559f855c4e99` |
| `dist/SHA256SUMS` | SHA-256 Checksum Manifest | `209` | Self-verified via `sha256sum -c SHA256SUMS` |

### Verified Compatibility Requirements
- **Headless CLI (`root`)**: Requires Linux x86_64 with `glibc >= 2.39` (`libc.so.6`, `libgcc_s.so.1`). Zero display server, X11, Wayland, or GTK dependencies.
- **Desktop GUI (`root-gui`)**: Requires Linux x86_64 with `glibc >= 2.39`, `libgtk-4-1 (>= 4.12)`, `libadwaita-1-0 (>= 1.4)`, and `libglib2.0-0 (>= 2.76)` on a Wayland or X11 session.
- **Validated & Compatible Distributions**:
  - **Tier 1 (Validated Reference)**: Kali GNU/Linux Rolling (verified natively on host with GNOME Shell 50.4 / Wayland) and Ubuntu 24.04 LTS / 26.04 (verified in clean container lifecycle tests).
  - **Tier 2 (Compatible via Tarball / Source)**: Fedora 40+ and Arch Linux (`glibc >= 2.39`).
  - **Tier 3 (Source Support Only)**: macOS (`macos-latest`) and Windows (`windows-latest`) headless platform adapters compile and pass unit tests in CI; native desktop installers and GUI bundles are not provided in `v0.1.0-rc.1`.

### Known Limitations
- **Read-Only Production Operation**: Root `v0.1.0-rc.1` is strictly a resource inspection and monitoring utility. It does not delete files, move directories to quarantine, or terminate processes in production.
- **glibc < 2.39 Distribution Constraint**: Pre-compiled binaries built against modern host toolchains record weak references to `pidfd_spawnp@GLIBC_2.39` and `pidfd_getpid@GLIBC_2.39` in the ELF `VERNEED` section. Systems running older C libraries (such as Debian 12 Bookworm with `glibc 2.36` or Ubuntu 22.04 LTS with `glibc 2.35`) must build from source (`cargo build --release`) or use a Debian 12 sysroot build. The `.deb` control file explicitly declares `Depends: libc6 (>= 2.39)` to prevent broken installations on older distributions.
- **Bounded Traversal**: Filesystem scans enforce a deterministic ceiling of 250,000 entries and a maximum depth of 64 directory levels.

---

## 4. Security

1. **Read-Only Production Boundary [VERIFIED]**:
   - Prohibited CLI subcommands (`clean`, `delete`, `purge`, `quarantine`, `destroy`, `kill`, `restore`) are unconditionally intercepted and rejected with `RootError::PolicyViolation`.
   - All seven GTK4/libadwaita GUI views (`Overview`, `Resources`, `Agents`, `Processes`, `Activity`, `Schedule`, `Settings`) expose strictly read-only inspection, filtering, and user-level scheduling controls.
   - Mode B scheduled inspections (`systemd --user`) and Mode C live monitoring (`inotify` + `/proc` polling) are disabled by default and strictly read-only when enabled.
2. **Guardian Experimental Mutation Isolation [VERIFIED]**:
   - Experimental quarantine and restoration routines inside `root-guardian` require a `FixtureSandbox` proof token and `AuthorizationReceipt`, remaining gated behind `#[cfg(target_os = "linux")]` and unreachable from `root-cli` or `root-gui`.
3. **Release Workflow Supply-Chain Security [VERIFIED]**:
   - [`.github/workflows/release.yml`](file:///home/madede/BAGOMWA/PROJECTS/Root/.github/workflows/release.yml) pins every third-party GitHub Action to its full 40-character commit SHA (enforced by Invariant 12 in [`.github/scripts/check_invariants.py`](file:///home/madede/BAGOMWA/PROJECTS/Root/.github/scripts/check_invariants.py)).
   - Default workflow permissions are `contents: read`. Only the isolated `publish-draft` job receives `contents: write`.
   - All Cargo commands enforce `--locked`, tag pushes are verified against `Cargo.toml` version `0.1.0-rc.1`, SLSA build provenance is attested via `actions/attest-build-provenance`, and release creation enforces `draft: true` requiring manual human publication sign-off.
4. **Exclusion of Private Development Files [VERIFIED]**:
   - Private governance instructions (`AGENTS.md`), credentials, and session transcripts are excluded from version control and absent from both `dist/root_0.1.0-rc.1-1_amd64.deb` and `dist/root-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz`.

---

## 5. Release Readiness

### Verdict: **PASS — ready for explicit tagging authorization**

All integration checks, quality gates, GTK4 GUI navigation tests, ELF glibc compatibility verifications, and supply-chain security invariants have passed on `main`. No tags have been created and no branches or releases have been pushed, awaiting explicit human authorization.
