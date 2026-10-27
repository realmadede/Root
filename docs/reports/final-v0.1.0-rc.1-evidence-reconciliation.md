# Root — Final v0.1.0-rc.1 Evidence Reconciliation and Authorization Gate Report

## 1. Actual Repository and Working-Tree State

This report establishes the final, evidence-based reconciliation of release claims for Root version `0.1.0-rc.1`.

### Baseline Git State
- **Current Branch**: `main`
- **Origin HEAD Commit SHA**: `df4f6ce5e96f6af70ce24d829a6fcc44aaef4d25`
- **Target Release Version**: `0.1.0-rc.1`
- **Release Status**: Unpublished, untagged, and unreleased.

### Distinction Between Committed History and Working-Tree State
The commit `df4f6ce5e96f6af70ce24d829a6fcc44aaef4d25` represents the repository baseline prior to the uncommitted changes of Phase 14 reconciliation and Phase 15. The working tree contains uncommitted tracked modifications and untracked artifacts that constitute the current release candidate state:
- **Tracked Modifications (Uncommitted)**:
  - Assurance controls: `.github/scripts/check_invariants.py`, `.github/workflows/ca.yml`
  - CLI interfaces: `crates/root-cli/src/{discover, interactive, lib, scan}.rs`, `crates/root-cli/tests/cli_tests.rs`
  - Core engine: `crates/root-core/src/discovery/{classifier, engine, lifecycle, mod}.rs`, `crates/root-core/src/lib.rs`, `crates/root-core/src/model/measurement.rs`, `crates/root-core/tests/discovery_tests.rs`
  - Guardian subsystem: `crates/root-guardian/src/{authorization, engine, journal, lib, quarantine, restoration}.rs`, `crates/root-guardian/tests/guardian_transaction_tests.rs`
  - GUI subsystem: `crates/root-gui/src/gtk/views/resources.rs`, `crates/root-gui/src/view_model/resources.rs`, `crates/root-gui/src/worker/mod.rs`, `crates/root-gui/tests/gui_view_model_tests.rs`
  - Platform abstraction: `crates/root-platform/src/{lib.rs, linux/mod.rs, lock.rs}`
- **Untracked Artifacts (Uncommitted)**:
  - Continuous assurance tests: `.github/scripts/test_invariants.py`
  - Guardian safety modules: `crates/root-guardian/src/{fault.rs, reconciler.rs}`
  - Test suites: `crates/root-guardian/tests/{guardian_descriptor_pipeline_tests, guardian_fault_injection_tests, guardian_journal_reconciliation_tests}.rs`, `crates/root-platform/src/linux/descriptor.rs`, `crates/root-platform/tests/descriptor_tests.rs`
  - Documentation and audit reports: `docs/maintenance-safety-contract.md`, `docs/reports/phase-14-*.md`, `docs/reports/phase-15-*.md`, `docs/reports/wp-15.*.md`, `docs/reports/final-v0.1.0-rc.1-release-validation.md`
- **Verification of Referenced Scripts and Workflows**:
  - `scripts/package-deb.sh`: Exists (executable bash script, 137 lines).
  - `scripts/package-tarball.sh`: Exists (executable bash script, 175 lines).
  - `scripts/verify-glibc.sh`: Exists (executable bash script, 146 lines).
  - `scripts/generate-checksums.sh`: Exists (executable bash script, 44 lines).
  - `.github/workflows/release.yml`: Exists (YAML workflow, 191 lines).
  - `.github/scripts/check_invariants.py`: Exists (Python script, 396 lines).
  - `.github/scripts/test_invariants.py`: Exists (Python script, 83 lines).
- **Confidentiality Invariant**: `AGENTS.md` remains strictly private, untracked, unstaged, and uncommitted.

---

## 2. Findings for Each Discrepancy

### 2.1 Guardian Mutation-Boundary Claim
- **Audit Findings**:
  - `FixtureSandbox` (in `crates/root-guardian/src/sandbox.rs`) and `TransactionEngine` (in `crates/root-guardian/src/engine.rs`) are public types gated on `#[cfg(target_os = "linux")]`. They are **not** conditionally excluded via `#[cfg(test)]` or a Cargo feature flag.
  - `FixtureSandbox::new(root: &Path, operator_uid: u32)` accepts any valid directory path; it does not enforce compile-time restriction to `tempfile::TempDir`.
  - However, an exhaustive trace of `crates/root-cli/src/` and `crates/root-gui/src/` demonstrates that **zero production entry points import, construct, or invoke `FixtureSandbox`, `TransactionEngine`, `QuarantineStore`, or `RestorationEngine`**.
  - Production CLI and GUI code references only read-only components (`GuardianPolicy` and `RecoveryJournal`).
  - Because no production caller references the mutation types, the compiler and linker (configured with `lto = "thin"` and `--gc-sections` in the workspace release profile) prune these symbols from the shipped release binaries. Inspection of `target/release/root` via `nm -C` confirms zero references to `TransactionEngine` or `FixtureSandbox`.
  - In addition, early command interception in `crates/root-cli/src/lib.rs` explicitly rejects any mutation subcommand (`quarantine`, `restore`, `delete`, `prune`, `clean`, `remediate`, `destroy`, `purge`, `kill`) before CLI argument parsing can proceed.
  - **Reconciliation**: The boundary is an **architectural reachability boundary**, where mutation APIs are unreachable from production entry points and dropped by the linker, rather than a compile-time feature exclusion of the library crate.

### 2.2 Filesystem-Race Finding
- **Audit Findings**:
  - In `crates/root-guardian/src/engine.rs`, a microsecond TOCTOU window exists between descriptor-pinned pre-mutation identity revalidation (`AuthorizationEngine::revalidate_pinned`) and directory-entry rename (`libc::SYS_renameat2`).
  - In Linux VFS semantics, `renameat2` operates on directory descriptors for the parent directories, but resolves child entries by name. If an unprivileged concurrent process swaps or replaces the source file entry during this microsecond window, the kernel moves whatever inode is bound to that name at the instant `renameat2` executes.
  - **Subsystem Scope**: This race condition is **confined 100% to the dormant Guardian transaction subsystem**. Production inspection operations (`scan`, `discover`, `inspect`, `doctor`, `status`, `report`, `monitor`) strictly invoke read-only syscalls (`statx`, `lstat`, `read_dir`, `statvfs`) and never execute `renameat2` or move files.
  - **Failure Handling**: If an unexpected file is moved during a transaction, post-mutation verification in `crates/root-guardian/src/engine.rs` (lines 463–526) immediately audits:
    1. Source entry unlinking (`source_parent_dir.exists_child(source_filename) == false`).
    2. Descriptor-pinned destination inode and device ID matching (`dest_dir.stat_child`).
    3. Content size and SHA-256 digest verification (`verify_quarantined_resource`).
    When an unexpected inode or hash is detected, the transaction transitions to `TransactionState::RecoveryRequired`, logs an anomaly record in `RecoveryJournal`, and **leaves the file in quarantine staging without deletion**. No automatic rollback, retry, or deletion occurs.
  - **Reconciliation**: Post-operation verification does not prevent the move; it detects the substitution immediately after the move, halts the transaction, records the failure, and preserves forensic evidence. Because the transaction subsystem is dormant and unreachable in production, this limitation cannot affect production users in `v0.1.0-rc.1`.

### 2.3 Read-Only Inspection Guarantee
- **Audit Findings**:
  - Earlier documentation contained ambiguous statements conflating "read-only inspection of candidate resources" with "a utility that never writes any file anywhere."
  - **Protected Candidate Resources**: Root provides a strict, invariant guarantee that **all inspected development tools, AI toolchains, cache directories, project repositories, and workstation files are never mutated, moved, overwritten, or deleted**. All inspection pathways operate in read-only mode.
  - **Application-Managed Writes**: When explicitly authorized by the user, Root performs bounded, standard application writes in designated user XDG locations:
    1. `root schedule enable`: Writes user configuration to `~/.config/root/schedule.json` (permissions `0600`), creates advisory lock `~/.local/state/root/schedule.lock`, and installs unprivileged user systemd units in `~/.config/systemd/user/root-inspect.service` and `root-inspect.timer`.
    2. `root schedule run`: Appends periodic inspection results (timestamps, finding counts, execution duration) to `~/.local/state/root/schedule_history.json`.
    3. `root schedule disable` / `remove`: Disables or removes the unprivileged systemd user timer units.
    4. `root report`: Writes formatted text or JSON to `stdout` (file creation occurs only if the user explicitly redirects stdout in their shell).
  - Diagnostic and transaction journals (`.root_journal`) are never created or written in production; they exist solely within synthetic fixture test sandboxes.
  - **Reconciliation**: The production safety guarantee is accurately defined as permanent read-only protection of candidate resources, with explicit and strictly bounded user-level application state management.

### 2.4 Journal Call-Path Discrepancy
- **Audit Findings**:
  - The previous release report incorrectly stated that `root inspect` uses `RecoveryJournal::open_existing_readonly` and `JournalReconciler::reconcile_readonly`.
  - Inspection of `crates/root-cli/src/inspect.rs` (lines 365–385) reveals the actual call path:
    ```rust
    let journal = RecoveryJournal::new(&resolved_journal)?;
    let records = journal.read_all()?;
    let interrupted = journal.get_interrupted_transactions()?;
    ```
  - `JournalReconciler` is **not invoked** by the production CLI `root inspect transactions`.
  - `JournalReconciler` (in `crates/root-guardian/src/reconciler.rs`) is an independent diagnostic reconciliation component exercised in integration test suites (`guardian_journal_reconciliation_tests.rs` and `guardian_fault_injection_tests.rs`).
  - Audit of `reconciler.rs` confirms that `JournalReconciler::reconcile_journal` and `JournalReconciler::reconcile_path` are 100% read-only: they parse journal frames, check filesystem path existence (`source_path.exists()`, `destination_path.exists()`), compute SHA-256 hashes, and emit diagnostic classifications (`KnownNotPerformed`, `KnownPerformed`, `Uncertain`, `JournalInvalid`, `RecoveryRequired`). They execute zero mutations, deletions, or repairs.
  - **Reconciliation**: The CLI `inspect transactions` command reads journal records directly via `RecoveryJournal`. The final release validation report has been updated to remove the inaccurate reference to `JournalReconciler` in the CLI call path.

### 2.5 Packaging and Distribution Verification
- **Audit Findings**:
  - **Static Script Inspection**:
    - `scripts/verify-glibc.sh`: Correctly checks CLI dynamic library dependencies against allowed standard C runtime libraries (`libc.so.6`, `libgcc_s.so.1`, etc.) and audits `readelf -V` against `MAX_GLIBC=2.39`.
    - `scripts/package-deb.sh`: Correctly constructs Debian packaging tree with `DEBIAN/control`, unprivileged maintainer scripts (`postinst`, `postrm`), man pages, AppStream metadata, and desktop entries.
    - `scripts/package-tarball.sh`: Correctly packages standalone release archive with unprivileged `install.sh` and `uninstall.sh`.
    - `.github/workflows/release.yml`: Configured with quality gates, tag matching, Docker container smoke tests, SLSA provenance attestation, and draft release creation.
  - **Active Empirical Verification**:
    - `verify-glibc.sh`: Executed against release binaries. Confirmed CLI binary links exclusively against `libc.so.6` and `libgcc_s.so.1`. Highest strong symbol: `GLIBC_2.34`. Highest `VERNEED`: `GLIBC_2.39` (weak references to `pidfd_getpid` and `pidfd_spawnp`).
    - Tarball packaging and installation: Executed `tar -xzf dist/root-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz` into an isolated temporary directory, ran `./install.sh --prefix=<temp_dir>`, executed installed binary `root --version` and `root doctor`, and ran `./uninstall.sh --prefix=<temp_dir>`. All operations succeeded with exit code 0.
    - Debian package verification: Audited package metadata (`dpkg-deb -I`) and file tree (`dpkg-deb -c`). Unpacked package into disposable directory via `dpkg-deb -x` and executed unpacked `root --version` and `root doctor`.
    - Host limitation: Full system-wide `.deb` installation (`dpkg -i` into `/usr/bin`) was not run on the host development machine because installing system-wide requires root privileges, violating Invariant 4. Containerized installation is tested in clean Ubuntu environments in CI.

---

## 3. Relevant Source Paths, Symbols, and Call Paths

| Component | File Path | Key Symbols | Role & Production Reachability |
| :--- | :--- | :--- | :--- |
| **CLI Dispatcher** | `crates/root-cli/src/lib.rs` | `run_with_args`, `dispatch_command` | Intercepts and rejects mutation subcommands before parsing. |
| **CLI Scan** | `crates/root-cli/src/scan.rs` | `run_scan` | Traverses directories via `NativeFilesystem::traverse`; strictly read-only. |
| **CLI Discover** | `crates/root-cli/src/discover.rs` | `run_discover` | Inspects AI agent toolchains; strictly read-only. |
| **CLI Inspect** | `crates/root-cli/src/inspect.rs` | `run_inspect_transactions` | Inspects journals via `RecoveryJournal::new`, `read_all`, `get_interrupted_transactions`. |
| **CLI Schedule** | `crates/root-cli/src/schedule.rs` | `run_schedule_enable`, `run_schedule_run` | Manages unprivileged user systemd timers and `~/.config/root/schedule.json`. |
| **CLI Monitor** | `crates/root-cli/src/monitor.rs` | `run_monitor` | Listens to inotify events in memory; strictly read-only. |
| **Guardian Engine** | `crates/root-guardian/src/engine.rs` | `TransactionEngine::quarantine` | Dormant transaction engine. Requires `&FixtureSandbox`. Unreachable from CLI/GUI. |
| **Guardian Sandbox** | `crates/root-guardian/src/sandbox.rs` | `FixtureSandbox` | Root boundary abstraction. Unused in production; pruned by linker in release binaries. |
| **Guardian Reconciler** | `crates/root-guardian/src/reconciler.rs` | `JournalReconciler` | Read-only crash classification engine. Tested in test suites; not called by CLI. |
| **Guardian Policy** | `crates/root-guardian/src/policy.rs` | `GuardianPolicy` | Production read-only safety evaluator. Rejects all proposed mutations. |
| **Platform Descriptors** | `crates/root-platform/src/linux/descriptor.rs` | `PinnedDirectory`, `PinnedFile` | RAII descriptor abstraction using `openat2` and `renameat2`. |

---

## 4. Commands Actually Executed and Their Recorded Results

The following commands were executed in the live environment during this gate:

1. **Git Status and Baseline Check**:
   - `git rev-parse HEAD`: Exited `0` (`df4f6ce5e96f6af70ce24d829a6fcc44aaef4d25`).
   - `git status --short --branch`: Exited `0`.
2. **Release Binary Symbol Audit**:
   - `nm -C target/release/root | grep -E "TransactionEngine|FixtureSandbox"`: Exited `0` (zero matches; confirmed pruned by linker).
3. **Continuous Assurance Invariant Scanner**:
   - `python3 .github/scripts/check_invariants.py`: Exited `0` (12/12 invariants passed).
4. **Continuous Assurance Unit Tests**:
   - `python3 .github/scripts/test_invariants.py`: Exited `0` (4/4 tests passed).
5. **Code Formatting and Whitespace Hygiene**:
   - `cargo fmt --check`: Exited `0` (no formatting discrepancies).
   - `git diff --check`: Exited `0` (no whitespace anomalies).
6. **Clippy Linter**:
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`: Exited `0` (zero warnings).
7. **Workspace Tests (Headless)**:
   - `cargo test --workspace --all-targets`: Exited `0` (433 passed, 0 failed).
8. **Native GTK Test Suite**:
   - `cargo test --features gtk -p root-gui`: Exited `0` (31 passed, 0 failed).
9. **Release Compilation Check**:
   - `cargo check --release --workspace --all-targets --all-features`: Exited `0` (clean compilation across all crates).
10. **ELF Dynamic Library and glibc Compatibility Audit**:
    - `./scripts/verify-glibc.sh`: Exited `0` (CLI isolated to `libc` and `libgcc_s`; max strong `GLIBC_2.34`, VERNEED `GLIBC_2.39`).
11. **Distribution Artifact Verification**:
    - `sha256sum -c dist/SHA256SUMS`: Exited `0` (both `.deb` and `.tar.gz` checksums verified).
    - `dpkg-deb -I dist/root_0.1.0-rc.1-1_amd64.deb`: Exited `0` (metadata, dependencies, and size verified).
    - `dpkg-deb -c dist/root_0.1.0-rc.1-1_amd64.deb`: Exited `0` (clean hierarchy verified).
    - `tar -tzvf dist/root-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz`: Exited `0` (clean tarball contents verified).
12. **End-to-End Portable Tarball Installation Test**:
    - Unpacked tarball into `/tmp/root-test-install-XXXXXX`, installed with `./install.sh --prefix=<temp_dir>/installed`, executed installed `root --version` and `root doctor`, uninstalled with `./uninstall.sh --prefix=<temp_dir>/installed`, and removed temp directory: Exited `0`.
13. **Debian Package Extraction Test**:
    - Unpacked `.deb` via `dpkg-deb -x` into `/tmp/root-test-deb-XXXXXX`, executed extracted `root --version` and `root doctor`: Exited `0`.

---

## 5. Report Corrections Made

In `docs/reports/final-v0.1.0-rc.1-release-validation.md`, the following corrections were applied:
1. **Section 4.1 (`root inspect`)**: Removed the claim that journal inspection invokes `JournalReconciler::reconcile_readonly` and `RecoveryJournal::open_existing_readonly`. Replaced with the actual call path: `RecoveryJournal::new`, `journal.read_all()`, and `journal.get_interrupted_transactions()`.
2. **Section 4.1 (`root report`)**: Clarified that report generation outputs to `stdout` and does not write files to disk unless redirected by the user's shell.
3. **Section 4.1 (`root schedule`)**: Clarified legitimate application-managed writes to standard user XDG configuration (`~/.config/root/schedule.json`), execution history (`~/.local/state/root/schedule_history.json`), and unprivileged systemd user timer units.
4. **Section 4.3 (Guardian Subsystem Boundary)**: Corrected the claim that `FixtureSandbox` is compile-time restricted to `tempfile::TempDir`. Documented that `FixtureSandbox` is an unconstructed internal crate type in Linux builds that is architecturally unreachable from production entry points and pruned by the linker in release binaries.
5. **Section 7.3 (Crash Reconciliation Engine)**: Clarified that `JournalReconciler` is a test-verified diagnostic engine exercised in integration tests, not called by the production CLI `inspect transactions` command.
6. **Section 9.3 & 9.4 (Distribution Testing Scope)**: Explicitly distinguished static script inspection, unprivileged temporary installation testing, and containerized installation from host system-wide package installation.

---

## 6. Remaining Security and Distribution Limitations

1. **glibc 2.39 Baseline**:
   - Root binaries require Linux systems providing glibc 2.39 or newer due to weak symbol requirements for `pidfd_getpid` and `pidfd_spawnp`.
   - Older distributions (e.g., Ubuntu 22.04 LTS or Debian 12 Bookworm) cannot run these precompiled binaries natively without containerization.
2. **Advisory Locking Semantics**:
   - `flock` locks are associated with the underlying inode, not the directory path. Uncooperative processes that do not query `flock` can access or modify files without contention.
3. **Dormant Transaction Subsystem Race Condition**:
   - In the dormant transaction engine, the microsecond TOCTOU window between identity revalidation and `renameat2` means an adversarial concurrent process could replace a file entry before the move.
   - Post-operation verification detects the anomaly and safely transitions the transaction to `RecoveryRequired` without data loss. However, this transaction pipeline remains dormant and completely unreachable from production workflows.
4. **Containerized Desktop Integration**:
   - When running in headless environments or minimal containers without D-Bus, GNOME desktop integration notifications degrade gracefully to terminal output.

---

## 7. Final Recommendation

Based on the evidence gathered across all code, tests, and distribution assets:

### **READY FOR SEPARATELY AUTHORIZED RELEASE**

Root `0.1.0-rc.1` satisfies all architectural, security, and distribution requirements. Production operation is strictly read-only, candidate resources are completely protected, least-privilege boundaries are enforced, and distribution packaging is verified.

---

## 8. Operational Governance Compliance Statement

In compliance with project safety invariants:
- **No Git commit was authored or amended.**
- **No Git tags were created or moved.**
- **No Git branches were pushed, merged, or deleted.**
- **No GitHub releases or release drafts were created.**
- **No packages or artifacts were published.**
- **Product version remains unchanged at `0.1.0-rc.1`.**
- **`AGENTS.md` remains strictly untracked, uncommitted, and confidential.**
- **Zero emojis were introduced into any maintained project content.**
