# Root: Phase 01 Completion Report
## Core Domain Models, Platform Traits, and Synthetic Fixtures

**Project Name**: Root  
**Category**: Secure System Resource Management  
**Current Phase**: Phase 01 (Core Models, Platform Traits, & Fixtures) — **COMPLETED**  
**Development Branch**: `feat/phase-01-core-foundation`  
**Base Commit**: `9023a52` (`docs/phase-00-foundation`)  
**Design Reference Commit SHA**: `2d228630ba1446365f614a108cb8252f1feda202`  
**Host Environment**: Kali GNU/Linux Rolling 2026.3, Kernel 7.1.5+kali-amd64 x86_64, Rust 1.99.0  

---

## 1. Executive Summary

Phase 01 of Project **Root** has established the operational software engineering foundation of the system. Transitioning from the theoretical research of Phase 00, Phase 01 establishes a pure Rust modular architecture, deterministic domain models, read-only platform abstraction traits, an independently testable security policy engine (`root-guardian`), comprehensive synthetic adversarial fixtures, and a minimal unprivileged CLI (`root doctor`, `root scan --dry-run`).

In strict compliance with the **Phase 01 Read-Only Invariant**, zero destructive actions, file deletions, process terminations, or system mutations exist in the codebase. All mutation requests are explicitly rejected by `root-guardian`.

All 13 security, model, and fixture tests pass cleanly in local CI, and the workspace compiles with zero errors and zero warnings under strict `clippy -- -D warnings` and `rustfmt`.

---

## 2. Branch and Commit Information

- **Previous Baseline Branch**: `docs/phase-00-foundation` (Commit `9023a52`)
- **Current Active Development Branch**: `feat/phase-01-core-foundation`
- **GPG/SSH Commit Signing**: Configured and active.

---

## 3. Files Created and Modified

### Modified Documentation (Incorporating 7 Architectural Corrections):
- `ARCHITECTURE.md`: Documented non-atomicity of cross-filesystem renames (`EXDEV`), restoration failure modes, process parentage nuances, hard link mechanics, and transactional robustness.
- `SECURITY.md`: Updated threat boundaries to include cross-device boundaries, ownership verification, and restoration conflict safeguards.
- `docs/cleanup-policy.md`: Codified cross-filesystem copy-verify-unlink requirements, restoration conflict management, hard link mechanics, multi-factor process abandonment, and agent lifecycle evidence.
- `docs/threat-model.md`: Detailed concurrent filesystem mutations, cross-filesystem transaction states, and hard link unlinking dynamics.

### Workspace & Infrastructure Created:
- `Cargo.toml`: Root Cargo workspace definition with resolver version 2.
- `Cargo.lock`: Pinned dependency graph.
- `.gitignore`: Ignore rules for build target artifacts.

### Crate Implementations Created:
- **`crates/root-core/`**:
  - `Cargo.toml`
  - `src/lib.rs`
  - `src/error.rs`: Strongly-typed `RootError` enum with `thiserror`.
  - `src/model/mod.rs`
  - `src/model/resource.rs`: `ResourceId`, `ResourceCategory`, `FileType`, `ResourceLocation`, `ResourceMetadata`, `ResourceOwnership`, `ResourceCandidate`.
  - `src/model/process.rs`: `ProcessState`, `ProcessIdentity`, `ProcessCandidate`.
  - `src/model/measurement.rs`: `StorageMeasurement`, `MemoryMeasurement`, `SystemMemorySummary`, `PressureMetrics`.
  - `src/model/provenance.rs`: `EvidenceProvenance`, `ConfidenceLevel`, `FindingEvidence`.
  - `src/model/classification.rs`: `ProtectionTier`, `ProposedAction`, `RejectionReason`, `SafetyDecision`.
  - `src/model/capabilities.rs`: `PlatformCapabilities`.
  - `src/model/finding.rs`: `FindingTarget`, `ScanFinding`, `ScanSummary`, `ScanReport`.
  - `src/fixtures/mod.rs`
  - `src/fixtures/synthetic.rs`: Full `SyntheticFixture` generator.
  - `tests/security_tests.rs`: Comprehensive integration test suite.
- **`crates/root-platform/`**:
  - `Cargo.toml`
  - `src/lib.rs`
  - `src/traits.rs`: `EnvironmentProvider`, `FilesystemProvider`, `ProcessProvider`, `ResourceAccountant`, `FilesystemWatcher`.
  - `src/linux/mod.rs`
  - `src/linux/environment.rs`: `LinuxEnvironment` implementation.
  - `src/linux/filesystem.rs`: `LinuxFilesystem` read-only implementation.
  - `src/linux/process.rs`: `LinuxProcess` unprivileged `/proc` parser.
  - `src/linux/accountant.rs`: `LinuxAccountant` memory and PSI parser.
  - `src/mock/mod.rs`
  - `src/mock/mock_platform.rs`: In-memory mock platform for multi-platform tests.
- **`crates/root-guardian/`**:
  - `Cargo.toml`
  - `src/lib.rs`
  - `src/policy.rs`: `GuardianPolicy` safety evaluator.
- **`crates/root-cli/`**:
  - `Cargo.toml`
  - `src/main.rs`: CLI entrypoint with `clap`.
  - `src/doctor.rs`: `root doctor` implementation.
  - `src/scan.rs`: `root scan --dry-run` and JSON reporter.

---

## 4. Rust Workspace Structure

The workspace follows a strict modular separation of concerns:

```
crates/
├── root-core/          # Pure domain models, policies, error types, synthetic fixtures
├── root-platform/      # Platform abstraction traits and unprivileged Linux /proc backends
├── root-guardian/      # Safety policy evaluation engine (read-only enforcement)
└── root-cli/           # Unprivileged command-line interface (doctor, scan --dry-run)
```

### Dependency Audit:
Every third-party crate was scrutinized for least privilege and necessity:
- `serde` (v1.0) & `serde_json` (v1.0): Structured JSON reporting without runtime network or AI dependencies.
- `thiserror` (v2.0): Zero-cost typed error handling without panics.
- `clap` (v4.5): Command-line argument parsing with declarative derive macros.
- `tempfile` (v3.27): Isolated ephemeral directory creation for synthetic testing.
- **Zero C-library dependencies**: Native Linux metadata is extracted via standard POSIX extensions in the standard library (`std::os::unix::fs::MetadataExt`).

---

## 5. Implemented Domain Models

1. **Resource Identity & Ownership**:
   - `ResourceId`: Hashed identifier based on path, device ID, and inode (`path:dev:ino`).
   - `ResourceLocation`: Tracks nominal path, canonicalized path, device ID (`st_dev`), and inode (`st_ino`).
   - `ResourceOwnership`: Validates user UID/GID and flags whether the resource belongs to the current user.
2. **Resource Categories**:
   - `PackageCache`, `BuildArtifact`, `AgentScratchpad`, `DiagnosticLog`, `SessionState`, `UserDocument`, `SystemFile`, `Unknown`.
3. **Storage & Memory Measurements**:
   - `StorageMeasurement`: Distinguishes apparent bytes, physical allocated blocks, sparse file status, and multi-link shared bytes (`st_nlink > 1`).
   - `MemoryMeasurement`: Captures RSS, PSS (`/proc/[pid]/smaps_rollup`), USS (Private Clean + Private Dirty), and Swap.
4. **Evidence & Provenance**:
   - `EvidenceProvenance`: Tracks whether a fact is a `VerifiedFact`, `DirectInspection`, `StructuralMatch`, `HeuristicDerivation`, or `ToolFingerprint`.
   - `ConfidenceLevel`: Ranked enum (`VerifiedFact` down to `Unknown`).
5. **Classifications & Safety Decisions**:
   - `ProtectionTier`: 4-tier model (`StrictlyProtected`, `UserConfirmRequired`, `ObsoleteTransient`, `SafeRecoverable`, `NonActionable`).
   - `SafetyDecision`: Strongly-typed `Allowed` vs `Rejected { reason: RejectionReason, explanation: String }`.
6. **Privacy Invariant**:
   - Models intentionally contain **zero file content fields**. Serialization to JSON never dumps or logs private file text.

---

## 6. Platform Abstraction Interfaces

Four core traits mediate all operating system interactions:

1. **`EnvironmentProvider`**: Exposes standard XDG base directory paths and invoking user UID/GID.
2. **`FilesystemProvider`**: Exposes non-symlink-following metadata (`lstat`), canonicalization, device ID verification, and inode extraction.
3. **`ProcessProvider`**: Enumerates PIDs, extracts multi-factor process identity (`/proc/[pid]/stat`, `/proc/[pid]/cmdline`, `/proc/[pid]/status`), and calculates memory via `smaps_rollup`.
4. **`ResourceAccountant`**: Reads host memory metrics (`/proc/meminfo`), PSI pressure stall rates (`/proc/pressure/memory`), and platform capabilities (`has_pidfd`, `has_cgroups_v2_psi`, `has_smaps_rollup`, `has_openat2`).

---

## 7. Guardian Policy Behavior

`GuardianPolicy` acts as the deterministic gatekeeper for all operations:
- **Phase 01 Read-Only Invariant**: All mutating actions (`Quarantine`, `Prune`, `TerminateGraceful`) are unconditionally rejected with `RejectionReason::Phase01ReadOnlyPolicy`.
- **Tier 1 Protection**: Rejects actions targeting `StrictlyProtected` resources.
- **Ownership Verification**: Rejects operations where `resource.uid != current_user_uid` (`RejectionReason::OwnershipMismatch`).
- **Protected Location Verification**: Rejects operations targeting `/etc`, `/usr`, `/boot`, `/sys`, `/proc`, `/dev`, `~/.ssh`, `~/.gnupg`, `oauth_creds.json`, or `.key` files.
- **Path Sanitization**: Rejects paths containing null bytes or invalid traversal sequences.

---

## 8. Synthetic Fixture Coverage

`SyntheticFixture` provides a hermetic sandbox generated in `/tmp` containing diverse test conditions:
1. **Normal temporary files**: Ephemeral cache buffers and lock files.
2. **Protected user files**: Simulated `.bashrc`, `.ssh/id_ed25519` key, and `Documents/`.
3. **Symbolic links**:
   - Valid relative link (`valid_rel.txt`).
   - Dangling link pointing to nonexistent file (`dangling.txt`).
   - Jail escape link pointing to `/etc/passwd` (`jail_escape.txt`).
   - Circular loop (`loop_a/link_to_b -> loop_b/link_to_a`).
4. **Hard links**: Triple-linked file (`st_nlink == 3`) sharing identical inode.
5. **Deep nesting**: 12 levels of directory hierarchy.
6. **Agent simulations**:
   - Antigravity: `brain/` active session with `transcript.jsonl`, abandoned session with `scratch/` and `.system_generated/steps/1/output.txt`, diagnostic logs, `oauth_creds.json`.
   - Claude Code: `sessions/` with `.json` and `.key`, empty `session-env/<uuid>` leaked directories, and `shell-snapshots/`.
   - Workspaces: Cargo `target/debug`, npm `node_modules/lodash`, and `.git/HEAD`.
7. **Unusual names**: Space characters, Unicode (`файл-тест-отчет.dat`), quotes (`"quoted_name".txt`), leading dashes (`--leading-dashes.tmp`), newlines (`\n`).
8. **Empty directories**: Orphan empty folders and nested empty folders.
9. **Permission scenarios**: Read-only directory (`0o555`).

---

## 9. CLI Capabilities

The `root` CLI binary provides two core subcommands in Phase 01:

1. **`root doctor`**:
   - Reports operating system, kernel release, and user UID/GID.
   - Audits Linux kernel interfaces: `pidfd`, cgroups v2 PSI, `smaps_rollup`, `openat2`.
   - Displays host memory accounting (Total, Available, Cached, Swap).
   - Displays real-time PSI memory pressure stalls.
   - Completely read-only; inspects zero private user files.
2. **`root scan --dry-run [--path <DIR>] [--json]`**:
   - Scans specified path (or generates synthetic fixture if omitted).
   - Classifies discovered artifacts into the 4 tiers.
   - Evaluates each candidate through `GuardianPolicy`.
   - Formats results into a clean table with tabular figures, middle-truncated paths, and explicit rejection explanations.
   - Supports `--json` for machine-readable JSON output.

---

## 10. Test Results & Quality Verification

All quality checks were executed and verified:

```
$ cargo fmt --check
(Clean - 0 diffs)

$ cargo check --workspace --all-targets
Finished `dev` profile in 0.79s (0 errors, 0 warnings)

$ cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile in 0.27s (0 errors, 0 warnings)

$ cargo test --workspace
running 13 tests across 4 test suites:
- test fixtures::synthetic::tests::test_synthetic_fixture_generation ... ok
- test test_ownership_mismatch_rejection ... ok
- test test_process_identity_and_abandonment_logic ... ok
- test test_protected_locations_and_credentials_rejection ... ok
- test test_protection_defaults ... ok
- test test_resource_accounting_multi_link_and_sparse ... ok
- test test_serialization_safety_no_file_content_leakage ... ok
- test test_unsupported_operations_rejected_in_phase01 ... ok
- test test_synthetic_fixtures_adversarial_coverage ... ok
- test policy::tests::test_allows_inspect_on_valid_resource ... ok
- test policy::tests::test_rejects_foreign_ownership ... ok
- test policy::tests::test_phase01_rejects_all_mutations ... ok
- test policy::tests::test_rejects_protected_locations ... ok

test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

---

## 11. Security Verification

- **Zero Elevated Privileges**: Verified running purely as UID 1000 without `sudo` or capabilities.
- **Sandbox Boundary Enforcement**: `SyntheticFixture::assert_within_bounds()` confirms tests cannot traverse outside temporary test directories.
- **Serialization Privacy**: Verified that JSON output contains only structural metadata and zero file contents.
- **Unicode Resilience**: Verified that filenames with multibyte UTF-8 characters and newlines are processed without panics.

---

## 12. Architectural Corrections Established

1. **Cross-Filesystem Rename Non-Atomicity**: Acknowledged `renameat2` failure across mount points (`EXDEV`) and designed verified copy-check-unlink transaction states.
2. **Restoration Uncertainty**: Documented restoration conflict handling for occupied paths and unmounted filesystems.
3. **Hard Link Dynamics**: Confirmed that unlinking a hard link does not corrupt remaining links; documented multi-link storage accounting rules.
4. **Process Parentage (PPID == 1)**: Corrected assumption that PID 1 reparenting implies abandonment; codified multi-factor corroboration.
5. **Agent File Lifecycle Evidence**: Mandated closed session checks and git status verification before treating agent scratchpads as recoverable.
6. **Independent Identity & Ownership**: Independent validation of filesystem metadata, process metadata, and UID ownership.
7. **Transactional Robustness**: Codified metadata preservation requirements and rollback journaling for future mutation phases.

---

## 13. Outstanding Risks & Unresolved Questions

1. **SQLite Concurrent Checkpointing**: Antigravity uses SQLite WAL mode. Inspection during active writes requires verifying database lock state before Phase 03/04 mutations.
2. **Overlayfs Device ID Virtualization**: In containerized environments, overlayfs creates virtual device IDs that require careful translation during Level 2 testing.

---

## 14. Phase 02 Readiness Assessment

Phase 01 acceptance criteria are **100% satisfied**:
- [x] Dedicated Phase 01 development branch created.
- [x] Phase 00 architectural assumptions corrected across documentation.
- [x] Rust workspace created (`root-core`, `root-platform`, `root-guardian`, `root-cli`).
- [x] Core domain models implemented with verified fact vs inference separation.
- [x] Read-only platform abstraction traits implemented for Linux.
- [x] Root Guardian policy foundation implemented with Phase 01 read-only enforcement.
- [x] Synthetic fixtures created for normal, protected, symlink, hardlink, agent, and adversarial paths.
- [x] CLI commands (`root --help`, `root --version`, `root doctor`, `root scan --dry-run`) operational.
- [x] Security test suite executed and passing.
- [x] `cargo fmt`, `cargo check`, `cargo clippy`, and `cargo test` pass with zero warnings.
- [x] Zero destructive operations performed.

Root is ready to proceed to **Phase 02: Linux Platform Engine (`root-platform-linux`)** upon human authorization.
