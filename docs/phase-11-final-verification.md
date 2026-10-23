# Root — Phase 11 Final Security Verification Gate Report

## Overview

This report provides the evidence-driven security verification of the Phase 11 implementation for Root. Root is an algorithmic, local-first, non-AI resource inspection and monitoring utility designed for developer environments subject to agentic coding workflows.

This verification gate was conducted to independently evaluate the security claims of Phase 11, reconcile reported test counts, investigate race conditions, evaluate authorization and journal durability models, verify production mutation isolation, and establish whether the repository is ready to advance to Phase 12 (1.0 Production Hardening, Packaging, and Distribution).

---

## A. Repository State

- **Active Branch**: `main` (strictly maintained as the single local and remote branch).
- **Starting Commit**: `d3597c5` (`fix(core): gate Unix-specific symlink and quoted-name assertions in security tests`).
- **Working Tree**: Clean prior to verification task; all changes tracked and verified.
- **Scope of Modifications**:
  - Verification and correction of test count reconciliation in `docs/phase-11-report.md` and `docs/roadmap.md`.
  - Correction of cryptographic claims in `docs/phase-11-authorization-model.md` and `crates/root-guardian/src/authorization.rs`.
  - Correction of platform mutation claims in `docs/phase-11-platform-mutation-matrix.md`.
  - Strengthening of Continuous Assurance invariant checks in `.github/scripts/check_invariants.py`.
  - Addition of 6 targeted security regression tests in `crates/root-guardian/tests/guardian_security_followup_tests.rs`.
  - Creation of this formal gate report: `docs/phase-11-final-verification.md`.

---

## B. Test Reconciliation

### 1. Investigation of the 208 vs 240 Discrepancy

In the initial Phase 11 completion report (`docs/phase-11-report.md`), the summary footer reported 240 passing workspace tests, while the table rows listed:
- `root-cli` (`cli_tests.rs`): 20
- `root-cli` (`monitor_tests.rs`): 25
- `root-cli` (`schedule_tests.rs`): 30
- `root-core` (unit tests): 11
- `root-guardian` (`guardian_transaction_tests.rs`): 15
- `root-guardian` (`guardian_adversarial_tests.rs`): 32
- `root-gui` (unit & integration tests): 27
- `root-platform` (unit tests): 36
- `root-platform` (`platform_engine_tests.rs`): 12

Summing these individual table rows yielded **208 tests** (a 32-test discrepancy compared to the reported 240).

### 2. Discovered and Executed Test Breakdown

An exhaustive execution of `cargo test --workspace --all-targets` revealed that the workspace actually contained **244 passing tests** prior to this verification gate. The root causes of the discrepancy were:
1. Four complete test suites containing 35 tests were omitted from the table rows:
   - `root-core` (`discovery_tests.rs`): 7 tests
   - `root-core` (`security_tests.rs`): 8 tests
   - `root-guardian` (unit tests in `src/lib.rs`): 14 tests
   - `root-guardian` (`guardian_security_followup_tests.rs`): 6 tests
2. Minor row count approximations existed in earlier documentation:
   - `root-core` unit tests: 12 (documented as 11)
   - `root-guardian` (`guardian_transaction_tests.rs`): 16 (documented as 15)
   - `root-gui` (`gui_view_model_tests.rs`): 26 (documented as 27)

### 3. Reconciled Test Inventory (Post-Verification)

With the addition of 6 targeted regression tests in `guardian_security_followup_tests.rs`, the verified workspace test inventory stands at **250 tests**:

| Crate / Integration Test Suite | Test File / Target | Executed | Passed | Failed | Ignored | Status |
|---|---|---|---|---|---|---|
| `root-cli` | `tests/cli_tests.rs` | 20 | 20 | 0 | 0 | [VERIFIED] |
| `root-cli` | `tests/monitor_tests.rs` | 25 | 25 | 0 | 0 | [VERIFIED] |
| `root-cli` | `tests/schedule_tests.rs` | 30 | 30 | 0 | 0 | [VERIFIED] |
| `root-core` | `src/lib.rs` (unit tests) | 12 | 12 | 0 | 0 | [VERIFIED] |
| `root-core` | `tests/discovery_tests.rs` | 7 | 7 | 0 | 0 | [VERIFIED] |
| `root-core` | `tests/security_tests.rs` | 8 | 8 | 0 | 0 | [VERIFIED] |
| `root-guardian` | `src/lib.rs` (unit tests) | 14 | 14 | 0 | 0 | [VERIFIED] |
| `root-guardian` | `tests/guardian_transaction_tests.rs` | 16 | 16 | 0 | 0 | [VERIFIED] |
| `root-guardian` | `tests/guardian_adversarial_tests.rs` | 32 | 32 | 0 | 0 | [VERIFIED] |
| `root-guardian` | `tests/guardian_security_followup_tests.rs` | 12 | 12 | 0 | 0 | [VERIFIED] |
| `root-gui` | `tests/gui_view_model_tests.rs` | 26 | 26 | 0 | 0 | [VERIFIED] |
| `root-platform` | `src/lib.rs` (unit tests) | 36 | 36 | 0 | 0 | [VERIFIED] |
| `root-platform` | `tests/platform_engine_tests.rs` | 12 | 12 | 0 | 0 | [VERIFIED] |
| **Total Workspace Tests** | **All 13 Suites** | **250** | **250** | **0** | **0** | **[VERIFIED]** |

---

## C. Security Findings

### SEC-01: Inaccurate Cryptographic Claims Regarding Consent Records
- **Severity**: Low
- **Affected Components**: `docs/phase-11-report.md`, `docs/phase-11-authorization-model.md`, `crates/root-guardian/src/authorization.rs`.
- **Evidence**: `ConsentRecord` was documented as "cryptographically bound" and "cryptographically signed". Code inspection revealed that consent identifiers were derived using standard library `DefaultHasher` over a string nonce, without public-key signatures (e.g. Ed25519) or HMAC authentication.
- **Exploit Preconditions**: Threat model misunderstanding; assuming records carry non-repudiation or tamper-resistance across network or untrusted process boundaries.
- **Remediation**: Corrected documentation and doc comments to specify that `ConsentRecord` is a structured in-memory domain record enforcing nonce identity binding, action constraints, and Unix epoch expiration.
- **Regression Tests**: `test_followup_consent_exact_boundary_conditions`, `test_followup_consent_mismatched_action`.
- **Final Status**: [VERIFIED] Corrected.

### SEC-02: Overstated Traversal Guarantees and TOCTOU Window Under AT_FDCWD
- **Severity**: Medium
- **Affected Components**: `docs/phase-11-platform-mutation-matrix.md`, `crates/root-guardian/src/engine.rs`, `crates/root-platform/src/linux/filesystem.rs`.
- **Evidence**: `docs/phase-11-platform-mutation-matrix.md` claimed `openat2(RESOLVE_BENEATH)` was verified for race-resistant traversal. In reality, `openat2` is only empirically probed in `accountant.rs` for capability reporting. Filesystem traversal and quarantine relocation operate on string paths relative to `AT_FDCWD`. While `revalidate_full` checks file and parent directory `(dev, ino)` immediately before mutation, a sub-millisecond race window remains against local unprivileged attackers concurrently swapping parent directories prior to the kernel executing `SYS_renameat2`.
- **Exploit Preconditions**: Local adversary with write permissions to an ancestor directory performing rapid directory rename swaps timed between `revalidate_full` and `renameat2`.
- **Remediation**: Updated documentation to eliminate unsupported claims of TOCTOU elimination. Documented the residual sub-millisecond window. Verified that pre-mutation revalidation catches parent swaps that occur prior to the syscall. Noted that true descriptor-relative pinning (`openat2` and directory fds) remains a prerequisite before production mutation could ever be contemplated.
- **Regression Tests**: `test_followup_parent_directory_swap_detection`, `test_followup_parent_directory_symlink_swap_detection`.
- **Final Status**: [VERIFIED] Remediated via accurate risk documentation and regression assertions.

### SEC-03: Documentation Test Count Discrepancy
- **Severity**: Low
- **Affected Components**: `docs/phase-11-report.md`, `docs/roadmap.md`.
- **Evidence**: Table rows summed to 208 while text claimed 240. Four test suites were omitted from table rows.
- **Exploit Preconditions**: N/A (Documentation defect).
- **Remediation**: Reconciled all 13 suites, added 6 targeted regression tests, updated documentation to reflect 250 verified passing tests.
- **Regression Tests**: `cargo test --workspace --all-targets`.
- **Final Status**: [VERIFIED] Resolved.

### SEC-04: Restoration Destination Conflict Robustness
- **Severity**: Low
- **Affected Components**: `crates/root-guardian/src/restoration.rs`, `crates/root-guardian/src/sandbox.rs`.
- **Evidence**: Lack of regression coverage ensuring that restoration safely aborts when the original path is reoccupied by a newly created directory or a dangling symbolic link.
- **Exploit Preconditions**: Process creates a dangling symlink or directory at the restored location before restoration.
- **Remediation**: Added targeted test verifying that `assert_within_bounds` rejects symlink destinations immediately with `PolicyViolation` and directories are rejected with `RestorationConflict`.
- **Regression Tests**: `test_followup_restoration_conflict_directory_and_dangling_symlink`.
- **Final Status**: [VERIFIED] Resolved.

### SEC-05: Reclaimable Storage Calculation on Multi-Link Resources
- **Severity**: Low
- **Affected Components**: `crates/root-core/src/model/storage.rs`, `docs/cleanup-policy.md`.
- **Evidence**: Multi-link files (`st_nlink > 1`) share storage extents. Unlinking one directory entry does not release underlying disk blocks. Reporting apparent size as reclaimable space without documenting link uncertainty would be misleading.
- **Exploit Preconditions**: Operator misinterprets apparent file size as guaranteed reclaimed disk blocks.
- **Remediation**: Multi-link files are rejected by default via `RejectionReason::HardLinkShared` unless `allow_multi_link` is explicitly set. Documented uncertainty in reclaimable storage calculations for shared inodes.
- **Regression Tests**: `test_followup_hard_link_rejection_and_explicit_allow`.
- **Final Status**: [VERIFIED] Documented and covered.

---

## D. Authorization Assessment

### 1. Nonce Generation
- **Source**: Nonces in `ConsentRecord` are passed in as unique strings.
- **Entropy**: In tests, nonces are deterministic strings; in production workflows, nonces must be supplied by the user confirmation interface.
- **Hashing**: `consent_id` is formatted as `csnt_{created_at}_{id_hash}` using standard `DefaultHasher`. This provides identifier uniqueness within a session, but not cryptographic non-repudiation.

### 2. Replay Protection
- **Single-Use Enforcement**: Evaluated in-memory per `AuthorizationRequest`. Once a file is quarantined, subsequent attempts against the same path fail at `revalidate_full` because the file is no longer present.
- **Cross-Restart Limitations**: Nonces are not persisted to a durable revocation store. If a process restarts, previously issued consent records cannot be tracked for historical replay, though expiration timestamps limit the active lifetime.

### 3. Expiration and Monotonicity
- **Expiration Semantics**: `is_valid_at(now)` enforces `now >= created_at && now < expires_at`.
- **Boundary Verification**: Verified that `created_at - 1` is invalid, `created_at` is valid, `expires_at - 1` is valid, and `expires_at` is invalid (strictly expired).
- **Default TTL**: Standard constructor initializes TTL to 300 seconds.

### 4. Resource and Action Binding
- Consent is strictly bound to `resource_id`, `approved_action`, and `target_path`. Mismatches between requested action and approved action are unconditionally rejected (`RejectionReason::ConsentNonceMismatch`).

---

## E. Filesystem Safety Assessment

### 1. Identity Verification
- Snapshot identity is captured via `(dev, ino, uid)`.
- Revalidation prior to mutation compares live `symlink_metadata` against expected device, inode, and UID.
- Symbolic links are unconditionally rejected (`RejectionReason::SymlinkJailEscape`).

### 2. Parent Directory Handling
- `revalidate_full` checks the containing parent directory `(dev, ino)`. If the parent directory is replaced or swapped to a symlink prior to revalidation, the operation is aborted with `ParentDirectoryChanged` or `SymlinkJailEscape`.

### 3. TOCTOU Exposure
- Relocation uses `SYS_renameat2` with `AT_FDCWD` and `RENAME_NOREPLACE`.
- `RENAME_NOREPLACE` guarantees atomic relocation without overwriting existing destinations.
- **Residual Window**: An unavoidable sub-millisecond race window remains if an adversary replaces the parent directory in the brief interval between `revalidate_full` and the execution of `renameat2`. Descriptor-relative operations via `openat2` and directory handles represent the required defense for any future production mutation.

### 4. Platform Limitations
- `renameat2(..., RENAME_NOREPLACE)` is Linux-specific. macOS (`renamex_np`) and Windows (`MoveFileExW`) implementations are not implemented and remain compiled out.

---

## F. Recovery Assessment

### 1. Transaction Durability
- `RecoveryJournal` maintains append-only JSON lines (`.root_journal`).
- Every record append invokes `file.sync_all()` to ensure physical synchronization to disk.
- Parent directories of source and quarantine paths are flushed via `sync_all` upon successful rename.

### 2. Journal Behavior and State Transitions
- State machine mandates ordered transitions: `Proposed -> Authorized -> Prepared -> Quarantined -> Verified -> Restored` (or `Failed` / `RecoveryRequired`).
- Unfinished transactions stopping at `Prepared` or `Quarantined` are correctly detected by `get_interrupted_transactions()` as requiring recovery.

### 3. Fault-Injection Coverage
- Verified across 32 adversarial scenarios and 12 security follow-up tests, including truncated records, corrupt journals, destination collisions, and interrupted transactions.

### 4. Crash-Consistency Guarantees
- Process-crash recovery is verified and idempotent.
- True power-loss consistency depends on host storage hardware barriers and filesystem journaling modes; durability guarantees are not overstated.

---

## G. Production Isolation Assessment

**[VERIFIED] Production mutation remains completely disabled across the entire Root codebase.**

1. **CLI**: `root-cli` exposes only read-only commands (`doctor`, `status`, `scan`, `discover`, `inspect`, `explain`, `report`, `monitor`, `schedule`, `gui`). No mutation subcommands (`clean`, `delete`, `quarantine`, `prune`, `restore`) or mutation flags exist.
2. **GUI**: `root-gui` contains only inspection view models and monitoring presentation views; no mutation callbacks exist.
3. **Monitor & Scheduler**: Read-only inspection events only; strictly prohibited from importing or invoking Guardian transaction coordinators.
4. **Environment Variables**: No undocumented environment variables exist to bypass fixture mode or enable production mutation.
5. **Continuous Assurance**: Script `.github/scripts/check_invariants.py` enforces 11 repository invariants across every build.

---

## H. Cross-Platform Evidence

| Operational Capability | Linux (Ubuntu / Kali) | macOS (Darwin) | Windows (Win32 / NTFS) |
|---|---|---|---|
| **Platform Traversal** | [VERIFIED] (Natively tested) | [VERIFIED] (Unit tested in CI) | [VERIFIED] (Unit tested in CI) |
| **Process Inspection** | [VERIFIED] (Natively tested) | [VERIFIED] (Unit tested in CI) | [VERIFIED] (Unit tested in CI) |
| **System Memory Inspection** | [VERIFIED] (Natively tested) | [VERIFIED] (Unit tested in CI) | [VERIFIED] (Unit tested in CI) |
| **Scheduler Adapter** | [VERIFIED] (systemd user units) | [VERIFIED] (launchd user plist) | [VERIFIED] (Task Scheduler XML) |
| **Continuous Monitoring** | [VERIFIED] (inotify + polling) | [VERIFIED] (kqueue / polling) | [VERIFIED] (ReadDirectoryChangesW / polling) |
| **Guardian Fixture Mutation** | [VERIFIED] (Synthetic fixtures only) | **Unsupported** (Compiled out) | **Unsupported** (Compiled out) |
| **Production Mutation** | **PROHIBITED** | **PROHIBITED** | **PROHIBITED** |

---

## I. Quality Gate Results

All workspace quality gates were executed and verified cleanly:

| Quality Gate Command | Target Scope | Result | Details |
|---|---|---|---|
| `cargo fmt --check` | Workspace | **PASSED** | 0 formatting diffs |
| `cargo check --workspace --all-targets` | Workspace | **PASSED** | 0 compilation errors |
| `cargo clippy --workspace --all-targets -- -D warnings` | Workspace | **PASSED** | 0 warnings across all targets |
| `cargo test --workspace --all-targets` | Workspace | **PASSED** | 250 passed, 0 failed, 0 ignored |
| `cargo doc --workspace --no-deps` | Workspace | **PASSED** | 0 warnings, documentation generated |
| `python3 .github/scripts/check_invariants.py` | Repository Invariants | **PASSED** | 11/11 invariants verified |

---

## J. Phase 12 Readiness Decision

**CONDITIONAL PASS — PHASE 12 MAY PROCEED WITH RESTRICTIONS**

### Evidence-Based Rationale:
1. **Production Boundary Is Verified**: Production mutation is 100% disabled across all platforms, interfaces, schedulers, monitors, and feature configurations. Root is proven to be a deterministic, read-only inspection utility in production.
2. **Phase 12 Scope Confirmation**: Phase 12 is authorized exclusively for 1.0 Production Hardening, Packaging, Web Documentation, and Cryptographic Release Distribution. It must package the read-only inspection engine without enabling production cleanup.
3. **Restrictions on Phase 12**:
   - Production packaging must maintain compile-time and runtime exclusion of production mutation commands.
   - Guardian transaction code remains strictly confined to Level 1 synthetic test fixtures.
   - Any future production mutation enablement would require descriptor-relative `openat2` directory pinning on Linux, platform-specific atomic primitives on macOS/Windows, durable consent nonce revocation, and explicit human authorization.
