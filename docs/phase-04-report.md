# Root — Phase 04 Completion Report
## Guardian Security Engine and Quarantine Rollback

This report details the implementation of Phase 04 of Root, establishing foundational security authorization, transactional quarantine state management, same-filesystem atomic relocation, recovery journaling, and conflict-aware restoration.

All mutating mechanics implemented in Phase 04 remain strictly restricted to verified synthetic fixture sandboxes (`FixtureSandbox`). Production CLI commands remain read-only.

---

### 1. Executive Summary

Phase 04 transforms Root's security foundation from a passive policy evaluator into an active transactional guardian. It introduces an explicit authorization engine requiring eight distinct security validations before any mutation is approved. It defines an eight-state transaction model (`Proposed` -> `Authorized` -> `Prepared` -> `Quarantined` -> `Verified` -> `Restored`), ensuring that operations are auditable, verifiable, and reversible.

Mutating operations leverage Linux native `SYS_renameat2` with `RENAME_NOREPLACE` for same-filesystem atomic movement, eliminating the risk of destination overwriting. An append-only JSONL recovery journal records operations with full data synchronization (`sync_data`). A conflict-aware restoration engine ensures that restoring quarantined files never clobbers newly created user files.

All 16 required adversarial security scenarios—including symlink jail escapes, TOCTOU directory replacements, destination collisions, hard-link semantics, sparse files, non-Latin Unicode, and corrupted journals—were implemented and verified across 51 workspace unit and integration tests.

---

### 2. Branch and Commit SHA

- **Repository Branch**: `feat/phase-04-guardian-transactions`
- **Base Commit**: `347e8a6` (Phase 03 Agent and Tool Discovery Engine)
- **Host Platform**: Kali Linux Rolling (Linux 6.12.38-amd64, x86_64)
- **Rust Toolchain**: rustc 1.99.0 / cargo 1.99.0

---

### 3. Files Created and Modified

#### Files Created:
- `crates/root-guardian/src/crypto.rs`: Pure-Rust FIPS 180-4 SHA-256 implementation with zero third-party dependencies.
- `crates/root-guardian/src/transaction.rs`: Explicit transaction state machine (`TransactionState`, `TransactionContext`) and legal transition validation.
- `crates/root-guardian/src/authorization.rs`: Multi-factor authorization engine (`AuthorizationEngine`, `AuthorizationReceipt`, `AuthorizationRequest`).
- `crates/root-guardian/src/sandbox.rs`: Mutation isolation sandbox (`FixtureSandbox`) preventing any operations outside verified test fixtures.
- `crates/root-guardian/src/quarantine.rs`: Quarantine staging store (`QuarantineStore`) with collision-resistant naming and atomic relocation.
- `crates/root-guardian/src/journal.rs`: Append-only recovery journal (`RecoveryJournal`, `JournalRecord`) with corruption and interruption detection.
- `crates/root-guardian/src/restoration.rs`: Conflict-aware restoration engine (`RestorationEngine`) preventing destination clobbering.
- `crates/root-guardian/src/engine.rs`: Unified transaction coordinator (`TransactionEngine`).
- `crates/root-guardian/tests/guardian_transaction_tests.rs`: Comprehensive 16-scenario adversarial security test suite.
- `docs/phase-04-report.md`: This completion report.

#### Files Modified:
- `crates/root-core/src/error.rs`: Added typed error variants for transactions, collisions, cross-device rejections, journal errors, and sandbox violations.
- `crates/root-core/src/model/classification.rs`: Added explicit rejection reasons (`UserConfirmationMissing`, `Phase04UnsupportedAction`, `FilesystemIdentityChanged`).
- `crates/root-core/src/model/resource.rs`: Added `ResourceId::as_str` accessor.
- `crates/root-platform/src/linux/filesystem.rs`: Implemented `LinuxFilesystem::atomic_rename_no_replace` using `SYS_renameat2` and directory `sync_all`.
- `crates/root-guardian/src/lib.rs`: Exported Phase 04 guardian transaction engine components.
- `crates/root-guardian/Cargo.toml`: Added dependencies on `root-platform` and `serde_json`.
- `crates/root-cli/src/doctor.rs`: Updated doctor diagnostic output to reflect Phase 04 governance status.
- `docs/platform-abstraction.md`: Documented atomic rename mechanics, cross-device realities, TOCTOU mitigation, and restoration conflicts.
- `docs/roadmap.md`: Updated roadmap to reflect Phase 04 completion.
- `ARCHITECTURE.md`: Documented Phase 04 transaction state machine and architectural guarantees.

---

### 4. Guardian Authorization Implementation

In strict compliance with Section 4 of the project specifications, `AuthorizationEngine::authorize` requires eight explicit conditions before approving an action:

1. **Explicit Resource Identification**: The resource must have a non-empty `ResourceId` and a non-empty path.
2. **Verified Ownership**: The candidate's `ownership.uid` must match the operator's UID, and `ownership.is_current_user` must be `true`.
3. **Verified Filesystem Identity**: The target path is stat'd via `symlink_metadata` (never following symlinks). The observed `st_dev` and `st_ino` must match the candidate snapshot.
4. **Symlink Non-Follow Invariant**: If the target path is a symbolic link, authorization is unconditionally denied (`RejectionReason::SymlinkJailEscape`).
5. **Permitted Protection Classification**:
   - `StrictlyProtected` -> Unconditionally denied (`RejectionReason::TierStrictlyProtected`).
   - `NonActionable` -> Unconditionally denied (`RejectionReason::UnknownResource`).
   - `UserConfirmRequired` -> Denied unless `explicit_user_consent == true`.
   - `ObsoleteTransient` / `SafeRecoverable` -> Permitted.
6. **Supported Operation**: In Phase 04, the only mutating operation allowed is `ProposedAction::Quarantine`. Permanent deletion (`Prune`) or signaling (`TerminateGraceful`) are rejected (`RejectionReason::Phase04UnsupportedAction`).
7. **Traceable Authorization Receipt**: Successful evaluation generates an `AuthorizationReceipt` containing a unique receipt ID, timestamp, operator UID, and supporting evidence.
8. **Pre-Mutation TOCTOU Revalidation**: `AuthorizationEngine::revalidate_before_mutation` re-stats the file immediately before physical movement to ensure that the file was not swapped, reparented, or altered between check and execution.

---

### 5. Transaction State Machine

The transaction lifecycle enforces strict, deterministic state transitions:

```mermaid
stateDiagram-v2
    [*] --> Proposed
    Proposed --> Authorized: Guardian Policy Approval
    Proposed --> Failed: Policy Denied
    Authorized --> Prepared: Pre-Flight Validation
    Authorized --> Failed: Inode/Device Mismatch
    Prepared --> Quarantined: renameat2(RENAME_NOREPLACE)
    Prepared --> Failed: Move Failure / Collision
    Prepared --> RecoveryRequired: Interrupted Move
    Quarantined --> Verified: Integrity & Unlink Verified
    Quarantined --> RecoveryRequired: Hash / Size Mismatch
    Verified --> Restored: RestorationEngine
    Verified --> RecoveryRequired: Destination Conflict
    RecoveryRequired --> Restored: Recovery Replay Success
    RecoveryRequired --> Failed: Unrecoverable Anomaly
    Restored --> [*]
    Failed --> [*]
```

- **Illegal State Transitions**: State jumps (such as `Proposed` -> `Quarantined` or `Proposed` -> `Restored`) are rejected with `RootError::InvalidStateTransition`.
- **Terminal States**: `Restored` and `Failed` are terminal. No transitions out of terminal states are permitted.

---

### 6. Quarantine Implementation

Quarantine staging is managed by `QuarantineStore` within `FixtureSandbox`:
- **Restrictive Permissions**: The quarantine directory (`.root_quarantine`) is created with POSIX `0o700` permissions.
- **Collision-Resistant Naming**: Quarantined files are staged using the format `<transaction_id>_<inode>_<sanitized_filename>`.
- **Atomic Same-Filesystem Relocation**: Relocation uses `LinuxFilesystem::atomic_rename_no_replace`.
- **Metadata Preservation**: Original POSIX permissions (`mode & 0o777`) are preserved on the quarantined destination.
- **Integrity Verification**: Immediately following relocation, Root verifies that:
  1. The original source path no longer exists.
  2. The quarantine destination file exists.
  3. The quarantine file length matches the pre-mutation byte count.
  4. The quarantine file SHA-256 matches the pre-mutation digest.

---

### 7. Recovery Journal Implementation

The recovery journal is managed by `RecoveryJournal` inside `.root_journal/journal.jsonl`:
- **Record Fields**: Each record logs `transaction_id`, `timestamp_epoch_secs`, `state`, `original_path`, `quarantine_path`, `device_id`, `inode`, `size_bytes`, `sha256`, `reason`, and optional `failure_reason`.
- **Physical Sync**: Each appended record issues `file.sync_data()` to ensure durability against sudden power loss.
- **Corruption Detection**: `read_all` parses every JSON line. Malformed or truncated lines immediately return `RootError::JournalError`.
- **Interrupted Transaction Recovery**: `get_interrupted_transactions` scans for transactions left in `Prepared` or `Quarantined` states that never reached `Verified` or `Restored`, providing the basis for automated recovery replays.

---

### 8. Restoration Implementation

Restoration is managed by `RestorationEngine`:
- **Pre-Restoration Integrity Check**: Before moving any file back, Root computes the SHA-256 hash of the quarantined file and verifies it against the journal's recorded digest. Corrupted quarantine files are rejected.
- **Destination Conflict Prevention**: Root tests the destination path before touching the quarantine file. If any file or directory already occupies the original path, restoration aborts with `RootError::RestorationConflict`. Existing files are never overwritten.
- **Missing Parent Recreation**: If enclosing parent directories were removed, Root recreates them before restoration.
- **Atomic Restoration**: Restoration executes via `LinuxFilesystem::atomic_rename_no_replace`, restoring original permissions.
- **State Finalization**: The transaction is updated to `Restored` and logged to the journal.

---

### 9. Filesystem Safety Mechanisms

- **`FixtureSandbox` Containment**: All quarantine and restore operations require a `FixtureSandbox` instance. Any path escaping the sandbox canonical prefix is rejected with `RootError::SandboxViolation`.
- **Internal Tree Protection**: Candidates attempting to target `.root_quarantine` or `.root_journal` are rejected with `RootError::PolicyViolation`.
- **Root Directory Protection**: Candidates targeting the sandbox root directory itself are rejected with `RootError::PolicyViolation`.
- **Symlink Non-Follow Invariant**: Symlinks are never followed during quarantine or restoration.
- **Cross-Device Safety**: Operations crossing filesystem boundaries (`source_dev != dest_dev`) return `RootError::CrossDeviceUnsupported` prior to data modification.

---

### 10. Security Test Results

All 16 adversarial security test cases in `guardian_transaction_tests.rs` passed cleanly:

| Test Case | Scenario Evaluated | Result |
|---|---|---|
| `test_01` | Symlink escape attempt outside sandbox | PASSED |
| `test_02` | TOCTOU directory replacement race | PASSED |
| `test_03` | Inode identity mismatch after recreation | PASSED |
| `test_04` | Destination collision rejection (`EEXIST`) | PASSED |
| `test_05` | Hard-link semantics (intact surviving links) | PASSED |
| `test_06` | Sparse file quarantine and restoration (2 MiB hole) | PASSED |
| `test_07` | Non-Latin Unicode filename preservation (Cyrillic) | PASSED |
| `test_08` | Special characters and spaces in filenames | PASSED |
| `test_09` | Invalid transaction state transition rejection | PASSED |
| `test_10` | Interrupted transaction identification from journal | PASSED |
| `test_11` | Corrupted journal line detection | PASSED |
| `test_12` | Restoration conflict rejection (occupied original path) | PASSED |
| `test_13` | Unsupported cross-device boundary rejection | PASSED |
| `test_14` | Permission restrictions rejection (`0o555` read-only parent) | PASSED |
| `test_15` | Tier 1 (Strictly Protected) authorization denial | PASSED |
| `test_16` | Sandbox root escape attempt (`/etc/hosts`) | PASSED |

Total workspace tests passing: **51 tests** (0 failed, 0 ignored).

---

### 11. Failure-Injection Results

- **Simulated Crashes**: Transactions left in `Prepared` or `Quarantined` state were successfully detected by `get_interrupted_transactions()`.
- **Simulated Corrupted Quarantines**: Bit flips or content changes in quarantine files were detected prior to restoration, aborting with `RootError::IntegrityVerificationFailed`.
- **Simulated Destination Re-occupation**: Files created at the original location during quarantine were detected, preventing restoration from clobbering new files.
- **Simulated Permission Errors**: Read-only directories (`0o555`) prevented unlinking, resulting in transaction failure logging with zero unlinked files.

---

### 12. Known Limitations

1. **Same-Filesystem Limitation**:
   - In Phase 04, quarantine movement is strictly limited to the same filesystem (`target.st_dev == quarantine.st_dev`). Cross-device quarantine is rejected.
2. **Crash Consistency on Power Failure**:
   - While `sync_data()` and directory `sync_all()` ensure standard POSIX durability, catastrophic sudden power loss during a file rename depends on host filesystem journal mode (e.g. ext4 `data=ordered` vs `data=journal`).
3. **Hard-Link Accounting**:
   - Quarantining one link of a multi-linked file (`st_nlink > 1`) successfully moves the directory entry, but physical disk blocks remain allocated on the filesystem as long as remaining links exist.

---

### 13. Remaining Risks

- **Cross-Filesystem Complexity (Phase 05+)**: Moving data across filesystems requires streaming copies, checksum verification, and unlinking. If a system crashes mid-copy, partial files remain on the destination volume.
- **Concurrent External Modifications**: If an external privileged tool (e.g., a background daemon running as root) mutates files during a quarantine operation, non-atomic interactions can occur outside unprivileged user-space control.
- **Host Disk Full Conditions**: If the target filesystem has zero free inodes or blocks, journal writes or directory renames can fail with `ENOSPC`.

---

### 14. Phase 05 Readiness Assessment

Phase 04 successfully establishes:
1. Multi-factor Guardian authorization preventing unauthorized mutation.
2. An 8-state transaction state machine with legal transition enforcement.
3. Linux same-filesystem atomic relocation using `SYS_renameat2(RENAME_NOREPLACE)`.
4. Durable JSONL recovery journaling with corruption and interruption recovery.
5. Conflict-aware restoration that never overwrites existing files.
6. A 16-scenario adversarial security test suite verifying all invariants.

The core transaction and rollback engine is mature, deterministic, and fully verified. The project is ready to proceed to Phase 05: "Command Line Interface", where production user interactions, interactive confirmation prompts, progress indicators, and tabular formatting will be implemented on top of the core engine.

---

**Phase 04 Gate Status**: Complete. Awaiting human authorization before Phase 05 execution.
