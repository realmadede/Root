# Root — Phase 11 Mutation Threat Model
## Production Mutation Security Architecture & Adversarial Risk Analysis

> [!IMPORTANT]
> **PHASE 11 SECURITY INVARIANT: PRODUCTION MUTATION PERMANENTLY DISABLED**  
> Root is an unprivileged inspection and audit utility. In Phase 11, all mutation operations against real user resources remain strictly prohibited. The transaction engine, quarantine store, and rollback mechanisms are exercised exclusively against Level 1 synthetic fixtures and isolated test sandboxes.

---

## 1. Threat Modeling Methodology & System Boundaries

Root operates on developer workstations where autonomous AI coding agents (such as Google Antigravity, Claude Code, Gemini CLI, Aider) and build toolchains (Node.js, Cargo, Python, Docker) execute concurrently. The threat environment assumes:
1. **Unprivileged Execution**: Root executes with standard user privileges (`UID != 0`). Root never executes as `root`, never requests `sudo`, and never relies on elevated kernel capabilities.
2. **Untrusted Working Trees**: Workspace paths inspected or operated on may contain adversarial symlink topologies, rapid file replacements, untrusted code repositories, and unexpected filesystem objects.
3. **Concurrent Background Processes**: Compilers, dev servers, agents, and filesystem watchers run concurrently with Root, creating inevitable concurrency races.
4. **No Full Kernel Guarantees**: User space cannot fully eliminate kernel-level filesystem race conditions or power loss anomalies without kernel transaction primitives; Root documents residual risks honestly and defaults to conservative rejection.

---

## 2. Threat Analysis Matrix

---

### Threat 01: Malicious or Compromised Local Process
- **Preconditions**: A compromised tool, untrusted third-party npm script, or adversarial background process executes under the same user UID.
- **Potential Impact**: Attempt to trick Root into deleting user source files, credentials, or system libraries by manipulating paths or arguments.
- **Existing Protection**: Multi-factor authorization (`AuthorizationEngine`); strictly protected path prefixes (`/etc`, `/usr`, `~/.ssh`, `~/.gnupg`, macOS `/System`, Windows `C:\Windows`); verification that candidate resource is within authorized sandbox boundaries.
- **Required Mitigation**: Multi-factor authorization bound to exact `FileIdentity` and explicit user consent record with nonces and timestamps; immediate pre-mutation revalidation.
- **Residual Risk**: A process with the same UID can directly mutate user files without Root; Root prevents *becoming the confused deputy* for such attacks.
- **Verification Test**: `test_adversarial_01_unauthorized_operation`.

---

### Threat 02: Path Replacement Between Inspection and Operation (TOCTOU)
- **Preconditions**: A target file inspected at time $T_0$ is unlinked and replaced by another file or directory at time $T_1$ before mutation at $T_2$.
- **Potential Impact**: Destruction or quarantine of legitimate user files or sensitive credentials placed in the path.
- **Existing Protection**: `AuthorizationEngine::revalidate_before_mutation` checks `st_dev`, `st_ino`, and `st_uid` immediately before calling rename syscalls.
- **Required Mitigation**: Atomic same-filesystem relocation using `SYS_renameat2` with `RENAME_NOREPLACE`; compare full `FileIdentity` (POSIX dev/ino; Windows volume serial + 128-bit file ID) and parent directory identity.
- **Residual Risk**: A microscopic race window between final `lstat` and `renameat2` exists; however, `RENAME_NOREPLACE` prevents overwriting an existing destination, and identity mismatch at destination verification causes transition to `RecoveryRequired`.
- **Verification Test**: `test_adversarial_04_modified_resource_identity`.

---

### Threat 03: Symlink Substitution
- **Preconditions**: An adversary replaces a target file or intermediate directory with a symbolic link pointing to sensitive data (e.g., `~/.ssh/id_rsa` or `/etc/passwd`).
- **Potential Impact**: Relocation or corruption of critical system or user files outside approved roots.
- **Existing Protection**: `symlink_metadata` (`lstat`) is used exclusively; `is_symlink()` check rejects symlinks unconditionally; `RENAME_NOREPLACE` prevents following destination symlinks.
- **Required Mitigation**: Strict symlink non-follow policy across all operations; parent directory resolution validation; refusal to mutate symlinks directly.
- **Residual Risk**: None for target nodes; parent directories must also be validated against symlink replacement.
- **Verification Test**: `test_adversarial_06_symlink_substitution`.

---

### Threat 04: Windows Junction and Reparse-Point Substitution
- **Preconditions**: On Windows, a directory or leaf node is replaced with an NTFS junction (`IO_REPARSE_TAG_MOUNT_POINT`), symbolic link, or cloud placeholder.
- **Potential Impact**: Traversal or deletion escaping into volume roots or remote storage targets.
- **Existing Protection**: Windows adapter opens all handles with `FILE_FLAG_OPEN_REPARSE_POINT`, inspecting the link rather than the target.
- **Required Mitigation**: Reparse points are treated strictly as leaf nodes; directory descent is prohibited; mutation engine is disabled at compile time on Windows in Phase 11.
- **Residual Risk**: Zero in Phase 11 (Windows mutation is disabled). Phase 12 production Windows mutation will require `MoveFileExW` with `MOVEFILE_FAIL_IF_EXISTS` and handle verification.
- **Verification Test**: `test_adversarial_28_non_linux_mutation_rejection`.

---

### Threat 05: Hard-Linked Files
- **Preconditions**: A candidate file has multiple hard links (`st_nlink > 1`), sharing data blocks across multiple directory entries.
- **Potential Impact**: Quarantining one entry breaks shared file access for other projects without reclaiming allocated storage; restores may break link graphs.
- **Existing Protection**: `ResourceCandidate` tracks `nlink` via `StorageMeasurement`; pnpm hard-link stores are classified as `StrictlyProtected`.
- **Required Mitigation**: Explicit rejection of multi-linked files (`st_nlink > 1`) unless explicit multi-link policy and shared-storage consent are provided; space reclamation calculation accounts for hard-link duplication.
- **Verification Test**: `test_adversarial_10_hard_linked_resource`.

---

### Threat 06: Sparse Files
- **Preconditions**: A file contains unallocated holes (`apparent_size >> allocated_bytes`).
- **Potential Impact**: Inaccurate reclamation estimates; unintended hole allocation during byte-by-byte copies; destination storage exhaustion.
- **Existing Protection**: `StorageMeasurement` records both apparent size (`len`) and allocated size (`st_blocks * 512`); atomic rename preserves sparse file extents without data copying.
- **Required Mitigation**: Enforce atomic same-filesystem rename exclusively (never copy-and-delete); preserve sparse inode allocation during quarantine.
- **Residual Risk**: Cross-device operations cannot preserve sparseness atomically and are therefore strictly rejected.
- **Verification Test**: `test_adversarial_11_sparse_file`.

---

### Threat 07: Shared Dependency Stores
- **Preconditions**: Multiple repositories share global or user-level package caches (e.g., `~/.pnpm-store`, `~/.cargo/registry`, `~/.cache/pip`).
- **Potential Impact**: Deleting a package considered "unused" by one project breaks compilation in other independent projects.
- **Existing Protection**: Discovery rule registry explicitly classifies shared package stores as `StrictlyProtected` with `ProposedAction::Ignore`.
- **Required Mitigation**: Hardcoded protection invariants for shared dependency roots; authorization engine unconditionally rejects mutations targeting shared package stores.
- **Residual Risk**: None; Root never mutates shared package caches.
- **Verification Test**: `test_adversarial_21_shared_dependency_store`.

---

### Threat 08: Cross-Device Operations
- **Preconditions**: Target resource and quarantine staging directory reside on different filesystems or mount points (`st_dev` differs).
- **Potential Impact**: Atomic rename fails (`EXDEV`); falling back to non-atomic copy-and-delete risks partial writes, data corruption, and inability to roll back.
- **Existing Protection**: `QuarantineStore::relocate_into_quarantine` checks `source_meta.dev() == expected_dev` and aborts with `RootError::CrossDeviceUnsupported`.
- **Required Mitigation**: Strict prohibition of non-atomic cross-device fallbacks. If quarantine directory is on another volume, operation is rejected.
- **Residual Risk**: None; cross-device relocations are permanently blocked.
- **Verification Test**: `test_adversarial_08_cross_device_operation`.

---

### Threat 09: Concurrent Agent Activity
- **Preconditions**: An AI coding agent or build runner creates, modifies, or reads files in the target directory while Root evaluates or executes.
- **Potential Impact**: Corruption of active agent work; broken agent builds; moving files currently held open by processes.
- **Existing Protection**: Active process tracking correlates open files and working directories; lifecycle assessment flags active resources as `StrictlyProtected`.
- **Required Mitigation**: Advisory single-writer locking (`AdvisoryLock`); active-use revalidation; verification that no active agent process holds the target.
- **Residual Risk**: Processes can open the file after Root's final check; mitigation is atomic relocation (processes holding open descriptors retain file access until closed).
- **Verification Test**: `test_adversarial_19_resource_currently_in_use`.

---

### Threat 10: PID Reuse
- **Preconditions**: An agent process exits, and its PID is reassigned by the kernel to an unrelated process before Root inspects process state.
- **Potential Impact**: Misattributing active processes to dead agents or vice versa.
- **Existing Protection**: Linux uses `start_time_ticks` from `/proc/[pid]/stat`; macOS uses BSD start ticks via `libproc`; Windows uses 64-bit creation `FILETIME`.
- **Required Mitigation**: Multi-factor process identity combining PID and process start time; unprivileged signaling requires verified process descriptors (`pidfd`).
- **Residual Risk**: Process termination is disabled in production builds.
- **Verification Test**: Unit tests in `platform_engine_tests.rs`.

---

### Threat 11: Resource Identity Changes
- **Preconditions**: Inode reuse or filesystem re-formatting causes nominal paths to map to different physical objects.
- **Potential Impact**: Replaying an authorization against an unintended newly created file.
- **Existing Protection**: `FileIdentity` captures both volume ID and object identifier (POSIX `st_dev` + `st_ino`; Windows volume serial + 128-bit file ID).
- **Required Mitigation**: Authorization receipts encode exact `FileIdentity`; pre-mutation check verifies identity match; journal records store device/inode for audit.
- **Residual Risk**: Inode numbers can theoretically be recycled after deletion; mitigated by atomic relocation where the original inode is preserved into quarantine.
- **Verification Test**: `test_adversarial_04_modified_resource_identity`.

---

### Threat 12: Permission Changes
- **Preconditions**: Target file or parent directory permissions are altered between authorization and operation (e.g., permissions changed to `0000` or read-only).
- **Potential Impact**: Failed mutation; permission loss upon restoration; permission escalation.
- **Existing Protection**: `QuarantineStore` preserves original permission bits on the quarantined artifact.
- **Required Mitigation**: Pre-mutation permission validation; atomic rename failure handling; restoration verifies that parent directory has write permissions before attempting rollback.
- **Residual Risk**: Restoring to a directory that became read-only fails safely without data loss, logging `RestorationConflict`.
- **Verification Test**: `test_adversarial_16_changed_permissions`.

---

### Threat 13: Filesystem Mount Changes
- **Preconditions**: A filesystem is remounted read-only (`ro`), unmounted, or shadowed by an overlay mount during execution.
- **Potential Impact**: Syscall errors (`EROFS`, `ENOENT`); incomplete operations.
- **Existing Protection**: `LinuxFilesystem::atomic_rename_no_replace` returns explicit `Io` or `PolicyViolation` errors; journal records failure reason.
- **Required Mitigation**: Failure transitions transaction directly to `Failed` without partial state persistence; journal sync verifies filesystem write capability.
- **Residual Risk**: Read-only remounts cause immediate clean rejection without data modification.
- **Verification Test**: `test_adversarial_18_unsupported_platform_capability`.

---

### Threat 14: Corrupted Transaction Journals
- **Preconditions**: Journal file on disk is truncated, partially overwritten, edited by a user, or corrupted by storage errors.
- **Potential Impact**: Crash during journal parse; inability to perform rollbacks; replaying invalid transactions.
- **Existing Protection**: `RecoveryJournal::read_all` validates each JSONL record individually and reports corrupted lines explicitly.
- **Required Mitigation**: Tolerant parse recovery: corrupt records are flagged as `RecoveryRequired` rather than causing an unhandled crash; recovery never deletes unknown records.
- **Residual Risk**: A severely corrupted journal may require manual administrator review; all quarantined files remain safely preserved on disk.
- **Verification Test**: `test_adversarial_12_corrupt_journal`.

---

### Threat 15: Disk Space Exhaustion
- **Preconditions**: Filesystem has zero free blocks or inodes during quarantine or journal writing.
- **Potential Impact**: Journal write failure (`ENOSPC`); partial record write.
- **Existing Protection**: Same-filesystem atomic rename creates no new data blocks (only moves directory entries); journal intent is recorded before moving files.
- **Required Mitigation**: If journal append fails due to `ENOSPC`, the mutation is aborted before any file is moved.
- **Residual Risk**: Running out of disk space during restore fails cleanly, leaving the artifact safely in quarantine.
- **Verification Test**: `test_adversarial_24_disk_space_exhaustion`.

---

### Threat 16: Process Crashes
- **Preconditions**: Root process is abruptly terminated (`SIGKILL`, segfault, abort) between transaction steps.
- **Potential Impact**: Incomplete transaction; target relocated but completion record not written.
- **Existing Protection**: Journal records intent (`Prepared`) before the rename executes; recovery identifies transactions without a terminal record.
- **Required Mitigation**: Idempotent journal recovery: on startup, transactions in `Prepared` or `Quarantined` state without `Verified` are classified as `RecoveryRequired` for inspection.
- **Residual Risk**: Small window between rename and `Verified` record write: file is safely in quarantine directory; recovery can restore it using journal `Prepared` metadata.
- **Verification Test**: `test_adversarial_13_interrupted_transaction`.

---

### Threat 17: Power Loss
- **Preconditions**: Sudden hardware power loss or kernel panic during transaction execution.
- **Potential Impact**: Filesystem journal rollback; unsynced directory entry modifications.
- **Existing Protection**: `File::sync_data()` is invoked on the recovery journal after writing records.
- **Required Mitigation**: Durable journal flushing; atomic filesystem rename primitives (`renameat2`) guaranteed atomic by modern filesystems (ext4, XFS, Btrfs, APFS, NTFS).
- **Residual Risk**: Disk controllers without non-volatile write caches may reorder flushes; Root guarantees user-space ordering to the maximum extent permitted by POSIX.
- **Verification Test**: Simulated crash point testing in `guardian_transaction_tests.rs`.

---

### Threat 18: Partial Writes
- **Preconditions**: A crash or storage error occurs during writing of configuration, history, or journal files.
- **Potential Impact**: Malformed JSON documents on disk.
- **Existing Protection**: Staged writes: configurations write to `.tmp` files and use atomic `fs::rename` over the destination.
- **Required Mitigation**: Staged writes for all configuration files; append-only JSONL with newline framing for recovery journals.
- **Residual Risk**: Append-only lines with missing newlines are detected and rejected as malformed by `RecoveryJournal::read_all`.
- **Verification Test**: `test_adversarial_12_corrupt_journal`.

---

### Threat 19: Quarantine Destination Collisions
- **Preconditions**: Quarantine destination path already exists due to a previous crashed transaction, hash collision, or intentional adversary creation.
- **Potential Impact**: Overwriting previously quarantined data.
- **Existing Protection**: `QuarantineStore::allocate_quarantine_path` incorporates timestamp, unique transaction ID, inode number, and sanitized leaf name; verifies `!dest_path.exists()`.
- **Required Mitigation**: Atomic rename enforces `RENAME_NOREPLACE` (`SYS_renameat2`), causing the kernel to fail with `EEXIST` if destination exists.
- **Residual Risk**: None; collision causes clean failure with `DestinationCollision`.
- **Verification Test**: `test_adversarial_09_destination_collision`.

---

### Threat 20: Restoration Conflicts
- **Preconditions**: Quarantined resource is being restored, but a new file or directory now occupies the original path.
- **Potential Impact**: Overwriting new user files during a rollback operation.
- **Existing Protection**: `RestorationEngine::restore_resource` checks `original_path.exists()` and fails with `RootError::RestorationConflict`.
- **Required Mitigation**: Mandatory pre-restoration destination check; atomic rename with `RENAME_NOREPLACE`; explicit user reporting.
- **Residual Risk**: None; Root never overwrites an existing file during restoration.
- **Verification Test**: `test_adversarial_15_restoration_conflict`.

---

### Threat 21: Maliciously Constructed Paths
- **Preconditions**: An agent or adversary creates files with path traversal components (`../../etc/shadow`), control characters, or Unicode normalization attacks.
- **Potential Impact**: Path traversal escaping designated workspace roots.
- **Existing Protection**: `FixtureSandbox::assert_within_bounds` validates canonical containment; `format_path_middle` sanitizes terminal output.
- **Required Mitigation**: Strict rejection of non-normalized relative paths; verification that canonical target path starts with authorized root prefix.
- **Residual Risk**: None; canonicalization and bounds assertions prevent path traversal.
- **Verification Test**: `test_adversarial_07_scope_escape`.

---

### Threat 22: Unexpected Filesystem Semantics
- **Preconditions**: Target files reside on filesystems with non-POSIX semantics (FAT32, exFAT, network NFS/SMB shares, case-insensitive APFS).
- **Potential Impact**: Failed atomic renames; loss of inode identity stability; case-collision hazards.
- **Existing Protection**: `platform_paths.rs` provides case-insensitive comparison helper; `FilesystemProvider::get_file_identity` reports scheme explicitly.
- **Required Mitigation**: Conservative rejection: unsupported or non-atomic filesystem configurations fail during pre-flight checks.
- **Residual Risk**: Network filesystems (NFS) without atomic `renameat2` support are rejected.
- **Verification Test**: `test_adversarial_18_unsupported_platform_capability`.

---

### Threat 23: Compromised or Stale Inspection Results
- **Preconditions**: User reviews a scan report generated minutes or hours ago, then requests an action on an obsolete candidate snapshot.
- **Potential Impact**: Operating on resources that have changed lifecycle status, been edited, or been replaced.
- **Existing Protection**: Multi-factor revalidation checks candidate snapshot against current filesystem state.
- **Required Mitigation**: Explicit consent records carry a strict expiration TTL (e.g. 300 seconds); revalidation checks verify that timestamps and sizes match snapshot.
- **Residual Risk**: None; stale consent or modified timestamps result in rejection.
- **Verification Test**: `test_adversarial_02_expired_consent`.

---

### Threat 24: Incorrect Resource Classification
- **Preconditions**: An unusual file name or directory structure in a user project matches an agent artifact rule pattern.
- **Potential Impact**: Misclassifying user project files as disposable build artifacts.
- **Existing Protection**: 12 deterministic rules with strict presence markers; unknown directories default to `StrictlyProtected`.
- **Required Mitigation**: Rule confidence scoring; presence marker verification; uncommitted Git change detection protects any file within a dirty worktree.
- **Residual Risk**: User custom directories outside Git without markers default to `NonActionable` (Protected).
- **Verification Test**: `test_adversarial_20_unknown_lifecycle`.

---

### Threat 25: Confused-Deputy Behavior Through GUI or Scheduler Interfaces
- **Preconditions**: An external script triggers a scheduler run or passes crafted parameters to the GUI view-model.
- **Potential Impact**: Executing unintended cleanup operations without direct interactive confirmation.
- **Existing Protection**: Schedulers (Mode B) and live monitoring (Mode C) are permanently read-only; GUI exposes zero mutation controls.
- **Required Mitigation**: Compile-time prohibition of mutation APIs from scheduler and monitor entry points; separate authorization tokens.
- **Residual Risk**: None; scheduler and monitor cannot invoke mutation.
- **Verification Test**: `test_adversarial_26_gui_authorization_mismatch` and `test_adversarial_27_scheduler_authorization_mismatch`.

---

### Threat 26: Unauthorized Access to Other Users' Resources
- **Preconditions**: Multi-user shared system where a user attempts to scan or mutate another user's files.
- **Potential Impact**: Information disclosure or unauthorized file modification.
- **Existing Protection**: Traversal validates `st_uid == current_uid`; `AuthorizationEngine` checks `candidate.ownership.uid == invoking_uid`.
- **Required Mitigation**: Unprivileged execution prevents access to files protected by POSIX permissions; Root ignores any file not owned by the calling user.
- **Residual Risk**: World-readable files owned by other users are ignored and never candidates for cleanup.
- **Verification Test**: `test_adversarial_17_changed_ownership`.

---

## 3. Threat Model Summary & Safety Guarantees

Root's Phase 11 threat model establishes that:
1. **Safety Over Reclamation**: Root will always choose to fail or abort rather than risk modifying a questionable, modified, or ambiguous resource.
2. **Deterministic Boundaries**: Reliance on cryptographic SHA-256 hashes, kernel `FileIdentity`, `RENAME_NOREPLACE`, and non-blocking advisory locks ensures multi-layer defense.
3. **Continuous Isolation**: Production mutation remains 100% disabled.
