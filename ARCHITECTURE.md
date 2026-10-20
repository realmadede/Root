# Root System Architecture

## 1. Architectural Blueprint

Root is architected as a local-first, modular, deterministic resource management system implemented in Rust. It provides deep, surgical visibility into developer workstations, enabling safe recovery of storage and memory consumed by agentic coding workflows.

```mermaid
graph TD
    subgraph UI_Frontends["Interface Layer"]
        CLI["root-cli (Terminal Interface)"]
        GUI["root-gui (Future GTK4 + libadwaita GUI)"]
        Timer["systemd user timer (Scheduled Inspections)"]
        MonitorDaemon["root-monitor (Live Event Daemon)"]
    end

    subgraph CoreEngine["Deterministic Core Engine"]
        Core["root-core<br>• Domain Models<br>• 4-Tier Policy Engine<br>• Transaction Coordinator"]
        Guardian["root-guardian<br>• Path Traversal Guards<br>• Symlink Jail Verifier<br>• TOCTOU Validator"]
        Audit["root-audit<br>• JSONL Rollback Journal<br>• SHA256 Checksumming<br>• 'root undo' Handler"]
        Storage["root-storage<br>• Filesystem Traversal<br>• Inode Deduplication<br>• Mount Boundary Guard"]
        Memory["root-memory<br>• PSS / USS Computation<br>• PSI Pressure Stall Reader<br>• Kernel Cache Analyzer"]
        Process["root-process<br>• Process Tree Generation<br>• pidfd Safe Signaling<br>• Orphan Fingerprinting"]
        Workspace["root-workspace<br>• Git Porcelain Status<br>• Uncommitted Work Guard<br>• Language Detector"]
    end

    subgraph PlatformLayer["Platform Abstraction Layer"]
        PlatformTraits["root-platform<br>• ProcessProvider<br>• ResourceAccountant<br>• FilesystemWatcher<br>• EnvironmentProvider"]
        LinuxBackend["Linux Engine (/proc, cgroups v2, pidfd, inotify, statx)"]
    end

    CLI --> Core
    GUI --> Core
    Timer --> CLI
    MonitorDaemon --> Core

    Core --> Guardian
    Core --> Audit
    Core --> Storage
    Core --> Memory
    Core --> Process
    Core --> Workspace

    Storage --> PlatformTraits
    Memory --> PlatformTraits
    Process --> PlatformTraits
    Workspace --> PlatformTraits
    PlatformTraits --> LinuxBackend
```

---

## 2. Component Directory & Crate Topology

Root is organized as a unified Cargo workspace. In Phase 00, the architecture is documented and established before crate initialization in Phase 01:

```
crates/
├── root-core/          # Pure domain logic, policy rules, classification types
├── root-platform/      # Cross-platform traits (ProcessProvider, FilesystemWatcher, etc.)
│   └── src/linux/      # Linux-specific implementation (/proc, cgroups v2, pidfd)
├── root-guardian/      # Security engine, path canonicalization, symlink jail enforcement
├── root-audit/         # Rollback journaling, SHA256 integrity, transaction logs
├── root-storage/       # Filesystem scanner, hardlink deduplication, directory walk
├── root-memory/        # PSS/USS computation, PSI memory pressure monitoring
├── root-process/       # Process tree inspection, orphan detection, safe signaling
├── root-workspace/     # Git repository state, branch checking, project detectors
├── root-cli/           # Terminal UI, interactive prompts, formatted output
├── root-monitor/       # (Future) Lightweight inotify / cgroup event daemon
└── root-gui/           # (Future) Native GNOME GTK4 + libadwaita desktop interface
```

---

## 3. Transactional Execution Lifecycle

Every mutating operation in Root follows a strict 6-stage transactional lifecycle:

```mermaid
sequenceDiagram
    participant User as Developer / Frontend
    participant Core as root-core
    participant Guardian as root-guardian
    participant Platform as root-platform
    participant Audit as root-audit
    participant Disk as Target Filesystem

    User->>Core: Request Action (e.g. Quarantine Candidate)
    Core->>Guardian: Pre-Flight Safety Validation(Candidate)
    Guardian->>Platform: Verify Inode, Device ID & Permissions
    Platform-->>Guardian: Attributes Match Snapshot
    Guardian-->>Core: Validation Passed

    Core->>Disk: Atomic Rename into Quarantine (~/.local/state/root/quarantine)
    Disk-->>Core: Rename Success
    Core->>Audit: Record Rollback Journal Entry (Path, Size, SHA256, Timestamp)
    Audit-->>Core: Journal Flushed & fsync'd
    Core-->>User: Success Notification with 'root undo' Token
```

### The 6 Stages:
1. **Identification**: Scanners collect candidates and calculate PSS/USS or storage bytes. Verified facts (paths, metadata, inodes) are kept strictly separate from inferred classifications.
2. **Classification**: `root-core` evaluates rules, assigning one of four tiers (`STRICTLY_PROTECTED`, `USER_CONFIRM_REQUIRED`, `OBSOLETE_TRANSIENT`, `SAFE_RECOVERABLE`).
3. **Pre-Flight Validation**: `root-guardian` ensures paths do not cross mount boundaries, escape via symlinks, or violate git safety invariants. Ownership (UID/GID) and process/filesystem identities are independently validated.
4. **Interactive Consent**: User reviews findings with transparent "Why" explanations; explicit confirmation required for non-transient items.
5. **Quarantine Movement**: Candidates are moved using `renameat2(RENAME_NOREPLACE)` on the same filesystem. For cross-filesystem operations, atomic rename is impossible; a verified copy-check-unlink transaction is required with complete metadata preservation.
6. **Journaling & Recovery Tracking**: `root-audit` records cryptographic hashes, path maps, ownership, permissions, and timestamps. Note that recovery cannot be guaranteed in every circumstance (e.g. occupied destination, unmounted mounts, deleted parent trees).

---

## 4. Concurrency & Synchronization Model

- **Advisory File Lock**: Single-writer model via `$XDG_STATE_HOME/root/root.lock` (`flock`). Prevents conflicting concurrent mutations between CLI, scheduled timer, and GUI.
- **Asynchronous Non-Blocking Scanning**: Traversal and `/proc` parsing run on dedicated worker threads using Rust's `tokio` or threadpools, streaming results to frontends via bounded channels with backpressure.
- **Zero UI Freezing**: Frontends (CLI progress spinners and GTK main loops) are never blocked by filesystem I/O or process inspection.

---

## 5. Architectural Corrections & Physical Realities (Phase 01 Revisions)

Phase 01 introduces seven foundational corrections to refine earlier Phase 00 assumptions against concrete operating system realities:

1. **Cross-Filesystem Rename Non-Atomicity**:
   - `renameat2(2)` fails with `EXDEV` across mount points or different filesystems.
   - Moving data across filesystem boundaries requires a multi-step sequence (streaming copy -> verification of bytes/hashes -> unlinking source). This sequence is inherently non-atomic and vulnerable to power failure, disk exhaustion, or concurrent interference.
2. **Quarantine Restoration Uncertainty**:
   - Restoration (`root undo`) cannot be guaranteed under all circumstances. The original path may become occupied by new user files, parent directory trees may have been unlinked, permissions on parent directories may have changed, or destination filesystems may be unmounted or out of space.
   - The transaction journal must explicitly support conflict detection and alternate recovery paths.
3. **Hard Link Unlinking Semantics**:
   - Unlinking a directory entry referencing a multi-linked inode (`st_nlink > 1`) decrements the link count and leaves all remaining hard links pointing to valid, intact data.
   - Removing a hard link does **not** corrupt remaining links. The genuine risks are:
     - Mutating a multi-linked file in-place (corrupts all other hard links referencing the same inode).
     - Incorrectly assuming that unlinking one link frees storage (disk space is only freed when `st_nlink` reaches 0).
4. **Process Parentage (PPID == 1) Nuances**:
   - A process re-parented to PID 1 is **not** automatically abandoned.
   - Daemons, systemd user services, background compilers, and detached interactive tasks (`nohup`, `tmux`, `daemon()`) legitimately have `PPID == 1`.
   - Abandonment requires multi-factor corroboration: absence of controlling TTY, dead session leader, inactive IPC pipes, absence of parent agent sessions, and process lifetime heuristics.
5. **Agent File Lifecycle Evidence**:
   - Agent-generated files (scratchpads, worktrees, test directories) must **never** be classified as disposable without sufficient corroborating lifecycle evidence.
   - Users may have edited files within agent scratchpads or saved intentional work. Deletion requires closed sessions, clean git trees, age thresholds, and explicit user consent.
6. **Independent Identity and Ownership Validation**:
   - Filesystem identity (`(st_dev, st_ino)` + canonical path + UID), process identity (PID + `starttime` + executable inode + UID + `pidfd`), and resource ownership must be independently authenticated before any action.
   - Root strictly verifies UID match to prevent acting on resources belonging to other users.
7. **Transactional Robustness & Metadata Preservation**:
   - Any mutation must preserve complete metadata: POSIX file modes, ownership UID/GID (where permitted), timestamps (mtime, atime), and extended attributes (xattrs).
   - The engine must gracefully abort and roll back if files are modified concurrently during execution.
