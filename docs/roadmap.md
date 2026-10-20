# Root Project Roadmap & Phased Implementation Plan

## 1. Governance Principles

Root adheres to a strict, phase-gated engineering methodology.
- **No phase may begin until the preceding phase meets 100% of its acceptance criteria.**
- **No production code may be introduced without corresponding unit tests and threat model verification.**
- **Security reviews and fixture verification precede UI development.**

---

## 2. Long-Term Implementation Phases

```mermaid
gantt
    title Root Development Roadmap
    dateFormat  YYYY-MM
    section Foundation & Core
    Phase 00 : Foundation, Research & Architecture     :active, p00, 2026-10, 2026-10
    Phase 01 : Core Models & Synthetic Fixtures         :p01, 2026-11, 2026-11
    Phase 02 : Linux Platform Engine (/proc, pidfd)     :p02, 2026-12, 2026-12
    section Analysis & Security
    Phase 03 : Agent & Tooling Scanners                 :p03, 2027-01, 2027-01
    Phase 04 : Guardian Security & Quarantine Rollback  :p04, 2027-02, 2027-02
    section Interfaces & Automation
    Phase 05 : Command Line Interface (root-cli)        :p05, 2027-03, 2027-03
    Phase 06 : Scheduled Inspections (systemd timers)   :p06, 2027-04, 2027-04
    Phase 07 : Live Event Monitoring (root-monitor)     :p07, 2027-05, 2027-05
    Phase 08 : Native Desktop GUI (GTK4 + libadwaita)   :p08, 2027-06, 2027-07
    section Multiplatform & Release
    Phase 09 : Cross-Platform Expansion (macOS, Win)    :p09, 2027-08, 2027-09
    Phase 10 : Hardening, Packaging & 1.0 Release       :p10, 2027-10, 2027-10
```

---

## 3. Detailed Phase Breakdown

### Phase 00: Foundation, Research, Architecture, Security, Design (Current)
- **Status**: **COMPLETE / READY FOR REVIEW**
- **Deliverables**: Comprehensive research documentation, threat model, cleanup eligibility policy, hybrid architecture, platform abstraction traits, sandboxed testing strategy, Designing-Skills GUI foundation, agent development rules, and acceptance report.
- **Gate**: No production code written. 100% documentation coverage.

---

### Phase 01: Core Domain Models, Platform Traits, & Synthetic Fixtures
- **Primary Goal**: Establish pure Rust data structures, policy evaluation logic, and Level 1 testing harness.
- **Key Tasks**:
  - Create Cargo workspace structure (`crates/root-core`, `crates/root-platform`).
  - Implement core domain models (`ResourceCandidate`, `ClassificationTier`, `ScanReport`, `QuarantineJournal`).
  - Define platform abstraction traits (`ProcessProvider`, `ResourceAccountant`, `FilesystemWatcher`, `EnvironmentProvider`).
  - Implement Level 1 synthetic fixture generator in `tests/fixtures/` (adversarial symlink trees, hardlinks, deep paths).
  - Write unit tests for classification rules against mock data.
- **Safety Gate**: All tests pass in unprivileged CI; zero OS-level side effects.

---

### Phase 02: Linux Platform Engine (`root-platform`) — COMPLETED
- **Primary Goal**: Implement safe, unprivileged Linux kernel interfaces.
- **Key Accomplishments**:
  - Implemented `/proc` parsing: `/proc/meminfo`, `/proc/[pid]/stat`, `/proc/[pid]/status`, and `/proc/[pid]/smaps_rollup` (PSS/USS calculation).
  - Implemented empirical capability probing for `/proc`, `/proc/meminfo`, PSI, `smaps_rollup`, cgroups v2, `pidfd_open`, `openat2`, and `statx` across 4 operational states.
  - Implemented defensive, bounded filesystem traversal engine (`LinuxFilesystem::traverse`) enforcing symlink non-follow, cross-device boundaries, cycle detection, depth limits (64), entry limits (250,000), and completeness reporting.
  - Implemented privacy-safe process command-line sanitization with credential and token redaction.
  - Implemented CLI inspection commands: `root inspect memory` and `root inspect processes`.
  - Upheld Root Guardian Phase 02 read-only policy: all file mutations and process signaling permanently prohibited.
- **Safety Gate**: Passed 25 workspace tests; zero host file mutation; memory and capability detection verified.

---

### Phase 03: Agent and Development Tool Discovery Engine (`root-core::discovery`, `root-cli::discover`)
- **Status**: COMPLETE
- **Primary Goal**: Build deterministic, read-only discovery engines for AI coding agents and development toolchains.
- **Key Accomplishments**:
  - Implemented 12 discovery targets across AI coding agents (Google Antigravity, Claude Code, OpenAI Codex, Gemini CLI, Aider) and development tooling (Node.js & npm, pnpm, Rust & Cargo, Python, Git, Language Servers, Dev Servers).
  - Implemented versioned, deterministic `DiscoveryRule` catalog (`RuleRegistry`) documenting evidence source, confidence level, and known limitations for every rule.
  - Implemented multi-factor `LifecycleAssessment` engine correlating file metadata, timestamps, presence markers, and active OS process tables (`Active`, `Persistent`, `DormantTransient`, `Unknown`).
  - Implemented dedicated pnpm hard-link store protection (`StrictlyProtected` with `ProposedAction::Ignore`) preventing cross-project inode corruption.
  - Upheld Root Guardian Phase 03 read-only policy: all mutations (`Quarantine`, `Prune`, `TerminateGraceful`) permanently prohibited.
  - Enforced metadata-only privacy safeguards: zero file content reading; verified no credentials, encryption keys, or transcripts leak into reports.
  - Implemented CLI discovery command: `root discover` supporting target filters (`--agents`, `--tools`, `--agent <name>`, `--tool <name>`) and JSON output (`--json`).
  - Added dedicated integration test suite (`tests/discovery_tests.rs`); passed 32 workspace tests with zero failures.
- **Safety Gate**: Passed all 32 tests; verified read-only non-destructive operation on synthetic fixture and host system.

---

### Phase 04: Guardian Security Engine and Quarantine Rollback (`root-guardian`)
- **Status**: COMPLETE
- **Primary Goal**: Enforce security boundaries and implement zero-data-loss rollback mechanics.
- **Key Accomplishments**:
  - Implemented 8-factor explicit authorization engine (`AuthorizationEngine`) ensuring unknown, non-actionable, or strictly protected resources are unconditionally rejected.
  - Implemented 8-state transaction state machine (`TransactionState`, `TransactionContext`) enforcing valid, deterministic state transitions (`Proposed` -> `Authorized` -> `Prepared` -> `Quarantined` -> `Verified` -> `Restored`).
  - Implemented strictly isolated synthetic fixture sandbox (`FixtureSandbox`) preventing any mutation of host or user files outside verified test boundaries.
  - Implemented Linux same-filesystem atomic relocation using `LinuxFilesystem::atomic_rename_no_replace` (`SYS_renameat2` with `RENAME_NOREPLACE`), eliminating destination overwrite risks and enforcing cross-device boundary checks.
  - Implemented durable recovery journal (`RecoveryJournal`) with JSONL serialization, data syncing, malformed record detection, and interrupted transaction identification.
  - Implemented conflict-aware restoration engine (`RestorationEngine`) guaranteeing that occupied destination paths are never overwritten.
  - Implemented self-contained FIPS 180-4 SHA-256 integrity verification (`sha256_file`) with zero third-party dependencies.
  - Added comprehensive 16-scenario adversarial security test suite (`guardian_transaction_tests.rs`) covering symlink escapes, TOCTOU races, destination collisions, hard links, sparse files, Unicode filenames, and journal corruption.
  - Passed all 51 workspace tests with zero failures.
- **Safety Gate**: Passed all 51 tests; zero host file mutation; 100% reversible test cleanups within synthetic sandbox.

---

### Phase 05: Professional Command Line Interface & Resource Inspection Experience (`root-cli`)
- **Status**: COMPLETE
- **Primary Goal**: Deliver a polished, accessible, deterministic terminal inspection experience.
- **Key Accomplishments**:
  - Implemented modular CLI architecture cleanly separating argument parsing (`args.rs`), command dispatch (`lib.rs`), terminal formatting (`terminal.rs`), state persistence (`history.rs`), and interactive navigation (`interactive.rs`).
  - Implemented `root status`: comprehensive system overview displaying OS, kernel release, invoking UID, available RAM, swap usage, PSI pressure indicators, supported targets, last scan activity, and current safety policy.
  - Implemented `root inspect storage`: filesystem capacity via kernel `statvfs`, free blocks, inode counts, and directory allocation breakdown distinguishing apparent size from physical blocks, sparse files, and deduplicated multi-link storage.
  - Implemented `root inspect transactions`: read-only diagnostic presentation of synthetic recovery journals, displaying chronological state transitions, SHA-256 hashes, and interrupted transaction detection.
  - Implemented `root explain <resource-id>`: explainability engine detailing observed facts, matched discovery rules, evidence provenance, lifecycle uncertainty, protection tiers, and Guardian policy decisions.
  - Implemented `root report`: consolidated diagnostic and audit report combining host health, storage capacity, discovery summaries, and security boundaries.
  - Implemented `root discover --interactive`: read-only interactive terminal browser supporting index selection, text filtering, tier filtering, and sorting without heavy external TUI frameworks.
  - Built terminal engine adhering to NO_COLOR specification, POSIX terminal width detection, tabular formatting, and middle truncation.
  - Added strict guardrails prohibiting production mutation commands (`clean`, `quarantine`, `restore`, `delete`, `prune`), maintaining production read-only invariants.
  - Expanded test suite with 6 Guardian security follow-up tests and 20 CLI integration tests, achieving 77 total passing tests across the workspace.
- **Safety Gate**: Passed all 77 workspace tests; production CLI is strictly read-only; zero mutation commands enabled.

---

### Phase 06: Scheduled Inspections (Mode B) — COMPLETED
- **Status**: COMPLETE
- **Primary Goal**: Enable non-intrusive periodic background inspections without running permanent daemons.
- **Key Accomplishments**:
  - Implemented core schedule domain models (`ScheduleConfig`, `ScheduleInterval`, `ScheduleRunStatus`, `ScheduleHistoryEntry`, `ScheduleStatus`) with validation rejecting unsafe targets and injection vectors.
  - Implemented Linux systemd user unit generator (`SystemdUnitGenerator`) producing hardened `root-inspect.service` (`NoNewPrivileges=true`, `Nice=19`, `IOSchedulingClass=idle`, `TimeoutSec=120`, direct binary invocation without shell wrappers) and `root-inspect.timer` (`Persistent=true`, `RandomizedDelaySec=15m`).
  - Implemented `LinuxScheduler` platform engine managing user units (`0o644`), daemon reload, timer enable/disable, active state check, and next trigger querying.
  - Implemented privacy-preserving desktop notification dispatcher (`DesktopNotifier`) via FreeDesktop `notify-send` and D-Bus with graceful non-fatal fallback.
  - Implemented concurrency protection using non-blocking POSIX file locking (`flock`) on `$XDG_STATE_HOME/root/schedule.lock`, cleanly skipping overlapping runs.
  - Implemented comprehensive `root schedule` CLI command family (`status`, `enable`, `disable`, `list`, `run`, `history`, `remove`) with pre-activation confirmation preview.
  - Implemented bounded history persistence in `$XDG_STATE_HOME/root/schedule_history.json` with strict `0o600` permissions and automated pruning to 50 records.
  - Updated `root status` and `root doctor` with systemd user unit and scheduler health auditing.
  - Added dedicated 20-scenario automated integration test suite (`tests/schedule_tests.rs`) utilizing isolated mock unit directories; achieved 97 total passing tests across the workspace.
- **Safety Gate**: Passed all 97 workspace tests; scheduled mode is strictly read-only; Guardian unconditionally rejects all scheduled mutations; zero permanent background daemons.

---

### Phase 07: Live Event Monitoring Engine (`root-monitor`, Mode C) — COMPLETED
- **Status**: COMPLETE
- **Primary Goal**: Provide lightweight, event-driven observation of filesystem mutations, agent process lifecycles, and memory pressure during active development sessions.
- **Key Accomplishments**:
  - Implemented core live monitoring domain models (`MonitorSessionState`, `DegradedReason`, `LiveFsEventKind`, `LiveFsEvent`, `ProcessEventKind`, `ProcessObservation`, `MemoryObservation`, `MonitorBudget`, `MonitorScope`, `MonitorEvent`, `MonitorSessionSummary`).
  - Implemented POSIX non-blocking `inotify` watcher (`InotifyWatcher`) via `inotify_init1(IN_NONBLOCK | IN_CLOEXEC)` with recursive directory watching, dynamic child directory registration, and strict symlink non-follow protection.
  - Implemented kernel inotify queue overflow (`IN_Q_OVERFLOW`) detection and degraded state transitions.
  - Implemented rapid write event coalescing within a 150ms deduplication window, mitigating event storms from rapid file saves.
  - Implemented unprivileged process lifecycle observation (`ProcessObserver`) via `/proc` polling, correlating active processes with agent signatures (`antigravity`, `claude`, `codex`, `gemini`, `aider`).
  - Implemented robust PID reuse disambiguation tracking immutable `start_time_ticks` (field 22 of `/proc/[pid]/stat`).
  - Implemented memory and PSI pressure sampling (`MemoryObserver`) via `/proc/meminfo` and `/proc/pressure/memory`, with elevated pressure detection (>40.0% stall).
  - Implemented session coordinator (`LinuxMonitorSession`) managing degraded transitions, watch descriptor lifecycles, and clean teardown on `drop`.
  - Implemented `root monitor` CLI command with target scope validation, POSIX signal handling (Ctrl+C), ANSI tabular dashboard adhering to `NO_COLOR`, and streaming newline-delimited JSON Lines (`--json`).
  - Upheld Root Guardian read-only invariant: unconditionally rejects all mutations during live monitoring.
  - Ensured concurrency independence: live monitoring does not acquire `schedule.lock`, allowing Mode B scheduled inspections and Mode C live monitoring to coexist without locking contention.
  - Added comprehensive 25-scenario automated integration test suite (`crates/root-cli/tests/monitor_tests.rs`); achieved 132 total passing tests across the workspace.
- **Safety Gate**: Passed all 132 workspace tests; live monitoring is strictly read-only; Guardian unconditionally rejects all mutations; zero permanent background daemons; zero credential or transcript leakage.

---

### Phase 08: Native Desktop Application (GTK4 + libadwaita, `root-gui`) — COMPLETED
- **Status**: COMPLETE
- **Primary Goal**: Deliver a world-class, Linux-native desktop resource manager integrating the Designing-Skills reference design (`2d228630ba1446365f614a108cb8252f1feda202`).
- **Key Accomplishments**:
  - Established new workspace crate `root-gui` strictly decoupled from the core engine, upholding the headless server isolation invariant (zero GTK dependencies in core crates).
  - Implemented complete navigation shell across seven dedicated views: Overview, Resources, Agents, Processes, Activity, Schedule, and Settings.
  - Implemented decoupled, testable view models (`OverviewViewModel`, `ResourcesViewModel`, `AgentsViewModel`, `ProcessesViewModel`, `ActivityViewModel`, `ScheduleViewModel`, `SettingsViewModel`).
  - Integrated Designing-Skills reference principles: tabular figures (`tnum=1`) eliminating numeric jitter, middle truncation for long paths (`format_path_middle`), sub-250ms purposeful transitions, zero animation on keyboard navigation (`<Control>1`..`<Control>7`), and light/dark theme adaptation (`AdwStyleManager`).
  - Implemented bounded resource list presentation (capped at 500 rows) with multi-criteria filtering and sorting to eliminate UI rendering overhead.
  - Implemented asynchronous background inspection worker (`InspectionWorker`) with atomic cancellation (`CancellationToken`) and generation fencing preventing stale results from overwriting newer state.
  - Integrated Mode C live monitoring and Mode B scheduling configuration into native desktop views with explicit user activation and authorization guardrails.
  - Maintained strict production read-only guarantee: zero cleanup, quarantine, or process termination actions exposed in the GUI; Guardian unconditionally rejects all mutating actions.
  - Created desktop integration metadata: `data/io.github.realmadede.Root.desktop` and `data/io.github.realmadede.Root.metainfo.xml`.
  - Added comprehensive 22-scenario automated integration test suite (`crates/root-gui/tests/gui_view_model_tests.rs`); achieved 154 total passing tests across the workspace.
- **Safety Gate**: Passed all 154 workspace tests; GUI runs completely unprivileged; zero GTK dependencies in core engine; headless compilation verified.

---

### Phase 09: Cross-Platform Expansion (macOS & Windows)
- **Primary Goal**: Bring Root's deterministic resource management to other platforms.
- **Key Tasks**:
  - Implement `root-platform-macos` (Darwin `proc_pidinfo`, launchd user agents, FSEvents).
  - Implement `root-platform-windows` (Win32 process handles, Job Objects, Task Scheduler).
- **Safety Gate**: Core engine remains identical; platform traits fully satisfied.

---

### Phase 10: 1.0 Production Hardening, Packaging & Security Audit
- **Primary Goal**: Publish audited, production-grade open source releases.
- **Key Tasks**:
  - Comprehensive third-party security audit.
  - Native packaging: `.deb` (Kali/Debian), `.rpm` (Fedora), Arch PKGBUILD, Flatpak for GNOME Software.
  - Reproducible builds and signed releases.
- **Safety Gate**: Zero high/medium security vulnerabilities.
