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

### Phase 05: Command Line Interface (`root-cli`)
- **Primary Goal**: Deliver a beautiful, deterministic terminal experience.
- **Key Tasks**:
  - CLI commands: `root scan`, `root status`, `root quarantine`, `root undo`, `root purge`.
  - Interactive terminal UI: tabular columns, colored tier badges, progress bars, middle-truncated paths.
  - JSON output format (`root scan --json`) for scripting and automation.
  - Explicit confirmation prompts with explanatory risk summaries.
- **Safety Gate**: No destructive action without explicit user confirmation flag (`--yes`).

---

### Phase 06: Scheduled Inspections (Mode B)
- **Primary Goal**: Enable non-intrusive periodic background inspections.
- **Key Tasks**:
  - Package systemd user service (`root-inspect.service`) and timer (`root-inspect.timer`).
  - Implement desktop notification dispatcher via D-Bus (`org.freedesktop.Notifications`).
  - CLI management commands (`root schedule enable`, `root schedule disable`, `root schedule status`).
- **Safety Gate**: Scheduled mode is strictly read-only; notifications only; zero automatic file mutations.

---

### Phase 07: Live Event Monitoring Engine (`root-monitor`, Mode C)
- **Primary Goal**: Provide lightweight, event-driven monitoring for active multi-agent workflows.
- **Key Tasks**:
  - Implement `inotify` watcher for targeted agent workspaces.
  - Implement cgroups v2 PSI memory pressure listener (`/sys/fs/cgroup/.../memory.pressure`).
  - Real-time orphan process detection upon parent exit.
  - Battery-aware throttling and sleep coalescing.
- **Safety Gate**: CPU usage verified < 0.1% when idle; zero disk I/O thrashing.

---

### Phase 08: Native Desktop Application (GTK4 + libadwaita, `root-gui`)
- **Primary Goal**: Deliver a world-class, Linux-native desktop resource manager.
- **Key Tasks**:
  - Implement GUI window using `AdwApplicationWindow`, `AdwHeaderBar`, `AdwViewSwitcher`.
  - Implement views: System Overview, Agents, Workspaces, Processes, Audit/Quarantine.
  - Integrate Emil Kowalski Designing-Skills principles:
    - Tabular figures (`tnum`) for byte counters and PIDs.
    - Middle truncation for paths.
    - Sub-250ms purposeful transitions (`AdwTimedAnimation`, `AdwSpringAnimation`).
    - Zero animation on keyboard navigation.
    - Light and dark theme integration (`AdwStyleManager`).
  - Adversarial Break-UI verification with worst-case data.
- **Safety Gate**: GUI runs completely unprivileged; 60fps/120fps frame budget verified.

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
