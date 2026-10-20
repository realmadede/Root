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

### Phase 02: Linux Platform Engine (`root-platform-linux`)
- **Primary Goal**: Implement safe, unprivileged Linux kernel interfaces.
- **Key Tasks**:
  - Implement `/proc` parser: `/proc/meminfo`, `/proc/[pid]/smaps_rollup` (PSS/USS calculation).
  - Implement safe process signaling via `pidfd_open(2)` and `pidfd_send_signal(2)`.
  - Implement filesystem traversal engine using `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`.
  - Implement `st_dev` mount boundary checks and `st_nlink` multi-link detection.
  - Implement cgroups v2 user slice reader (`/sys/fs/cgroup/user.slice/...`).
- **Safety Gate**: Verified in Level 2 rootless containers; PID reuse test suite passes.

---

### Phase 03: Agent & Tooling Scanners (`root-storage`, `root-process`, `root-workspace`)
- **Primary Goal**: Build deterministic scanners for development tools and AI agents.
- **Key Tasks**:
  - Implement Antigravity scanner (`brain/`, `.system_generated/`, `scratch/`, `log/`, `crashes/`).
  - Implement Claude Code scanner (`sessions/`, `session-env/`, `shell-snapshots/`, `backups/`).
  - Implement tooling scanners: Cargo `target/`, npm/pnpm `node_modules/`, Python `__pycache__`/`.venv`.
  - Implement Git workspace checker (`git status --porcelain`, uncommitted work protection).
  - Implement orphaned process fingerprinting (LSPs, dev servers with PPID == 1).
- **Safety Gate**: Accurate identification without touching credentials or conversation transcripts.

---

### Phase 04: Guardian Security Engine & Quarantine Rollback (`root-guardian`, `root-audit`)
- **Primary Goal**: Enforce security boundaries and implement zero-data-loss rollback mechanics.
- **Key Tasks**:
  - Implement `root-guardian` path validator (canonicalization, prefix boundary verification).
  - Implement atomic quarantine mover (`renameat2(RENAME_NOREPLACE)`).
  - Implement JSONL rollback journal with SHA256 checksums and restore command (`root undo`).
  - Implement 30-day quarantine retention expiration tracker.
- **Safety Gate**: Level 3 Kali Linux VM validation; verify 100% reversible test cleanups.

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
