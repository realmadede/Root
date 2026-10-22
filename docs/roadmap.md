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
    Phase 00 : Foundation, Research & Architecture     :done, p00, 2026-10, 2026-10
    Phase 01 : Core Models & Synthetic Fixtures         :done, p01, 2026-11, 2026-11
    Phase 02 : Linux Platform Engine (/proc, pidfd)     :done, p02, 2026-12, 2026-12
    section Analysis & Security
    Phase 03 : Agent & Tooling Scanners                 :done, p03, 2027-01, 2027-01
    Phase 04 : Guardian Security & Quarantine Rollback  :done, p04, 2027-02, 2027-02
    section Interfaces & Automation
    Phase 05 : Command Line Interface (root-cli)        :done, p05, 2027-03, 2027-03
    Phase 06 : Scheduled Inspections (systemd timers)   :done, p06, 2027-04, 2027-04
    Phase 07 : Live Event Monitoring (root-monitor)     :done, p07, 2027-05, 2027-05
    Phase 08 : Native Desktop GUI (GTK4 + libadwaita)   :done, p08, 2027-06, 2027-07
    Phase 09 : Desktop Usability & Security Validation :done, p09, 2027-07, 2027-07
    section Multiplatform & Release
    Phase 10 : Cross-Platform Expansion (macOS, Win)    :p10, 2027-08, 2027-09
    Phase 11 : Controlled Mutation Enablement           :p11, 2027-10, 2027-11
    Phase 12 : Hardening, Web, Packaging & Release      :p12, 2027-12, 2027-12
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

### Phase 09: Native Desktop Integration, Usability & Security Validation — COMPLETED
- **Status**: COMPLETE
- **Primary Goal**: Validate, integrate, test, and refine Root's native GTK4/libadwaita desktop application on real Linux desktops (Kali Linux Rolling with GNOME on Wayland).
- **Key Accomplishments**:
  - Validated native GTK4 and libadwaita compilation with `default = ["gtk"]` and clean headless fallback (`--no-default-features`) for CI.
  - Implemented real GTK view modules across all seven tabs (`Overview`, `Resources`, `Agents`, `Processes`, `Activity`, `Schedule`, `Settings`) displaying live kernel and discovery telemetry.
  - Added Pango markup character escaping (`escape_markup`), eliminating all GTK markup parsing warnings on ampersands and special characters.
  - Integrated `AdwStyleManager` theme switching (System Default, Force Light, Force Dark).
  - Verified FreeDesktop desktop entry (`data/io.github.realmadede.Root.desktop`) via `desktop-file-validate` with zero errors.
  - Recorded empirical performance measurements on host workstation (1.0s launch time, 126.89 MiB idle RSS, 15.5ms shutdown latency, <1ms cancellation latency).
  - Extended regression suite to 27 automated tests in `root-gui` covering all Section 23 areas, including Level B native GTK component construction and Unicode path handling; achieved 159 total passing tests across the workspace.
- **Safety Gate**: Passed all 159 workspace tests; strictly read-only execution; zero mutation actions exposed; Guardian rejects all mutating requests unconditionally.

---

### Phase 10: Cross-Platform Expansion (macOS & Windows)
- **Primary Goal**: Bring Root's deterministic resource management to other platforms.
- **Key Tasks**:
  - Implement `root-platform-macos` (Darwin `proc_pidinfo`, launchd user agents, FSEvents).
  - Implement `root-platform-windows` (Win32 process handles, Job Objects, Task Scheduler).
- **Status**: NOT STARTED; PENDING HUMAN AUTHORIZATION. Scope is read-only inspection, scheduling, and monitoring parity; mutation stays disabled on every platform until Phase 11.
- **Safety Gate**: Core engine remains identical; platform traits fully satisfied.

---

### Phase 11: Controlled Mutation Enablement — NOT STARTED
- **Status**: PENDING HUMAN AUTHORIZATION (design documented only; no implementation)
- **Primary Goal**: Expose the already-built Guardian quarantine engine to users through explicit, confirmed, reversible commands. Through Phase 09 the engine exists and is tested against synthetic fixtures, but the production CLI, scheduler, monitor, and GUI are strictly read-only and Guardian rejects every mutating request issued from them.
- **Current State (verified in Phase 09)**:
  - Implemented in `root-guardian`: 8-factor authorization, 8-state transaction state machine, `RENAME_NOREPLACE` same-filesystem relocation, SHA-256 recovery journal, rollback.
  - Not implemented: any production command or GUI control that invokes it. `clean`, `quarantine`, `restore`, `delete`, and `prune` are rejected by explicit guardrails in `root-cli`.
- **Scope Note**: Runs after Phase 10, so the mutation contract (quarantine relocation, journal, locking, process termination) is specified against the `root-platform` traits and implemented for each supported platform, rather than Linux only. Linux remains the reference implementation.
- **Planned Tasks** (to be refined in a Phase 11 design document before any code):
  - Introduce `root quarantine <resource-id>` and `root restore <transaction-id>` with a mandatory dry-run preview and an explicit confirmation step; no implicit or bulk deletion.
  - Define the lifecycle of quarantined data (retention, expiry, permanent purge) in `docs/cleanup-policy.md` under the Quarantine-First policy; permanent deletion remains a separate, later decision.
  - Acquire the single-writer lock (`$XDG_STATE_HOME/root/root.lock`) for every mutation; scheduled (Mode B) and monitor (Mode C) paths remain permanently read-only.
  - Process termination (via `pidfd_open` and `pidfd_send_signal`) is evaluated separately and stays disabled unless explicitly approved.
  - GUI mutation controls only after CLI behavior is verified, following the Designing-Skills confirmation patterns.
  - Re-run threat model review (`docs/threat-model.md`) for the newly reachable mutation paths.
- **Safety Gate**: All destructive tests run only against Level 1 synthetic fixtures, Level 2 rootless containers, or Level 3 disposable VMs; crash-recovery and rollback verified; protected tiers (transcripts, credentials, dirty Git trees) proven unreachable by any mutation path; Guardian remains the sole mutation authority.

---

### Phase 12: 1.0 Production Hardening, Packaging, SHA-256 Distribution & Security Audit
- **Primary Goal**: Publish audited, production-grade open source releases distributed via GitHub Releases, native system packages, and cryptographic verification manifests.
- **Key Tasks**:
  - **Standalone GitHub Release Binaries**:
    - Pre-compile optimized, standalone release binaries for `root` (CLI) and `root-gui` (desktop application) targeting Linux (`x86_64`, `aarch64`), macOS (`x86_64`, `arm64`), and Windows (`x86_64`).
    - Eliminate the requirement for end users to clone the Git repository or install the Rust/Cargo toolchain.
  - **Deterministic SHA-256 Checksums and Provenance Verification**:
    - Compute and publish official `SHA256SUMS` manifests alongside every release archive on the GitHub Releases page.
    - Support standard user-side checksum verification (`sha256sum -c SHA256SUMS`).
    - Provide cryptographic release signatures (`SHA256SUMS.sig`) via GPG and Sigstore (`cosign`) to guarantee release provenance.
  - **Native Linux System Packaging**:
    - Build `.deb` packages for Debian, Ubuntu, and Kali Linux with desktop launcher integration and manpages.
    - Build `.rpm` packages for Fedora and RHEL.
    - Publish official PKGBUILD for Arch Linux (AUR).
    - Publish official Flatpak package for GNOME Software and Flathub.
  - **Ecosystem Distribution**:
    - Publish `root-cli` and core workspace crates to crates.io for standard `cargo install root-cli` workflows.
  - **Automated CI/CD Release Pipeline**:
    - Establish GitHub Actions release automation triggered strictly on verified Git release tags (`v*`).
  - **Official Project Landing Website & Documentation Portal**:
    - Design and deploy a modern, lightweight, privacy-respecting landing website showcasing Root's architecture, interactive CLI terminal demonstrations, native GTK4/libadwaita desktop showcase, security guarantees, and performance benchmarks.
    - Provide direct download links for standalone platform binaries with instant copyable SHA-256 verification commands and cryptographic signature validation guides.
    - Host statically with zero telemetry, zero tracking scripts, and complete adherence to Root's local-first privacy standards.
  - **Comprehensive Security Audit**:
    - Third-party security review of the Guardian transaction engine and Linux platform abstraction layers.
- **Safety Gate**: Zero high or medium security vulnerabilities; reproducible release builds; 100% verified SHA-256 checksums.
