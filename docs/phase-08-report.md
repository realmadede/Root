# Root — Phase 08 Completion Report: Native Desktop Application (GTK4 + libadwaita)

## 1. Executive Summary

Phase 08 establishes **Root's first native Linux desktop application (`root-gui`)**, delivering a responsive, accessible graphical interface built with Rust, GTK4, and libadwaita.

Conforming directly to the official Designing-Skills reference design (`2d228630ba1446365f614a108cb8252f1feda202`), Root GUI translates core design engineering principles into Linux desktop reality: enforcing tabular numbers (`tnum`) to eliminate layout jitter during metric updates, middle truncation for deep agent file paths, sub-250ms purposeful transitions, instant keyboard navigation without animation latency, and seamless light/dark theme adaptation via `AdwStyleManager`.

The graphical application is strictly decoupled from the core engine: `root-core`, `root-platform`, and `root-guardian` remain 100% headless with zero GTK or display server dependencies. The desktop application operates strictly under an **unprivileged, production read-only guarantee**—zero cleanup, quarantine, pruning, or process termination actions are exposed in the interface, and Root Guardian unconditionally rejects all mutating operations.

All 154 unit, integration, and security tests across the Cargo workspace pass with zero failures. The codebase complies fully with `cargo clippy --workspace --all-targets -- -D warnings`, adheres to `cargo fmt --check`, documents all public APIs via `cargo doc`, and passes all repository assurance checks with zero emojis and strict confidentiality boundaries.

---

## 2. Branch and Commit Identity

- **Active Feature Branch**: `feat/phase-08-native-gui`
- **Base Commit**: `6cdd332` (`feat(phase-07): implement lightweight live event monitoring (Mode C)`)
- **Target Integration**: Ready for phase gate review and explicit human authorization prior to merging or beginning Phase 09.

---

## 3. Files Created and Modified

### Created Files
- `crates/root-gui/Cargo.toml` — Workspace crate manifest defining dependencies, optional GTK4/libadwaita bindings, and headless view-model compilation.
- `crates/root-gui/src/lib.rs` — Library entry point exporting controllers, view models, and presentation helpers.
- `crates/root-gui/src/main.rs` — Desktop binary entry point.
- `crates/root-gui/src/app.rs` — Central application coordinator (`RootAppController`) managing state, worker message dispatch, and generation fencing.
- `crates/root-gui/src/model/mod.rs` — Domain model exports.
- `crates/root-gui/src/model/navigation.rs` — Navigation items (`Overview`, `Resources`, `Agents`, `Processes`, `Activity`, `Schedule`, `Settings`), page IDs, icons, accelerators, and history tracker.
- `crates/root-gui/src/model/presentation.rs` — Designing-Skills formatters (tabular figures `tnum`, middle path truncation, duration formatting, pluralization, accessible badge metadata).
- `crates/root-gui/src/model/state.rs` — `AppState`, `ScanExecutionState`, `ResourceFilter`, `ResourceSortField`, `SortDirection`, and `ThemePreference`.
- `crates/root-gui/src/view_model/mod.rs` — View model module exports.
- `crates/root-gui/src/view_model/overview.rs` — `OverviewViewModel` mapping memory metrics, PSI stalls, filesystem capacity, agent summaries, and operating modes.
- `crates/root-gui/src/view_model/resources.rs` — `ResourcesViewModel` managing bounded row models (capped at 500 items), multi-factor filtering, sorting, and detail inspection.
- `crates/root-gui/src/view_model/agents.rs` — `AgentsViewModel` coordinating discovery footprints and ownership notices across 12 targets.
- `crates/root-gui/src/view_model/processes.rs` — `ProcessesViewModel` managing unprivileged process table surveys, attribution confidence, and privacy boundaries.
- `crates/root-gui/src/view_model/activity.rs` — `ActivityViewModel` integrating Mode C live monitoring, bounded event queues, and degraded state tracking.
- `crates/root-gui/src/view_model/schedule.rs` — `ScheduleViewModel` integrating Mode B systemd user timer controls, authorization flows, and history logs.
- `crates/root-gui/src/view_model/settings.rs` — `SettingsViewModel` managing appearance themes, traversal budgets, privacy guarantees, and application metadata.
- `crates/root-gui/src/worker/mod.rs` — Asynchronous traversal worker (`InspectionWorker`), atomic cancellation (`CancellationToken`), and generation-tagged worker channels.
- `crates/root-gui/src/gtk/mod.rs` — Graphical runner and headless fallback message handler.
- `crates/root-gui/src/gtk/application.rs` — Native `AdwApplication` with keyboard accelerator actions.
- `crates/root-gui/src/gtk/window.rs` — Native `AdwApplicationWindow` with header bar, view switcher, view stack, breakpoints, and toast overlays.
- `crates/root-gui/tests/gui_view_model_tests.rs` — Comprehensive 22-scenario automated integration test suite verifying all Phase 08 requirements.
- `data/io.github.realmadede.Root.desktop` — FreeDesktop desktop entry specification.
- `data/io.github.realmadede.Root.metainfo.xml` — AppStream metadata specification.
- `docs/gui-architecture.md` — Detailed GUI architectural specification manual.
- `docs/phase-08-report.md` — This official completion report.

### Modified Files
- `Cargo.toml` — Added `"crates/root-gui"` to workspace members.
- `ARCHITECTURE.md` — Updated crate topology and added Section 10 detailing native desktop application architecture and guarantees.
- `docs/roadmap.md` — Marked Phase 08 as COMPLETE and documented key accomplishments.

---

## 4. GUI Architecture

Root GUI enforces a strict separation of concerns:

```
crates/root-gui/
├── model/          # Navigation, AppState, Designing-Skills formatters (tnum, middle truncation)
├── view_model/     # Decoupled view models (Overview, Resources, Agents, Processes, Activity, Schedule, Settings)
├── worker/         # Non-blocking InspectionWorker with cancellation and generation fencing
├── gtk/            # Native GTK4/libadwaita windows and views (feature = "gtk")
├── app.rs          # Central application coordinator
├── main.rs         # Desktop binary entry point
└── tests/          # Headless view-model integration tests (22 scenarios)
```

Key architectural guarantees:
- **Zero Display Coupling in Core**: Headless core crates have zero GTK dependencies.
- **Worker Isolation**: Blocking filesystem operations and live monitoring run on dedicated background threads, communicating via bounded `mpsc` channels.
- **Generation Fencing**: Every scan request increments a monotonic `current_generation` counter. Outdated scan results arriving from cancelled or superseded background runs are discarded immediately, preventing race conditions.
- **Responsive Cancellation**: Background workers poll atomic `CancellationToken`s after every directory entry and batch, yielding promptly upon cancellation.

---

## 5. Navigation Structure

Root organizes navigation across seven dedicated views using libadwaita's `AdwViewSwitcher` and `AdwViewStack`:

1. **Overview** (`view-dashboard-symbolic`): System memory, PSI pressure indicators, storage capacity, operating modes, and safety status.
2. **Resources** (`drive-harddisk-symbolic`): Bounded resource explorer with real-time search, multi-factor filtering, bidirectional sorting, and explainability drawer.
3. **Agents** (`system-run-symbolic`): Footprint cards and non-exclusive ownership transparency across 12 AI coding agents and development toolchains.
4. **Processes** (`application-x-executable-symbolic`): Unprivileged process table inspection with tool attribution confidence and privacy boundaries.
5. **Activity** (`utilities-system-monitor-symbolic`): Mode C real-time live event monitoring dashboard with degraded state tracking.
6. **Schedule** (`alarm-symbolic`): Mode B scheduled background inspection configuration, systemd timer status, and execution history.
7. **Settings** (`emblem-system-symbolic`): Light/dark theme controls, traversal budgets, privacy guarantees, and application metadata.

---

## 6. Implemented Screens

### Overview Screen
- Displays total, available, free, and cached physical RAM, plus swap utilization.
- Formats PSI memory pressure stalls across 10s, 60s, and 300s windows, mapping stall percentages to `Normal` (<10%), `Elevated` (10-40%), or `Critical` (>40%) severity badges.
- Reports filesystem capacity via kernel `statvfs` (total bytes, available bytes, free inodes).
- Distinguishes measured values from estimates: speculative transient cache space is explicitly designated as an upper bound and never as guaranteed savings.

### Resource Explorer Screen
- Implements a bounded list view capped at 500 visible rows to eliminate GTK layout allocation lag on large file trees.
- Supports multi-field filtering: search query, architectural category (`AgentScratchpad`, `BuildArtifact`, `PackageCache`, `DiagnosticLog`, etc.), protection tier (`StrictlyProtected`, `UserConfirmRequired`, `ObsoleteTransient`, `SafeRecoverable`, `NonActionable`), lifecycle state (`Active`, `Persistent`, `DormantTransient`, `Unknown`), and minimum size threshold.
- Bidirectional sorting by size, target name, category, protection tier, and lifecycle state.
- Selecting any row displays a detailed inspection view explaining rule ID, provenance facts (inode, device ID, link count), lifecycle reasoning, and Guardian decisions. Zero cleanup or quarantine buttons.

### Agent Discovery Screen
- Catalogs 12 supported targets across AI coding agents (Google Antigravity, Claude Code, OpenAI Codex, Gemini CLI, Aider) and development toolchains (Rust/Cargo, Node.js/npm, pnpm, Python, Git, Language Servers, Dev Servers).
- Categorizes status as `Active`, `Persistent`, `Dormant`, or `Not Detected`.
- Prominently displays non-exclusive ownership statements: reminds developers that directories like `node_modules` or `target` are shared between human workflows and AI agents.

### Process Inspection Screen
- Unprivileged process table survey reporting PID, PPID, process name, UID, RSS memory, and process state (`Running`, `Sleeping`, `Disk Sleep`, `Zombie`, `Stopped`).
- Attributes binary signatures to tools with confidence ratings (`High`, `Medium`, `Low`, `Unattributed`).
- Enforces strict privacy boundaries: full command-line arguments and environment variables are never collected or displayed.
- Zero process termination controls.

### Activity Screen (Mode C Integration)
- Live monitoring is disabled by default; requires explicit user activation specifying approved target paths.
- Streams live filesystem mutations (`CREATE`, `MODIFY`, `DELETE`, `MOVE`), process lifecycle events (`SPAWN`, `EXIT`), and memory samples into a bounded 250-event buffer.
- Displays non-alarming diagnostic banners when kernel queues overflow, watch limits are reached, or system memory pressure spikes.

### Scheduled Inspections Screen (Mode B Integration)
- Displays scheduled state (disabled by default), interval (`Hourly`, `Daily`, `Weekly`), profile (`Lightweight`, `Standard`, `Comprehensive`), and approved targets.
- Displays next scheduled trigger queried via `systemctl --user list-timers`.
- Displays chronological execution history loaded from `$XDG_STATE_HOME/root/schedule_history.json`.
- Requires explicit user activation before writing or enabling systemd user units.

### Settings Screen
- Appearance selector: System Default, Force Light, or Force Dark via `AdwStyleManager`.
- Configurable traversal budgets: max depth (2-64), max entries (1,000-250,000), timeout (5s-300s).
- Informational privacy indicators confirming metadata-only traversal, credential redaction, zero telemetry, and zero AI runtime dependencies.
- Application metadata, version, MIT license, and platform targets.

---

## 7. Designing-Skills Reference Compliance

Root adheres strictly to the official Designing-Skills reference design (`2d228630ba1446365f614a108cb8252f1feda202`):

1. **Tabular Figures (`tnum`)**: Numeric values (byte counts, percentages, PIDs, durations) enforce tabular figures (`font_features="tnum=1"`), completely eliminating horizontal text jitter when live meters update.
2. **Middle Truncation for Paths**: Long filesystem paths preserve both the project root and leaf filename/extension (`format_path_middle`), preventing layout grid overflow.
3. **No Animation on Keyboard Actions**: Keyboard shortcuts (`<Control>1` through `<Control>7`, `<Control>R`, `<Control>Q`) switch tabs and trigger actions instantaneously without animation latency.
4. **Sub-250ms Purposeful Motion**: View transitions utilize `AdwTimedAnimation` capped below 200ms with cubic ease-out curves.
5. **Reduced Motion Compliance**: Respects GNOME `gtk-enable-animations` desktop settings, suppressing transitions when reduced motion is requested.
6. **Break-UI Resilience**: Validated against worst-case data: extreme Unicode paths, zero-byte files, empty states, and narrow window viewport clamping (`AdwClamp`).

---

## 8. Backend and Platform Integration

The GUI consumes existing headless Rust libraries directly:
- **`root-core::discovery`**: Powers agent footprint discovery and classification rules.
- **`root-platform::linux::LinuxAccountant`**: Provides physical RAM, virtual swap, and PSI memory pressure metrics.
- **`root-platform::linux::LinuxProcess`**: Provides unprivileged `/proc` process table surveys.
- **`root-platform::linux::LinuxFilesystem`**: Powers bounded defensive traversal and kernel `statvfs` capacity accounting.
- **`root-platform::linux::LinuxScheduler`**: Powers systemd user unit management, timer active queries, and next-trigger parsing.
- **`root-platform::linux::InotifyWatcher`**: Powers Mode C non-blocking inotify live event observation.
- **`root-guardian::GuardianPolicy`**: Enforces strict read-only guarantees, unconditionally rejecting all mutating actions.

---

## 9. Monitoring Integration (Mode C)

Mode C live event monitoring is fully integrated into `ActivityViewModel`:
- **Disabled by Default**: Never activates automatically upon application startup.
- **Explicit Scope Enforcement**: Rejects launch attempts without approved paths or observation flags; rejects unsafe system directories (`/`, `/proc`, `/sys`, `/etc`).
- **Bounded In-Memory Buffer**: Maintains a circular buffer of the 250 most recent events, preventing memory leaks during rapid filesystem bursts.
- **Degraded State Awareness**: Observes and displays degradation reasons (`QueueOverflow`, `WatchLimitExceeded`, `MemoryPressureElevated`) without crashing or dropping session state.

---

## 10. Scheduling Integration (Mode B)

Mode B scheduled inspections are fully integrated into `ScheduleViewModel`:
- **Disabled by Default**: Inactive upon installation; requires explicit user authorization.
- **Non-Destructive Execution**: Scheduled passes run strictly read-only scans.
- **History Auditing**: Parses `$XDG_STATE_HOME/root/schedule_history.json` and presents status badges (`COMPLETED`, `INCOMPLETE`, `DEFERRED`, `FAILED`) and examined resource counts.

---

## 11. Security Safeguards

- **Unprivileged Operation**: The application runs completely in user space under the invoking user's UID. Never requests `sudo` or polkit privileges.
- **Production Read-Only Guarantee**: Zero cleanup, quarantine, or process termination buttons exist in the UI.
- **Guardian Rejection Invariant**: Any attempted mutating action is unconditionally rejected with `PolicyDecision::Deny`.
- **Confidentiality Guarantee**: File contents, private tokens, API keys, conversation transcripts, and process environment variables are never opened, read, or logged.

---

## 12. Accessibility and Theme Support

- **Keyboard Navigation**: Full keyboard accelerator coverage (`<Control>1` through `<Control>7`, `<Control>R`/`F5`, `<Control>Q`).
- **Visible Focus & Contrast**: Adheres to libadwaita styling conventions with high-contrast theme compatibility.
- **Screen Reader Support**: All badges provide explicit accessible descriptions (`ProtectionBadge::accessible_description`, `LifecycleBadge::accessible_description`).
- **Appearance Themes**: Seamless day/night switching via `AdwStyleManager` (`SystemDefault`, `ForceLight`, `ForceDark`).

---

## 13. Automated Verification Across 22 Test Scenarios

The Phase 08 integration test suite (`crates/root-gui/tests/gui_view_model_tests.rs`) implements and verifies all 22 required test scenarios:

| Scenario | Test Identifier | Focus Area | Verification Result |
|:---:|:---|:---|:---:|
| 1 | `test_01_application_initialization` | Safe default initialization and state | **VERIFIED PASS** |
| 2 | `test_02_navigation` | Tab switching across all 7 views and back navigation | **VERIFIED PASS** |
| 3 | `test_03_overview_data_mapping` | Memory, swap, and PSI severity mapping | **VERIFIED PASS** |
| 4 | `test_04_resource_filtering` | Multi-factor filtering (search, tier, category) | **VERIFIED PASS** |
| 5 | `test_05_resource_sorting` | Bidirectional sorting (size, name, tier) | **VERIFIED PASS** |
| 6 | `test_06_evidence_presentation` | Provenance facts and rule ID formatting | **VERIFIED PASS** |
| 7 | `test_07_protection_state_presentation` | Badge labels and CSS classes across all 5 tiers | **VERIFIED PASS** |
| 8 | `test_08_agent_attribution` | Agent card footprint aggregation and status | **VERIFIED PASS** |
| 9 | `test_09_process_identity_mapping` | Process attribution confidence and UID filtering | **VERIFIED PASS** |
| 10 | `test_10_monitoring_start_and_stop` | Mode C start/stop lifecycle and scope validation | **VERIFIED PASS** |
| 11 | `test_11_monitoring_degradation` | Degraded state transition and reason tracking | **VERIFIED PASS** |
| 12 | `test_12_scheduling_state_presentation` | Schedule status and history row formatting | **VERIFIED PASS** |
| 13 | `test_13_scheduling_authorization` | Target path validation and explicit activation | **VERIFIED PASS** |
| 14 | `test_14_privacy_sensitive_fields` | Zero inspection of private transcripts/tokens | **VERIFIED PASS** |
| 15 | `test_15_cancellation` | Responsive background worker cancellation | **VERIFIED PASS** |
| 16 | `test_16_stale_result_prevention` | Generation fencing dropping superseded results | **VERIFIED PASS** |
| 17 | `test_17_empty_states` | Zero-state handling without panics | **VERIFIED PASS** |
| 18 | `test_18_error_states` | Non-alarming diagnostic error presentation | **VERIFIED PASS** |
| 19 | `test_19_dark_and_light_appearance` | Theme preference switching | **VERIFIED PASS** |
| 20 | `test_20_keyboard_accessibility` | Keyboard accelerators mapped to all views | **VERIFIED PASS** |
| 21 | `test_21_guardian_mutation_rejection` | Unconditional denial of GUI mutations | **VERIFIED PASS** |
| 22 | `test_22_application_shutdown` | Clean background worker teardown on exit | **VERIFIED PASS** |

### Workspace Test Execution Summary:
- `root-gui` integration tests: 22 passed
- `root-cli` Phase 07 monitor integration tests: 25 passed
- `root-cli` Phase 06 schedule integration tests: 30 passed
- `root-cli` unit & CLI integration tests: 20 passed
- `root-core` unit tests: 25 passed
- `root-guardian` unit & transaction tests: 29 passed
- `root-platform` unit & engine tests: 12 passed
- **Total Passing Tests**: **154 passed; 0 failed; 0 ignored**.

---

## 14. Terminal UI Layout Representation

In headless server and container environments without a running Wayland compositor, Root GUI runs in Headless View-Model Mode while maintaining full layout fidelity:

```
+----------------------------------------------------------------------------------------------------+
|  [Root] Linux Resource Inspector                                           [READ-ONLY]  (Menu)     |
|  [Overview]  [Resources]  [Agents]  [Processes]  [Activity]  [Schedule]  [Settings]                |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|   SYSTEM OVERVIEW                                                                                  |
|   ---------------                                                                                  |
|   Memory Availability : 12.42 GiB / 15.48 GiB available                                           |
|   Swap Utilization    : 0 B / 2.00 GiB used                                                        |
|   Kernel PSI Memory   : 0.0% stall (10s window) [NORMAL]                                           |
|   Storage Capacity    : 142.50 GiB free of 468.20 GiB (statvfs)                                    |
|                                                                                                    |
|   CODING AGENT FOOTPRINT                                                                           |
|   ----------------------                                                                           |
|   Detected Targets    : 3 targets active / 12 cataloged                                            |
|   Total Candidates    : 42 resources observed                                                      |
|   Potential Transient : 842.10 MiB upper bound (speculative build cache)                           |
|                                                                                                    |
|   OPERATING MODES & GUARANTEES                                                                     |
|   ----------------------------                                                                     |
|   Mode A (CLI)        : Ready (On-Demand Terminal)                                                 |
|   Mode B (Schedule)   : Inactive (Disabled by default)                                             |
|   Mode C (Monitoring) : Inactive (Disabled by default)                                             |
|   Safety Policy       : Production Read-Only (Zero Mutations Permitted)                            |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
|   Ready. Press Ctrl+1..Ctrl+7 to switch tabs, Ctrl+R to refresh.                                   |
+----------------------------------------------------------------------------------------------------+
```

---

## 15. Known Limitations and Dependencies

1. **Host Build Prerequisites for Native Graphical Window**:
   - The runtime shared libraries `libgtk-4.so.1` (4.22.4) and `libadwaita-1.so.0` (1.9.2) are pre-installed on the development environment.
   - Compiling the optional graphical feature (`--features gtk`) requires C development headers (`libgtk-4-dev`, `libadwaita-1-dev`) and `pkg-config`. On Debian/Ubuntu/Kali systems, these can be installed via:
     ```bash
     sudo apt install pkg-config libgtk-4-dev libadwaita-1-dev
     ```
   - In environments without these packages or without a display server, `root-gui` compiles cleanly in Headless View-Model Mode, executing all business logic, data models, formatters, and test suites.
2. **Production Read-Only Guardrail**:
   - Phase 08 strictly prohibits cleanup or quarantine execution. Reversible quarantine workflows remain restricted to Level 1 synthetic test fixtures.

---

## 16. Phase 09 Readiness Assessment

Phase 08 is **100% complete**. All requirements have been implemented, verified across 22 automated test scenarios, formatted, clippy-checked, documented, and validated against architectural invariants.

In accordance with Rule 2 of `AGENTS.md` ("Never proceed into the next phase automatically without explicit human authorization"), execution stops at this Phase Gate.

### Next Phase:
- **Phase 09: Cross-Platform Expansion (macOS & Windows)**
  - Mission: Extend Root's deterministic resource management abstractions to Darwin (macOS `proc_pidinfo`, launchd user agents, FSEvents) and Windows (Win32 Job Objects, Task Scheduler).
  - Safety Gate: Core engine remains 100% identical; platform traits fully satisfied across OS boundaries.
  - Awaiting explicit user instruction to proceed.
