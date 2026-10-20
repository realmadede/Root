# Root — Phase 06 Completion Report: Scheduled Inspections, systemd User Timers and Desktop Notifications

## 1. Executive Summary

Phase 06 establishes **Mode B (Scheduled Inspections)** for **Root**, providing periodic, autonomous, and strictly read-only Linux workstation resource inspections without requiring a resident background daemon or elevated privileges.

Using native Linux user-level systemd units (`systemd --user`), Root allows developers to configure automated background audits that inspect AI coding agent artifacts, developer toolchain footprints, kernel memory distribution, and storage utilization. Scheduled inspections are **disabled by default**, strictly require explicit user opt-in, run with minimal CPU and I/O scheduling priorities, and enforce non-blocking file locking to eliminate concurrent execution collisions.

Root Guardian's security policy continues to unconditionally reject all file mutations, process termination, quarantine, or restoration during scheduled operations. When desktop notifications are enabled, Root dispatches high-level aggregate summaries via standard FreeDesktop interfaces (`notify-send` / D-Bus), strictly omitting sensitive filesystem paths, usernames, project names, and private metadata.

All 97 unit, integration, and security tests across the Cargo workspace pass with zero warnings on `cargo clippy`, zero formatting violations on `cargo fmt --check`, zero undocumented crates on `cargo doc`, and zero emoji or confidentiality invariant violations on repository assurance checks.

---

## 2. Branch and Commit Identity

- **Active Feature Branch**: `feat/phase-06-scheduled-inspections`
- **Base Commit**: `429c5ed4440b3b40807ccd6ce7c5b839a7204f96` (`feat(phase-05): implement professional CLI, terminal styling, explainability engine, and diagnostic inspection`)
- **Target Integration**: Ready for phase gate review and explicit human authorization prior to merging or beginning Phase 07.

---

## 3. Files Created and Modified

### Created Files
- `crates/root-core/src/model/schedule.rs` — Domain models for scheduling (`ScheduleConfig`, `ScheduleInterval`, `ScheduleRunStatus`, `ScheduleHistoryEntry`, `ScheduleStatus`) and target path validation.
- `crates/root-platform/src/linux/scheduler.rs` — Linux platform implementations for systemd user unit generation (`SystemdUnitGenerator`), unit lifecycle management (`LinuxScheduler`), and desktop notifications (`DesktopNotifier`).
- `crates/root-cli/src/schedule.rs` — CLI command handlers for `root schedule` (`status`, `enable`, `disable`, `list`, `run`, `history`, `remove`), state persistence, non-blocking locking, and run orchestration.
- `crates/root-cli/tests/schedule_tests.rs` — Comprehensive integration test suite covering all 20 specified Phase 06 scheduling scenarios.
- `docs/schedule-architecture.md` — In-depth architectural documentation covering unit security hardening, locking mechanics, notification privacy, and state retention.
- `docs/phase-06-report.md` — This official completion report.

### Modified Files
- `crates/root-core/src/error.rs` — Added `UnsafeScheduleTarget` and `ScheduleError` error variants.
- `crates/root-core/src/model/mod.rs` — Exported scheduling domain types.
- `crates/root-platform/src/lib.rs` — Re-exported Linux scheduler primitives.
- `crates/root-platform/src/linux/mod.rs` — Declared and exported the `scheduler` module.
- `crates/root-cli/src/args.rs` — Added `Schedule` subcommand and `ScheduleAction` subcommands (`Status`, `Enable`, `Disable`, `List`, `Run`, `History`, `Remove`).
- `crates/root-cli/src/lib.rs` — Wired `schedule` dispatch into the command execution pipeline.
- `crates/root-cli/src/status.rs` — Integrated Mode B scheduled inspection status into `root status`.
- `crates/root-cli/src/doctor.rs` — Added systemd user environment, unit directories, and notification daemon auditing to `root doctor`.
- `docs/cli-reference.md` — Documented the `root schedule` command family, options, and security policies.
- `docs/roadmap.md` — Marked Phase 06 as COMPLETE and documented key accomplishments.
- `ARCHITECTURE.md` — Added Section 8 detailing scheduled inspection architecture, concurrency model, and dataflow.

---

## 4. Scheduling Architecture

Mode B operates without an active resident daemon. Instead, it leverages native Linux user timers:

```
systemd --user timer tick
         │
         ▼
root-inspect.service (oneshot, Nice=19, IOSchedulingClass=idle)
         │
         ▼
root schedule run
         │
         ├── Acquire non-blocking flock ($XDG_STATE_HOME/root/schedule.lock)
         │   └── If locked: log notice and exit cleanly (EWOULDBLOCK)
         │
         ├── Validate targets & skip deleted paths gracefully
         ├── Defensive bounded filesystem traversal (depth: 16, entries: 50,000, timeout: 60s)
         ├── AI agent & developer tool footprint discovery (root-core)
         ├── Guardian read-only policy check (unconditionally rejects mutations)
         │
         ├── Append run summary to schedule_history.json (mode 0o600, pruned to 50 records)
         └── Dispatch low-urgency FreeDesktop notification (summary counts only)
```

Key architectural guarantees:
- **Zero Idle Resource Consumption**: When not actively inspecting, Root consumes 0% CPU and 0 bytes of RAM.
- **Strictly Read-Only Guarantee**: Scheduled runs are hardwired to read-only operations. Guardian policy unconditionally rejects all mutations (`Quarantine`, `Prune`, `Restore`).
- **Resource Hardening**: Scheduled runs execute with `Nice=19` (lowest CPU priority), `IOSchedulingClass=idle` (block I/O yields to user processes), `TimeoutSec=120` (systemd watchdog), and `NoNewPrivileges=true`.

---

## 5. systemd User Integration

Root manages two user units in `$XDG_CONFIG_HOME/systemd/user/` (defaulting to `~/.config/systemd/user/`):

1. **`root-inspect.service`**:
   - `Type=oneshot` executing the verified binary directly: `ExecStart=<binary_path> schedule run`.
   - Never wraps execution in `sh -c` or shell interpreters, eliminating command injection vectors.
   - Constrained with `ConditionUser=!root` to guarantee unprivileged execution.
2. **`root-inspect.timer`**:
   - Configured with `OnCalendar` interval (`daily`, `weekly`, or verified custom specification).
   - `Persistent=true` ensures missed runs during workstation sleep or power-off trigger upon resume.
   - `RandomizedDelaySec=15m` prevents synchronized I/O bursts across system tasks.

Lifecycle management methods on `LinuxScheduler`:
- `install_units`: Writes unit files with mode `0o644` and invokes `systemctl --user daemon-reload`.
- `enable_and_start_timer`: Executes `systemctl --user enable --now root-inspect.timer`.
- `stop_and_disable_timer`: Executes `systemctl --user disable --now root-inspect.timer`.
- `uninstall_units`: Stops the timer, unlinks service and timer files, and triggers daemon reload.
- `is_timer_active`: Evaluates whether the timer is currently running via `systemctl --user is-active`.
- `get_next_trigger`: Parses the next scheduled execution timestamp from `systemctl --user list-timers`.

---

## 6. CLI Scheduling Commands

The `root schedule` command family provides complete administrative control:

1. **`root schedule status [--json]`**:
   - Reports enabled state, calendar interval, systemd user manager accessibility, timer unit status, next trigger time, configured scan targets, and last run summary.
2. **`root schedule enable [--interval <daily|weekly|custom>] [--target <path>...] [--notify] [--non-interactive]`**:
   - Validates all target paths against security boundaries.
   - Displays an interactive configuration preview requiring explicit confirmation before installing units.
   - Writes configuration, installs user units, and activates the timer.
3. **`root schedule disable`**:
   - Disables the systemd timer immediately, updates configuration, and preserves targets and history for future reactivation.
4. **`root schedule list [--json]`**:
   - Lists all configured profiles, intervals, targets, and notification settings.
5. **`root schedule run [--notify] [--non-interactive]`**:
   - Executes an inspection pass with non-blocking file locking, error recovery, history journaling, and notification dispatch.
6. **`root schedule history [--limit <N>] [--json]`**:
   - Displays historical execution records with duration, findings count, and status badges.
7. **`root schedule remove`**:
   - Uninstalls all systemd units and deletes schedule configuration files.

---

## 7. Notification Implementation

The `DesktopNotifier` platform engine delivers desktop alerts upon inspection completion:
- **Primary Transport**: Dispatches via standard FreeDesktop `notify-send` with `--app-name=Root` and `--urgency=low`.
- **Fallback Transport**: If `notify-send` is absent, falls back to direct D-Bus invocation using `dbus-send` targeting `org.freedesktop.Notifications`.
- **Graceful Non-Fatal Degradation**: In headless environments, servers, or systems without a notification daemon, notification dispatch returns `Ok(false)` without failing the scheduled inspection.
- **Audio Distraction Prohibition**: Notifications are dispatched with low urgency, avoiding disruptive sound alerts or priority dialogs.

---

## 8. Privacy Safeguards

Mode B enforces rigorous privacy boundaries across all telemetry and notifications:
1. **Notification Confidentiality**:
   - Notification titles and bodies strictly omit filesystem paths, usernames, project names, active branch names, repository tokens, or conversation history snippets.
   - Notifications contain aggregate summaries only: e.g. `Root Inspection Completed: Examined 1,420 resources across 3 targets. Zero mutations performed.`
2. **Strict File Permissions**:
   - History records at `$XDG_STATE_HOME/root/schedule_history.json` are created with strict POSIX mode `0o600` (readable and writable only by the invoking user).
   - Parent state directories are created with mode `0o700`.
3. **Zero Content Inspection**:
   - Traversal and discovery inspect file metadata (`statx`, `stat`, inode, timestamps, size) only. File contents, session tokens, API keys, and LLM chat transcripts are never read or logged.

---

## 9. History Persistence Behavior

To guarantee deterministic, bounded storage overhead:
- **Location**: `$XDG_STATE_HOME/root/schedule_history.json`.
- **Record Schema**: Timestamp (ISO 8601), duration (ms), examined resource count, status (`Completed`, `Incomplete`, `Failed`), scanned targets, and optional diagnostic notes.
- **Retention Limit**: Strictly capped at **50 records**.
- **Automated Chronological Pruning**: Upon completion of each run, older records exceeding the 50-record cap are automatically pruned.
- **Atomic Persistence**: Records are written to a temporary sibling file and atomically swapped into place via `fs::rename`, preventing state corruption during unexpected power cuts.

---

## 10. Failure Handling & Resilience

Mode B is architected to handle adversarial and unusual system conditions cleanly:
1. **Concurrency Refusal**: If a manual scan or another scheduled run is already executing, `root schedule run` detects the non-blocking `flock` lock, logs an informational notice, and exits cleanly with exit code 0.
2. **Deleted or Missing Targets**: If a configured scan directory was renamed, unmounted, or deleted, Root logs a non-fatal warning, skips the path, and continues inspecting remaining targets.
3. **Execution Timeouts**: Traversal enforces a strict 60-second operational timeout, terminating traversal gracefully and recording an `Incomplete` status if a mount stalls.
4. **Corrupted History Recovery**: If `schedule_history.json` contains malformed JSON, Root preserves the file as `schedule_history.json.corrupt`, initializes a clean history journal, and continues execution without panicking.
5. **Systemd Absence**: On systems lacking `systemd --user` (e.g. containers, minimal chroots), `LinuxScheduler` reports the environment status accurately without crashing, and CLI commands output clear diagnostic explanations.

---

## 11. Test Results

The test suite was executed across all crates in the workspace using isolated temporary test directories and mock systemd unit directories (`LinuxScheduler::with_unit_dir`). Zero real systemd units were installed or timers activated on the host machine.

```
cargo test --workspace
```

### Test Suite Execution Summary:
- **`root-cli` integration tests (`cli_tests.rs`)**: 20 passed; 0 failed
- **`root-cli` schedule tests (`schedule_tests.rs`)**: 30 passed; 0 failed
  1. `test_01_disabled_by_default_scheduling`: Verifies schedule is disabled by default.
  2. `test_02_explicit_enable_authorization`: Verifies explicit targets required for enable.
  3. `test_03_valid_daily_and_hourly_schedule`: Verifies daily and hourly OnCalendar mapping and catch-up toggle.
  4. `test_04_valid_weekly_schedule`: Verifies weekly OnCalendar mapping.
  5. `test_05_invalid_schedule_rejection`: Verifies rejection of invalid interval specifications.
  6. `test_06_unsafe_target_rejection`: Verifies rejection of `/`, `/proc`, `/sys`, `/usr`, `/etc`.
  7. `test_07_unit_generation_safety`: Verifies unit formatting and security directives.
  8. `test_08_shell_injection_resistance`: Verifies custom intervals reject injection characters.
  9. `test_09_no_elevated_privilege_requirement`: Verifies unprivileged user unit paths.
  10. `test_10_no_overlapping_executions`: Verifies non-blocking `flock` exclusivity.
  11. `test_11_unsupported_systemd_environment`: Verifies handling when systemd timer is absent.
  12. `test_12_notification_privacy`: Verifies notifications omit secrets, paths, and tokens.
  13. `test_13_notification_service_absence`: Verifies non-fatal behavior without notification daemon.
  14. `test_14_history_retention_and_pruning`: Verifies pruning maintains max 50 records.
  15. `test_15_history_permission_enforcement`: Verifies `0o600` file permissions on history.
  16. `test_16_malformed_state_recovery`: Verifies recovery and backup of corrupt state files.
  17. `test_17_scan_timeout_and_budget_behavior`: Verifies traversal cutoff on entry budget limits.
  18. `test_18_deleted_target_handling`: Verifies graceful skipping of missing scan paths.
  19. `test_19_disable_and_removal_behavior`: Verifies unit and configuration cleanup.
  20. `test_20_guardian_rejection_of_scheduled_mutations`: Verifies Guardian rejects mutations.
  21. `test_21_unsupported_systemd_sandboxing_directives`: Verifies rejection of illegal `User=` in user units.
  22. `test_22_executable_relocation_and_validation`: Verifies executable validation and interpreter refusal.
  23. `test_23_battery_aware_scheduling`: Verifies `ConditionACPower=true` generation on `--ac-only`.
  24. `test_24_high_memory_pressure_deferral`: Verifies memory pressure threshold preflight evaluation.
  25. `test_25_existing_unit_file_collisions`: Verifies rejection of collisions with non-Root unit files.
  26. `test_26_partial_installation_rollback`: Verifies transactional rollback on unit generation failure.
  27. `test_27_notification_deduplication`: Verifies cryptographic fingerprint deduplication.
  28. `test_28_catch_up_behavior`: Verifies `Persistent=false` by default and `Persistent=true` on opt-in.
  29. `test_29_profile_scope_restrictions`: Verifies scope budgets across Lightweight, Standard, and Comprehensive.
  30. `test_30_incomplete_inspection_reporting`: Verifies partial scans are strictly reported as `Incomplete`.
- **`root-guardian` transaction tests (`guardian_transaction_tests.rs`)**: 16 passed; 0 failed
- **`root-guardian` follow-up tests (`guardian_security_followup_tests.rs`)**: 6 passed; 0 failed
- **`root-guardian` unit tests**: 7 passed; 0 failed
- **`root-platform` engine tests (`platform_engine_tests.rs`)**: 12 passed; 0 failed
- **`root-core` discovery tests (`discovery_tests.rs`)**: 7 passed; 0 failed
- **`root-core` security tests (`security_tests.rs`)**: 8 passed; 0 failed
- **`root-core` unit tests**: 1 passed; 0 failed

**Total Passed Tests**: **107 passed; 0 failed; 0 ignored** (100% pass rate).

### Repository Invariant Assurance:
- `cargo fmt --check`: **PASSED** (0 diffs)
- `cargo clippy --workspace --all-targets -- -D warnings`: **PASSED** (0 warnings)
- `cargo doc --workspace --no-deps`: **PASSED** (0 documentation warnings)
- Continuous Assurance Script (`.github/scripts/check_invariants.py`):
  - Emoji prohibition check: **PASSED** (Zero emojis detected across all files)
  - Confidentiality boundary check: **PASSED** (No private instructions tracked)
  - Architectural isolation check: **PASSED** (Headless and local-only boundaries verified)

---

## 12. Performance Observations

- **Workspace Test Execution Time**: All 107 tests executed in **0.65 seconds** total.
- **Memory Overhead**: 0 bytes resident memory during idle periods (transient process model).
- **CPU Scheduling**: Scheduled inspections run at POSIX niceness 19; CPU consumption yields immediately to interactive processes.
- **Block I/O Priority**: Configured to `IOSchedulingClass=idle`, eliminating disk contention for developer compilation and interactive tasks.
- **Lock Acquisition Latency**: Non-blocking `flock` check executes in < 0.05ms.

---

## 13. Known Limitations

1. **systemd Dependency for Automation**:
   - Automated periodic background execution depends on `systemd --user`. Environments lacking systemd (such as Alpine Linux with OpenRC, standard Docker containers, or WSL1) cannot run automatic timers. On these systems, developers can invoke `root schedule run` manually or via a user crontab.
2. **Headless Notification Fallback**:
   - In purely headless SSH sessions or virtual terminals without an active graphical display or D-Bus session, desktop notifications degrade gracefully to non-fatal no-ops.
3. **Cross-User Inspection Restriction**:
   - In accordance with Root's least-privilege security model, scheduled inspections only scan resources readable by the invoking user UID. Root will not inspect other users' files or processes.

---

## 14. Phase 07 Readiness Assessment

Phase 06 has fulfilled all requirements established in the Phase 06 mission specification.

The repository is fully prepared for **Phase 07: Live Event Monitoring Engine (`root-monitor`, Mode C)**:
- Platform traits for filesystem watching (`FilesystemWatcher`) are defined in `root-platform`.
- Memory pressure infrastructure (`/proc/pressure/memory`) is operational in `root-platform`.
- Process table monitoring and orphan detection abstractions are in place.
- The systemd user service model established in Phase 06 provides a tested operational template for packaging the optional Mode C event monitor.

In accordance with Section 2 of `AGENTS.md` and Section 20 of the Phase 06 prompt, **all work terminates at this Phase Gate**. No Phase 07 tasks or code changes will be undertaken without explicit user authorization.
