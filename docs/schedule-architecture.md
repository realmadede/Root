# Root Scheduled Inspections & systemd User Timer Architecture (Mode B)

## 1. Architectural Mission & Invariants

Root provides three distinct operational modes to accommodate varying developer workflows:
- **Mode A (On-Demand CLI)**: Ad-hoc terminal inspections invoked directly by the developer (`root inspect`, `root discover`, `root scan`).
- **Mode B (Scheduled Inspections)**: Periodic, autonomous, strictly read-only inspections triggered by systemd user timers.
- **Mode C (Live Monitoring)**: Real-time, event-driven monitoring responding to filesystem inotify and cgroups v2 pressure events (Phase 07).

Mode B is governed by foundational architectural invariants:
1. **Disabled by Default**: Scheduling is completely inactive upon initial installation. Enabling requires explicit, intentional user activation with configuration preview.
2. **Strictly Read-Only Execution**: Scheduled executions perform discovery, traversal, memory accounting, and state reporting. Under no circumstance does Mode B mutate, move, quarantine, prune, or delete files, nor terminate processes. Guardian unconditionally rejects mutating actions during scheduled operations.
3. **Zero Permanent Background Daemons**: Root does not run an idle resident daemon process waiting for timer ticks. Instead, native Linux `systemd --user` units trigger transient CLI executions (`root schedule run`), exiting immediately upon completion.
4. **Least-Privilege Operation**: Mode B operates purely within unprivileged user space (`$HOME/.config/systemd/user/`). Neither `sudo`, superuser privileges, nor root daemon access are ever required or permitted.
5. **Non-Intrusive Resource Footprint**: Scheduled inspections run with minimal kernel scheduling priority (`Nice=19`, `IOSchedulingClass=idle`, `TimeoutSec=120`), bounded traversal parameters, and concurrency locks preventing resource thrashing.

---

## 2. systemd User Unit Security Model & Directives

Root implements a verified security model for `systemd --user` units that explicitly accounts for unprivileged user service constraints:

### 2.1. Critical Security Assumptions & Realities
- **No `User=` Directives**: In `systemd --user` session managers, `User=` or `User=%h` directives are invalid and rejected. The service manager inherently executes processes under the UID of the running user session.
- **`ProtectHome=read-only` Limitations**: In user services, sandboxing directives such as `ProtectHome=` or `ProtectSystem=` cannot be assumed to function without unprivileged user namespaces (`kernel.unprivileged_userns_clone = 1`), and `ProtectHome=read-only` does not prevent reading private user credentials. Root instead relies on internal Unix UID checking and strict path validation.
- **XDG State Path Independence**: Root does not assume systemd's built-in `StateDirectory=` specifiers match Root's runtime configuration. Root explicitly determines and manages its own paths according to the XDG Base Directory specification (`$XDG_STATE_HOME/root` and `$XDG_CONFIG_HOME/root`).
- **Mandatory Protections vs Optional Hardening**: Root enforces internal mandatory validation (path safety, ownership checks, Guardian read-only policies) within pure Rust code, treating systemd directives (`Nice=19`, `NoNewPrivileges=true`, `IOSchedulingClass=idle`) as defense-in-depth hardening.

### 2.2. Service Unit Specification (`root-inspect.service`)

```ini
# Root System Resource Inspection Service
[Unit]
Description=Root System Resource Inspection (Mode B Scheduled)
Documentation=https://github.com/realmadede/Root
ConditionPathExists=/path/to/canonical/root
ConditionACPower=true   # Included only when ac_power_only is configured

[Service]
Type=oneshot
ExecStart=/path/to/canonical/root schedule run
Nice=19
IOSchedulingClass=idle
IOSchedulingPriority=7
TimeoutSec=120
NoNewPrivileges=true
```

#### Directive Analysis:
- **`ConditionPathExists`**: Prevents the unit from triggering if the Root executable has been uninstalled or relocated.
- **`ConditionACPower=true`**: Optional battery-aware scheduling directive preventing execution on battery power.
- **`Type=oneshot`**: Ensures the process executes to completion and exits immediately. Zero background memory footprint.
- **`Nice=19`**: Sets the lowest POSIX CPU scheduling priority, yielding cycles to interactive developer tasks.
- **`IOSchedulingClass=idle`**: Configures the BFQ/CFQ block scheduler to yield I/O queues whenever other processes request disk access.
- **`TimeoutSec=120`**: Watchdog timeout terminating hung or unresponsive scans.
- **`NoNewPrivileges=true`**: Prevents privilege escalation through setuid binaries.
- **Direct Executable Invocation**: Invokes the verified binary path directly; shell wrappers (`sh -c`) are prohibited to eliminate command injection vectors.

### 2.3. Timer Unit Specification (`root-inspect.timer`)

```ini
# Root Scheduled Resource Inspection Timer
[Unit]
Description=Root Scheduled Resource Inspection Timer
Documentation=https://github.com/realmadede/Root

[Timer]
OnCalendar=daily
Persistent=false
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
```

#### Timer Mechanics & Post-Login Load Mitigation:
- **Interval Preferences**: Daily and weekly intervals are preferred. Hourly intervals require explicit opt-in.
- **`Persistent=false` by Default**: Missed timer triggers during power-off or suspension do **not** trigger catch-up executions upon login. This avoids unexpected disk thrashing and high load immediately after workstation boot or login.
- **Configurable Catch-Up**: Users can explicitly enable catch-up execution (`--catch-up`) when deterministic historical auditing is prioritized over login responsiveness.
- **`RandomizedDelaySec=15m`**: Desynchronizes scheduled timer executions, preventing simultaneous load spikes with other scheduled maintenance tasks.

---

## 3. Executable Validation & Command Security

To prevent arbitrary command substitution and binary hijacking:
1. **Canonicalization**: The executable path is resolved and canonicalized (`validate_executable`) via `fs::canonicalize`.
2. **File & Mode Verification**: Validates that the path is an existing regular file with Unix execution permissions (`mode & 0o111 != 0`).
3. **Interpreter Refusal**: Refuses to configure shell interpreters (`sh`, `bash`) or language runtimes (`python`, `python3`) as the Root executable.
4. **Current Executable Resolution**: When enabling scheduling without `--exec-path`, Root resolves `std::env::current_exe()` and validates the resulting binary.

---

## 4. Inspection Profiles & Resource Budgets

Root introduces three deterministic inspection profiles to balance audit depth against system overhead:

| Profile | Traversal Depth | Entry Limit | Duration Budget | Memory Limit (RSS) | Intended Use |
|:---|:---:|:---:|:---:|:---:|:---|
| **`Lightweight`** | 4 | 10,000 | 15 seconds | 256 MiB | Shallow check of top-level agent scratchpads and marker files |
| **`Standard`** *(Default)* | 16 | 50,000 | 60 seconds | 512 MiB | General agent and toolchain footprint discovery across projects |
| **`Comprehensive`** | 32 | 150,000 | 120 seconds | 1,024 MiB | Deep recursive audit across extensive multi-repo workspaces |

### Budget Enforcement & Incomplete Scan Integrity:
- **Scanned Entries Budget**: Traversal halts immediately when the entry count limit is reached.
- **Wall-Clock Timeout**: Traversal enforces operational cutoff when duration exceeds the profile budget.
- **Memory RSS Budget**: During inspection, Root monitors its own RSS via `/proc/self/statm`. If memory exceeds the profile limit, traversal halts early.
- **Honest Status Reporting**: Scans that halt due to budget exhaustion or timeouts are strictly recorded as **`Incomplete`** with the explicit reason recorded. Partial scans are **never** reported as `Completed`.

---

## 5. Battery and Workload Awareness

Root incorporates preflight checks to prevent scheduled scans from degrading laptop battery life or compounding system resource contention:

### 5.1. Battery-Aware Scheduling (`--ac-only`)
- When enabled via `--ac-only`, Root checks `/sys/class/power_supply/` prior to scanning.
- If an AC/Mains adapter is offline or any battery reports `Discharging`, Root logs a notice and records the run as `Deferred: System running on battery power (AC-only mode)`.
- If power supply telemetry is absent (e.g. containers, VMs), Root assumes AC power.

### 5.2. System Memory Pressure Preflight
- Prior to starting filesystem traversal, Root inspects host memory metrics.
- Evaluates `/proc/pressure/memory` (PSI) 10-second stall percentage against the configured threshold (default: 60%).
- Verifies that `/proc/meminfo` available memory (`MemAvailable`) exceeds 200 MiB.
- If memory pressure is elevated, Root defers execution with status `Deferred: Host memory pressure exceeds safe operational threshold`.

---

## 6. Transactional Installation & Collision Protection

To prevent partial configuration corruption or accidental overwriting of unrelated unit files:

1. **Collision Protection**: Before modifying user units, `LinuxScheduler` inspects any existing `root-inspect.service` or `root-inspect.timer`. If an existing file does not contain the Root header marker (`Root System Resource Inspection`), installation halts with an error (`Collision: existing unit file was not created by Root`).
2. **Staged Writes**: Unit files are generated and written to sibling temporary files (`.tmp`) with mode `0o644`.
3. **Transactional Swap**: Temporary files are atomically renamed into place.
4. **Rollback on Failure**: If the second unit file fails to write, or if `systemctl --user daemon-reload` returns an error, Root rolls back by removing installed units and restoring clean state.
5. **Separation of Installation and Activation**: Unit generation and timer activation are distinct operations; automated tests never activate host timers.

---

## 7. Concurrency Protection & Non-Blocking Locking

Root implements kernel-managed advisory locking to prevent overlapping executions:
- **Lock Target**: `$XDG_STATE_HOME/root/schedule.lock`.
- **Acquisition**: `libc::flock(fd, LOCK_EX | LOCK_NB)`.
- **Contention Differentiation**: If another scheduled inspection is actively running, `flock` returns `EWOULDBLOCK`. Root logs a clean notice and records a `Deferred` entry (`Skipped: Concurrently running scheduled inspection`).
- **Non-Interference with Manual Inspections**: Manual CLI inspection commands (`root inspect`, `root discover`, `root scan --dry-run`) do not acquire the scheduled lock and are never blocked by scheduled runs.
- **Automatic Release**: The kernel guarantees lock release when the process terminates, preventing deadlocks across system reboots or sudden crashes.

---

## 8. Privacy-Preserving Desktop Notifications & Deduplication

Desktop notifications are delivered via FreeDesktop interfaces (`notify-send` or D-Bus) with strict privacy safeguards:

### 8.1. Confidentiality Boundaries
- **Zero Sensitive Metadata**: Notification bodies strictly omit filesystem paths, usernames, project names, active branch names, repository tokens, or conversation transcript contents.
- **Summary Metrics Only**: E.g. `Root Inspection Completed: Examined 1,420 resources across 3 targets with zero mutations.`
- **No False Claims**: Notifications never claim resources are safely recoverable solely based on discovery rule matches.

### 8.2. Notification Deduplication
- After each inspection, Root computes a privacy-safe cryptographic fingerprint of aggregate findings:
  `fingerprint = SHA256(status:total_inspected:total_findings)`
- If the fingerprint matches `config.last_notification_fingerprint`, Root suppresses the desktop notification to avoid alert fatigue.
- When findings change, a notification is dispatched and the fingerprint updated in `schedule.json`.

---

## 9. State Persistence & Retention Policy

- **Configuration Storage**: `$XDG_CONFIG_HOME/root/schedule.json` (mode `0o600`).
- **History Journal**: `$XDG_STATE_HOME/root/schedule_history.json` (mode `0o600`).
- **Retention Cap**: Strictly bounded at **50 records**. Older records are chronologically pruned.
- **Crash Resilience**: State updates use staged sibling writes and atomic `rename`. Corrupted files are backed up to `.corrupt` and replaced with clean default state.
