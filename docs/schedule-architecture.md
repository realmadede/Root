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

## 2. systemd User Unit Design & Hardening

Mode B integrates natively with systemd through two user-level unit files installed into `$XDG_CONFIG_HOME/systemd/user/` (defaulting to `~/.config/systemd/user/`):

### 2.1. The Service Unit (`root-inspect.service`)

```ini
[Unit]
Description=Root Scheduled Resource Inspection (Mode B)
Documentation=https://github.com/realmadede/Root
ConditionUser=!root

[Service]
Type=oneshot
ExecStart=/path/to/root schedule run
Nice=19
IOSchedulingClass=idle
TimeoutSec=120
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal
```

#### Hardening & Security Directives:
- **`Type=oneshot`**: The process runs to completion and exits immediately. Zero background memory footprint.
- **`ConditionUser=!root`**: Systemd verifies the unit is never executed under UID 0, enforcing unprivileged execution.
- **`Nice=19`**: Sets the lowest CPU priority, ensuring user builds, interactive shells, and desktop applications retain scheduling priority.
- **`IOSchedulingClass=idle`**: Configures the BFQ/CFQ block I/O scheduler to service Root filesystem reads only when storage queues are otherwise idle.
- **`TimeoutSec=120`**: Hardware watchdog preventing runaway or stalled scans on unresponsive or stalling mounts.
- **`NoNewPrivileges=true`**: Prevents the process and its descendants from gaining additional capabilities through setuid binaries.
- **Direct Executable Invocation**: Root directly targets the verified binary path without wrapping execution in `sh -c` or intermediate shell scripts, eliminating shell injection vectors.

### 2.2. The Timer Unit (`root-inspect.timer`)

```ini
[Unit]
Description=Periodic Timer for Root Resource Inspection (Mode B)
Documentation=https://github.com/realmadede/Root
ConditionUser=!root

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
```

#### Reliability & Load-Spreading Directives:
- **`OnCalendar`**: Maps to verified schedules (`daily`, `weekly`, or strict custom OnCalendar patterns).
- **`Persistent=true`**: If the workstation was suspended or powered down when the timer was scheduled to trigger, systemd executes the missed inspection immediately upon workstation wake.
- **`RandomizedDelaySec=15m`**: Desynchronizes scheduled inspections, avoiding simultaneous load spikes with other system cron and timer events.

---

## 3. Concurrency Protection & Non-Blocking File Locking

To prevent race conditions, cache thrashing, and storage bottlenecks caused by concurrent scans (e.g. manual CLI execution running simultaneously with a scheduled timer tick), Mode B implements non-blocking POSIX file locking:

1. Prior to commencing traversal, `root schedule run` acquires an exclusive lock on `$XDG_STATE_HOME/root/schedule.lock` using `libc::flock(fd, LOCK_EX | LOCK_NB)`.
2. If another instance of Root is actively scanning, the kernel returns `EWOULDBLOCK` / `EAGAIN`.
3. Root detects the lock collision, logs a clean diagnostic notice, and exits cleanly with status 0 without thrashing disk I/O or waiting indefinitely.
4. When execution finishes, the lock is released and the file handle closed.

---

## 4. Privacy-Preserving Desktop Notifications

Mode B provides optional FreeDesktop desktop notifications upon completion of scheduled inspections, informing developers of resource state without leaking sensitive workstation metadata:

### 4.1. Privacy Safeguards
- **Zero Sensitive Data in Notification Bodies**: Notification payloads never include raw filesystem paths, usernames, project names, active branch names, repository tokens, or conversation transcript contents.
- **Summary Metrics Only**: Notifications report aggregate statistics only (e.g. `Root Scheduled Inspection: Examined 1,420 resources across 3 targets. Zero mutations performed.`).
- **Low-Distraction Urgency**: Notifications are dispatched with `urgency=low` to respect focus modes and do not trigger audio alerts.

### 4.2. Dispatch Architecture
1. **Primary Mechanism (`notify-send`)**: Dispatches notifications via the standard FreeDesktop `notify-send` binary with explicit app-name (`--app-name=Root`) and low urgency (`--urgency=low`).
2. **Fallback Mechanism (`dbus-send`)**: If `notify-send` is absent, falls back to raw D-Bus invocation targeting the `org.freedesktop.Notifications` interface.
3. **Graceful Non-Fatal Degradation**: In headless servers, container environments, or environments without a running D-Bus session or notification daemon, notification dispatch returns `Ok(false)` without failing the scheduled inspection run.

---

## 5. State Persistence & Retention Policy

Mode B records configuration and bounded run telemetry within the XDG state directory hierarchy:

### 5.1. File Hierarchy
- **Schedule Configuration**: `$XDG_CONFIG_HOME/root/schedule.json` (mode `0o644`) storing enabled state, interval, scan targets, and notification preference.
- **Schedule Run History**: `$XDG_STATE_HOME/root/schedule_history.json` (mode `0o600`) storing historical execution summaries.
- **Schedule Run Lock**: `$XDG_STATE_HOME/root/schedule.lock` protecting against overlapping runs.

### 5.2. Strict Permissions & Confidentiality
- Both the configuration and history files are created with strict POSIX permissions (`0o600` on history, `0o700` on parent directories), preventing other unprivileged users on multi-tenant machines from reading inspection summaries.
- Atomic file updates: Writes are serialized to temporary sibling files (`schedule.json.tmp`) and atomically swapped into place using `rename`, ensuring crash-resilience against sudden power loss.

### 5.3. Retention Pruning Policy
To maintain a deterministic, bounded storage footprint:
- The history journal maintains a hard maximum of **50 execution records**.
- Upon completion of every inspection run, `prune_history` trims older entries chronologically, retaining only the most recent 50 runs.
- Malformed history files (e.g. partial writes or manual user corruption) are gracefully backed up to `.corrupt` and replaced with an empty history list rather than crashing subsequent runs.

---

## 6. Target Safety Validation & Deleted Target Resilience

### 6.1. Target Safety Validation
When configuring scan targets via `root schedule enable --target <path>`, Root enforces strict safety boundaries:
- **Canonicalization**: Targets are resolved and canonicalized against symlinks.
- **Root Directory Rejection**: Root directory `/` is rejected.
- **Pseudo-Filesystem Rejection**: `/proc`, `/sys`, `/dev` are unconditionally rejected.
- **System Directory Rejection**: `/usr`, `/bin`, `/sbin`, `/etc`, `/lib`, `/boot`, `/var` are unconditionally rejected.
- **Control Character Rejection**: Paths containing control characters (newlines, null bytes, tabs) are rejected.

### 6.2. Deleted Target Handling
If a target directory configured for scheduled scanning is renamed, unmounted, or deleted by the user between scheduled timer runs:
- `root schedule run` inspects target existence before starting traversal.
- Missing targets are logged as non-fatal warnings and skipped.
- The scan continues evaluating remaining valid targets and completes successfully.
