# Root CLI Reference & Terminal Architecture Manual

## 1. Architectural Mission

The Root command-line interface (`root-cli`) provides an explainable, deterministic, and security-first terminal experience for Linux developers.

Root allows developers to audit resources accumulated during agentic coding workflows—inspecting kernel memory distribution, active processes, filesystem storage allocations, and agent artifacts—without modifying system state, compromising user files, or requiring privileged daemon infrastructure.

---

## 2. Command Reference

### `root --help` & `root --version`
Prints summary usage information and crate version (`0.1.0`).

### `root doctor`
Performs an audit of host platform capabilities, kernel interfaces, memory metrics, XDG directory configurations, and systemd user scheduler health.

- **Kernel Interfaces Inspected**: `/proc`, `/proc/meminfo`, `/proc/pressure/memory`, `/proc/[pid]/smaps_rollup`, `/sys/fs/cgroup` (cgroups v2), `pidfd_open`, `openat2`, `statx`.
- **Scheduler & Notification Audited**: User systemd availability (`systemctl --user`), user unit directory status (`~/.config/systemd/user`), desktop notification dispatchers (`notify-send`, `dbus-send`), and schedule history storage permissions.
- **Privilege Guarantee**: Unprivileged user-space operation (UID/GID reported; zero sudo/root requirement).

### `root status [--json]`
Emits a concise system overview:
- **Operating System & Kernel Release**: Empirical values from `uname`.
- **Invoking UID**: User ID executing the CLI.
- **Physical RAM & Swap**: Total, available, free, and swap usage.
- **PSI Pressure Stalls**: Memory stall percentages across 10s, 60s, and full thrashing windows.
- **Supported Targets**: Complete enumeration of all 12 supported agent and tool categories.
- **Scheduled Inspection State (Mode B)**: Reports current schedule status (enabled/disabled), calendar interval, target count, next trigger time from systemd timer, and last scheduled run summary.
- **Last Completed Scan**: Reads persistent scan summary from `$XDG_STATE_HOME/root/last_scan.json`. If no scan history exists, explicitly outputs: `No previous scan available`.
- **Safety Policy**: Production Read-Only status.

### `root scan [--path <path>] [--dry-run] [--json] [--interactive]`
Scans a target directory tree to identify development artifacts:
- **Default Path**: If omitted, generates and executes within an isolated synthetic sandbox tree (`SyntheticFixture`).
- **Defensive Traversal**: Enforces maximum depth limit (64), maximum entry limit (250,000), single-device boundary (`allow_cross_device = false`), and timeout cutoff.
- **Dry-Run Mode**: Mandated in Phase 05. Reports observations without mutating files.

### `root discover [--path <path>] [--agents] [--tools] [--agent <name>] [--tool <name>] [--json] [--interactive]`
Discovers and classifies resources associated with AI coding agents and development toolchains:
- **Supported Agents**: `antigravity`, `claude`, `codex`, `gemini`, `aider`.
- **Supported Tools**: `node`, `npm`, `pnpm`, `rust`, `cargo`, `python`, `git`, `lsp`, `dev`.
- **Classification Output**: Target name, architectural category, lifecycle badge (`[ACTIVE]`, `[PERSISTENT]`, `[DORMANT TRANSIENT]`, `[UNKNOWN LIFECYCLE]`), apparent size, middle-truncated path, and protection tier.
- **Interactive Browser (`--interactive`)**: Launches the read-only interactive browser in interactive TTY sessions.

### `root inspect memory [--json]`
Examines kernel memory distribution and pressure:
- Total RAM, available RAM, reclaimable cache, free RAM.
- Swap total, swap used, swap free.
- Kernel PSI memory pressure metrics (`/proc/pressure/memory`).
- Technical invariants explaining why cached memory is reclaimable and RSS summation overcounts shared pages.

### `root inspect processes [--user-only] [--json]`
Enumerates running processes via `/proc`:
- Reports PID, PPID, real UID, process name, RSS memory, and process state (`Running`, `Sleeping`, `Zombie`, `Stopped`).
- `--user-only`: Filters processes to those matching the current invoking UID.
- Privacy: Process command-line secrets and environment variables are not dumped.

### `root inspect storage [--path <path>] [--json]`
Audits filesystem storage capacity and directory allocations:
- **Filesystem Capacity**: Read directly from kernel `statvfs` syscall (total capacity, available space for unprivileged user, free blocks, total and free inodes).
- **Directory Allocation (Bounded Traversal)**:
  - **Apparent (Logical) Size**: Sum of file lengths.
  - **Allocated Disk Blocks**: Physical 512-byte blocks allocated on disk.
  - **Sparse Files**: Identifies files where allocated blocks are less than apparent length.
  - **Multi-Link Files**: Identifies hard-linked files sharing inodes (`st_nlink > 1`), avoiding double counting of shared storage.
- **Accounting Note**: Speculative savings are reported as upper bounds and never as guaranteed recoverable space.

### `root inspect transactions [--journal-path <path>] [--json]`
Read-only diagnostic inspection for synthetic recovery journals:
- Reads append-only JSONL journal records from `.root_journal` or a specified `--journal-path`.
- Formats chronological transaction history: Transaction ID, state, apparent size, original path, and verification/failure reason.
- Detects interrupted transactions requiring operator recovery.
- Re-enforces that quarantine transactions remain isolated to synthetic test fixtures.

### `root explain <resource-id> [--json]`
Explains why a resource or rule was classified and how Guardian policies evaluate it:
- **Input Identifier**: Supports discovery rule IDs (`antigravity-scratch`, `claude-session-data`, `rust-target`, `pnpm-store`), filesystem paths, or canonical resource identifiers (`path:dev:ino`).
- **Explanation Breakdown**:
  1. **Finding Identity**: Target name, rule ID, rule version, architectural category, pattern description.
  2. **Observed Facts**: Real physical allocation, inode, permissions, ownership, and evidence provenance.
  3. **Lifecycle Uncertainty**: Explains what remains uncertain and why classification does not imply automatic deletion safety.
  4. **Protection Tier**: Explicit tier badge (`[TIER 1: PROTECTED]`, `[TIER 2: CONFIRM]`, `[TIER 3: TRANSIENT]`, `[TIER 4: RECOVERABLE]`).
  5. **Guardian Safety Invariant**: Explicit explanation of why actions (`Inspect`, `Quarantine`, `Prune`, `Delete`) are permitted or rejected.

### `root report [--path <path>] [--json]`
Generates a comprehensive audit report combining host identity, kernel capabilities, memory metrics, filesystem capacity, agent/tool discovery footprint, and architectural safety guarantees.

### `root schedule status [--json]`
Displays the current configuration and operational status of Mode B scheduled inspections:
- Schedule enabled state (`[ACTIVE]` or `[DISABLED by default]`).
- Configured calendar interval badge (`[DAILY]`, `[WEEKLY]`, or custom spec).
- systemd user manager accessibility and timer unit active state.
- Next scheduled timer trigger time (queried via `systemctl --user list-timers`).
- List of configured scan target directories with existence status.
- Summary of the most recent scheduled execution (timestamp, status, examined resource count).
- Safety policy invariant: explicit confirmation of read-only non-destructive operation.

### `root schedule enable [--interval <daily|weekly|custom>] [--target <path>...] [--notify] [--non-interactive]`
Enables periodic background inspections using systemd user timers:
- **Interactive Preview**: Presents a confirmation summary displaying frequency interval, notification preference, target directories, traversal bounds, and watchdog timeouts. Requires explicit confirmation unless `--non-interactive` is passed.
- **Interval Selection**: `--interval daily` (default), `--interval weekly`, or `--interval "<calendar-spec>"`.
- **Target Directories**: One or more `--target <path>` arguments specifying approved scan roots. Rejects `/`, pseudo-filesystems, system directories, and control characters.
- **Desktop Notifications**: `--notify` enables completion notifications via `notify-send` / FreeDesktop D-Bus.
- **Unit Installation**: Installs security-hardened `root-inspect.service` and `root-inspect.timer` units into `~/.config/systemd/user/` and enables the timer via `systemctl --user enable --now root-inspect.timer`.

### `root schedule disable`
Disables periodic background inspections:
- Stops and disables `root-inspect.timer` via `systemctl --user disable --now root-inspect.timer`.
- Updates configuration to `enabled: false`.
- Preserves configured target paths, intervals, and historical execution records for future reactivation.

### `root schedule list [--json]`
Lists all configured scheduled profiles, interval settings, desktop notification preferences, and approved scan target directories.

### `root schedule run [--notify] [--non-interactive]`
Executes a single scheduled inspection pass (normally invoked by systemd user timer `root-inspect.service`):
- **Concurrency Guard**: Acquires exclusive non-blocking file lock on `$XDG_STATE_HOME/root/schedule.lock` via `flock`. Skips execution gracefully if another scan is active.
- **Strictly Read-Only**: Traverses configured targets, discovers agent artifacts, assesses lifecycle states, and queries memory distribution. Zero file mutations or process signaling.
- **Resilient Target Handling**: Safely detects and skips targets that have been deleted or unmounted without failing the overall run.
- **History Tracking**: Appends an execution summary entry to `$XDG_STATE_HOME/root/schedule_history.json` (mode `0o600`), automatically pruning older entries to maintain a maximum 50-record retention limit.
- **Notification Dispatch**: If notifications are enabled, dispatches an aggregate summary to the desktop environment via `notify-send` or D-Bus.

### `root schedule history [--limit <N>] [--json]`
Displays chronological history of scheduled inspection runs:
- Lists execution timestamp, duration, status badge (`[COMPLETED]`, `[INCOMPLETE]`, `[FAILED]`), examined resource count, and targets scanned.
- Supports filtering output to the most recent `N` entries (default: 10).

### `root schedule remove`
Completely removes Mode B scheduled units and configuration:
- Disables and removes `root-inspect.timer` and `root-inspect.service` from `~/.config/systemd/user/`.
- Executes `systemctl --user daemon-reload`.
- Deletes the schedule configuration file `$XDG_CONFIG_HOME/root/schedule.json`.
- Retains execution history for auditing purposes unless manually cleared.

---

## 3. Terminal Design & Formatting Standards

1. **NO_COLOR Specification Adherence**:
   - If the `NO_COLOR` environment variable is set (regardless of value), all ANSI color sequences are suppressed.
   - If output is piped (`!std::io::stdout().is_terminal()`) or `TERM=dumb`, color styling is disabled automatically.

2. **Terminal Width Handling**:
   - Dynamically queries terminal width via POSIX `TIOCGWINSZ` ioctl or the `COLUMNS` environment variable.
   - Defaults to 100 columns if detection is unavailable or in non-interactive pipelines.

3. **Text Formatting & Numeric Stability**:
   - Long paths use middle truncation (`truncate_middle`) preserving the beginning and ending components (e.g. `/home/user/.../scratch`).
   - Byte counts use standard binary units (B, KiB, MiB, GiB, TiB) formatted with consistent numeric precision and right-alignment.
   - Strictly zero decorative emojis across all terminal outputs, error messages, and table headers.

---

## 4. Structured JSON Output & Determinism

All primary inspection commands support `--json`. When enabled:
- Clean, machine-readable JSON is written exclusively to standard output (`stdout`).
- Informational messages and notices are directed to standard error (`stderr`).
- JSON output is completely free of ANSI escape codes, terminal formatting, or progress spinners.
- File contents, private tokens, API keys, and unredacted command lines are strictly omitted from all schemas.

---

## 5. Exit Codes

| Exit Code | Meaning | Condition |
|:---:|:---|:---|
| `0` | Success | Command executed and completed successfully |
| `1` | Runtime Error / Policy Violation | Filesystem I/O error, policy rejection, or attempted mutation command |
| `2` | Argument Parsing Error | Invalid CLI flag, missing argument, or unknown option emitted by clap |

---

## 6. Security Boundaries & Guardrails

1. **Strict Production Read-Only Mode**:
   - In Phase 05, all filesystem mutation operations (`clean`, `quarantine`, `restore`, `delete`, `prune`) are strictly prohibited in the production CLI.
   - Any attempt to invoke these commands returns an immediate `RootError::PolicyViolation` explaining that mutation mechanisms are restricted to synthetic test fixtures.

2. **Least Privilege**:
   - Root never requires or requests superuser privileges (`sudo`, `su`, `setuid`).
   - Operations are bounded to the invoking user's permissions.

3. **Privacy by Design**:
   - Root operates strictly on metadata (`stat`, `statx`, `/proc` status).
   - Real user documents, conversation histories (`transcript.jsonl`), and credentials are never read, indexed, or logged.
