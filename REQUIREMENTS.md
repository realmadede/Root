# Root System Requirements

## 1. Functional Requirements (FR)

### 1.1 Resource Discovery & Inspection
- **FR-01 (Agent Artifact Discovery)**: Discover and classify storage artifacts from AI coding agents (Google Antigravity, Claude Code, OpenAI Codex tooling, Gemini CLI, Aider) across user configuration and state directories.
- **FR-02 (Toolchain Build Artifacts)**: Discover build caches, incremental compilation artifacts, and dependency directories (`target/`, `node_modules/`, `__pycache__/`, `.venv/`) across developer workspaces.
- **FR-03 (Accurate Memory Calculation)**: Measure process memory using Proportional Set Size (PSS) and Unique Set Size (USS) from `/proc/[pid]/smaps_rollup`, preventing shared-library double counting.
- **FR-04 (Orphaned Process Identification)**: Identify abandoned development processes, language servers, and test runners that have been orphaned (re-parented to PID 1) without an active controlling terminal or attached agent session.
- **FR-05 (System Pressure Monitoring)**: Read Linux Pressure Stall Information (PSI) from `/proc/pressure/memory` to report whether the workstation is actively memory-constrained or thrashing.

### 1.2 Policy & Safety Enforcement
- **FR-06 (Deterministic 4-Tier Classification)**: Classify every candidate entity into one of four deterministic tiers (`STRICTLY_PROTECTED`, `USER_CONFIRM_REQUIRED`, `OBSOLETE_TRANSIENT`, `SAFE_RECOVERABLE`) as defined in [docs/cleanup-policy.md](docs/cleanup-policy.md).
- **FR-07 (Git Safety Invariant)**: Refuse to mark build artifacts or directories for recovery if the enclosing Git repository contains dirty or uncommitted changes (`git status --porcelain`).
- **FR-08 (Path Traversal & Symlink Protection)**: Refuse to traverse across filesystem mount boundaries (`st_dev`), follow symbolic links, or operate outside designated target roots.
- **FR-09 (PID Reuse Protection)**: Use Linux `pidfd_open` and `pidfd_send_signal` for all process signaling to guarantee signals never hit a recycled PID.

### 1.3 Recovery, Quarantine & Rollback
- **FR-10 (Quarantine-First Mutation)**: Move candidate files into a private staging directory (`$XDG_STATE_HOME/root/quarantine/`, permissions `0700`) using atomic `renameat2` rather than immediately unlinking.
- **FR-11 (Deterministic Undo)**: Provide a `root undo <id>` command that restores quarantined files to their exact original filesystem paths using an append-only JSONL rollback journal.
- **FR-12 (Audit Explanations)**: Every recovery recommendation must provide a human-readable explanation including reclaimable size, purpose, risk assessment, and regeneration instructions.

### 1.4 Operating Modes
- **FR-13 (Mode A: On-Demand)**: Execute complete inspection and recovery on manual user invocation via CLI or GUI.
- **FR-14 (Mode B: Scheduled)**: Execute passive, non-destructive background scans via `systemd --user` timers, dispatching non-intrusive desktop notifications via D-Bus when thresholds are exceeded.
- **FR-15 (Mode C: Live Monitoring)**: Provide an optional event-driven daemon (`root-monitor`) utilizing `inotify` and cgroups v2 PSI to detect agent crashes and resource spikes in real-time.

---

## 2. Non-Functional Requirements (NFR)

### 2.1 Security & Least Privilege
- **NFR-01 (Zero Elevated Privilege)**: Root must execute completely without `root`, `sudo`, `pkexec`, or elevated Linux capabilities.
- **NFR-02 (Zero Network I/O)**: Root must make zero network requests, run no telemetry, and require no cloud connectivity or API keys.
- **NFR-03 (Zero AI Runtime Dependency)**: Root must not depend on local or remote LLM runtimes. All logic must be deterministic and algorithmic.

### 2.2 Performance & Resource Overhead
- **NFR-04 (Low Idle Overhead)**: When running in Mode C (Live Monitoring), Root's CPU consumption must remain below 0.1% while idle, with zero disk I/O thrashing.
- **NFR-05 (Scan Performance)**: Directory scanning must use multi-threaded iterative traversal with backpressure, completing a 100,000-file scan in under 2 seconds on modern SSDs.
- **NFR-06 (Memory Footprint)**: Root's core scanning engine must maintain an active memory footprint (PSS) under 35 MiB.

### 2.3 User Experience & Design
- **NFR-07 (GNOME Human Interface Guidelines)**: The future GUI must strictly adhere to GNOME HIG, using libadwaita widgets (`AdwApplicationWindow`, `AdwActionRow`, `AdwViewSwitcher`).
- **NFR-08 (Animation Frame Budget)**: GUI animations must adhere to Emil Kowalski's Designing-Skills standards (transitions < 250ms, ease-out curves, no animation on keyboard navigation, 60fps/120fps frame budgets).
- **NFR-09 (Tabular Figures)**: All live counters, PIDs, and byte values must use tabular monospace numbers (`tnum`) to eliminate layout jitter.

---

## 3. Platform & Target Requirements

- **Reference Operating System**: Kali GNU/Linux Rolling 2026.3 (Kernel 5.10+, recommended 6.x / 7.x).
- **Desktop Environment**: GNOME 4x on Wayland compositor.
- **Init & Service Manager**: `systemd` v240+ with cgroups v2 unified hierarchy enabled.
- **Primary Toolchain**: Rust 1.85+ (tested on Rust 1.99.0).
- **Target Architecture**: `x86_64` (primary), `aarch64` (secondary).
