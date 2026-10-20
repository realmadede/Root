# Root: Phase 00 Completion Report
## Research, Architecture, Security, and Design Foundation

**Project Name**: Root  
**Category**: Secure System Resource Management  
**Current Phase**: Phase 00 (Foundation & Research)  
**Lead Systems Architect, Linux Security Researcher & Engineer**: Antigravity  
**Date**: October 20, 2026  
**Reference Environment**: Kali GNU/Linux Rolling 2026.3, GNOME 4x, Wayland, Kernel 7.1.5+kali-amd64 x86_64  

---

## 1. Executive Summary

Phase 00 of Project **Root** has achieved its foundational objectives. Root is established not merely as a simple disk-cleaning script, but as a deterministic, security-first, architecturally rigorous Linux resource management system.

During this phase:
1. Deep systems research was conducted on the Linux kernel memory architecture, virtual filesystem interfaces (`/proc`, `/sys/fs/cgroup`), modern process management APIs (`pidfd`), and XDG directory standards.
2. Real-world empirical investigation of AI coding agents (Google Antigravity, Claude Code, OpenAI Codex, Gemini CLI, Aider) and development stacks (Node.js/pnpm, Rust/Cargo, Python) uncovered critical storage accumulation vectors and process leaks.
3. A zero-elevated-privilege threat model was constructed to mitigate path traversal, symlink traps, shared inode corruption, PID reuse, and TOCTOU race conditions.
4. A deterministic 4-tier cleanup classification policy was codified, introducing the Git Safety Invariant and a quarantine-first, 100% reversible rollback model (`root undo`).
5. A hybrid architecture supporting three unified modes (On-Demand, Scheduled via systemd timers, and Live Event Monitoring via inotify/cgroups v2) was designed.
6. Clean cross-platform abstraction boundaries were formalized in Rust traits, isolating platform-specific Linux syscalls from pure domain logic.
7. A three-level sandboxed testing harness was architected to protect host developer files from destructive execution tests.
8. The official design reference repository ([Designing-Skills](https://github.com/realmadede/Designing-Skills.git), commit `2d228630ba1446365f614a108cb8252f1feda202`) was inspected and adapted to native GNOME (GTK4 + libadwaita) desktop development.
9. Enforceable development invariants for AI agents and human contributors were codified in `AGENTS.md`.

No production application code was written; no files were deleted; no processes were terminated; no privileged commands were executed.

---

## 2. Exact Repository Inventory

The following 21 structured documentation and governance files have been authored and verified:

```
Root/
├── README.md                                  # Master project introduction and directory index
├── AGENTS.md                                  # 14 mandatory operating rules for AI coding assistants
├── ARCHITECTURE.md                            # Crate boundaries, component layout, and transaction model
├── SECURITY.md                                # Least privilege guarantee, vulnerability disclosure policy
├── REQUIREMENTS.md                            # Functional, non-functional, and platform requirements
├── CONTRIBUTING.md                            # Contribution workflow, code standards, review rules
├── LICENSE                                    # Open source MIT license
└── docs/
    ├── threat-model.md                        # Formal threat model, attack vectors, and mitigations
    ├── cleanup-policy.md                      # 4-tier classification policy and Git safety invariant
    ├── hybrid-architecture.md                 # Three operating modes (On-Demand, Scheduled, Live)
    ├── platform-abstraction.md                # Rust traits: ProcessProvider, ResourceAccountant, etc.
    ├── testing-strategy.md                    # 3-tier testing strategy (Synthetic, Container, VM)
    ├── design-foundation.md                   # Native GNOME GTK4 + libadwaita design foundation
    ├── roadmap.md                             # Phased implementation plan from Phase 00 to 1.0
    ├── phase-00-report.md                     # This comprehensive Phase 00 completion report
    └── research/
        ├── linux-resource-management.md       # Linux memory, virtual filesystems, and pidfd research
        ├── agent-storage-behavior.md          # Multi-agent comparative analysis and taxonomy
        ├── antigravity.md                     # Empirical research on Google Antigravity storage
        ├── claude-code.md                     # Empirical research on Claude Code storage and keys
        ├── codex.md                           # Research on OpenAI Codex, Gemini CLI, and Aider
        └── development-artifacts.md           # Tooling research: Git, pnpm hardlinks, Cargo, LSPs
```

---

## 3. Key Research Findings

### 3.1 Linux Resource Management
- **RAM is Not "Wasted"**: Linux intentionally caches files in unused RAM (`Cached` and `Buffers` in `/proc/meminfo`). The kernel reclaims clean pages in microseconds under memory pressure.
- **`drop_caches` is an Anti-Pattern**: Clearing kernel caches (`echo 3 > /proc/sys/vm/drop_caches`) requires root privileges, forces disk I/O, degrades application responsiveness, and provides zero user benefit. Root explicitly forbids cache clearing.
- **Accurate Process Memory (PSS & USS)**: Standard RSS double-counts shared memory. By parsing `/proc/[pid]/smaps_rollup`, Root extracts Proportional Set Size (PSS) and Unique Set Size (USS) in a single pass without overhead.
- **PID Reuse Race Conditions**: Traditional `kill(pid, sig)` is vulnerable to PID recycling. Root leverages Linux 5.3+ `pidfd_open(pid, 0)` and Linux 5.4+ `pidfd_send_signal(pidfd, sig)` to guarantee signals target the exact process instance.
- **cgroups v2 User Delegation**: On systemd v240+, the user control group slice (`/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/`) is delegated to the unprivileged user, allowing Root to read accurate memory and pressure metrics (PSI) without root access.

### 3.2 AI Coding Agents Storage & Behavior
- **Google Antigravity (`~/.gemini/antigravity-cli/`)**:
  - Accumulated **758 MiB** on the reference machine.
  - Key storage consumer: `brain/<conversation-id>/scratch/` reached **254 MiB** in a single session due to cloned repos and live worktrees.
  - Step logs: `.system_generated/steps/<step-id>/output.txt` archives truncated tool output, reaching 15–80 MiB per conversation.
  - Critical security files: `oauth_creds.json`, `google_accounts.json`, and `transcript*.jsonl` contain tokens and private chats and must be **strictly protected**.
- **Claude Code (`~/.claude/`)**:
  - Found **56 empty UUID directories** in `~/.claude/session-env/` leaked by command environment setup.
  - Shell snapshots (`~/.claude/shell-snapshots/*.sh`) export user interactive shell environments, posing credential leakage risks if tokens were in memory.
  - Session encryption keys (`~/.claude/sessions/*.key`) are required to decrypt session history and must be **strictly protected**.
- **Aider (`.aider*`)**:
  - Stores AST tags cache (`.aider.tags.cache.v3`) in project roots (50–200 MiB), which can be rebuilt automatically.
  - Conversation log (`.aider.chat.history.md`) is user audit history and must be strictly protected.
- **Development Tooling & Package Stores**:
  - **The pnpm Inode Hazard**: pnpm hard-links packages from `~/.local/share/pnpm/store/v3/` into project `node_modules`. Deleting files directly corrupts all projects sharing that inode. Root enforces `st_nlink == 1` checks.
  - **Cargo `target/`**: Consumes tens of gigabytes across dormant projects; safe to clean but requires CPU time to rebuild (`USER_CONFIRM_REQUIRED`).
  - **Orphaned Language Servers (LSPs)**: Headless instances of `rust-analyzer` and `tsserver` frequently remain running under PID 1 when parent tools crash, consuming 1–4 GiB of RAM.

---

## 4. Evidentiary Classification: Verified vs. Hypothesized vs. Unknown

| Item | Classification | Notes & Evidence |
|---|---|---|
| Linux `/proc` and cgroups v2 unprivileged metrics | **[VERIFIED]** | Confirmed via live shell queries on Kali Linux 7.1.5 kernel. |
| Linux `pidfd_open` / `pidfd_send_signal` | **[VERIFIED]** | Kernel 7.1.5 supports syscalls 434 (`pidfd_open`) and 424 (`pidfd_send_signal`). |
| Antigravity `brain/` and `scratch/` ballooning | **[VERIFIED]** | Confirmed 758 MiB total footprint; 254 MiB in single scratch directory. |
| Antigravity step outputs in `.system_generated/` | **[VERIFIED]** | Confirmed multiple 15–80 MiB step directories. |
| Claude Code leaked empty `session-env/` directories | **[VERIFIED]** | Confirmed 56 empty UUID directories present in `~/.claude/session-env/`. |
| Claude Code `shell-snapshots/` script contents | **[VERIFIED]** | Confirmed full zsh environment capture scripts in `~/.claude/shell-snapshots/`. |
| Claude Code session encryption `.key` files | **[VERIFIED]** | Confirmed mode 0600 keys in `~/.claude/sessions/`. |
| pnpm hard-link inode sharing behavior | **[VERIFIED]** | Confirmed via `stat -c "%i %h"` on pnpm store and node_modules files. |
| Orphaned LSPs (`tsserver`, `rust-analyzer`) | **[VERIFIED]** | Confirmed via `ps -u madede -o pid,ppid,comm` showing running LSPs. |
| OpenAI Codex local CLI caching topology | **[HYPOTHESIS]** | Deduced from OpenAI API client conventions; not directly present on reference host. |
| macOS Darwin `proc_pidinfo` and launchd metrics | **[HYPOTHESIS]** | Derived from Darwin kernel documentation; pending empirical verification on macOS in Phase 09. |
| Deep recovery behavior on Btrfs/ZFS subvolumes | **[UNKNOWN]** | Requires testing on systems with copy-on-write subvolumes and snapshots. |

---

## 5. Security & Architectural Decisions

1. **Zero Elevated Privilege Policy**: Root operates exclusively as an unprivileged user process. No setuid binaries, no `sudo` prompts, no root daemons.
2. **Defensive Invariant**: Any unclassified, ambiguous, or error-yielding filesystem path or process is treated as `STRICTLY_PROTECTED`.
3. **No Direct Execution in Scanned Workspaces**: Root never invokes package managers (`npm run clean`, `cargo clean`) from untrusted repositories to prevent arbitrary code execution attacks.
4. **Symlink and Traversal Defense**: Traversal utilizes `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, verifying `st_dev` on every descent to halt at mount boundaries.
5. **Reversibility Guarantee**: Destructive actions move files atomically to `$XDG_STATE_HOME/root/quarantine/` with a JSONL rollback journal, enabling instant restoration via `root undo`.
6. **The Git Safety Invariant**: Workspaces with uncommitted edits (`git status --porcelain` is non-empty) or unpushed commits are automatically protected.

---

## 6. Design Reference Findings (Designing-Skills)

- **Reference Git Commit SHA**: `2d228630ba1446365f614a108cb8252f1feda202`
- **Source**: `https://github.com/realmadede/Designing-Skills.git`
- **Application to GNOME (GTK4 + libadwaita)**:
  - **Animation Decision Framework**: Zero animation on keyboard navigation; UI transitions kept under 250ms with `ease-out` curves; physics-based springs (`AdwSpringAnimation`) reserved for gestures and toast entries.
  - **Frame Budget Adherence**: Avoid widget allocation animations (`width`, `height`); animate composite-only GSK render nodes (`transform`, `opacity`).
  - **Tabular Figures (`tnum`)**: Mandatory for all memory metrics, PIDs, and byte counters to prevent layout jitter during live scanning.
  - **Middle Truncation**: Applied to all filesystem paths (`/home/user/.../src/index.ts`) to ensure readable filenames and workspace origins.
  - **Adversarial Break-UI Testing**: Stress-testing UI components with worst-case data (unbounded paths, localized plural rules, empty states) before release.

---

## 7. Sandboxed Testing Strategy

To eliminate host risk during development:
- **Level 1 (Synthetic Fixtures)**: Fast unit tests in `cargo test` using `tempfile` trees, symlink loops, and mock trait providers.
- **Level 2 (Rootless Containers)**: Isolated container tests with dedicated PID namespaces and mock `$HOME` trees for POSIX syscall verification.
- **Level 3 (Disposable Kali Linux VM)**: Snapshot-based QEMU/KVM virtual machine with zero writable host mounts and isolated credentials for all destructive integration and recovery tests.

---

## 8. Outstanding Risks & Unresolved Questions

1. **File Locking in SQLite Databases**: Antigravity uses SQLite WAL mode (`conversation_summaries.db-wal`). Quarantining or copying while SQLite checkpoints are occurring could yield inconsistent state. Solution: Check for active locks before touching database directories.
2. **Container Filesystem Differences**: Overlayfs in Docker/Podman alters `st_dev` behavior, requiring Level 3 VM testing for definitive filesystem boundary validation.
3. **Multi-User Environments**: In shared Linux servers, `/tmp` contains files from other users. Root must strictly restrict inspection to files owned by the calling user's UID (`st_uid`).

---

## 9. Phase 01 Readiness Assessment

Phase 00 acceptance criteria have been **100% satisfied**:
- [x] Project mission, philosophy, and boundaries documented.
- [x] Hybrid architecture (Modes A, B, C) fully specified.
- [x] Linux resource management research empirically validated.
- [x] Agent storage behaviors researched with explicit verification labels.
- [x] Formal threat model and mitigations established.
- [x] Cleanup eligibility policy and Git safety invariant defined.
- [x] Cross-platform abstraction traits designed in pure Rust.
- [x] Three-level sandboxed testing strategy documented.
- [x] Mandatory design reference reviewed (Commit `2d228630ba1446365f614a108cb8252f1feda202`).
- [x] Native GNOME GTK4 + libadwaita design foundation established.
- [x] Enforceable agent rules codified in `AGENTS.md`.
- [x] Relative documentation links verified.
- [x] Zero destructive operations performed.
- [x] Zero production application code introduced.

**Recommendation**: The architectural, security, and research foundation is rock-solid. Root is fully prepared to enter **Phase 01: Core Domain Models, Platform Traits, & Synthetic Fixtures** upon human authorization.
