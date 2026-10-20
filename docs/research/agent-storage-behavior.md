# AI Coding Agent and Tooling Storage Research

## 1. Executive Summary

Modern AI coding agents and development environments accumulate massive storage footprints, process hierarchies, and temporary execution artifacts. Because these tools run autonomous shell commands, background tasks, and code generators, they introduce failure modes unseen in traditional IDEs:
1. **Unbounded log and step output accumulation**: Capturing megabytes of stdout/stderr per executed tool command.
2. **Abandoned scratchpads and worktrees**: Cloning repositories or creating test workspaces that are never purged after conversation closure.
3. **Leaked environment snapshots and empty directory structures**: Residual metadata after subshell execution.
4. **Orphaned language servers and development servers**: Child processes that outlive parent CLI agent crashes.

This document synthesizes empirical filesystem observations, architectural analysis, and safety classifications for the major AI coding agents and development stacks.

---

## 2. Research Methodology & Evidence Classification

Every finding in this research is explicitly classified according to the following evidentiary hierarchy:

- **[VERIFIED]**: Confirmed via direct live filesystem inspection on the Kali Linux reference environment, source code analysis, or official technical specifications.
- **[HYPOTHESIS]**: Deduced through standard architectural patterns and runtime behavior, pending explicit empirical verification.
- **[UNKNOWN]**: Behavior or storage path not yet deterministically identified; requires sandboxed empirical reproduction before creating cleanup policies.

---

## 3. Comprehensive Agent & Tooling Comparison Matrix

| Tool / Ecosystem | Primary Base Directories | Primary Storage Classes | Verified Disk Footprint Range | Background Processes | Classification Risk Level |
|---|---|---|---|---|---|
| **Google Antigravity** | `~/.gemini/antigravity-cli/`<br>`~/.gemini/` | Transcripts, scratchpads, step outputs, SQLite DB, CLI logs, OAuth tokens | **750 MiB – Multi-GiB** [VERIFIED] | Subagents, MCP servers, background bash runners | High (contains private chats & credentials) |
| **Claude Code** | `~/.claude/`<br>`.claude/` (project) | Sessions (`.json`), Session keys (`.key`), Shell snapshots (`.sh`), empty session-env UUID dirs | **10 MiB – 1 GiB+** [VERIFIED] | Node.js workers, ripgrep processes, LSP subprocesses | High (contains session keys & shell secrets) |
| **OpenAI Codex / CLI** | `~/.openai/`<br>`~/.cache/openai/` | API cache, token metrics, command execution logs | **5 MiB – 200 MiB** [HYPOTHESIS] | Minimal (stateless CLI or client daemon) | Medium (API keys & prompt caches) |
| **Gemini CLI** | `~/.gemini/`<br>`~/.config/gemini/` | OAuth tokens, history logs, project bindings | **5 MiB – 50 MiB** [VERIFIED] | Short-lived CLI commands | High (OAuth credentials) |
| **Aider** | Project roots (`.aider*`)<br>`~/.aider/` | Chat history (`.aider.chat.history.md`), input history, tags cache (`.aider.tags.cache.v3`) | **1 MiB – 100 MiB per repo** [VERIFIED] | Git subprocesses, ctags/tree-sitter parsers | Low-Medium (project history & cache) |
| **Node / npm / pnpm** | `~/.npm/_cacache/`<br>`~/.local/share/pnpm/store/`<br>`node_modules/` | Content-addressable package caches, hardlink stores, vendor directories | **1 GiB – 50 GiB+** [VERIFIED] | Dev servers (Vite, Next.js, Webpack) | High (pnpm hardlinks share inodes across projects!) |
| **Rust / Cargo** | `~/.cargo/registry/`<br>`target/` | Crate tarballs, git clones, incremental compilation objects, debug symbols | **2 GiB – 100 GiB+** [VERIFIED] | `rust-analyzer`, test runners, cargo watch | Low (safely rebuildable via `cargo build`) |
| **Python** | `~/.cache/pip/`<br>`__pycache__/`<br>`.venv/` | Downloaded wheels, bytecode cache, isolated virtual environments | **500 MiB – 20 GiB+** [VERIFIED] | Jupyter kernels, Celery workers, Pytest processes | Low-Medium (re-creatable via `pip install`) |
| **Language Servers** | `/tmp/`<br>`~/.cache/` | IPC pipes, socket cancellation tokens, AST indices | **100 MiB – 4 GiB (RAM)** [VERIFIED] | `tsserver`, `rust-analyzer`, `pyright`, `clangd` | High (orphaned processes consuming RAM & CPU) |

---

## 4. Deep-Dive Taxonomy of Storage Categories

### 4.1 Session State & Conversation History
- **Description**: Structural records of developer interactions with AI models.
- **Examples**: `~/.gemini/antigravity-cli/brain/<uuid>/transcript.jsonl`, `~/.claude/sessions/*.json`, `.aider.chat.history.md`.
- **Regeneration**: **Impossible**. Once deleted, developer context, reasoning steps, and agent memory cannot be restored.
- **Root Policy**: **STRICTLY PROTECTED**. Root will never delete or truncate conversation history.

### 4.2 Credentials and Identity Data
- **Description**: Authentication tokens, OAuth refresh secrets, API keys, and session cryptography keys.
- **Examples**: `~/.gemini/oauth_creds.json`, `~/.claude/sessions/*.key`, `~/.claude.json`.
- **Regeneration**: Requires manual user re-authentication or token revocation.
- **Root Policy**: **STRICTLY PROTECTED**. Root will refuse any operation targeting authentication files.

### 4.3 Execution Artifacts and Scratchpads
- **Description**: Ephemeral working directories, git clones, and scratch scripts generated by agents to solve sub-tasks.
- **Examples**: `~/.gemini/antigravity-cli/brain/<uuid>/scratch/` (observed at 254 MiB in a single session), `~/.claude/shell-snapshots/*.sh`.
- **Regeneration**: Generally not needed if the task is finished, but user code or temporary patches may reside here if explicitly placed by the user.
- **Root Policy**: **USER_CONFIRM_REQUIRED**. Requires verification that the associated agent conversation is closed and no active process holds open descriptors in the path.

### 4.4 Tooling and Registry Caches
- **Description**: Downloaded packages, tarballs, and pre-compiled wheels fetched from public registries.
- **Examples**: `~/.npm/_cacache/`, `~/.cache/pip/`, `~/.cargo/registry/cache/*.crate`.
- **Regeneration**: **100% Deterministic**. Can be re-downloaded bit-for-bit from upstream servers.
- **Root Policy**: **SAFE_RECOVERABLE**. Eligible for cache reclamation subject to age thresholds.

### 4.5 Hard-Linked Package Stores (The pnpm Special Case)
- **Description**: pnpm uses a content-addressable store (`~/.local/share/pnpm/store/v3/`) and creates hard links into project `node_modules`.
- **Risk**: A file in `node_modules` shares an inode (`st_ino`) with the global store. Deleting or modifying files in the store destroys active projects across the entire system.
- **Root Policy**: **SPECIAL HANDLING REQUIRED**. Root checks `st_nlink > 1`. Direct file unlinking is forbidden; only official pruning interfaces (`pnpm store prune`) or verified orphan inodes may be touched.

### 4.6 Orphaned Background Processes
- **Description**: Background servers, watchers, and language servers left running after an agent disconnects, crashes, or closes without sending `SIGTERM` to its process group.
- **Examples**: `node /path/to/vite`, `tsserver.js`, `rust-analyzer` consuming 100% of a CPU core in an infinite spin.
- **Root Policy**: Detect parentage (PPID == 1), check for active controlling terminals, confirm no active agent session owns the PID, and provide explicit termination actions using `pidfd_send_signal`.

---

## 5. Official Cleanup Mechanisms vs. Root's Role

Most tools offer fragmented, manual CLI cleanup tools:
- `cargo clean`: Empties `target/` for a single project, but developer must remember to run it in every forgotten repository.
- `pnpm store prune`: Scans store for unreferenced packages.
- `npm cache clean --force`: Cleans npm cache, but deletes active metadata unnecessarily.
- `git gc --prune=now`: Compacts git repositories.
- `docker system prune`: Cleans docker containers and images.

### Root's Value Proposition:
Root does not replace upstream package managers. Instead, Root:
1. **Aggregates cross-ecosystem visibility** into a single deterministic report.
2. **Identifies abandoned workspaces** across the filesystem that official tools cannot discover.
3. **Catches non-standard artifacts** (such as agent scratchpads and step logs) that official package managers know nothing about.
4. **Enforces unified security, quarantine, and audit logging** before any destructive action takes place.
