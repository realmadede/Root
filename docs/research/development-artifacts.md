# Research: Development Tooling Storage, Process & Cache Behavior

## 1. Executive Overview

Modern software development tooling generates the vast majority of ephemeral disk consumption and orphaned background processes on a developer workstation. When coupled with autonomous AI agents that run builds, execute tests, and launch servers, these artifacts multiply rapidly across dormant repositories.

This document analyzes the storage topology, cache structures, process models, and reclamation risks across the primary developer toolchains.

---

## 2. Git & Version Control Systems

### 2.1 Storage Topology & Growth Vectors
Every Git repository stores its entire revision history, branch topology, and object graph inside the `.git/` directory:
- `.git/objects/`: Loose objects (SHA-1/SHA-256 hashed zlib-compressed blobs, trees, and commits).
- `.git/objects/pack/`: Packed object archives (`.pack`) and index files (`.idx`), generated during `git gc` or fetch.
- `.git/refs/original/`: Created during filter-branch or interactive rebases.
- `.git/logs/`: The Reflog (`HEAD`, branch heads). Preserves commit pointers even after rebase, reset, or branch deletion.
- `.git/worktrees/`: Metadata for linked worktrees created via `git worktree add`.

### 2.2 Reclaimable Artifacts & Invariants
- **Dangling Objects**: Commits or blobs unreferenced by any branch or tag.
- **Reflog Expiration**: By default, Git retains reflog entries for 90 days for reachable commits, and 30 days for unreachable commits (`gc.reflogExpireUnreachable`).
- **Orphan Worktree Metadata**: If a worktree directory is deleted from disk without running `git worktree remove`, `.git/worktrees/<name>` remains orphaned.
- **Root Safety Policy**:
  > [!IMPORTANT]
  > Root **never modifies or compacts `.git` without explicit user confirmation**.
  > Calling `git prune` or `git gc --prune=now` permanently destroys unreferenced commits, eliminating the developer's ability to recover lost work via the reflog.
  > Root will only propose `git worktree prune` for missing worktree paths, and flag repositories with high loose-object counts for optional user-initiated `git gc`.

---

## 3. Node.js, npm, pnpm, and Bun Ecosystems

### 3.1 The `node_modules` Disk Explosion
The traditional Node.js resolution algorithm creates deep, duplicate dependency trees inside `node_modules/`. In developer environments with multiple branches, microservices, or agent scratchpads, `node_modules/` frequently consumes tens of gigabytes.

### 3.2 Global Caches: npm vs pnpm vs Yarn
- **npm Cache (`~/.npm/_cacache/`)**:
  - Content-addressable cache containing raw tarballs (`content-v2`) and index entries (`index-v5`).
  - **Reclaimability**: Safe to clean via `npm cache clean --force` or manual pruning. Packages will simply be re-downloaded on next install.
- **pnpm Store (`~/.local/share/pnpm/store/v3/`) [CRITICAL RISK]**:
  - Unlike npm, pnpm uses a **content-addressable hard-link store**.
  - When pnpm installs packages in a project, it hard-links files from the global store into the project's `node_modules/.pnpm/` directory.
  - **The Inode Linkage Hazard**:
    - File `foo.js` in Project A and Project B shares the exact same inode (`st_ino`) as `~/.local/share/pnpm/store/v3/files/...`.
    - If Root naively deletes an unreferenced-looking file in the pnpm store, it could corrupt projects across the entire system.
    - If Root deletes a project `node_modules`, it decrements the inode link count (`st_nlink`). Only when `st_nlink` drops to 1 is the file exclusive to the pnpm store.
  - **Root Policy on pnpm**:
    - Root **never manually deletes files** from `~/.local/share/pnpm/store/`.
    - Root delegates store pruning exclusively to the official `pnpm store prune` command or inspects `st_nlink == 1` with extreme safety guarantees.
- **Yarn Cache (`~/.cache/yarn/v6/`)**: Standard tarball cache; safe to prune.
- **Bun Cache (`~/.bun/install/cache/`)**: Flat package cache; safe to prune.

---

## 4. Rust & Cargo Ecosystem

### 4.1 Target Directory (`target/`) Architecture
Rust build artifacts are notoriously large due to static linking, monomorphization, and debug symbols:
- `target/debug/`: Unoptimized binaries and object files.
- `target/release/`: Optimized production builds.
- `target/debug/incremental/`: Incremental compilation cache (thousands of fine-grained `.bin` and `.o` files).
- `target/debug/deps/`: Intermediate compiled libraries (`.rlib`, `.rmeta`, `.so`).

### 4.2 Cargo Global Cache (`~/.cargo/`)
- `~/.cargo/registry/cache/`: Downloaded `.crate` gzip archives from crates.io.
- `~/.cargo/registry/src/`: Extracted source code of all cached crates.
- `~/.cargo/git/db/`: Bare git clones of git dependencies.
- `~/.cargo/git/checkouts/`: Checked-out working copies of git dependencies.

### 4.3 Reclamation Policies & Cargo Clean
- **Project Target Pruning**:
  - `cargo clean`: Deletes the entire `target/` directory.
  - `cargo clean --doc`: Deletes generated documentation.
  - Stale compilation targets: In multi-target projects (e.g., cross-compiling for `x86_64` and `wasm32`), old target subdirectories often sit unused for months.
- **Safety Invariant**: Target directories contain no source code or user configuration. They can always be regenerated via `cargo build`. Root classifies dormant `target/` directories as `USER_CONFIRM_REQUIRED` (because rebuilding consumes CPU time and battery).

---

## 5. Python Toolchain & Caches

### 5.1 Bytecode & Cache Directories
- `__pycache__/` and `*.pyc`: Compiled Python bytecode. Automatically regenerated on module import if timestamps differ.
- `.pytest_cache/`: Pytest test ordering, failure cache, and step timings.
- `.mypy_cache/`: Mypy type-checking incremental cache.
- `.ruff_cache/`: Ruff linter and formatter cache.
- `.tox/`: Tox multi-environment test runners.

### 5.2 Virtual Environments (`venv/`, `.venv/`)
- Isolated directories containing Python binaries, site-packages, and activate scripts.
- **Dormancy**: When an AI agent experiments with a Python script, it often creates a `.venv` with dozens of pip dependencies that are abandoned once the conversation ends.
- **Reclamation Risk**: Deleting a `.venv` is safe if `requirements.txt` or `pyproject.toml` exists, but requires a fresh `pip install` to recreate. Classified as `USER_CONFIRM_REQUIRED`.

### 5.3 Global pip Cache (`~/.cache/pip/`)
- Contains downloaded `.whl` and `.tar.gz` wheels. Safe to clear; completely re-fetchable.

---

## 6. Language Servers & Development Processes

### 6.1 Language Server Process Lifecycle (LSP)
Language servers index large ASTs in memory and run persistent background processes:
- `rust-analyzer`: In-memory index of all crates in the workspace. Memory consumption often reaches **1 GiB – 4 GiB RSS**.
- `tsserver` / `vtsls` / `typescript-language-server`: Spawns multiple Node.js worker processes (`typingsInstaller.js`, `tsserver.js`).
- `pyright` / `basedpyright`: Node-based Python type analyzer.
- `gopls`: Go language server.
- `clangd`: C/C++ background indexer.

### 6.2 The Abandoned LSP Phenomenon
- When an AI agent or headless IDE crashes, kills its shell, or disconnects without a clean `exit`, child language servers frequently become orphaned under PID 1.
- Because LSPs maintain file watches via `inotify`, orphaned LSPs continue consuming CPU cycles and memory indefinitely.
- **Socket & Pipe Leaks**: LSPs create IPC pipes in `/tmp/` (e.g. `/tmp/vscode-typescript1000/.../tscancellation-*.tmp`). When the process dies without cleanup, these files remain in `/tmp`.

### 6.3 Development Servers & Watchers
- Web development servers (`vite`, `next dev`, `webpack-dev-server`, `turbo`) listen on TCP ports (e.g., `3000`, `5173`, `8080`) and hold in-memory bundle caches.
- If an agent launches a dev server in a background subtask and the conversation ends, the server remains bound to the port, blocking future development sessions.
- **Root Process Detection**:
  - Inspect process tree for parentage.
  - Match command line against known development server signatures.
  - Verify if listening sockets are active via `/proc/net/tcp` or `/proc/[pid]/fd`.
  - Classify as orphaned dev server if PPID == 1 and no active IDE/agent session is attached.
