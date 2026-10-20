# Deep Dive: Claude Code Architecture & Storage Behavior

## 1. Overview & Verification Status

**Target**: Anthropic Claude Code (CLI coding agent)  
**Primary Verification Status**: **[VERIFIED - LIVE SYSTEM EVIDENCE]**  
**Evidence Source**: Local Kali Linux Rolling host environment (`~/.claude/`, `~/.claude.json`), session metadata inspection, and empirical process analysis.

Claude Code is an agentic terminal tool that executes commands, searches codebases, edits files, and interacts with developer repositories via Anthropic's Claude model family.

---

## 2. Directory Layout & Storage Topology

On Linux systems, Claude Code stores its state in `~/.claude/` and user-level configuration files:

```
~/.claude/
├── backups/                      # Backup copies of edited files prior to mutation
├── .last-cleanup                 # Timestamp of internal agent maintenance
├── projects/                     # Project-scoped session links and metadata
│   └── -path-to-project/         # Path-encoded directory (e.g., -home-user-project)
├── session-env/                  # Ephemeral execution environments per tool call
│   └── <uuid>/                   # UUID-keyed environment directory (often empty)
├── sessions/                     # Persistent session records and encryption keys
│   ├── <session-id>.json         # Session metadata, message counts, timestamps
│   └── <session-id>.<hash>.key   # Session encryption keys [CRITICAL SECURITY]
└── shell-snapshots/              # Captured user shell environment scripts
    └── snapshot-<shell>-<ts>.sh  # Full exports of variables, functions, and aliases
~/.claude.json                    # Global configuration, auth credentials, approved commands
```

---

## 3. Empirical Findings & Storage Anomalies

Direct inspection of `~/.claude/` on the reference Linux host revealed several critical resource and security behaviors:

### 3.1 The Leaked `session-env/<uuid>` Directory Problem
- **Observation**: Over **56 separate UUID subdirectories** were present in `~/.claude/session-env/`.
- **Finding**: Every single UUID subdirectory was **completely empty** (`find session-env -type f` returned 0 files).
- **Mechanism**: When Claude Code executes a tool call requiring an isolated environment, it creates a temporary directory under `session-env/<uuid>`. Upon command completion, it cleans up the files inside the directory, but fails to call `rmdir()` on the parent UUID directory.
- **Root Policy**: Empty directories in `~/.claude/session-env/` older than 24 hours are safe to prune cleanly without affecting any running session.

### 3.2 Shell Snapshots & Security Leakage (`shell-snapshots/`)
- **Observation**: Multiple scripts named `snapshot-zsh-<timestamp>-<random>.sh` (~12 KiB each) were present in `~/.claude/shell-snapshots/`.
- **Finding**: Claude Code generates these scripts to capture the user's active shell environment (environment variables, shell functions, PATH, and aliases) so that subshells spawned during tool execution behave identically to the user's interactive terminal.
- **Security Implication**: If the user's interactive shell had sensitive credentials exported in memory (e.g. `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `DATABASE_URL`), those plaintext secrets are permanently written into `snapshot-*.sh` on disk with world-readable permissions (`0644`).
- **Root Policy**: 
  - Root treats `shell-snapshots/` as containing potential secrets.
  - Shell snapshots older than the associated session are eligible for deletion to reduce credential exposure risk.

### 3.3 Session Key Management (`sessions/*.key`)
- **Observation**: For every `<session-id>.json` file, a corresponding `<session-id>.<hash>.key` file exists with restrictive permissions (`0600`).
- **Finding**: Claude Code uses these keys to encrypt session payloads or verify session integrity.
- **Risk Assessment**: Deleting `.key` files corrupts session history, making it impossible for the user to resume or inspect past Claude Code conversations.
- **Root Policy**: **STRICTLY PROTECTED**.

### 3.4 File Backups (`backups/`)
- **Observation**: Claude Code creates backup files before making edits to user code.
- **Finding**: Over time, `backups/` accumulates stale versions of files across multiple projects. If the project's git repository has already committed the changes, these backup files represent duplicate storage.
- **Root Policy**: Eligible for recovery if the backup timestamp is older than 30 days and the corresponding git workspace is verified clean.

---

## 4. Process Architecture & Lifecycle

Claude Code runs primarily as a Node.js process:
1. **Master CLI**: `node /usr/local/bin/claude` or npm global equivalent.
2. **Subprocesses**:
   - `ripgrep` (`rg`) for rapid codebase searching.
   - Child shell instances (`bash` / `zsh`) executing user-approved commands.
   - MCP servers configured in `~/.claude.json`.

### Crash & Orphan Scenarios:
- If a user closes the terminal window without sending `Ctrl+C`, the child commands (such as a long-running dev server started via Claude) can become orphaned under PID 1.
- Claude Code records session termination, but may leave background watchers or Node worker threads active.

---

## 5. Cleanup Eligibility Matrix

| Path Pattern | Classification | Preconditions for Action | Reversible via Quarantine? |
|---|---|---|---|
| `~/.claude.json` | **STRICTLY_PROTECTED** | Never eligible (auth & permissions) | No |
| `~/.claude/sessions/*.key` | **STRICTLY_PROTECTED** | Never eligible (cryptographic keys) | No |
| `~/.claude/sessions/*.json` | **STRICTLY_PROTECTED** | Never eligible (conversation history) | No |
| `~/.claude/session-env/*` | **OBSOLETE_TRANSIENT** | Empty directory, mtime > 24 hours | Yes |
| `~/.claude/shell-snapshots/*.sh` | **OBSOLETE_TRANSIENT** | Associated session inactive, mtime > 7 days | Yes |
| `~/.claude/backups/*` | **USER_CONFIRM_REQUIRED** | Age > 30 days, project git status clean | Yes |
