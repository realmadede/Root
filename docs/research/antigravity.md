# Deep Dive: Google Antigravity Architecture & Storage Behavior

## 1. Overview & Verification Status

**Target**: Google Antigravity (CLI & IDE ecosystem)  
**Primary Verification Status**: **[VERIFIED - LIVE SYSTEM EVIDENCE]**  
**Evidence Source**: Local Kali Linux Rolling host environment (`~/.gemini/`), process table inspection, and system architecture specifications.

Google Antigravity is a multimodal agentic AI development environment capable of orchestrating complex pair-programming workflows, launching autonomous subagents, managing background terminal tasks, and generating markdown artifacts.

---

## 2. Directory Layout & Storage Topology

Antigravity concentrates its persistent and transient state under `~/.gemini/` and subdirectories:

```
~/.gemini/
├── antigravity/                  # IDE / desktop state and extensions
├── antigravity-cli/              # Core CLI runtime and agent workspace
│   ├── annotations/              # User/system annotations
│   ├── bin/                      # CLI helper binaries
│   ├── brain/                    # Persistent conversation memories and workspaces
│   │   └── <conversation-id>/    # Unique UUID per conversation session
│   │       ├── .system_generated/# Internal logs, step outputs, and transcripts
│   │       │   ├── logs/
│   │       │   │   ├── transcript.jsonl        # Compact transcript
│   │       │   │   └── transcript_full.jsonl   # Unabridged transcript
│   │       │   └── steps/
│   │       │       └── <step_id>/
│   │       │           └── output.txt          # Truncated tool output archives
│   │       ├── scratch/          # Temporary execution scripts and clones
│   │       └── *.md              # Generated artifacts
│   ├── builtin/                  # Built-in skills and agent configurations
│   ├── cache/                    # Internal runtime caches
│   ├── conversations/            # Session metadata
│   ├── conversation_summaries.db # SQLite database tracking all sessions
│   ├── conversation_summaries.db-shm # SQLite Shared Memory WAL index
│   ├── conversation_summaries.db-wal # SQLite Write-Ahead Log
│   ├── crashes/                  # Crash dump logs (crash_<pid>_<uuid>.log)
│   ├── history.jsonl             # Master global history log
│   ├── implicit/                 # Implicit preference state
│   ├── installation_id           # Unique installation identifier
│   ├── jetbox_summaries_proto.pb # Protocol buffer state cache
│   ├── jetski_state.pbtxt        # Text-format protobuf configuration
│   ├── knowledge/                # Learned facts and index
│   ├── last_check.timestamp     # Update check marker
│   ├── log/                      # Session execution logs (cli-*.log)
│   ├── presence/                 # Active session presence markers
│   ├── settings.json             # User settings and flags
│   └── updater/                  # Self-update staging
├── antigravity-ide/              # IDE specific assets
├── config/                       # Global Gemini configuration
├── google_accounts.json          # Google account identities [CRITICAL SECURITY]
├── history/                      # Legacy history
├── installation_id               # Root installation GUID
├── oauth_creds.json              # Active OAuth credentials & tokens [CRITICAL SECURITY]
├── projects.json                 # Project mappings
└── tmp/                          # Ephemeral agent tempfiles
```

---

## 3. Storage Footprint Analysis & Findings

Empirical inspection of the reference host reveals specific growth vectors:

### 3.1 The `brain/<conversation-id>/scratch/` Directory
- **Observed Size**: Single conversation `scratch/` directories were observed reaching **254 MiB**.
- **Nature**: Agents create scratch directories to clone git repositories, run test suites, or create temporary live worktrees (`scratch/live-worktree`).
- **Lifecycle**: Agents often complete tasks without cleaning up these scratch directories. Once the conversation is finished, the scratch files remain on disk indefinitely.
- **Risk Assessment**: High storage accumulation. However, a user may occasionally save work directly inside a scratch folder. Root must verify conversation inactivity before suggesting recovery.

### 3.2 The `.system_generated/steps/<step_id>/output.txt` Files
- **Observed Size**: Reaches **15 MiB – 80 MiB per conversation** across active sessions.
- **Nature**: When a command executed via `run_command` produces excessive output (e.g. large test runs, `ls -la`, compiler logs), Antigravity truncates the context window and streams the full output to `steps/<step_id>/output.txt`.
- **Lifecycle**: These files are archival. Once a conversation is archived or closed, the raw step outputs are rarely re-read.
- **Root Policy**: Eligible for compression or quarantine upon conversation closure.

### 3.3 The `log/cli-YYYYMMDD_HHMMSS.log` Files
- **Observed Size**: Approximately **500 KiB – 1.5 MiB per invocation**, totaling ~7 MiB within a few days.
- **Nature**: Full diagnostic logs containing CLI execution traces, latency metrics, and API request timings.
- **Root Policy**: Log rotation policy. Logs older than 14 days with no active session attachment can be safely purged.

### 3.4 Crash Dumps (`crashes/`)
- **Observed**: Zero-byte crash markers `crash_<pid>_<uuid>.log`.
- **Root Policy**: Safe to remove if older than 7 days.

---

## 4. Security & Privacy Boundaries

### 4.1 Strictly Protected Files
The following files under `~/.gemini/` contain sensitive credentials, active identities, and unrecoverable user interactions:
- `~/.gemini/oauth_creds.json`: Contains OAuth tokens with permissions to interact with Google APIs.
- `~/.gemini/google_accounts.json`: User profile identifiers and email addresses.
- `~/.gemini/antigravity-cli/brain/<uuid>/.system_generated/logs/transcript*.jsonl`: Complete conversational transcripts containing developer prompts, proprietary code snippets, and internal reasoning.
- `~/.gemini/antigravity-cli/conversation_summaries.db*`: Master index of all user sessions.

> [!CAUTION]
> Root **must never** delete, modify, or read the textual contents of `oauth_creds.json`, `google_accounts.json`, or conversation transcripts. Root inspects file metadata (size, mtime, inode) only.

---

## 5. Process Lifecycle & Orphan Detection

Antigravity operates with a multi-process architecture:
1. **CLI Master Process**: The primary interactive shell.
2. **Subagents**: Spawned via `invoke_subagent` (e.g. `research`, `image-generator`, `self`).
3. **Background Tasks**: Spawned via `run_command` with `IsDaemon: true` or async timeouts (e.g., test runners, watchers).
4. **MCP Servers**: Model Context Protocol child servers spawned via stdio.

### Failure Scenarios & Orphan Identification:
- If the CLI master process crashes or receives `SIGKILL`, background daemon tasks spawned by `run_command` or MCP server subprocesses may become orphaned and re-parented to PID 1.
- Root identifies Antigravity processes by inspecting:
  1. `/proc/[pid]/exe` pointing to the Antigravity binary.
  2. Command line arguments matching agent patterns (`antigravity-cli`, subagent flags).
  3. Parent PID (PPID == 1 indicates orphaned status).
  4. Process age compared against the latest entry in `~/.gemini/antigravity-cli/presence/`.

---

## 6. Cleanup Eligibility Matrix

| Path Pattern | Classification | Preconditions for Action | Reversible via Quarantine? |
|---|---|---|---|
| `~/.gemini/oauth_creds.json` | **STRICTLY_PROTECTED** | Never eligible | No |
| `~/.gemini/antigravity-cli/brain/*/transcript*.jsonl` | **STRICTLY_PROTECTED** | Never eligible | No |
| `~/.gemini/antigravity-cli/brain/*/scratch/` | **USER_CONFIRM_REQUIRED** | Conversation closed > 7 days, no active locks, git status clean | Yes |
| `~/.gemini/antigravity-cli/brain/*/.system_generated/steps/` | **OBSOLETE_TRANSIENT** | Conversation closed > 14 days | Yes |
| `~/.gemini/antigravity-cli/log/cli-*.log` | **OBSOLETE_TRANSIENT** | Age > 14 days, not symlinked to `cli.log` | Yes |
| `~/.gemini/antigravity-cli/crashes/*.log` | **OBSOLETE_TRANSIENT** | Age > 7 days | Yes |
| `~/.gemini/antigravity-cli/cache/*` | **SAFE_RECOVERABLE** | Age > 3 days | Yes |
