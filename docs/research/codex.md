# Research: OpenAI Codex, Gemini CLI, and Aider Storage Behavior

## 1. Overview & Verification Status

This document investigates Priority 1 (OpenAI Codex CLI tooling) and Priority 2 agents (Gemini CLI and Aider), examining their configuration directories, chat histories, caching behaviors, and operational risks.

| Agent | Target Class | Verification Status | Primary Interface |
|---|---|---|---|
| **OpenAI Codex / CLI** | Priority 1 | **[HYPOTHESIS / SPECIFICATION]** | CLI / API wrappers / Playground |
| **Gemini CLI** | Priority 2 | **[VERIFIED - LIVE SYSTEM EVIDENCE]** | Terminal CLI / Python package |
| **Aider** | Priority 2 | **[VERIFIED - REPO SPECIFICATION]** | Interactive Git-integrated CLI |

---

## 2. OpenAI Codex & CLI Tooling

### 2.1 Storage & Topology [HYPOTHESIS]
OpenAI's developer tools and CLI clients adhere to standard XDG conventions or home directory dotfiles:
- Configuration: `~/.openai/` or `~/.config/openai/` containing `api_key` or session tokens.
- Request/Response Caching: `~/.cache/openai/` storing prompt cache hashes and model response tokens.
- Project level: `.openai/` configuration or schema definitions.

### 2.2 Lifecycle & Risks
- **Authentication Protection**: Any file containing `OPENAI_API_KEY` or organization IDs must be **STRICTLY_PROTECTED**.
- **Cache Volatility**: API response caches in `~/.cache/openai/` are safe to recover; however, clearing them may incur increased API token costs for the user if the CLI attempts to re-query models for deterministic tasks.
- **Root Policy**: API caches older than 30 days are classified as `SAFE_RECOVERABLE`. Authentication and project configs are strictly protected.

---

## 3. Gemini CLI

### 3.1 Storage & Topology [VERIFIED]
Empirically verified on the reference host under `~/.gemini/`:
- `~/.gemini/config/`: Configuration files and runtime defaults.
- `~/.gemini/history/`: Historical CLI command inputs.
- `~/.gemini/oauth_creds.json`: Active OAuth tokens (`client_id`, `client_secret`, `refresh_token`).
- `~/.gemini/projects.json`: Mapping of local project paths to Google Cloud / AI Studio project IDs.
- `~/.gemini/tmp/`: Temporary response buffers and multipart upload scratch files.

### 3.2 Risks & Safe Reclamation
- `oauth_creds.json` and `google_accounts.json` must **never** be touched.
- `~/.gemini/tmp/` accumulates orphaned temporary chunks when large file uploads (e.g. codebase tarballs or multimodal media) are interrupted mid-flight.
- **Root Policy**: Files in `~/.gemini/tmp/` with mtime > 48 hours and no open file descriptors are classified as `OBSOLETE_TRANSIENT`.

---

## 4. Aider (Git-Integrated Pair Programmer)

### 4.1 Storage & Topology [VERIFIED]
Aider is unique because it integrates directly into git repositories rather than storing state exclusively in the user's home directory:
- Project Root Files:
  - `.aider.chat.history.md`: Markdown record of the conversational interaction with the model.
  - `.aider.input.history`: Terminal input readline history (arrows, command recalls).
  - `.aider.tags.cache.v3`: Pre-computed repository symbol index (ctags / tree-sitter AST tags) used to build code context maps without re-reading the entire codebase on every turn.
  - `.aider.conf.yml`: Project-specific configuration and model parameters.
- Global Directory:
  - `~/.aider/`: Global configuration, global readline history, and global model settings.

### 4.2 Resource Impact & Lifecycle
- **Tags Cache (`.aider.tags.cache.v3`)**: In large multi-thousand file repositories, the tags cache can grow to 50 MiB – 200 MiB per repository.
  - **Rebuild Cost**: If deleted, Aider will automatically re-index the repository on the next launch. Re-indexing incurs high CPU usage for several minutes on large codebases.
  - **Root Policy**: Classified as `SAFE_RECOVERABLE`, but with a warning to the user that re-launching Aider in that workspace will trigger AST re-parsing.
- **Chat History (`.aider.chat.history.md`)**:
  - Serves as the audit log of all changes made by the AI.
  - **Root Policy**: Classified as **STRICTLY_PROTECTED**. Root will never delete Aider chat history files.
- **Git Commits**: Aider commits every edit directly to the repository's git reflog. Root relies on git invariants; unpushed Aider commits are protected as uncommitted/unpushed project work.

---

## 5. Comparative Cleanup Policy Matrix

| Agent | Artifact Path | Classification | Preconditions for Action | Reversibility |
|---|---|---|---|---|
| **OpenAI** | `~/.openai/api_key` | **STRICTLY_PROTECTED** | Never eligible | No |
| **OpenAI** | `~/.cache/openai/*` | **SAFE_RECOVERABLE** | Age > 30 days | Yes |
| **Gemini CLI** | `~/.gemini/oauth_creds.json` | **STRICTLY_PROTECTED** | Never eligible | No |
| **Gemini CLI** | `~/.gemini/tmp/*` | **OBSOLETE_TRANSIENT** | Age > 48 hours, no active process | Yes |
| **Aider** | `**/.aider.chat.history.md` | **STRICTLY_PROTECTED** | Never eligible | No |
| **Aider** | `**/.aider.input.history` | **STRICTLY_PROTECTED** | Never eligible (user readline history) | No |
| **Aider** | `**/.aider.tags.cache.v3` | **SAFE_RECOVERABLE** | Project dormant > 14 days | Yes (auto-rebuilt) |
| **Aider** | `**/.aider.conf.yml` | **STRICTLY_PROTECTED** | Never eligible (project config) | No |
