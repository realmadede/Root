# Mandatory Agent Development Rules & Governance

> [!IMPORTANT]
> **ENFORCEABLE RULES FOR ALL AI AGENTS & PAIR PROGRAMMERS**  
> Any AI agent, LLM-based coding assistant, or automated system working within this repository **must strictly abide by the permanent rules established in this document**. Violations compromise system safety and integrity.

---

## 1. Absolute Operating Invariants

1. **Read Documentation Before Implementation**:
   - Before proposing or writing any code, the agent must thoroughly read `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, and the relevant design/research documents in `docs/`.
   - Never assume architectural patterns, paths, or policies.

2. **Follow the Defined Project Phases**:
   - Work is organized into strict phases defined in `docs/roadmap.md`.
   - Agents must only execute tasks belonging to the currently active, approved phase.
   - **Never proceed into the next phase automatically** without explicit human authorization.

3. **Never Perform Destructive Operations Without Authorization**:
   - Never delete, move, truncate, or overwrite user files on the host machine.
   - Never terminate processes without explicit, confirmed user consent.
   - Deletion must always follow the Quarantine-First policy outlined in `docs/cleanup-policy.md`.

4. **Never Run Privileged Commands Automatically**:
   - Never execute `sudo`, `su`, `pkexec`, or request root privileges.
   - Root is an unprivileged utility operating under least-privilege principles. Any feature requiring root is architecturally invalid.

5. **Never Inspect Private File Contents Unnecessarily**:
   - Never dump, log, or summarize private user documents, credentials, API keys, or conversation histories (`transcript.jsonl`, `sessions/*.json`, `.key` files, `oauth_creds.json`).
   - Root operates on file metadata (paths, sizes, timestamps, inodes, permissions) only.

6. **Never Introduce AI Runtime Dependencies**:
   - Root is an algorithmic, deterministic system utility.
   - Never introduce dependencies on LLM runtimes, OpenAI/Anthropic APIs, cloud inference, embedding models, or telemetry frameworks. Root must run 100% locally and deterministically.

7. **Keep the Core Deterministic**:
   - Resource classification and cleanup rules must be based on explicit, testable, deterministic invariants.
   - Never use probabilistic guessing, heuristic scoring based solely on file size, or unexplainable rules.

8. **Prefer Native Platform Capabilities**:
   - On Linux, utilize native kernel and user-space mechanisms: `/proc`, `/sys/fs/cgroup`, `pidfd_open`, `pidfd_send_signal`, `statx`, `openat2`, `inotify`, and systemd user services.
   - Do not wrap arbitrary CLI tools (e.g. running `killall -9` via bash) when safe POSIX/Linux syscalls exist.

9. **Follow the Designing-Skills Reference for Future UI Work**:
   - Any interface or visual work must adhere to the official reference repository `https://github.com/realmadede/Designing-Skills.git` at commit `2d228630ba1446365f614a108cb8252f1feda202`.
   - Obey the Animation Decision Framework (no animation on keyboard shortcuts, UI transitions < 250ms, ease-out curves, springs for physics).
   - Enforce Break-UI resilience: tabular numbers (`tnum`), middle truncation for long paths, pluralization handling, empty states.

10. **Keep the GUI Independent from the Core Engine**:
    - The core engine (`root-core`, `root-storage`, `root-process`, `root-guardian`) must compile and run on headless servers with zero GTK or display dependencies.
    - The GUI (`root-gui`) is strictly an optional visualization layer consuming core Rust APIs.

11. **Test Potentially Destructive Behavior in Isolated Environments**:
    - Never test file deletion, quarantine moves, or process termination on the host development machine.
    - Destructive tests must run against Level 1 synthetic fixtures, Level 2 rootless containers, or Level 3 disposable VMs as specified in `docs/testing-strategy.md`.

12. **Avoid Unnecessary Dependencies**:
    - Scrutinize every third-party Rust crate.
    - Avoid bloated dependency trees, unmaintained crates, or crates pulling in C libraries when pure Rust or standard POSIX bindings exist.

13. **Do Not Invent Test Results or Behavior**:
    - Clearly distinguish **[VERIFIED]** findings, **[HYPOTHESIS]** deductions, and **[UNKNOWN]** behaviors.
    - Never claim a test passed unless it was actually executed and verified in the environment.

14. **Document Uncertainty**:
    - When researching or encountering ambiguous operating system or agent behavior, explicitly document the unknowns rather than inventing assumptions.

---

## 2. Agent Workflow Protocol

When invoked for any task on Root:
1. **Assess Context**: Verify current branch, git status, and active roadmap phase.
2. **Review Constraints**: Check this document (`AGENTS.md`) and verify proposed actions comply with all 14 invariants.
3. **Confirm Boundaries**: Ensure no production implementation is attempted during design/research phases.
4. **Produce Verifiable Work**: Accompany every change with documentation, tests, or explicit verification logs.
5. **Stop at Phase Gate**: Summarize accomplishments, report outstanding questions, and pause for user guidance.
