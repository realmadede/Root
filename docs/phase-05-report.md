# Root — Phase 05 Completion Report: Professional Command Line Interface and Resource Inspection Experience

## 1. Executive Summary

Phase 05 establishes a polished, deterministic, and explainable command-line interface for **Root**.

The CLI exposes granular Linux system resource inspection—spanning kernel memory accounting, running process inspection, physical filesystem allocation metrics, AI coding agent and developer tool footprint discovery, and synthetic transaction recovery journals—while maintaining the absolute production read-only safety invariant established in earlier phases.

Every command adheres strictly to professional terminal standards:
- Support for the standard `NO_COLOR` specification.
- Dynamic POSIX terminal width detection via `TIOCGWINSZ`.
- Middle truncation for deep filesystem paths.
- Consistent tabular alignment with binary units.
- Deterministic, versioned, machine-readable JSON output on stdout with diagnostics on stderr.
- Transparent explainability detailing rule provenance, lifecycle uncertainty, and Root Guardian authorization guardrails.
- Zero decorative emojis across all terminal messages and test suites.

All 77 unit, integration, and security tests across the workspace pass with zero warnings on `cargo clippy`.

---

## 2. Branch and Commit Identity

- **Active Branch**: `feat/phase-05-cli-experience`
- **Base Commit**: `55bd418` (Phase 04 Base)
- **Target Integration**: Ready for human review and phase-gate approval prior to Phase 06.

---

## 3. Files Created and Modified

### Created Files
- `crates/root-cli/src/lib.rs` — Library exports, argument dispatch, and production mutation guardrails.
- `crates/root-cli/src/args.rs` — Structured argument definitions, clap subcommands, and flag validators.
- `crates/root-cli/src/terminal.rs` — Terminal styling engine (`NO_COLOR` detection, POSIX terminal width calculation, middle truncation, binary unit formatting).
- `crates/root-cli/src/status.rs` — Implementation of `root status` concise system overview.
- `crates/root-cli/src/explain.rs` — Implementation of `root explain <resource-id>` explainability engine.
- `crates/root-cli/src/report.rs` — Implementation of `root report` consolidated diagnostic audit.
- `crates/root-cli/src/interactive.rs` — Read-only interactive terminal navigation browser for findings.
- `crates/root-cli/src/history.rs` — XDG-compliant state persistence for recent scan summaries (`last_scan.json`).
- `crates/root-cli/tests/cli_tests.rs` — Integration test suite covering all 20 specified CLI scenarios.
- `crates/root-guardian/tests/guardian_security_followup_tests.rs` — Security follow-up test suite covering sandbox containment, race conditions, journal durability, and SHA-256 edge cases.
- `docs/cli-reference.md` — User-facing command reference, JSON schemas, exit codes, and security policies.
- `docs/phase-05-report.md` — This official completion document.

### Modified Files
- `crates/root-cli/Cargo.toml` — Added `[lib]` entry and Linux `libc = "0.2"` dependency for POSIX terminal width detection.
- `crates/root-cli/src/main.rs` — Streamlined binary entry point calling `root_cli::run()`.
- `crates/root-cli/src/doctor.rs` — Updated diagnostic check to reflect Phase 05 governance.
- `crates/root-cli/src/scan.rs` — Added scan history recording, interactive flag, and updated terminal rendering.
- `crates/root-cli/src/discover.rs` — Added scan history recording, interactive browser trigger, and updated terminal rendering.
- `crates/root-cli/src/inspect.rs` — Added `storage` (kernel `statvfs` capacity and directory breakdown) and `transactions` (synthetic journal diagnostics).
- `crates/root-core/src/discovery/rules.rs` — Added `RuleRegistry::get_rule(rule_id: &str)`.
- `crates/root-core/src/model/measurement.rs` — Added `FilesystemUsage` domain model.
- `crates/root-core/src/model/mod.rs` — Re-exported `FilesystemUsage`.
- `crates/root-platform/src/traits.rs` — Added `get_filesystem_usage` to `FilesystemProvider`.
- `crates/root-platform/src/linux/filesystem.rs` — Implemented `get_filesystem_usage` wrapping `libc::statvfs`.
- `crates/root-platform/src/mock/mock_platform.rs` — Added mock implementation of `get_filesystem_usage`.
- `docs/roadmap.md` — Marked Phase 05 complete and documented accomplishments.
- `ARCHITECTURE.md` — Documented modular CLI architecture.

---

## 4. CLI Architecture

In accordance with Section 4 of the project requirements, `root-cli` separates concerns cleanly:

```
crates/root-cli/src/
├── main.rs         # Binary entry point; handles top-level exit codes
├── lib.rs          # Dispatcher, execution pipeline, and production mutation guardrails
├── args.rs         # Argument parsing and clap subcommand validation
├── terminal.rs     # Presentation layer (NO_COLOR, width detection, tables, units)
├── history.rs      # XDG-compliant state persistence (last_scan.json)
├── status.rs       # Concise system overview command handler
├── scan.rs         # Development artifact scanner handler
├── discover.rs     # AI coding agent and tool footprint discovery handler
├── inspect.rs      # Subsystem inspection (memory, processes, storage, transactions)
├── explain.rs      # Explainability engine detailing provenance and Guardian policies
├── report.rs       # Comprehensive diagnostic and audit report generator
├── doctor.rs       # Platform capability auditor
└── interactive.rs  # Read-only interactive terminal navigation browser
```

Business logic, classification rules, and security policies remain strictly encapsulated in `root-core`, `root-platform`, and `root-guardian`.

---

## 5. Implemented Commands

| Command | Purpose | Supported Options |
|:---|:---|:---|
| `root --help` / `--version` | Display usage and crate version | Standard clap flags |
| `root doctor` | Audit kernel interfaces, capabilities, and XDG paths | Standard |
| `root status` | Concise system overview and scan activity | `--json` |
| `root scan` | Audit development resources (dry-run simulation) | `--path <path>`, `--dry-run`, `--json`, `--interactive` |
| `root discover` | Discover agent and development tool artifacts | `--path <path>`, `--agents`, `--tools`, `--agent <name>`, `--tool <name>`, `--json`, `--interactive` |
| `root inspect memory` | Inspect RAM, swap accounting, and kernel PSI pressure | `--json` |
| `root inspect processes` | Inspect running processes via `/proc` with privacy | `--user-only`, `--json` |
| `root inspect storage` | Inspect filesystem capacity (`statvfs`) and directory allocations | `--path <path>`, `--json` |
| `root inspect transactions` | Inspect synthetic recovery journals and state transitions | `--journal-path <path>`, `--json` |
| `root explain <id>` | Detail observed facts, matched rule, uncertainty, and Guardian policy | `--json` |
| `root report` | Consolidated diagnostic and resource audit report | `--path <path>`, `--json` |

---

## 6. Terminal Design Decisions

1. **NO_COLOR Standard**:
   The CLI strictly adheres to `<https://no-color.org/>`. When the `NO_COLOR` environment variable is present, ANSI escape codes are omitted. Color is also automatically disabled if standard output is piped to a file or non-TTY program (`!is_terminal()`).
2. **Terminal Width Handling**:
   The terminal formatter inspects `COLUMNS` and calls Linux POSIX `ioctl(STDOUT_FILENO, TIOCGWINSZ)`. In narrow windows or when table columns exceed width, paths are middle-truncated (`truncate_middle`) to guarantee readable output without line-wrapping glitches.
3. **Typography and Numbers**:
   Byte amounts are converted into human-readable binary units (B, KiB, MiB, GiB, TiB) with stable decimal precision and right-alignment.
4. **Zero Emojis Invariant**:
   Maintained across all output text, error messages, and table badges. Clear typographic badges (`[TIER 1: PROTECTED]`, `[TIER 2: CONFIRM]`, `[TIER 3: TRANSIENT]`, `[TIER 4: RECOVERABLE]`) are used instead of decorative Unicode symbols.

---

## 7. JSON Output Behavior

All inspection commands implement `--json`:
- JSON is output directly to `stdout`.
- Diagnostic messages and warnings are directed to `stderr`.
- Output is deterministic and machine-readable.
- Schemas strictly exclude confidential file contents, conversation transcripts, API credentials, or unredacted process command lines.

---

## 8. Explainability Features

`root explain <resource-id>` provides full transparency into Root's reasoning:
1. **Target Identification**: Associates the identifier with an official toolchain or agent.
2. **Rule Provenance**: Displays the matched rule ID, version, pattern description, and nominal path base.
3. **Observed Facts**: Real physical allocation, inode, permissions, and ownership from `stat`/`statx`.
4. **Lifecycle Uncertainty**: Explicitly details what Root cannot guarantee (e.g. active background sessions, parent project status) and why a classification is not proof of deletion safety.
5. **Guardian Invariants**: Evaluates `GuardianPolicy` to explain why destructive operations (`Quarantine`, `Prune`, `Delete`) are permitted or rejected.

---

## 9. Security Review Findings (Including Phase 04 Follow-Up)

As required by Section 13, the Phase 04 transaction mechanisms were reviewed and augmented with automated adversarial security follow-up tests:
1. **Sandbox Containment**: Verified that relative traversal sequences (`..`) escaping the canonical sandbox root are rejected.
2. **Directory Replacement Races**: Verified that replacing an authorized target with a symlink right before transaction execution is caught and rejected by pre-mutation TOCTOU revalidation.
3. **Journal Durability**: Verified that multiple sequential journal records are flushed with `sync_data()`, preserving chronological order and valid SHA-256 digests.
4. **Recovery Ordering**: Verified that interrupted transactions (`Prepared` or `Quarantined`) are detected across re-scans.
5. **SHA-256 Edge Cases**: Tested zero-byte files, exact 64-byte blocks, 65-byte blocks (multi-chunk padding), and 128 KiB binary streams.
6. **Production Mutation Guardrails**: Verified that attempts to invoke mutation commands (`root clean`, `root quarantine`, `root restore`, `root delete`, `root prune`) in the production CLI are unconditionally blocked with a typed `PolicyViolation`.

---

## 10. Test Results

### Automated Test Suite Execution
```
cargo test --workspace
```

| Crate / Integration Test Suite | Test Count | Result |
|:---|:---:|:---:|
| `root-cli` unit tests | 0 | PASSED |
| `root-cli` integration tests (`tests/cli_tests.rs`) | 20 | **20 PASSED** |
| `root-core` unit tests (`src/fixtures/synthetic.rs`) | 1 | **1 PASSED** |
| `root-core` discovery tests (`tests/discovery_tests.rs`) | 7 | **7 PASSED** |
| `root-core` security tests (`tests/security_tests.rs`) | 8 | **8 PASSED** |
| `root-guardian` unit tests (`src/crypto.rs`, `policy.rs`, `transaction.rs`) | 7 | **7 PASSED** |
| `root-guardian` security follow-up tests (`tests/guardian_security_followup_tests.rs`) | 6 | **6 PASSED** |
| `root-guardian` transaction tests (`tests/guardian_transaction_tests.rs`) | 16 | **16 PASSED** |
| `root-platform` platform tests (`tests/platform_engine_tests.rs`) | 12 | **12 PASSED** |
| **Total Workspace Test Suite** | **77** | **77 PASSED, 0 FAILED** |

### Linter & Style Checks
- `cargo fmt --check`: **PASSED** (zero formatting diffs)
- `cargo clippy --workspace --all-targets -- -D warnings`: **PASSED** (0 warnings)
- `cargo doc --workspace --no-deps`: **PASSED** (0 warnings)
- Python Invariant Verification: **PASSED** (zero decorative emojis; `AGENTS.md` strictly untracked)

---

## 11. Performance Observations

1. **Startup Latency**: `root status`, `root inspect memory`, and `root doctor` execute in under 15ms by querying `/proc` and `statvfs` directly without traversing the disk.
2. **Bounded Traversal**: `root scan` and `root discover` enforce strict entry limits, depth limits, and timeout cutoffs (default 15–30s), ensuring bounded memory and CPU usage.
3. **Zero Background Daemons**: Root operates completely on-demand without background workers or daemons.

---

## 12. Known Limitations

1. **Read-Only Production CLI**: Production mutation operations remain disabled by design. Quarantine and restoration mechanics are isolated to synthetic test fixtures.
2. **Statvfs Granularity**: Filesystem capacity reported by `statvfs` represents the enclosing mount point; disk allocation breakdowns in subdirectories represent bounded traversals.
3. **Interactive Browser Environment**: Interactive navigation requires an interactive TTY session (`is_terminal()`); non-interactive pipes fall back to standard text or JSON reports.

---

## 13. Phase 06 Readiness Assessment

Phase 05 satisfies all functional, architectural, and security objectives for the terminal user experience.

The system is now ready for **Phase 06: Scheduled Inspections (Mode B)**:
- Background inspection timer and service (`root-inspect.timer`, `root-inspect.service`).
- Non-intrusive desktop notification dispatch via D-Bus (`org.freedesktop.Notifications`).
- Scheduled management commands (`root schedule enable`, `root schedule disable`, `root schedule status`).
- Enforcement that scheduled inspections remain strictly read-only.
