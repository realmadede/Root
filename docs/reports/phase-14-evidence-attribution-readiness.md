# Phase 14 Completion Report — Evidence Quality, Resource Attribution, and Maintenance Readiness

## 1. Executive Summary

Phase 14 delivers critical hardening to Root's evidence representation, process correlation mechanics, and storage accounting integrity, while establishing a formal, defensible contract for future user-authorized maintenance capabilities.

Root is a local-first, deterministic Linux system utility engineered to inspect development environments and agentic coding toolchains. Following the read-only hardening completed in Phase 13, Phase 14 addresses fundamental inspection accuracy questions: distinguishing directly observed activity from indirect inference, eliminating false-positive process attribution caused by generic tool runtimes, providing conservative and mathematically sound candidate reclaimable storage estimates, and codifying the strict preconditions required before any mutating maintenance operations can ever be authorized.

In accordance with strict project governance, **Root remains strictly read-only in production builds**. All mutating actions—including cleanup, quarantine, restoration, pruning, permanent deletion, process termination, and automatic remediation—remain permanently disabled.

All Phase 14 hardening objectives have been completed, verified against native synthetic fixtures, and validated across the full test suite and Continuous Assurance security invariants.

---

## 2. Starting Baseline & Release Governance

- **Repository**: `realmadede/Root`
- **Starting Git Commit**: `df4f6ce5e96f6af70ce24d829a6fcc44aaef4d25`
- **Target Branch**: `main`
- **Release Version**: `0.1.0-rc.1` (Preserved intact; untagged and unpublished)
- **Safety Boundary**: Production Read-Only (Inspection and Attribution only; Mutation permanently disabled)
- **Confidentiality**: Zero private files tracked; `AGENTS.md` strictly excluded from commits and reports
- **Emoji Prohibition**: Zero decorative Unicode emojis in source code, comments, CLI strings, documentation, or test suites

---

## 3. Audit Traceability Matrix

The following matrix documents the disposition of audit gaps (GAP-01 through GAP-10) originally identified in `docs/research/root-comprehensive-product-audit.md`, evaluated using explicit, verified classification statuses:

| Gap ID | Audit Description | Severity / Priority | Explicit Status | Supporting Evidence & Resolution |
| :--- | :--- | :--- | :--- | :--- |
| **GAP-01** | Rule Ordering Shadowing (`antigravity-state` vs `presence`, `node-modules` vs `.vite`) | Critical / P0 | **Implemented and verified** | Resolved in `RuleRegistry::all_rules()` (`crates/root-core/src/discovery/rules.rs`); verified in `discovery_tests.rs::test_phase13_rule_precedence_and_credential_protection`. |
| **GAP-02** | Broad Token Cache Matching (`cargo-cache`, `npm-cache` exposing secrets) | Critical / P0 | **Implemented and verified** | Resolved by narrowing match paths and adding explicit credential rules in `RuleRegistry`; verified in `discovery_tests.rs`. |
| **GAP-03** | `root scan` Naive Classifier (Bypassed `RuleRegistry`, divergent logic) | High / P1 | **Implemented and verified** | Unified `crates/root-cli/src/scan.rs` with `RuleRegistry::match_path`; added multi-link boundary detection and conservative reclaimable estimates; verified in `cli_tests.rs::test_21` and `test_22`. |
| **GAP-04** | Missing GUI Interactive Controls (Search, filter, tier dropdowns) | High / P1 | **Implemented and verified** | Implemented filter/search state in `crates/root-gui/src/view_model/resources.rs` and wired widgets in `crates/root-gui/src/gtk/views/resources.rs`; verified in `gui_view_model_tests.rs::test_04`, `test_05`, `test_27`, and `test_31`. |
| **GAP-05** | Disconnected GUI Activity Tab (Unconnected to Mode C inotify) | Medium / P1 | **Partially implemented** | Informative status disclosure implemented explaining CLI-managed monitoring; live inotify event streaming into GTK list is deferred. |
| **GAP-06** | Disconnected GUI Schedule Tab (Cannot edit timer units) | Medium / P1 | **Partially implemented** | Read-only inspection of systemd timer status and run history implemented and verified; interactive enable/disable and timer configuration from GUI is deferred. |
| **GAP-07** | Git Working-Tree Invariant (FR-07: Refuse action on dirty Git tree) | High / P1 | **Documented only** | Codified as Stage D requirement in `docs/maintenance-safety-contract.md`; no Git porcelain check exists in current code. |
| **GAP-08** | Missing `root undo` CLI Command (Transaction rollback CLI entry) | Medium / P2 | **Deferred** | Rollback engine exists in `root-guardian` test fixtures; exposing `root undo` CLI entry is deferred pending owner authorization of maintenance capabilities. |
| **GAP-09** | CPU Utilization Uncalculated (Missing from `/proc/[pid]/stat`) | Low / P2 | **Deferred** | Observability enhancement; private memory (PSS/USS) remains primary resource accounting metric. |
| **GAP-10** | Uninstallation Service Mismatch (`root-audit` vs `root-inspect`) | Low / P3 | **Implemented and verified** | Corrected unit names in `docs/uninstallation.md`; verified matching systemd template units. |

---

## 4. Evidence Quality and Confidence

### 4.1. Direct Observation vs. Inferred Activity
Root now explicitly differentiates between what it directly observes and what it infers:
- **`ProcessAttribution::Direct`**: Directly observed when a running process's command-line arguments explicitly reference the resource path or its canonical directory boundary.
- **`ProcessAttribution::Inferred`**: Inferred when an active process binary matches a specialized tool (e.g., `cargo`, `rustc`, `aider`), but specific command-line arguments cannot be correlated to the path.
- **`ProcessAttribution::Inconclusive`**: Reported when generic runtime processes (such as `python` or `node`) are running on the system without command-line path correlation. Root refuses to assume that a generic runtime is actively modifying an unrelated resource.
- **`ProcessAttribution::Unavailable`**: Reported when process enumeration or inspection is restricted by platform permissions (e.g., unprivileged user without ptrace permissions) or OS capabilities.
- **`ProcessAttribution::None`**: Confirmed absence of matching active processes.

### 4.2. Non-Degradation of Unknown and Protected Resources
- Unknown resources (`ResourceCategory::Unknown` or matched by `default-unknown`) are preserved as `LifecycleState::Unknown` with `ConfidenceLevel::LowConfidence`. File age alone never causes an unrecognized resource to be classified as `DormantTransient`.
- `StrictlyProtected` resources (credentials, private keys, system configurations, active session locks) unconditionally preserve their `Persistent` lifecycle state regardless of file age or process correlation status.

---

## 5. Resource and Process Attribution

### 5.1. Generic Runtime Isolation
Prior to Phase 14, if a developer ran a background `python` or `node` process, all Python or Node project files on the system could be marked as `LifecycleState::Active`.

Phase 14 resolves this vulnerability via `is_generic_runtime()` in `crates/root-core/src/discovery/classifier.rs`:
- Targets `TargetId::NodeNpm` and `TargetId::Python` are classified as generic runtimes.
- If a running process matches a generic runtime by name, but its command-line arguments do not explicitly match the resource path, the attribution evaluates to `ProcessAttribution::Inconclusive` and the lifecycle state evaluates to `LifecycleState::Unknown`.
- False-positive active claims are eliminated.

### 5.2. Boundary-Aware Argument Parsing
Path matching within process command lines (`match_path_in_arg`) enforces boundary safety:
- Tokens such as `[REDACTED]` are ignored.
- Flag arguments (e.g., `--target`, `--cache-dir`) are parsed to inspect their values rather than matching flag names.
- Exact boundary matching ensures that `/home/user/project` does not falsely match `/home/user/project_other`.
- Symbolic normalization strips trailing slashes and resolves current-directory relative references.

---

## 6. Storage Accounting and Estimate Integrity

### 6.1. Multi-Link Files and Inode Deduping
When inspecting hard-linked files:
- If a hard link shares an inode with a file outside the scan scope (`observed_count < link_count`), unlinking the discovered path will free zero disk blocks. Root assigns `0` candidate reclaimable bytes to this entry.
- If all hard links referencing an inode reside within the scan scope (`observed_count == link_count`), the physical allocated blocks are counted exactly once across the inode group. Subsequent references contribute `0` reclaimable bytes.

### 6.2. Sparse File Allocation
- `StorageMeasurement::from_raw` now correctly recognizes hollow sparse files where `bytes > allocated_bytes` even if `allocated_bytes == 0`.
- Candidate reclaimable byte calculations strictly use physical disk allocation (`allocated_bytes`), preventing multi-gigabyte logical estimates for hollow sparse files.

### 6.3. Directory and Symlink Block Exclusion
- Directory dentry blocks (`FileType::Directory`) and symlink pointers (`FileType::Symlink`) are excluded from candidate reclaimable storage estimates to prevent double-counting child entries or inflating estimates with filesystem metadata tables.

### 6.4. Storage Metric Taxonomy
Root enforces a strict separation across five storage metrics:
1. **Logical File Size**: Apparent byte stream length.
2. **Apparent Candidate Bytes**: Sum of logical stream lengths.
3. **Unique Allocated Storage**: Physical blocks allocated on disk (`allocated_bytes`), deduped by inode.
4. **Bytes Moved to Quarantine**: Storage relocated to staging. **This releases zero storage blocks to the host filesystem.**
5. **Storage Actually Released**: Storage reclaimed on disk. This only occurs after permanent purge (`unlink`), which is permanently prohibited in production builds.

---

## 7. Maintenance Safety Contract

Phase 14 establishes the foundational requirements for future user-authorized maintenance in `docs/maintenance-safety-contract.md`. The contract specifies:
1. **Eight Foundational Invariants**: Local authority only, least privilege, zero telemetry, non-bypassable Guardian gates, quarantine-first reversibility, TOCTOU race immunity via `openat2` descriptor pinning, atomic auditability, and deterministic explainability.
2. **Seven Operational Stages (A through G)**:
   - Stage A: Read-Only Discovery and Evidence Collection.
   - Stage B: Policy Evaluation and Recommendation Formulation.
   - Stage C: Explicit Human Authorization (Single-use cryptographic nonce with 60s TTL).
   - Stage D: Pre-Operation Verification (Hard link checks, open file handles via `/proc/[pid]/fd`, dirty Git working-tree check via `git status --porcelain`).
   - Stage E: Safe Execution via Atomic Relocation (`SYS_renameat2` with `RENAME_NOREPLACE` within same device boundary).
   - Stage F: Reversibility and Journaling (Append-only JSONL journal, checksummed payloads, `root undo` rollback capability).
   - Stage G: Audit Logging and Reporting.
3. **Fail-Safe Deny-by-Default Matrix**: Explicit rejection codes distinguishing code-enforced checks from future requirements.

---

## 8. CLI and GUI Presentation

### 8.1. CLI Detail Inspection (`root scan -i` & `root discover -i`)
- Detail modal now explicitly displays:
  - `Process Attribution`: `Direct (Command-line path match)`, `Inferred (Tool process active)`, `Inconclusive (Generic runtime active without path match)`, `Unavailable (Restricted)`, or `None`.
  - `Hard Link Count`: Explicit count of filesystem links to explain non-zero or zero unique block estimates.

### 8.2. GUI Resource View & Overview
- `crates/root-gui/src/view_model/resources.rs`: Added `lifecycle_attribution` field to `ResourceItemViewModel`.
- `crates/root-gui/src/gtk/views/resources.rs`: Displays attribution badges (`Direct`, `Inferred`, `Inconclusive`) directly in row subtitles.
- `crates/root-gui/src/worker/mod.rs`: Passes conservative `report.summary.reclaimable_bytes_estimate` to overview `potential_transient_bytes` rather than naive logical sums.

---

## 9. Regression Test Suite & Count Reconciliation

### 9.1. Workspace Test Breakdown (`cargo test --workspace --all-targets`)
The workspace regression run executes 17 test suites across the five crates. Four unit test suites contain zero tests, and 13 suites contain active assertions:

| Crate | Binary / Target | Tests Passed | Tests Failed | Tests Ignored | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `root-cli` | `unittests (src/lib.rs)` | 0 | 0 | 0 | Header / dispatch only |
| `root-cli` | `unittests (src/main.rs)` | 0 | 0 | 0 | Entrypoint wrapper |
| `root-cli` | `tests/cli_tests.rs` | 22 | 0 | 0 | Terminal commands & flags |
| `root-cli` | `tests/monitor_tests.rs` | 25 | 0 | 0 | Mode C inotify engine |
| `root-cli` | `tests/schedule_tests.rs` | 30 | 0 | 0 | Mode B systemd scheduling |
| `root-core` | `unittests (src/lib.rs)` | 12 | 0 | 0 | Core domain models |
| `root-core` | `tests/discovery_tests.rs` | 12 | 0 | 0 | 36 rules & lifecycle |
| `root-core` | `tests/security_tests.rs` | 8 | 0 | 0 | Adversarial fixtures |
| `root-guardian` | `unittests (src/lib.rs)` | 14 | 0 | 0 | Crypto & policy |
| `root-guardian` | `tests/guardian_adversarial_tests.rs` | 32 | 0 | 0 | Security invariants |
| `root-guardian` | `tests/guardian_security_followup_tests.rs` | 12 | 0 | 0 | TOCTOU & boundary tests |
| `root-guardian` | `tests/guardian_transaction_tests.rs` | 18 | 0 | 0 | Transaction engine fixtures |
| `root-gui` | `unittests (src/lib.rs)` | 0 | 0 | 0 | Library exports |
| `root-gui` | `unittests (src/main.rs)` | 0 | 0 | 0 | Desktop entry point |
| `root-gui` | `tests/gui_view_model_tests.rs` | 30 | 0 | 0 | Headless view-models |
| `root-platform` | `unittests (src/lib.rs)` | 36 | 0 | 0 | OS traits & parsing |
| `root-platform` | `tests/platform_engine_tests.rs` | 12 | 0 | 0 | Linux platform engine |
| **Total Default Workspace** | **17 binaries** | **263 passed** | **0 failed** | **0 ignored** | Finished in 5.3s |

### 9.2. GTK GUI Feature Suite (`cargo test --features gtk -p root-gui`)
- `tests/gui_view_model_tests.rs`: **31 passed**; 0 failed.
- **Overlap Explanation**: 30 of these 31 tests are identical to the view-model tests executed in the default workspace run. Exactly 1 test (`test_26_native_gtk_component_construction_and_navigation`) is conditionally compiled under `#[cfg(feature = "gtk")]`.
- **Total Unique Tests**: 263 default workspace tests + 1 GTK-only test = **264 unique tests** (233 non-GUI tests + 31 GUI tests = 264 unique tests).

---

## 10. Quality Gates Summary

| Verification Gate | Command | Result |
| :--- | :--- | :--- |
| Code Formatting | `cargo fmt --check` | **PASS** (Zero formatting discrepancies) |
| Static Compilation | `cargo check --workspace --all-targets --all-features` | **PASS** (Zero compilation errors) |
| Clippy Lints | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **PASS** (Zero warnings) |
| Workspace Regression Tests | `cargo test --workspace --all-targets` | **PASS** (263 passed; 0 failed) |
| GTK Feature Tests | `cargo test --features gtk -p root-gui` | **PASS** (31 passed; 0 failed; 1 unique GTK test; 264 unique tests overall) |
| Documentation Build | `cargo doc --workspace --no-deps` | **PASS** (Zero warnings or broken links) |
| Continuous Assurance Invariants | `python3 .github/scripts/check_invariants.py` | **PASS** (12/12 security invariants verified) |

---

## 11. Security & Safety Review

1. **Production Read-Only Boundary Maintained**:
   - Zero mutation entry points were introduced into the CLI or GUI.
   - `root scan` and `root discover` remain strictly non-destructive.
   - All transaction and quarantine operations remain confined to test fixtures.
2. **Confidentiality & Privacy**:
   - Path argument matching ignores secret tokens (`[REDACTED]`).
   - No file contents, conversation histories, or credentials are read or stored.
3. **Absence of AI Dependencies**:
   - Implementation remains 100% deterministic Rust using standard kernel interfaces.
4. **Supply Chain & Dependencies**:
   - Zero new external dependencies added to `Cargo.toml`.

---

## 12. Files Changed in Phase 14

### Created:
- `docs/maintenance-safety-contract.md` (Formal safety specification)
- `docs/reports/phase-14-evidence-attribution-readiness.md` (This document)

### Modified:
- `crates/root-core/src/discovery/lifecycle.rs` (Added `ProcessAttribution` enum and badges)
- `crates/root-core/src/discovery/classifier.rs` (Generic runtime isolation, boundary-safe arg matching)
- `crates/root-core/src/discovery/engine.rs` (Inode deduping, multi-link boundary detection, conservative reclaimable estimates)
- `crates/root-core/src/discovery/mod.rs` (Exported `ProcessAttribution`)
- `crates/root-core/src/model/measurement.rs` (Sparse detection for 0-block hollow files)
- `crates/root-core/src/lib.rs` (Exported `ProcessAttribution`)
- `crates/root-core/tests/discovery_tests.rs` (Added Phase 14 attribution & storage regression tests)
- `crates/root-guardian/tests/guardian_transaction_tests.rs` (Added tests 17 & 18: expired consent and failed state restoration refusal)
- `crates/root-cli/src/scan.rs` (Hard link accounting, candidate storage labels)
- `crates/root-cli/src/discover.rs` (Estimated candidate storage labels)
- `crates/root-cli/src/interactive.rs` (Display Process Attribution and Hard Link Count in detail modal)
- `crates/root-cli/tests/cli_tests.rs` (Added CLI storage accounting test)
- `crates/root-gui/src/view_model/resources.rs` (Added `lifecycle_attribution` field)
- `crates/root-gui/src/gtk/views/resources.rs` (Render attribution badges in GTK rows)
- `crates/root-gui/src/worker/mod.rs` (Pass conservative reclaimable estimate to overview model)
- `crates/root-gui/tests/gui_view_model_tests.rs` (Added GUI attribution & storage test)

---

## 13. Deferred Work

The following items are intentionally deferred to future authorized phases:
1. **Interactive Quarantine and Rollback CLI (`root undo`)**: Fully specified in `docs/maintenance-safety-contract.md`; deferred until explicit human authorization for maintenance capabilities is granted.
2. **Git Working-Tree Validation (`git status --porcelain`)**: Specified in Stage D of the Maintenance Safety Contract; deferred until mutating operations are implemented.
3. **Open File Descriptor Checks via `/proc/[pid]/fd`**: Specified in Stage D of the Maintenance Safety Contract; deferred until mutating operations are implemented.
4. **Process CPU Utilization Calculation**: Observability enhancement (GAP-09); deferred in favor of core memory and storage metrics.
5. **Interactive GUI Maintenance and Live Activity Streaming**: Controls for Mode C event streams and Mode B scheduling in GUI deferred to future desktop integration work.

---

## 14. Production Safety Confirmation

It is formally confirmed that Root remains 100% read-only in production:
- No file or directory can be deleted, renamed, quarantined, or modified by production commands.
- No running process can be signaled or terminated.
- No system service can be altered.
- All mutating engines in `root-guardian` are disabled in production builds and reject requests with `RootError::PolicyViolation`.

---

## 15. Release Governance

- Git tags: **Untouched** (No tags created or moved).
- Remote repository: **Unpushed** (No branch or commit pushed).
- Release version: **0.1.0-rc.1** (Preserved without modification).
- Private files: **`AGENTS.md` strictly excluded** from commits, diffs, and reports.

---

## 16. Final Verdict

# Final Phase 14 Verdict: **PASS**

Phase 14 has successfully resolved all verified evidence quality, process attribution, and storage estimation risks. The Maintenance Safety Contract provides an unyielding architectural foundation for any future user-authorized maintenance capabilities. Root `0.1.0-rc.1` is hardened, verifiable, and secure.

---

## 17. Recommended Next Phase

**Phase 15: Cross-Platform Parity and Controlled Maintenance Prototype**
- Focus: macOS and Windows event engine parity (FSEvents, ReadDirectoryChangesW), alongside the first prototype implementation of the Maintenance Safety Contract under strict synthetic fixture environments.
- Prerequisite: Explicit human authorization before implementing any mutating capabilities.
