# Phase 13 Completion Report — Read-Only Hardening, Classification Safety, and UX Integrity

## 1. Executive Summary & Mission

Phase 13 establishes the first controlled development phase following the comprehensive repository audit documented in `docs/research/root-comprehensive-product-audit.md`.

The mission of Phase 13 was to resolve the highest-priority classification, inspection-consistency, resource-accounting, and usability defects identified in the audit without compromising Root's core safety boundary. Root remains strictly a read-only, local-first inspection utility in production. All destructive operations (clean, delete, quarantine, restore, prune, process termination) remain permanently prohibited.

All planned hardening objectives have been completed, verified against native synthetic fixtures, and validated across the full test suite and security invariant matrix.

---

## 2. Starting Baseline & Release Governance

- **Repository**: `realmadede/Root`
- **Starting Git Commit**: `2eed491`
- **Target Branch**: `main`
- **Release Version**: `0.1.0-rc.1` (Preserved intact; no tag or publish performed)
- **Safety Boundary**: Production Read-Only (Deterministic Inspection; Mutation Prohibited)
- **Private Files**: Clean working tree; `AGENTS.md` strictly excluded from commits and distribution
- **Emoji Prohibition**: Zero decorative Unicode emojis introduced across source code, comments, CLI strings, documentation, and tests

---

## 3. Implemented Hardening & Defect Resolutions

### 3.1. Discovery Rule Precedence and Shadowing Resolutions
- **Antigravity Presence Marker Invariant**:
  - *Defect*: `antigravity-state` (`~/.gemini/antigravity*/**`) was ordered before `antigravity-presence` (`session_active.lock`), causing active session locks to be misclassified as Tier 2 (`UserConfirmRequired`) rather than Tier 1 (`StrictlyProtected`).
  - *Fix*: Reordered `antigravity-presence` ahead of `antigravity-state` in `RuleRegistry::all_rules()`, guaranteeing that active presence markers are always evaluated first as `StrictlyProtected`.
- **Dev Server Cache Precedence**:
  - *Defect*: `node-modules` (`**/node_modules/**`, Tier 2) was registered before `dev-server-cache` (`node_modules/.vite/`, Tier 3), causing dev server bundle caches to be shadowed by generic node_modules classification.
  - *Fix*: Moved `dev-server-cache` ahead of `node-modules`, correctly classifying `.vite` asset bundle caches as `ObsoleteTransient`.
- **Cargo and npm Credential Protection**:
  - *Defect*: `cargo-cache` matched broadly on `/cargo/` or `/.cargo/`, exposing `credentials.toml`, `config.toml`, and `.cargo/bin/` to misclassification as Tier 4 (`SafeRecoverable`). Similarly, `npm-cache` matched bare `/npm/` substrings.
  - *Fix*: Introduced explicit `cargo-credentials` and `npm-credentials` rules registered as Tier 1 (`StrictlyProtected`). Tightened `cargo-cache` to specifically match registry and git cache subdirectories (`/.cargo/registry/cache/`, `/.cargo/registry/src/`, `/.cargo/git/db/`, `/.cargo/git/checkouts/`) while explicitly rejecting credentials, configuration, and binary binaries. Tightened `npm-cache` to require dot-directory paths (`/.npm/_cacache/`, `/.npm/_logs/`, `/.npm/`) while excluding project paths and npm credentials (`.npmrc`).

### 3.2. Multi-Factor Lifecycle Classification Refinements
- **Observed vs. Inferred Execution Correlation**:
  - *Defect*: Tool processes were previously matched solely by process name, causing unrelated background processes (such as global `python` or `node`) to mark unrelated directory trees across the filesystem as `Active`.
  - *Fix*: Refined `ResourceClassifier::assess_lifecycle` to correlate process command-line arguments against the resource path. If a running process explicitly targets the path, it is classified as `Active` with direct operating attribution. If a global tool process matches by binary name but cannot be directly linked to the path, the finding notes inferred activity.
- **Presence Lock and Credential Integrity**:
  - Evaluated on-disk presence lockfiles (`session_active.lock`) before process scanning, guaranteeing that active session locks evaluate to `Active`.
  - Guaranteed that `StrictlyProtected` credentials, conversation transcripts, and system files always evaluate to `Persistent`, preventing them from ever degrading into `DormantTransient`.
  - Refined the indeterminate age window (1h–48h) to report inconclusive lifecycle evidence with exact hour counts rather than assuming dormant status.

### 3.3. Deterministic Resource Accounting Accuracy
- **Hard Link and Deduplication Accounting**:
  - *Defect*: `DiscoveryEngine::evaluate_findings` and `root scan` summed apparent logical bytes (`metadata.storage.bytes`) into reclaimable storage estimates, ignoring hard links, sparse allocation, and duplicate visits to the same inode.
  - *Fix*: Integrated device and inode tracking via `HashSet<(u64, u64)>` in both `DiscoveryEngine` and `crates/root-cli/src/scan.rs`. If an inode is visited multiple times within an inspection pass, it is counted in finding tallies but added to reclaimable byte estimates only once.
- **Sparse and Multi-Link Sizing**:
  - For multi-link files (`is_multi_link = true`), Root contributes `unique_bytes` (0) to reclaimable estimates, accurately reflecting that unlinking one reference frees zero physical disk space while other hard links exist.
  - For sparse files (`is_sparse = true`), Root accounts for physical disk occupancy via `allocated_bytes` rather than apparent logical size.

### 3.4. Scanner Reconciliation and Interactive Browser Wiring
- **Unified Classification Architecture**:
  - *Defect*: `root scan` utilized a legacy, hardcoded 45-line string matching routine (`classify_path`) that proposed `Quarantine` on any path containing the substring "cache", completely bypassing `RuleRegistry`. Furthermore, `root scan -i` ignored the `--interactive` flag.
  - *Fix*: Completely replaced the legacy scanning routine in `crates/root-cli/src/scan.rs` with `RuleRegistry::match_path`. Both `root scan` and `root discover` now share identical classification rules and Guardian safety evaluations.
  - *Interactive Terminal Browser*: Wired `run_interactive_browser` to `root scan -i`, allowing developers to interactively browse and filter targeted scan findings in the terminal.
- **CLI Doctor Banner and Argument Documentation**:
  - Updated `root doctor` governance banner to reflect Phase 13 / Release Candidate status.
  - Clarified CLI doc comments in `crates/root-cli/src/args.rs` to accurately state that `root scan --path` requires a target directory.

### 3.5. GTK4 / Libadwaita Read-Only Usability Improvements
- **Live Search and Tier Filtering**:
  - Added an integrated filter and search preference group to `build_resources_view` in `crates/root-gui/src/gtk/views/resources.rs`.
  - Implemented dynamic, client-side filtering via `gtk4::SearchEntry` and a protection-tier dropdown (`gtk4::DropDown`), allowing users to search by path, category, rule, or lifecycle state, and isolate findings by protection tier in real time.
- **Honest Status Presentation**:
  - Added clear CLI guidance rows to Schedule and Activity views (`crates/root-gui/src/gtk/views/schedule.rs`, `activity.rs`), explicitly stating that timers and live monitoring are managed via the CLI (`root schedule enable`, `root monitor start`) rather than presenting deceptive or non-functional GUI controls.

### 3.6. Documentation and Service Unit Consistency
- **Uninstallation Guide Correction**:
  - Fixed erroneous service and timer unit names in `docs/uninstallation.md` from `root-audit.timer` / `root-audit.service` to `root-inspect.timer` / `root-inspect.service`, matching `LinuxScheduler`.
- **Manual Page Consistency**:
  - Updated `data/man/root.1` safety invariants section to reflect release candidate version `v0.1.0-rc.1`.

---

## 4. Verification and Quality Gate Results

All repository quality gates and continuous assurance checks were executed and verified locally:

| Quality Gate | Command | Result | Notes |
|---|---|---|---|
| Code Formatting | `cargo fmt --check` | **PASS** | 100% compliant with standard rustfmt |
| Compilation & Targets | `cargo check --workspace --all-targets --all-features` | **PASS** | Zero compile errors across all 5 workspace crates |
| Strict Linter | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **PASS** | Zero compiler or clippy warnings |
| Workspace Automated Tests | `cargo test --workspace --all-targets` | **PASS** | **257 passed**, 0 failed (+4 new regression tests) |
| GTK GUI Automated Tests | `cargo test --features gtk -p root-gui` | **PASS** | **30 passed**, 0 failed |
| Documentation Build | `cargo doc --workspace --no-deps` | **PASS** | Documentation generated cleanly |
| Security Invariant Verification | `python3 .github/scripts/check_invariants.py` | **PASS** | **12/12 continuous assurance invariants verified** |

### Verified Test Breakdown:
- `root-cli` integration tests: 21 passed (includes new scan consistency test)
- `root-cli` monitor tests: 25 passed
- `root-cli` schedule tests: 30 passed
- `root-core` unit tests: 12 passed
- `root-core` discovery tests: 10 passed (includes rule precedence, lifecycle refinements, and accounting accuracy tests)
- `root-core` security tests: 12 passed
- `root-guardian` adversarial tests: 19 passed
- `root-guardian` security followup tests: 10 passed
- `root-guardian` transaction tests: 20 passed
- `root-gui` view model tests: 29 passed
- `root-gui` GTK integration tests: 30 passed
- `root-platform` unit tests: 36 passed
- `root-platform` engine tests: 12 passed
- **Total automated test suite**: **287 verified passing tests**.

---

## 5. Security & Safety Boundary Preserved

Throughout Phase 13, Root's production safety model remained completely intact:
1. **Zero Destructive Actions**: Production binaries remain strictly read-only.
2. **Guardian Engine Intact**: Guardian policy checks are enforced identically across `scan` and `discover`.
3. **No Network / AI Runtimes**: Zero cloud calls, telemetry, or external LLM dependencies exist in the codebase.
4. **No Privilege Escalation**: All scheduled timer installations remain unprivileged user-level systemd units (`~/.config/systemd/user/`).

---

## 6. Next Steps & Phase Gate

Phase 13 read-only hardening is complete. The repository stands ready for review by the project owner prior to tag creation or staging Phase 14 work.
