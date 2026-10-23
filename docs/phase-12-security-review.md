# Root — Phase 12 Security Review

This document provides the security audit and invariant verification for Root's production release configuration.

---

## 1. Production Mutation Isolation Boundary

### Non-Negotiable Boundary
Root v1.0 operates strictly in **Read-Only Safety Mode**. No user files, project directories, processes, or system structures can be modified, deleted, quarantined, or terminated in production builds.

### Verification of Potential Mutation Entry Points
- **CLI Commands**: Checked against prohibited mutation keywords (`clean`, `delete`, `quarantine`, `prune`, `restore`, `kill`). CLI rejects any such invocations immediately via `RootError::PolicyViolation`.
- **CLI Flags**: Arguments audited to ensure no command exposes `--clean`, `--delete`, `--quarantine`, or `--prune` flags.
- **GUI Controls**: View models and GTK window callbacks audited. Zero mutation buttons, actions, or IPC channels exist in the desktop application.
- **Background Schedulers**: Scheduler units generate read-only diagnostic invocations (`root scan`, `root status`). Schedulers contain zero mutation logic and are forbidden from importing Guardian mutation engines.
- **Live Monitoring**: Monitor emits read-only filesystem observation events (`Created`, `Modified`, `Deleted`). It cannot trigger reactive cleanup.
- **Experimental Guardian Mechanics**: Sandboxed transaction logic (`TransactionEngine::quarantine`, `RestorationEngine::restore`) remains strictly confined to Level 1 synthetic test fixtures.

---

## 2. Hardening and Least Privilege

1. **Unprivileged Runtime Execution**:
   Root does not execute as `root`, invoke `sudo`, or demand elevated system capabilities. All file operations run with invoking user permissions.
2. **Safe Target Selection**:
   Phase 12 eliminated silent fallbacks to development workspaces (`cwd`) and fabricated synthetic fixtures.
   - `root scan` requires an explicit target path (`--path <DIRECTORY>`).
   - `root discover` audits allowlisted agent locations in `$HOME` or user-specified paths.
   - `root-gui` triggers a native `FileChooserNative` dialog when requesting resource discovery, ensuring that the operator explicitly selects the target workspace.
3. **No Private Content Inspection**:
   Root inspects file metadata (inodes, devices, sizes, permissions, timestamps) and never reads private user documents, conversation histories (`transcript.jsonl`), encryption keys, or API credentials.
4. **Offline and Local-Only Guarantee**:
   Root contains zero cloud AI dependencies, analytics tracking, or external network calls. It operates 100% offline.
5. **Path and Symlink Defense**:
   All filesystem traversals enforce defensive depth bounds (max 16–64), entry limits (max 50,000–250,000), cross-device boundary checks, and unconditional refusal to follow symbolic links.

---

## 3. Package Security & Integrity Audit

- **Debian Package Ownership**: Built with `dpkg-deb --root-owner-group`, ensuring all installed system files are owned by `root:root` with standard POSIX permissions (`0755` for executables, `0644` for data).
- **Package Lifecycle Safety**: Maintainer scripts (`postinst`, `postrm`) execute only standard desktop and icon cache updates (`update-desktop-database`, `gtk-update-icon-cache`). They contain zero user file deletion logic.
- **Cryptographic Checksums**: Distributable packages are hashed using streaming SHA-256 and published in a `SHA256SUMS` manifest.
- **Continuous Assurance**: Script `.github/scripts/check_invariants.py` enforces 11 mandatory repository invariants across every commit.
