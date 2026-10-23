# Root — Phase 11 Platform Mutation Readiness Matrix
## Operating-System Capabilities, Primitives, and Mutation Feasibility

> [!IMPORTANT]
> **GOVERNANCE INVARIANT: COMPILE-TIME MUTATION ISOLATION**  
> In Phase 11, production mutation is disabled on all operating systems. Fixture-level mutation testing is enabled exclusively on Linux within isolated synthetic test fixtures. Mutation APIs remain strictly absent from non-Linux builds at compile time (`#[cfg(target_os = "linux")]`).

---

## 1. Cross-Platform Mutation Capability Matrix

| Mutation Security Capability | Linux (Reference) | macOS (Darwin) | Windows (Win32 / NTFS) |
|---|---|---|---|
| **Resource Identity Verification** | **Verified**<br>`(st_dev, st_ino)` via `lstat` | **Not Implemented**<br>Mutation compiled out<br>(Inspection uses `lstat`) | **Not Implemented**<br>Mutation compiled out<br>(Inspection uses volume ID + path) |
| **Race-Resistant Traversal** | **Mitigated (Path-Based)**<br>Symlink non-follow, depth bounds, root checks (`openat2` capability probed) | **Mitigated (Path-Based)**<br>Symlink non-follow, depth bounds (Inspection only) | **Mitigated (Path-Based)**<br>Reparse point non-follow, depth bounds (Inspection only) |
| **Atomic No-Replace Relocation** | **Verified in Fixtures**<br>`SYS_renameat2` with `RENAME_NOREPLACE` via `AT_FDCWD` | **Not Implemented**<br>Mutation compiled out | **Not Implemented**<br>Mutation compiled out |
| **Same-Filesystem Quarantine Feasibility** | **Verified in Fixtures**<br>Same-device quarantine verified via Level 1 fixtures | **Not Implemented**<br>Mutation compiled out | **Not Implemented**<br>Mutation compiled out |
| **Restoration Feasibility** | **Verified in Fixtures**<br>Conflict-aware atomic rollback verified | **Not Implemented**<br>Mutation compiled out | **Not Implemented**<br>Mutation compiled out |
| **Recovery Journal Durability** | **Verified in Fixtures**<br>Append-only JSONL with `file.sync_all()` | **Not Implemented**<br>Mutation compiled out | **Not Implemented**<br>Mutation compiled out |
| **File Metadata Preservation** | **Verified in Fixtures**<br>POSIX mode bits, timestamps, UID/GID | **Not Implemented**<br>Mutation compiled out | **Not Implemented**<br>Mutation compiled out |
| **Hard-Link Handling** | **Verified in Fixtures**<br>`st_nlink > 1` default rejection & explicit consent | **Not Implemented**<br>Mutation compiled out | **Not Implemented**<br>Mutation compiled out |
| **Sparse-File Handling** | **Verified in Fixtures**<br>`st_blocks * 512` vs apparent length | **Not Implemented**<br>Mutation compiled out | **Not Implemented**<br>Mutation compiled out |
| **Crash Recovery Guarantees** | **Verified in Fixtures**<br>Idempotent journal replay verified | **Not Implemented**<br>Mutation compiled out | **Not Implemented**<br>Mutation compiled out |
| **Production Mutation Readiness** | **PROHIBITED**<br>(Gated until Phase 12) | **UNSUPPORTED**<br>(Compile-time disabled) | **UNSUPPORTED**<br>(Compile-time disabled) |

---

## 2. Platform Primitives Detailed Evaluation

### Linux (Reference Implementation)
- **Strengths**: Native `renameat2(2)` with `RENAME_NOREPLACE` guarantees atomic same-filesystem moves without overwriting destinations. Linux 5.4+ `pidfd_open` eliminates PID reuse races. `openat2` capability is probed empirically.
- **Limitations**: Cross-filesystem moves (`EXDEV`) cannot be atomic; Root strictly rejects cross-device operations instead of falling back to non-atomic copy-and-delete. Path-based `renameat2(AT_FDCWD, ...)` retains a sub-millisecond race window for parent directory swaps after `revalidate_full`.
- **Status in Phase 11**: Fully exercised in Level 1 synthetic fixture tests; production mutation remains permanently disabled.

### macOS (Darwin)
- **Strengths**: `renamex_np` with `RENAME_EXCL` provides atomic rename without overwriting existing files on APFS and HFS+. `libproc` provides BSD start ticks for PID reuse detection.
- **Limitations**: Standard POSIX `fsync` on Darwin does not guarantee physical platter flush on APFS; `fcntl(fd, F_FULLFSYNC)` is required for durable transaction journals. APFS copy-on-write file clones (`clonefile`) share disk extents, making file size accounting non-trivial for storage reclamation.
- **Status in Phase 11**: Inspection only. Mutation code is completely compiled out via `#[cfg(target_os = "linux")]`.

### Windows (Win32 & NTFS)
- **Strengths**: `MoveFileExW` with `MOVEFILE_FAIL_IF_EXISTS` prevents destination overwrites. `FILE_ID_INFO` provides a 128-bit file identifier paired with a 32-bit volume serial number. Toolhelp32 snapshots and 64-bit creation `FILETIME` anchor process identity.
- **Limitations**: POSIX permission bits (`0755`, `0644`) do not exist; Windows uses discretionary access control lists (DACLs). Reparse points and directory junctions require explicit handle flags (`FILE_FLAG_OPEN_REPARSE_POINT`) to avoid following links. Open file handles on Windows can lock files against deletion or renaming unless `FILE_SHARE_DELETE` was specified during creation.
- **Status in Phase 11**: Inspection only. Mutation code is completely compiled out via `#[cfg(target_os = "linux")]`.

---

## 3. Security Boundary Conclusion

No platform is permitted to execute production mutation in Phase 11. Testing is strictly confined to Level 1 synthetic fixtures on Linux. Any future expansion to macOS or Windows mutation in Phase 12 will require platform-specific implementations of the atomic no-replace primitive (`renamex_np` and `MoveFileExW`) and independent sandboxed verification.
