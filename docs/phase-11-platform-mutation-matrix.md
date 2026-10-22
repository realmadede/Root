# Root — Phase 11 Platform Mutation Readiness Matrix
## Operating-System Capabilities, Primitives, and Mutation Feasibility

> [!IMPORTANT]
> **GOVERNANCE INVARIANT: COMPILE-TIME MUTATION ISOLATION**  
> In Phase 11, production mutation is disabled on all operating systems. Fixture-level mutation testing is enabled exclusively on Linux within isolated synthetic test fixtures. Mutation APIs remain strictly absent from non-Linux builds at compile time (`#[cfg(target_os = "linux")]`).

---

## 1. Cross-Platform Mutation Capability Matrix

| Mutation Security Capability | Linux (Reference) | macOS (Darwin) | Windows (Win32 / NTFS) |
|---|---|---|---|
| **Resource Identity Verification** | **Verified**<br>`(st_dev, st_ino)` via `lstat` | **Partially Verified**<br>`(st_dev, st_ino)` via `lstat`<br>(APFS clones share extents) | **Verified**<br>32-bit Volume Serial + 128-bit `FILE_ID_INFO` |
| **Race-Resistant Traversal** | **Verified**<br>`openat2` (`RESOLVE_BENEATH`), `O_NOFOLLOW` | **Partially Verified**<br>`openat` descriptor-relative, `O_NOFOLLOW` | **Partially Verified**<br>`CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` |
| **Atomic No-Replace Relocation** | **Verified**<br>`SYS_renameat2` with `RENAME_NOREPLACE` | **Partially Verified**<br>`renamex_np(..., RENAME_EXCL)` (Darwin 10.12+) | **Partially Verified**<br>`MoveFileExW` (`MOVEFILE_FAIL_IF_EXISTS`) |
| **Same-Filesystem Quarantine Feasibility** | **Verified**<br>Same-device quarantine verified via Level 1 fixtures | **Not Tested**<br>APFS container staging feasible; not verified | **Not Tested**<br>NTFS volume staging feasible; not verified |
| **Restoration Feasibility** | **Verified**<br>Conflict-aware atomic rollback verified | **Not Tested**<br>Atomic rollback feasible via `renamex_np` | **Not Tested**<br>Atomic rollback feasible via `MoveFileExW` |
| **Recovery Journal Durability** | **Verified**<br>Append-only JSONL with `file.sync_data()` | **Partially Verified**<br>`fcntl(F_FULLFSYNC)` required for APFS | **Partially Verified**<br>`FlushFileBuffers` required for NTFS |
| **File Metadata Preservation** | **Verified**<br>POSIX mode bits, timestamps, UID/GID | **Partially Verified**<br>BSD flags and ACLs require Darwin xattr APIs | **Unsupported**<br>POSIX permissions do not exist on Windows |
| **Hard-Link Handling** | **Verified**<br>`st_nlink > 1` detection & pnpm protection | **Verified**<br>`st_nlink > 1` detection supported | **Partially Verified**<br>`nNumberOfLinks` from `BY_HANDLE_FILE_INFORMATION` |
| **Sparse-File Handling** | **Verified**<br>`st_blocks * 512` vs apparent length | **Partially Verified**<br>`st_blocks` reflects APFS extent sharing | **Partially Verified**<br>`FILE_ATTRIBUTE_SPARSE_FILE` detection |
| **Crash Recovery Guarantees** | **Verified**<br>Idempotent journal replay verified | **Not Tested**<br>Requires live crash injection on APFS | **Not Tested**<br>Requires live crash injection on NTFS |
| **Production Mutation Readiness** | **PROHIBITED**<br>(Gated until Phase 12) | **UNSUPPORTED**<br>(Compile-time disabled) | **UNSUPPORTED**<br>(Compile-time disabled) |

---

## 2. Platform Primitives Detailed Evaluation

### Linux (Reference Implementation)
- **Strengths**: Native `renameat2(2)` with `RENAME_NOREPLACE` guarantees true atomic same-filesystem moves without race conditions. Descriptor-relative `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` prevents path resolution jail escapes. Linux 5.4+ `pidfd_open` eliminates PID reuse races.
- **Limitations**: Cross-filesystem moves (`EXDEV`) cannot be atomic; Root strictly rejects cross-device operations instead of falling back to non-atomic copy-and-delete.
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
