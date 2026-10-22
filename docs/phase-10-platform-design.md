# Phase 10 — Cross-Platform Engine Design

Status: design for Phase 10 (read-only macOS and Windows adapters). Production mutation stays disabled on every platform. Phase 11 (mutation enablement) and Phase 12 (release) are out of scope.

Verification labels used below follow `AGENTS.md`: **[VERIFIED]** (observed in this repository), **[HYPOTHESIS]**, **[UNKNOWN]**.

## 1. Existing traits and their limits

`crates/root-platform/src/traits.rs` defines five traits: `EnvironmentProvider`, `FilesystemProvider`, `ProcessProvider`, `ResourceAccountant`, and the stub `FilesystemWatcher` (`is_supported` only). [VERIFIED]

Limits found while auditing the tree:

| Area | Linux assumption | Where |
|---|---|---|
| Identity | `(st_dev, st_ino)` as two `u64` | `ResourceLocation`, `ResourceId::from_path_and_inode`, `FilesystemProvider::get_device_id/get_inode`, `DiscoveredEntry` |
| Capabilities | `/proc`, PSI, `smaps_rollup`, cgroups, pidfd, openat2, statx fields; `is_linux`; POSIX `uid/gid` | `PlatformCapabilities`, `root doctor` |
| Memory | `swap_bytes: u64` (unsupported would read as zero) | `MemoryMeasurement` |
| Process | `/proc/[pid]/stat` state letters; `start_time_ticks` in jiffies; `real_uid` | `ProcessIdentity`, `ProcessState` |
| Scheduling | systemd types used directly by the CLI and GUI | `LinuxScheduler`, `SystemdUnitGenerator` |
| Monitoring | inotify types used directly by the CLI | `LinuxMonitorSession`, `InotifyWatcher` |
| Locking | `libc::flock` in `root-cli` | `schedule.rs` |
| Concrete types | `Linux*` types named directly in `root-cli`, `root-gui`, and `root-guardian` | many |
| Paths | Unix pseudo-filesystem prefixes and protected prefixes only | `root-core` schedule/monitor validation, `GuardianPolicy` |
| Build | `root-platform::linux` compiled unconditionally; `root-guardian` mutation engine uses `std::os::unix` and `renameat2` | `lib.rs` files |

## 2. Proposed trait changes

Extend, do not replace. Existing method names and Linux behavior are preserved.

1. `FilesystemProvider::get_file_identity(&self, path) -> Result<FileIdentity>` — new method with a default implementation derived from `get_device_id`/`get_inode` (POSIX kind). Windows overrides it. Needed because a `(u64, u64)` pair cannot express a Windows volume serial plus a 128-bit file id.
2. `Scheduler` (new trait) — the operations the CLI and GUI already perform against `LinuxScheduler`: availability, transactional install, uninstall, enable, disable, active query, next-trigger query, and artifact-path listing. Implemented by `LinuxScheduler` (systemd), `MacScheduler` (launchd), `WindowsScheduler` (Task Scheduler). Needed so `root-cli` stops naming systemd types.
3. `AdvisoryLock` (concrete type, not a trait) — see section 10. One implementation serves all targets because the standard library provides the primitive.
4. `FilesystemWatcher` — extended from the stub to a polling-oriented event-source contract (`start`, `poll`, `active_watches`, `backend_name`, `is_supported`). Needed because the three operating systems deliver events differently and the monitor session must not depend on inotify.
5. `native` module — type aliases (`NativeEnvironment`, `NativeFilesystem`, `NativeProcess`, `NativeAccountant`, `NativeScheduler`, `NativeMonitorSession`) selected by `cfg(target_os)`. Needed so callers compile unchanged on every target.

The mock platform implements all new methods.

## 3. Resource identity model

```
FileIdentity { kind: IdentityKind, volume: u64, object: u128 }
IdentityKind  = PosixDeviceInode | WindowsFileId | Unavailable
```

- Linux [VERIFIED]: `volume = st_dev`, `object = st_ino` (`PosixDeviceInode`). Existing behavior and `ResourceId` strings are unchanged.
- macOS [HYPOTHESIS]: `st_dev` + `st_ino` through `std::os::unix::fs::MetadataExt`, `PosixDeviceInode`. Limits: APFS inode numbers are stable within a volume but `st_dev` is not guaranteed stable across reboots, remounts, or snapshot mounts; clones (`clonefile`) have distinct inodes but share extents; firmlinks present one path on two volumes. Identity is therefore valid only within one observation session and never proves that two paths hold distinct physical data.
- Windows [HYPOTHESIS]: `GetFileInformationByHandleEx(FileIdInfo)` yielding a 64-bit volume serial and a 128-bit file id; fallback to `GetFileInformationByHandle` (32-bit volume serial, 64-bit file index) on filesystems that reject `FileIdInfo`. ReFS uses the full 128 bits; NTFS file ids can be reused after deletion; FAT-family and many network filesystems may report zero or unstable ids. A zero or failed result is reported as `IdentityKind::Unavailable`.

Rules: a path never uniquely identifies a resource; two paths differing only by case are *not* assumed equal (per-directory case sensitivity exists on NTFS and APFS can be case-sensitive); identity is not assumed stable across moves, mounts, replacement, or network filesystems. `ResourceLocation` keeps `device_id`/`inode` (low 64 bits) and gains `identity_kind` (serde default: POSIX) so existing serialized data remains readable.

## 4. Platform capability model

`CapabilityStatus` gains `Unsupported` (the platform has no such feature by design). The full set is:

| State | Meaning |
|---|---|
| `SupportedAndAccessible` | Present and usable by the unprivileged user |
| `PermissionRestricted` | Present but denied |
| `Unavailable` | Expected on this platform but missing on this host |
| `Unsupported` | No equivalent exists on this platform; Root does not invent one |
| `NotTested` | Not probed |

`PlatformCapabilities` gains `platform: PlatformKind` and cross-platform entries: `process_enumeration`, `process_start_time`, `process_rss`, `process_private_memory`, `process_swap`, `system_memory`, `memory_pressure`, `file_identity`, `filesystem_events`, `scheduler`, `file_locking`. Existing Linux fields (`proc_fs`, `proc_pressure_memory`, `proc_smaps_rollup`, `cgroups_v2`, `pidfd`, `openat2`, `statx`, ...) remain and are `Unsupported` off Linux. PSI, PSS, USS, and cgroup reporting on Linux are untouched. `doctor`, `status`, and `report` branch on `platform` and drop the hardcoded phase labels.

## 5. Process identity model

`ProcessIdentity` keeps `pid`, `ppid`, `start_time_ticks`, `name`, `executable`. The tick unit is platform-defined and documented, and is only ever compared for equality against the same platform:

- Linux: clock ticks since boot (field 22 of `/proc/[pid]/stat`) [VERIFIED].
- macOS: `pbi_start_tvsec * 1_000_000 + pbi_start_tvusec` (microseconds since the Unix epoch) from `proc_pidinfo(PROC_PIDTBSDINFO)`.
- Windows: `GetProcessTimes` creation `FILETIME` (100 ns units since 1601).

Identity = `(pid, start_time_ticks)`; a changed start time with the same pid is PID reuse. Process disappearance is not an error: inspection returns `Ok(None)`. Access-restricted processes are skipped, never elevated. Command-line arguments and environments are **not** read on macOS or Windows (`cmdline` is empty); the executable path is the only extra attribute. Windows has no POSIX uid; `real_uid` uses the sentinel `0` and `process_ownership` capability reads `Unsupported`; only processes the user can open without privilege appear. Consumers that filter by owner treat Windows enumeration as already user-scoped.

## 6. Filesystem traversal contract

One platform-neutral engine (`traversal.rs`) runs the loop that existed in `linux/filesystem.rs`: bounded depth, bounded entry count, timeout, deterministic child ordering, cycle detection, volume-boundary check, explicit `is_complete`/`incomplete_reason`. Each platform supplies a `NodeProbe`:

- `probe(path)` returns identity, type, storage measurement, mode, times, and a `is_link_like` flag. It never follows links.
- `is_pseudo(path)` and `refuses_root(path)` implement per-platform scan refusal.

Linux and macOS share the POSIX probe (`lstat`). Windows probes with `CreateFileW` (`FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`, zero data access) so the link itself, never its target, is inspected; any reparse point (symlink, junction, mount point, cloud placeholder) is recorded and **not descended** (`SkipReason::ReparsePointNotFollowed`). Volume boundary uses `FileIdentity.volume`.

Windows specifics: drive-letter, UNC, and verbatim (`\\?\`) paths are classified by pure functions in `root-core`; long paths are handled by prefixing `\\?\` only when needed and never rewriting UNC semantics; sparse files are detected through `FILE_ATTRIBUTE_SPARSE_FILE` and allocated size through `GetCompressedFileSizeW`; hard-link count comes from `nNumberOfLinks`. `ctime` has no Windows equivalent in the standard library; the creation time is substituted and documented.

macOS specifics: APFS clones and snapshots share extents. `st_blocks * 512` is reported as allocated size, but it is **not** presented as reclaimable bytes (the shared-extent accounting is unknowable from file metadata). Directories under `/System`, `/dev`, `/Volumes` (other volumes), and `/private/var/vm` are refused or skipped.

## 7. Memory accounting contract

`MemoryMeasurement { rss_bytes, pss_bytes: Option, uss_bytes: Option, swap_bytes: Option }`. `swap_bytes` changes from `u64` to `Option<u64>` so an unmeasured value is never reported as zero. `None` means "not measured on this platform".

- Linux: unchanged (PSS/USS from `smaps_rollup`, swap from `VmSwap`).
- macOS: RSS from `proc_pidinfo(PROC_PIDTASKINFO).pti_resident_size`; PSS/USS/swap `None` (no unprivileged equivalent; `task_info` requires a Mach task port that needs entitlements). System memory from `sysctl hw.memsize`, `vm.page_free_count`, `vm.page_speculative_count`, `vm.pagesize`, and swap from `vm.swapusage`. `available_bytes` is a lower bound (free + speculative) because purgeable and file-backed pages are not summed. Pressure: `Unsupported`.
- Windows: RSS = working set and private usage from `GetProcessMemoryInfo`; PSS/USS `None` (private working set is not a USS equivalent); swap `None`. System memory from `GlobalMemoryStatusEx` (physical; page-file figures are commit limits, not swap usage, so swap is reported only as the page-file commit delta and labeled as such). Pressure: `Unsupported`.

## 8. Scheduling contract

`Scheduler` is disabled by default, requires explicit user action, installs only user-level artifacts, runs no privileged daemon, and never installs automatically. Required behavior for every adapter:

- Validate the executable path (absolute, exists, regular file, no control characters, not world-writable on POSIX).
- Safe naming: fixed Root-owned identifier (`io.github.realmadede.root.inspect`, `\Root\Inspect`); collision detection by refusing to overwrite a definition that lacks Root's marker.
- Transactional change: write to a temporary file in the same directory, validate, then atomically rename; restore the prior definition if activation fails.
- Explicit uninstall removes only Root-marked artifacts.
- Status reports `installed`, `active`, `next trigger`, or "backend unavailable" with a reason.

Backends:
- Linux: systemd user timer/service (unchanged).
- macOS: a LaunchAgent plist in `~/Library/LaunchAgents/` (user domain only, never `/Library/LaunchDaemons`), activated with `launchctl bootstrap gui/<uid>` and removed with `launchctl bootout`.
- Windows: a Task Scheduler task registered for the current user at `LeastPrivilege` with an interactive-token principal, imported from generated XML with `schtasks.exe /Create /XML`, removed with `/Delete`.

Why launchctl/schtasks instead of a native API: launchd has no public C API for user agents other than `launchctl`/XPC, and the Task Scheduler API is COM, which would add a large binding dependency. Both tools are invoked directly (no shell, fixed arguments). This is a documented exception to the "prefer native capabilities" rule. [HYPOTHESIS: acceptable; to be reviewed in Phase 12 audit.]

The pure parts (plist and XML generation, validation, name checks, path layout) compile and are tested on all hosts. Only the tool invocations are platform-gated at runtime.

## 9. Monitoring contract

`MonitorEvent` and `MonitorSessionState` are unchanged. The session coordinator is generic over a `FilesystemWatcher` backend plus provider-based process and memory observers.

- Linux: inotify, unchanged.
- macOS and Windows (Phase 10): a bounded polling snapshot-diff watcher (metadata only; no content read; no symlink/reparse following; bounded watches, bounded queue, cancellation by dropping/stopping). Native backends (FSEvents, `ReadDirectoryChangesW`) are **not implemented in Phase 10**: they require substantial unsafe callback and run-loop/overlapped-I/O code that could not be executed or even compiled on the development host, which has only Linux. The trait boundary keeps those backends a drop-in addition.

Semantic differences, stated plainly: the polling watcher reports create/delete/modify by comparing snapshots, so it coalesces intermediate changes, cannot see a change that is reverted between polls, and detects a rename as delete plus create (move detection is best-effort by identity within one poll). It cannot overflow a kernel queue; overflow means the internal event queue bound was exceeded and is reported as `DegradedReason::QueueOverflow`. It is not event-for-event equivalent to inotify, FSEvents, or `ReadDirectoryChangesW`.

## 10. File-locking contract

`AdvisoryLock::try_acquire(path) -> Result<LockStatus>` with `LockStatus::{Acquired(LockGuard), Contended}`. Built on `std::fs::File::try_lock`, which uses `flock(LOCK_EX|LOCK_NB)` on Linux and macOS and `LockFileEx` on Windows. Non-blocking, ownership tied to the guard's lifetime, released automatically on drop or process exit, and the lock file is never deleted to release the lock. This raises the workspace `rust-version` to 1.89 (the release that stabilized `File::try_lock`). The Linux scheduling concurrency protection keeps identical semantics (same `flock`).

## 11. Agent discovery strategy

Discovery rules stay metadata-only with evidence provenance and lifecycle-uncertainty fields. Rules are keyed by platform; existing Linux rules are unchanged. New roots:

- macOS: `~/Library/Application Support`, `~/Library/Caches`, `~/Library/Logs` subdirectories **only where an agent's per-platform layout is documented in `docs/research/`**; dot-directories under the home directory (`~/.claude`, `~/.codex`, `~/.gemini`) apply on macOS as on Linux because those tools use the same home-relative layout. [HYPOTHESIS for each tool until verified on a macOS host.]
- Windows: `%USERPROFILE%` dot-directories, `%APPDATA%` and `%LOCALAPPDATA%` subdirectories.

Where a tool's macOS/Windows layout is not documented, Root adds no rule and the location stays unclassified — it does not copy Linux paths into other locations on speculation. Transcripts, sessions, and credentials remain protected tiers on every platform; shared storage protection rules apply unchanged.

## 12. Unsupported capability behavior

An operation with no platform equivalent returns an explicit `Unsupported`/`None` and is displayed as such ("not supported on <platform>"). It never returns zero, an empty success, or a fabricated equivalent. The CLI exits non-zero with a clear message when the user requests a subsystem that cannot work (for example `root inspect memory --pressure` on Windows).

## 13. Security boundaries

- Production mutation stays disabled everywhere. The Guardian mutation engine (`TransactionEngine`, quarantine, restoration, fixture sandbox, `atomic_rename_no_replace`) is compiled only for `target_os = "linux"` and exists for fixture tests; it is absent from macOS and Windows builds, and from every CLI/GUI path.
- The Guardian policy and the scheduler/monitor validators gain platform path protections (Windows: `C:\Windows`, `Program Files`, `ProgramData`, device namespaces; macOS: `/System`, `/Library`, `/usr`, `/bin`, `/sbin`, `/private/etc`).
- No process termination, privilege escalation, or administrator request. No process environment or command-line reads on macOS and Windows.
- No telemetry, no network, no new AI dependency. New dependencies are target-gated (`windows-sys` on Windows; `libc` already used on Unix).

## 14. Dependencies

| Crate | Target | Why | Alternative rejected |
|---|---|---|---|
| `libc` 0.2 (existing) | unix | `statvfs`, `proc_listallpids`, `proc_pidinfo`, `sysctlbyname`, `ioctl` | Mach bindings crates add more surface |
| `windows-sys` 0.61 | windows | thin raw FFI: `GetFileInformationByHandle[Ex]`, `GetDiskFreeSpaceExW`, `GetCompressedFileSizeW`, toolhelp, `GetProcessTimes`, `GetProcessMemoryInfo`, `GlobalMemoryStatusEx`, console size | `windows` crate (larger, COM/WinRT generation) |

No FSEvents or Core Foundation crate is added (see section 9). `windows-sys` is already present in `Cargo.lock` transitively.

## 15. Cross-platform testing strategy

1. Pure logic (path classification, plist/XML generation, name validation, sysctl/FILETIME conversion, capability and identity types, polling watcher, lock) is platform-independent and tested on Linux CI and Linux hosts.
2. Platform FFI adapters are compiled and tested only on their own runner (`macos-latest`, `windows-latest`).
3. A shared contract test suite exercises every platform's `FilesystemProvider`/`ProcessProvider`/`ResourceAccountant` through the same assertions (current-process inspection, nonexistent PID returns `Ok(None)`, symlink/reparse non-follow, temp-dir traversal).
4. Cross-platform classification consistency: the same synthetic fixture tree classified through the mock platform must yield identical tiers regardless of host.
5. All existing Linux tests must keep passing (159 baseline).
6. Destructive tests are not added; no real user data is touched; temp directories only.
7. Verification states: **Verified** (executed on that OS), **Partially verified** (type-checked or logic tested elsewhere), **Blocked**, **Not tested**. Compilation is never reported as runtime verification.

## 16. GUI boundary (documentation only)

No GUI rewrite in Phase 10. `root-gui` keeps its GTK4/libadwaita Linux implementation; its non-GTK view-model layer is updated only to use `Native*` aliases. Native macOS/Windows GUI would require: a GTK4 runtime for each OS or a different toolkit, platform-specific theming, per-OS packaging, and a re-run of the Phase 09 usability validation. A successful headless build does not establish GTK compatibility on either OS.
