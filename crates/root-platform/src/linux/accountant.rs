use root_core::{
    error::Result,
    model::{CapabilityStatus, PlatformCapabilities, PressureMetrics, SystemMemorySummary},
};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

use crate::traits::ResourceAccountant;

#[derive(Debug, Default, Clone)]
pub struct LinuxAccountant;

impl LinuxAccountant {
    pub fn new() -> Self {
        Self
    }

    fn parse_kernel_version() -> String {
        if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            return release.trim().to_string();
        }
        "Unknown".to_string()
    }

    #[cfg(target_os = "linux")]
    fn probe_file_access(path: &str) -> CapabilityStatus {
        match fs::File::open(path) {
            Ok(_) => CapabilityStatus::SupportedAndAccessible,
            Err(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => CapabilityStatus::PermissionRestricted,
                std::io::ErrorKind::NotFound => CapabilityStatus::Unavailable,
                _ => CapabilityStatus::Unavailable,
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_dir_access(path: &str) -> CapabilityStatus {
        match fs::read_dir(path) {
            Ok(_) => CapabilityStatus::SupportedAndAccessible,
            Err(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => CapabilityStatus::PermissionRestricted,
                std::io::ErrorKind::NotFound => CapabilityStatus::Unavailable,
                _ => CapabilityStatus::Unavailable,
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_cgroups_v2() -> CapabilityStatus {
        let controllers_path = "/sys/fs/cgroup/cgroup.controllers";
        if Path::new(controllers_path).exists() {
            return Self::probe_file_access(controllers_path);
        }

        // Secondary check: verify filesystem magic of /sys/fs/cgroup
        unsafe {
            let mut statbuf: libc::statfs = std::mem::zeroed();
            let c_path = std::ffi::CString::new("/sys/fs/cgroup").unwrap();
            if libc::statfs(c_path.as_ptr(), &mut statbuf) == 0 {
                // 0x63677270 is CGROUP2_SUPER_MAGIC
                if statbuf.f_type == 0x63677270 {
                    return CapabilityStatus::SupportedAndAccessible;
                }
            }
        }

        CapabilityStatus::Unavailable
    }

    #[cfg(target_os = "linux")]
    fn probe_pidfd_syscall() -> CapabilityStatus {
        // Empirically probe pidfd_open(-1, 0).
        // If supported, the kernel returns EINVAL or ESRCH.
        // If unsupported or blocked by seccomp, returns ENOSYS or EPERM.
        unsafe {
            let res = libc::syscall(libc::SYS_pidfd_open, -1i32, 0u32);
            if res >= 0 {
                // Should not happen for PID -1, but if it did, close it
                libc::close(res as i32);
                CapabilityStatus::SupportedAndAccessible
            } else {
                let err = *libc::__errno_location();
                match err {
                    libc::EINVAL | libc::ESRCH => CapabilityStatus::SupportedAndAccessible,
                    libc::EPERM | libc::EACCES => CapabilityStatus::PermissionRestricted,
                    libc::ENOSYS => CapabilityStatus::Unavailable,
                    _ => CapabilityStatus::Unavailable,
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_openat2_syscall() -> CapabilityStatus {
        // Empirically probe openat2(-1, null, null, 0).
        // If supported, the kernel validates arguments and returns EFAULT or EINVAL.
        // If unsupported or blocked by seccomp, returns ENOSYS or EPERM.
        unsafe {
            let res = libc::syscall(
                libc::SYS_openat2,
                -1i32,
                std::ptr::null::<libc::c_void>(),
                std::ptr::null::<libc::c_void>(),
                0usize,
            );
            if res >= 0 {
                libc::close(res as i32);
                CapabilityStatus::SupportedAndAccessible
            } else {
                let err = *libc::__errno_location();
                match err {
                    libc::EFAULT | libc::EINVAL => CapabilityStatus::SupportedAndAccessible,
                    libc::EPERM | libc::EACCES => CapabilityStatus::PermissionRestricted,
                    libc::ENOSYS => CapabilityStatus::Unavailable,
                    _ => CapabilityStatus::Unavailable,
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn probe_statx_syscall() -> CapabilityStatus {
        unsafe {
            let mut statxbuf: libc::statx = std::mem::zeroed();
            let c_path = std::ffi::CString::new(".").unwrap();
            let res = libc::statx(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                0,
                &mut statxbuf,
            );
            if res == 0 {
                CapabilityStatus::SupportedAndAccessible
            } else {
                let err = *libc::__errno_location();
                match err {
                    libc::EPERM | libc::EACCES => CapabilityStatus::PermissionRestricted,
                    libc::ENOSYS => CapabilityStatus::Unavailable,
                    _ => CapabilityStatus::Unavailable,
                }
            }
        }
    }
}

impl ResourceAccountant for LinuxAccountant {
    fn get_system_memory(&self) -> Result<SystemMemorySummary> {
        let content = fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let mut total_kb = 0u64;
        let mut avail_kb = 0u64;
        let mut free_kb = 0u64;
        let mut cached_kb = 0u64;
        let mut buffers_kb = 0u64;
        let mut sreclaimable_kb = 0u64;
        let mut swap_total_kb = 0u64;
        let mut swap_free_kb = 0u64;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "MemTotal:" => total_kb = parts[1].parse().unwrap_or(0),
                    "MemAvailable:" => avail_kb = parts[1].parse().unwrap_or(0),
                    "MemFree:" => free_kb = parts[1].parse().unwrap_or(0),
                    "Cached:" => cached_kb = parts[1].parse().unwrap_or(0),
                    "Buffers:" => buffers_kb = parts[1].parse().unwrap_or(0),
                    "SReclaimable:" => sreclaimable_kb = parts[1].parse().unwrap_or(0),
                    "SwapTotal:" => swap_total_kb = parts[1].parse().unwrap_or(0),
                    "SwapFree:" => swap_free_kb = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        // Total reclaimable cache includes regular page cache, filesystem buffers, and slab reclaimable
        let total_cached_bytes = (cached_kb + buffers_kb + sreclaimable_kb) * 1024;

        Ok(SystemMemorySummary {
            total_bytes: total_kb * 1024,
            available_bytes: avail_kb * 1024,
            cached_bytes: total_cached_bytes,
            free_bytes: free_kb * 1024,
            swap_total_bytes: swap_total_kb * 1024,
            swap_free_bytes: swap_free_kb * 1024,
        })
    }

    fn get_pressure_metrics(&self) -> Result<Option<PressureMetrics>> {
        let path = "/proc/pressure/memory";
        if !Path::new(path).exists() {
            return Ok(None);
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        let mut some_10 = 0.0f32;
        let mut some_60 = 0.0f32;
        let mut some_300 = 0.0f32;
        let mut full_10 = 0.0f32;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            if parts[0] == "some" {
                for token in &parts[1..] {
                    if let Some(val) = token.strip_prefix("avg10=") {
                        some_10 = val.parse().unwrap_or(0.0);
                    } else if let Some(val) = token.strip_prefix("avg60=") {
                        some_60 = val.parse().unwrap_or(0.0);
                    } else if let Some(val) = token.strip_prefix("avg300=") {
                        some_300 = val.parse().unwrap_or(0.0);
                    }
                }
            } else if parts[0] == "full" {
                for token in &parts[1..] {
                    if let Some(val) = token.strip_prefix("avg10=") {
                        full_10 = val.parse().unwrap_or(0.0);
                    }
                }
            }
        }

        Ok(Some(PressureMetrics {
            some_10s_pct: some_10,
            some_60s_pct: some_60,
            some_300s_pct: some_300,
            full_10s_pct: full_10,
        }))
    }

    fn get_capabilities(&self) -> Result<PlatformCapabilities> {
        let kernel_version = Self::parse_kernel_version();
        let is_linux = cfg!(target_os = "linux");

        let (
            proc_fs,
            proc_meminfo,
            proc_pressure_memory,
            proc_smaps_rollup,
            cgroups_v2,
            pidfd,
            openat2,
            statx,
        ) = if is_linux {
            #[cfg(target_os = "linux")]
            {
                (
                    Self::probe_dir_access("/proc"),
                    Self::probe_file_access("/proc/meminfo"),
                    Self::probe_file_access("/proc/pressure/memory"),
                    Self::probe_file_access("/proc/self/smaps_rollup"),
                    Self::probe_cgroups_v2(),
                    Self::probe_pidfd_syscall(),
                    Self::probe_openat2_syscall(),
                    Self::probe_statx_syscall(),
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                (
                    CapabilityStatus::Unavailable,
                    CapabilityStatus::Unavailable,
                    CapabilityStatus::Unavailable,
                    CapabilityStatus::Unavailable,
                    CapabilityStatus::Unavailable,
                    CapabilityStatus::Unavailable,
                    CapabilityStatus::Unavailable,
                    CapabilityStatus::Unavailable,
                )
            }
        } else {
            (
                CapabilityStatus::Unavailable,
                CapabilityStatus::Unavailable,
                CapabilityStatus::Unavailable,
                CapabilityStatus::Unavailable,
                CapabilityStatus::Unavailable,
                CapabilityStatus::Unavailable,
                CapabilityStatus::Unavailable,
                CapabilityStatus::Unavailable,
            )
        };

        let user_uid = fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(1000);
        let user_gid = fs::metadata("/proc/self").map(|m| m.gid()).unwrap_or(1000);

        let supported = CapabilityStatus::SupportedAndAccessible;
        let inotify = Self::probe_inotify();
        Ok(PlatformCapabilities {
            os_name: format!("Linux ({})", Self::distribution_name()),
            kernel_version,
            platform: root_core::model::PlatformKind::Linux,
            is_linux,
            user_uid,
            user_gid,
            proc_fs,
            proc_meminfo,
            proc_pressure_memory,
            proc_smaps_rollup,
            cgroups_v2,
            pidfd,
            openat2,
            statx,
            process_enumeration: proc_fs,
            process_start_time: proc_fs,
            process_rss: proc_fs,
            process_private_memory: proc_smaps_rollup,
            process_swap: proc_fs,
            system_memory: proc_meminfo,
            memory_pressure: proc_pressure_memory,
            file_identity: supported,
            filesystem_events: inotify,
            scheduler: CapabilityStatus::NotTested,
            file_locking: supported,
            posix_ownership: supported,
        })
    }
}

impl LinuxAccountant {
    /// Reads `PRETTY_NAME` from os-release; falls back to a generic label.
    fn distribution_name() -> String {
        fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|c| {
                c.lines()
                    .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                    .map(|v| v.trim_matches('"').to_string())
            })
            .unwrap_or_else(|| "GNU/Linux".to_string())
    }

    fn probe_inotify() -> CapabilityStatus {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            CapabilityStatus::SupportedAndAccessible
        } else {
            CapabilityStatus::Unavailable
        }
    }
}
