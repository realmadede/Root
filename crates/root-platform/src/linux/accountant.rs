use root_core::{
    error::Result,
    model::{PlatformCapabilities, PressureMetrics, SystemMemorySummary},
};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

use crate::traits::ResourceAccountant;

#[derive(Debug, Default, Clone)]
pub struct LinuxAccountant;

impl LinuxAccountant {
    pub fn new() -> Self {
        Self
    }

    fn parse_kernel_version() -> (String, u32, u32) {
        if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            let release = release.trim();
            let mut parts = release.split('.');
            let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
            let minor: u32 = parts
                .next()
                .and_then(|p| p.split(&['-', '+'][..]).next())
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);
            return (release.to_string(), major, minor);
        }
        ("Unknown".to_string(), 0, 0)
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
                    "SwapTotal:" => swap_total_kb = parts[1].parse().unwrap_or(0),
                    "SwapFree:" => swap_free_kb = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(SystemMemorySummary {
            total_bytes: total_kb * 1024,
            available_bytes: avail_kb * 1024,
            cached_bytes: (cached_kb + buffers_kb) * 1024,
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
        let (kernel_version, major, minor) = Self::parse_kernel_version();
        let is_linux = cfg!(target_os = "linux");

        // Linux 5.3+ supports pidfd_open
        let has_pidfd = is_linux && (major > 5 || (major == 5 && minor >= 3));

        // Linux 4.20+ supports PSI pressure
        let has_cgroups_v2_psi = Path::new("/proc/pressure/memory").exists();

        // Linux 4.14+ supports smaps_rollup
        let has_smaps_rollup = Path::new("/proc/self/smaps_rollup").exists();

        // Linux 5.6+ supports openat2
        let has_openat2 = is_linux && (major > 5 || (major == 5 && minor >= 6));

        let user_uid = fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(1000);
        let user_gid = fs::metadata("/proc/self").map(|m| m.gid()).unwrap_or(1000);

        Ok(PlatformCapabilities {
            os_name: "Linux (Kali GNU/Linux Rolling)".to_string(),
            kernel_version,
            has_pidfd,
            has_cgroups_v2_psi,
            has_smaps_rollup,
            has_openat2,
            is_linux,
            user_uid,
            user_gid,
        })
    }
}
