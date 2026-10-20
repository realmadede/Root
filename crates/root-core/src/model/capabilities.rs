use serde::{Deserialize, Serialize};

/// Operating system features and kernel interface availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os_name: String,
    pub kernel_version: String,
    /// Linux 5.3+ `pidfd_open` and 5.4+ `pidfd_send_signal` support.
    pub has_pidfd: bool,
    /// Linux 4.20+ Pressure Stall Information (`/proc/pressure/memory`).
    pub has_cgroups_v2_psi: bool,
    /// Linux 4.14+ fast PSS/USS rollups (`/proc/[pid]/smaps_rollup`).
    pub has_smaps_rollup: bool,
    /// Linux 5.6+ `openat2` traversal with `RESOLVE_BENEATH`.
    pub has_openat2: bool,
    pub is_linux: bool,
    pub user_uid: u32,
    pub user_gid: u32,
}

impl PlatformCapabilities {
    pub fn unknown() -> Self {
        Self {
            os_name: "Unknown".to_string(),
            kernel_version: "Unknown".to_string(),
            has_pidfd: false,
            has_cgroups_v2_psi: false,
            has_smaps_rollup: false,
            has_openat2: false,
            is_linux: false,
            user_uid: 0,
            user_gid: 0,
        }
    }
}
