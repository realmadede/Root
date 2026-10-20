use serde::{Deserialize, Serialize};

/// Detailed status of an individual platform capability or kernel interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Interface is available and verified readable/usable by unprivileged user space.
    SupportedAndAccessible,
    /// Interface is supported by the kernel, but restricted by permissions or seccomp.
    PermissionRestricted,
    /// Interface or syscall is not supported by the kernel or missing from the platform.
    Unavailable,
    /// Capability check was skipped or not evaluated.
    NotTested,
}

impl CapabilityStatus {
    pub fn is_operational(&self) -> bool {
        matches!(self, CapabilityStatus::SupportedAndAccessible)
    }

    pub fn display_badge(&self) -> &'static str {
        match self {
            CapabilityStatus::SupportedAndAccessible => "SUPPORTED & ACCESSIBLE",
            CapabilityStatus::PermissionRestricted => "PERMISSION RESTRICTED",
            CapabilityStatus::Unavailable => "UNAVAILABLE",
            CapabilityStatus::NotTested => "NOT TESTED",
        }
    }
}

/// Operating system features and kernel interface availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os_name: String,
    pub kernel_version: String,
    pub is_linux: bool,
    pub user_uid: u32,
    pub user_gid: u32,

    pub proc_fs: CapabilityStatus,
    pub proc_meminfo: CapabilityStatus,
    pub proc_pressure_memory: CapabilityStatus,
    pub proc_smaps_rollup: CapabilityStatus,
    pub cgroups_v2: CapabilityStatus,
    pub pidfd: CapabilityStatus,
    pub openat2: CapabilityStatus,
    pub statx: CapabilityStatus,
}

impl PlatformCapabilities {
    pub fn unknown() -> Self {
        Self {
            os_name: "Unknown".to_string(),
            kernel_version: "Unknown".to_string(),
            is_linux: false,
            user_uid: 0,
            user_gid: 0,
            proc_fs: CapabilityStatus::Unavailable,
            proc_meminfo: CapabilityStatus::Unavailable,
            proc_pressure_memory: CapabilityStatus::Unavailable,
            proc_smaps_rollup: CapabilityStatus::Unavailable,
            cgroups_v2: CapabilityStatus::Unavailable,
            pidfd: CapabilityStatus::Unavailable,
            openat2: CapabilityStatus::Unavailable,
            statx: CapabilityStatus::Unavailable,
        }
    }

    pub fn has_pidfd(&self) -> bool {
        self.pidfd.is_operational()
    }

    pub fn has_cgroups_v2_psi(&self) -> bool {
        self.proc_pressure_memory.is_operational()
    }

    pub fn has_smaps_rollup(&self) -> bool {
        self.proc_smaps_rollup.is_operational()
    }

    pub fn has_openat2(&self) -> bool {
        self.openat2.is_operational()
    }

    pub fn has_statx(&self) -> bool {
        self.statx.is_operational()
    }
}
