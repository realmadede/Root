use serde::{Deserialize, Serialize};

use super::platform_paths::PlatformKind;

/// Detailed status of an individual platform capability or kernel interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Interface is available and verified readable/usable by unprivileged user space.
    SupportedAndAccessible,
    /// Interface is supported by the kernel, but restricted by permissions or seccomp.
    PermissionRestricted,
    /// Interface is expected on this platform but is missing on this host (for example an old
    /// kernel or a disabled service).
    Unavailable,
    /// The platform has no equivalent of this feature. Root does not invent one and never reports
    /// the corresponding measurement as zero.
    Unsupported,
    /// Capability check was skipped or not evaluated.
    #[default]
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
            CapabilityStatus::Unsupported => "NOT SUPPORTED ON THIS PLATFORM",
            CapabilityStatus::NotTested => "NOT TESTED",
        }
    }
}

/// Operating system features and kernel interface availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os_name: String,
    pub kernel_version: String,
    /// Operating system family. `is_linux` is kept for existing consumers and mirrors it.
    #[serde(default = "PlatformKind::current")]
    pub platform: PlatformKind,
    pub is_linux: bool,
    /// POSIX user id. Meaningless on Windows; see `posix_ownership`.
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

    // Cross-platform capabilities. Linux-specific fields above are `Unsupported` elsewhere.
    #[serde(default)]
    pub process_enumeration: CapabilityStatus,
    #[serde(default)]
    pub process_start_time: CapabilityStatus,
    #[serde(default)]
    pub process_rss: CapabilityStatus,
    /// Per-process private/unique memory (Linux USS). Unsupported where no equivalent exists.
    #[serde(default)]
    pub process_private_memory: CapabilityStatus,
    #[serde(default)]
    pub process_swap: CapabilityStatus,
    #[serde(default)]
    pub system_memory: CapabilityStatus,
    /// System memory pressure (Linux PSI).
    #[serde(default)]
    pub memory_pressure: CapabilityStatus,
    #[serde(default)]
    pub file_identity: CapabilityStatus,
    #[serde(default)]
    pub filesystem_events: CapabilityStatus,
    #[serde(default)]
    pub scheduler: CapabilityStatus,
    #[serde(default)]
    pub file_locking: CapabilityStatus,
    /// POSIX uid/gid ownership of files and processes.
    #[serde(default)]
    pub posix_ownership: CapabilityStatus,
}

impl PlatformCapabilities {
    pub fn unknown() -> Self {
        Self {
            os_name: "Unknown".to_string(),
            kernel_version: "Unknown".to_string(),
            platform: PlatformKind::Other,
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
            process_enumeration: CapabilityStatus::NotTested,
            process_start_time: CapabilityStatus::NotTested,
            process_rss: CapabilityStatus::NotTested,
            process_private_memory: CapabilityStatus::NotTested,
            process_swap: CapabilityStatus::NotTested,
            system_memory: CapabilityStatus::NotTested,
            memory_pressure: CapabilityStatus::NotTested,
            file_identity: CapabilityStatus::NotTested,
            filesystem_events: CapabilityStatus::NotTested,
            scheduler: CapabilityStatus::NotTested,
            file_locking: CapabilityStatus::NotTested,
            posix_ownership: CapabilityStatus::NotTested,
        }
    }

    /// Baseline for a non-Linux platform: every Linux-only interface is `Unsupported` and every
    /// cross-platform capability starts `NotTested` until an adapter probes it.
    pub fn non_linux_baseline(
        platform: PlatformKind,
        os_name: String,
        kernel_version: String,
    ) -> Self {
        Self {
            os_name,
            kernel_version,
            platform,
            is_linux: false,
            proc_fs: CapabilityStatus::Unsupported,
            proc_meminfo: CapabilityStatus::Unsupported,
            proc_pressure_memory: CapabilityStatus::Unsupported,
            proc_smaps_rollup: CapabilityStatus::Unsupported,
            cgroups_v2: CapabilityStatus::Unsupported,
            pidfd: CapabilityStatus::Unsupported,
            openat2: CapabilityStatus::Unsupported,
            statx: CapabilityStatus::Unsupported,
            ..Self::unknown()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_linux_baseline_marks_linux_interfaces_unsupported_not_unavailable() {
        let caps = PlatformCapabilities::non_linux_baseline(
            PlatformKind::Windows,
            "Windows".into(),
            "10".into(),
        );
        assert_eq!(caps.proc_pressure_memory, CapabilityStatus::Unsupported);
        assert_eq!(caps.proc_smaps_rollup, CapabilityStatus::Unsupported);
        assert!(!caps.has_pidfd());
        assert!(!caps.has_cgroups_v2_psi());
        assert_eq!(caps.process_enumeration, CapabilityStatus::NotTested);
        assert!(!caps.is_linux);
    }

    #[test]
    fn unsupported_is_not_operational_and_has_distinct_badge() {
        assert!(!CapabilityStatus::Unsupported.is_operational());
        assert_ne!(
            CapabilityStatus::Unsupported.display_badge(),
            CapabilityStatus::Unavailable.display_badge()
        );
        assert_eq!(CapabilityStatus::default(), CapabilityStatus::NotTested);
    }
}
