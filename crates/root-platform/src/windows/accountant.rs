//! Windows system memory and capability reporting.

use root_core::{
    error::{Result, RootError},
    model::{
        CapabilityStatus, PlatformCapabilities, PlatformKind, PressureMetrics, SystemMemorySummary,
    },
};
use windows_sys::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX, OSVERSIONINFOW},
};

use super::parse::memory_summary;
use crate::traits::{ProcessProvider, ResourceAccountant};

#[derive(Debug, Default, Clone)]
pub struct WindowsAccountant;

impl WindowsAccountant {
    pub fn new() -> Self {
        Self
    }

    fn version_string() -> String {
        let mut info: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
        // RtlGetVersion returns the true version, unlike GetVersionExW which lies without a manifest.
        if unsafe { RtlGetVersion(&mut info) } == 0 {
            format!(
                "{}.{}.{}",
                info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber
            )
        } else {
            "unknown".to_string()
        }
    }
}

impl ResourceAccountant for WindowsAccountant {
    fn get_system_memory(&self) -> Result<SystemMemorySummary> {
        let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
            return Err(RootError::Platform(format!(
                "GlobalMemoryStatusEx failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(memory_summary(
            status.ullTotalPhys,
            status.ullAvailPhys,
            status.ullTotalPageFile,
            status.ullAvailPageFile,
        ))
    }

    /// Linux PSI has no Windows equivalent; Root does not synthesize one.
    fn get_pressure_metrics(&self) -> Result<Option<PressureMetrics>> {
        Ok(None)
    }

    fn get_capabilities(&self) -> Result<PlatformCapabilities> {
        let supported = CapabilityStatus::SupportedAndAccessible;
        let mut caps = PlatformCapabilities::non_linux_baseline(
            PlatformKind::Windows,
            "Windows".to_string(),
            Self::version_string(),
        );

        caps.system_memory = if self.get_system_memory().is_ok() {
            supported
        } else {
            CapabilityStatus::Unavailable
        };
        let procs = super::WindowsProcess::new();
        caps.process_enumeration = if procs.list_pids().is_ok() {
            supported
        } else {
            CapabilityStatus::Unavailable
        };
        let own_pid = std::process::id();
        let own = procs.inspect_process(own_pid).ok().flatten();
        caps.process_start_time = if own.is_some() {
            supported
        } else {
            CapabilityStatus::Unavailable
        };
        caps.process_rss = caps.process_start_time;

        caps.process_private_memory = CapabilityStatus::Unsupported;
        caps.process_swap = CapabilityStatus::Unsupported;
        caps.memory_pressure = CapabilityStatus::Unsupported;
        caps.posix_ownership = CapabilityStatus::Unsupported;

        caps.file_identity = supported;
        // The monitor uses metadata polling; ReadDirectoryChangesW is not wired in Phase 10.
        caps.filesystem_events = CapabilityStatus::NotTested;
        caps.scheduler = CapabilityStatus::NotTested;
        caps.file_locking = supported;
        Ok(caps)
    }
}
