//! macOS system memory and capability reporting through `sysctl`.

use root_core::{
    error::{Result, RootError},
    model::{
        CapabilityStatus, PlatformCapabilities, PlatformKind, PressureMetrics, SystemMemorySummary,
    },
};
use std::{ffi::CString, mem};

use super::parse::{available_memory_lower_bound, parse_swap_usage};
use crate::traits::{ProcessProvider, ResourceAccountant};

#[derive(Debug, Default, Clone)]
pub struct MacAccountant;

fn sysctl_bytes(name: &str, expected: usize) -> Option<Vec<u8>> {
    let c_name = CString::new(name).ok()?;
    let mut buf = vec![0u8; expected];
    let mut len = buf.len();
    let rc = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

fn sysctl_u64(name: &str) -> Option<u64> {
    let bytes = sysctl_bytes(name, mem::size_of::<u64>())?;
    match bytes.len() {
        4 => Some(u32::from_ne_bytes(bytes[..4].try_into().ok()?) as u64),
        8 => Some(u64::from_ne_bytes(bytes[..8].try_into().ok()?)),
        _ => None,
    }
}

fn sysctl_string(name: &str) -> Option<String> {
    let bytes = sysctl_bytes(name, 256)?;
    Some(
        String::from_utf8_lossy(&bytes)
            .trim_end_matches('\0')
            .to_string(),
    )
}

impl MacAccountant {
    pub fn new() -> Self {
        Self
    }
}

impl ResourceAccountant for MacAccountant {
    fn get_system_memory(&self) -> Result<SystemMemorySummary> {
        let total = sysctl_u64("hw.memsize")
            .ok_or_else(|| RootError::Platform("sysctl hw.memsize unavailable".to_string()))?;
        let page_size = sysctl_u64("vm.pagesize")
            .or_else(|| sysctl_u64("hw.pagesize"))
            .unwrap_or(4096);
        let free_pages = sysctl_u64("vm.page_free_count").unwrap_or(0);
        let speculative_pages = sysctl_u64("vm.page_speculative_count").unwrap_or(0);
        let external_pages = sysctl_u64("vm.page_pageable_external_count").unwrap_or(0);

        // Lower bound: file-backed (external) pages are reclaimable but are reported separately as
        // `cached_bytes`, not folded into `available_bytes`.
        let available = available_memory_lower_bound(free_pages, speculative_pages, page_size);

        let swap = sysctl_bytes("vm.swapusage", 32).and_then(|b| parse_swap_usage(&b));
        let (swap_total, swap_free) = swap
            .map(|s| (s.total_bytes, s.available_bytes))
            .unwrap_or((0, 0));

        Ok(SystemMemorySummary {
            total_bytes: total,
            available_bytes: available.min(total),
            cached_bytes: external_pages.saturating_mul(page_size).min(total),
            free_bytes: free_pages.saturating_mul(page_size).min(total),
            swap_total_bytes: swap_total,
            swap_free_bytes: swap_free,
        })
    }

    /// Linux PSI has no equivalent; Root does not synthesize one.
    fn get_pressure_metrics(&self) -> Result<Option<PressureMetrics>> {
        Ok(None)
    }

    fn get_capabilities(&self) -> Result<PlatformCapabilities> {
        let kernel = sysctl_string("kern.osrelease").unwrap_or_else(|| "unknown".to_string());
        let product = sysctl_string("kern.osproductversion").unwrap_or_default();
        let os_name = if product.is_empty() {
            "macOS".to_string()
        } else {
            format!("macOS {}", product)
        };

        let supported = CapabilityStatus::SupportedAndAccessible;
        let mut caps =
            PlatformCapabilities::non_linux_baseline(PlatformKind::MacOs, os_name, kernel);
        caps.user_uid = unsafe { libc::geteuid() };
        caps.user_gid = unsafe { libc::getegid() };

        // Probed capabilities
        caps.system_memory = if sysctl_u64("hw.memsize").is_some() {
            supported
        } else {
            CapabilityStatus::Unavailable
        };
        let me = unsafe { libc::getpid() } as u32;
        caps.process_enumeration = if super::MacProcess::new().list_pids().is_ok() {
            supported
        } else {
            CapabilityStatus::Unavailable
        };
        let own = crate::traits::ProcessProvider::inspect_process(&super::MacProcess::new(), me)
            .ok()
            .flatten();
        caps.process_start_time = if own.is_some() {
            supported
        } else {
            CapabilityStatus::Unavailable
        };
        caps.process_rss = caps.process_start_time;

        // Reported as unsupported by design, not failures.
        caps.process_private_memory = CapabilityStatus::Unsupported;
        caps.process_swap = CapabilityStatus::Unsupported;
        caps.memory_pressure = CapabilityStatus::Unsupported;

        caps.file_identity = supported;
        // The monitor uses metadata polling; FSEvents is not wired in Phase 10.
        caps.filesystem_events = CapabilityStatus::NotTested;
        caps.scheduler = CapabilityStatus::NotTested;
        caps.file_locking = supported;
        caps.posix_ownership = supported;
        Ok(caps)
    }
}
