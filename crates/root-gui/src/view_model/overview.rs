use crate::model::presentation::format_bytes_tabular;
use root_platform::traits::{FilesystemProvider, ResourceAccountant};
use root_platform::{LinuxAccountant, LinuxFilesystem};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Severity classification for kernel PSI memory pressure stalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PressureSeverity {
    Normal,
    Elevated,
    Critical,
}

impl PressureSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Elevated => "Elevated",
            Self::Critical => "Critical",
        }
    }

    pub fn css_class(&self) -> &'static str {
        match self {
            Self::Normal => "pressure-normal",
            Self::Elevated => "pressure-elevated",
            Self::Critical => "pressure-critical",
        }
    }
}

/// System overview view-model summarizing workstation health, memory, and Root operating state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverviewViewModel {
    // Memory
    pub total_ram_bytes: u64,
    pub available_ram_bytes: u64,
    pub free_ram_bytes: u64,
    pub cached_ram_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub swap_used_bytes: u64,

    // Pressure
    pub psi_supported: bool,
    pub psi_10s_stall: f32,
    pub psi_60s_stall: f32,
    pub psi_300s_stall: f32,
    pub pressure_severity: PressureSeverity,

    // Storage
    pub filesystem_capacity_bytes: u64,
    pub filesystem_available_bytes: u64,
    pub filesystem_free_inodes: u64,

    // Agent discovery summary
    pub detected_agents_count: usize,
    pub active_agents_count: usize,
    pub total_resources_count: usize,
    /// Speculative upper-bound potential savings (clearly labeled as upper bound, never guaranteed savings).
    pub potential_transient_bytes: u64,

    // Root operating modes
    pub mode_a_status: &'static str,
    pub mode_b_enabled: bool,
    pub mode_c_active: bool,
    pub safety_guarantee: &'static str,

    // Last scan
    pub last_scan_timestamp: Option<String>,
    pub last_scan_summary: String,
}

impl Default for OverviewViewModel {
    fn default() -> Self {
        Self {
            total_ram_bytes: 0,
            available_ram_bytes: 0,
            free_ram_bytes: 0,
            cached_ram_bytes: 0,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
            swap_used_bytes: 0,

            psi_supported: false,
            psi_10s_stall: 0.0,
            psi_60s_stall: 0.0,
            psi_300s_stall: 0.0,
            pressure_severity: PressureSeverity::Normal,

            filesystem_capacity_bytes: 0,
            filesystem_available_bytes: 0,
            filesystem_free_inodes: 0,

            detected_agents_count: 0,
            active_agents_count: 0,
            total_resources_count: 0,
            potential_transient_bytes: 0,

            mode_a_status: "Ready (On-Demand)",
            mode_b_enabled: false,
            mode_c_active: false,
            safety_guarantee: "Production Read-Only (Zero Mutations)",

            last_scan_timestamp: None,
            last_scan_summary: "No previous scan recorded".to_string(),
        }
    }
}

impl OverviewViewModel {
    /// Refreshes system metrics from Linux kernel interfaces.
    pub fn refresh_system_metrics(&mut self, root_path: &Path) {
        let accountant = LinuxAccountant::new();

        // 1. Read memory metrics
        if let Ok(mem) = accountant.get_system_memory() {
            self.total_ram_bytes = mem.total_bytes;
            self.available_ram_bytes = mem.available_bytes;
            self.free_ram_bytes = mem.free_bytes;
            self.cached_ram_bytes = mem.cached_bytes;
            self.swap_total_bytes = mem.swap_total_bytes;
            self.swap_free_bytes = mem.swap_free_bytes;
            self.swap_used_bytes = mem.swap_total_bytes.saturating_sub(mem.swap_free_bytes);
        }

        // 2. Read PSI memory pressure
        if let Ok(Some(psi)) = accountant.get_pressure_metrics() {
            self.psi_supported = true;
            self.psi_10s_stall = psi.some_10s_pct;
            self.psi_60s_stall = psi.some_60s_pct;
            self.psi_300s_stall = psi.some_300s_pct;

            self.pressure_severity = if psi.some_10s_pct > 40.0 {
                PressureSeverity::Critical
            } else if psi.some_10s_pct > 10.0 {
                PressureSeverity::Elevated
            } else {
                PressureSeverity::Normal
            };
        } else {
            self.psi_supported = false;
        }

        // 3. Read filesystem capacity via FilesystemProvider
        let fs = LinuxFilesystem::new();
        if let Ok(usage) = fs.get_filesystem_usage(root_path) {
            self.filesystem_capacity_bytes = usage.total_bytes;
            self.filesystem_available_bytes = usage.available_bytes;
            self.filesystem_free_inodes = usage.free_inodes;
        }
    }

    /// Updates agent and resource footprint summaries.
    pub fn update_discovery_summary(
        &mut self,
        detected_agents: usize,
        active_agents: usize,
        total_resources: usize,
        potential_bytes: u64,
    ) {
        self.detected_agents_count = detected_agents;
        self.active_agents_count = active_agents;
        self.total_resources_count = total_resources;
        self.potential_transient_bytes = potential_bytes;
    }

    /// Formatted memory availability string (e.g. "12.4 GiB / 16.0 GiB available").
    pub fn memory_availability_display(&self) -> String {
        format!(
            "{} / {} available",
            format_bytes_tabular(self.available_ram_bytes),
            format_bytes_tabular(self.total_ram_bytes)
        )
    }

    /// Formatted swap usage string.
    pub fn swap_usage_display(&self) -> String {
        if self.swap_total_bytes == 0 {
            "No swap configured".to_string()
        } else {
            format!(
                "{} / {} used",
                format_bytes_tabular(self.swap_used_bytes),
                format_bytes_tabular(self.swap_total_bytes)
            )
        }
    }

    /// Formatted filesystem capacity display.
    pub fn filesystem_capacity_display(&self) -> String {
        format!(
            "{} free of {}",
            format_bytes_tabular(self.filesystem_available_bytes),
            format_bytes_tabular(self.filesystem_capacity_bytes)
        )
    }

    /// Formatted potential savings upper-bound note.
    pub fn potential_savings_display(&self) -> String {
        format!(
            "{} upper bound (speculative transient cache)",
            format_bytes_tabular(self.potential_transient_bytes)
        )
    }
}
