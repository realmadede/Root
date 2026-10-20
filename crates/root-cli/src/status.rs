use root_core::{
    error::{Result, RootError},
    model::PressureMetrics,
    DiscoveryTargetId,
};
use root_platform::{
    traits::{EnvironmentProvider, ResourceAccountant},
    LinuxAccountant, LinuxEnvironment,
};
use serde::{Deserialize, Serialize};

use crate::{
    history::{load_last_scan, ScanHistoryRecord},
    terminal::{format_bytes, format_percent, Style},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub root_version: String,
    pub operating_system: String,
    pub kernel_release: String,
    pub invoking_uid: u32,
    pub total_memory_bytes: u64,
    pub available_memory_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub memory_pressure: Option<PressureMetrics>,
    pub supported_discovery_targets: Vec<String>,
    pub last_completed_scan: Option<ScanHistoryRecord>,
    pub safety_mode: String,
}

pub fn run_status(json_output: bool) -> Result<()> {
    let env = LinuxEnvironment::new();
    let accountant = LinuxAccountant::new();

    let caps = accountant.get_capabilities()?;
    let mem = accountant.get_system_memory()?;
    let pressure = accountant.get_pressure_metrics()?;
    let last_scan = load_last_scan();

    let supported_targets = DiscoveryTargetId::all()
        .iter()
        .map(|t| t.name().to_string())
        .collect::<Vec<_>>();

    let swap_used = mem.swap_total_bytes.saturating_sub(mem.swap_free_bytes);

    let report = StatusReport {
        root_version: env!("CARGO_PKG_VERSION").to_string(),
        operating_system: caps.os_name.clone(),
        kernel_release: caps.kernel_version.clone(),
        invoking_uid: env.current_uid(),
        total_memory_bytes: mem.total_bytes,
        available_memory_bytes: mem.available_bytes,
        swap_total_bytes: mem.swap_total_bytes,
        swap_used_bytes: swap_used,
        memory_pressure: pressure,
        supported_discovery_targets: supported_targets,
        last_completed_scan: last_scan.clone(),
        safety_mode: "Production Read-Only (Quarantine isolated to synthetic fixtures; all mutations rejected)".to_string(),
    };

    if json_output {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    render_status_terminal(&report);
    Ok(())
}

fn render_status_terminal(report: &StatusReport) {
    println!("================================================================================");
    println!(" {}", Style::bold("ROOT SYSTEM STATUS OVERVIEW"));
    println!("================================================================================");
    println!("Platform Identity:");
    println!("  Operating System      : {}", report.operating_system);
    println!("  Kernel Release        : {}", report.kernel_release);
    println!("  Invoking UID          : {}", report.invoking_uid);
    println!("  Root Version          : v{}", report.root_version);
    println!(
        "  Safety Policy         : {}",
        Style::green(&report.safety_mode)
    );

    println!("\nHost Memory & Pressure:");
    println!(
        "  Physical RAM Total    : {:>10} | Available: {:>10}",
        format_bytes(report.total_memory_bytes),
        format_bytes(report.available_memory_bytes)
    );
    println!(
        "  Swap Storage Total    : {:>10} | Used:      {:>10}",
        format_bytes(report.swap_total_bytes),
        format_bytes(report.swap_used_bytes)
    );

    if let Some(press) = report.memory_pressure {
        println!(
            "  Memory Stalls (PSI)   : 10s: {:>5} | 60s: {:>5} | Full Thrashing: {:>5}",
            format_percent(press.some_10s_pct),
            format_percent(press.some_60s_pct),
            format_percent(press.full_10s_pct)
        );
    } else {
        println!("  Memory Stalls (PSI)   : Not available (CONFIG_PSI unconfigured)");
    }

    println!("\nSupported Discovery Targets (12 Categories):");
    println!("  Agents: Google Antigravity, Claude Code, OpenAI Codex, Gemini CLI, Aider");
    println!(
        "  Tools : Node.js, npm, pnpm (Store Protection), Rust/Cargo, Python/pip, Git, LSP Servers, Dev Servers"
    );

    println!("\nScan Activity:");
    if let Some(ref scan) = report.last_completed_scan {
        println!(
            "  Last Completed Scan   : Completed via '{}'",
            scan.command_source
        );
        println!("  Scanned Root Path     : {}", scan.scan_root);
        println!(
            "  Identified Findings   : {} findings across {} inspected entries",
            scan.total_findings, scan.total_scanned
        );
        println!(
            "  Completeness Status   : {}",
            if scan.is_complete {
                Style::green("COMPLETE")
            } else {
                Style::yellow("INCOMPLETE (halted early)")
            }
        );
    } else {
        println!("  Last Completed Scan   : No previous scan available (run 'root scan' or 'root discover')");
    }

    println!("================================================================================");
}
