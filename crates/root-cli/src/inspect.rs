use root_core::{
    error::Result,
    model::{PressureMetrics, ProcessCandidate, SystemMemorySummary},
};
use root_platform::{
    traits::{EnvironmentProvider, ProcessProvider, ResourceAccountant},
    LinuxAccountant, LinuxEnvironment, LinuxProcess,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryInspectionReport {
    pub memory: SystemMemorySummary,
    pub pressure: Option<PressureMetrics>,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessInspectionReport {
    pub invoking_uid: u32,
    pub user_only_filter: bool,
    pub total_processes: usize,
    pub processes: Vec<ProcessCandidate>,
}

pub fn run_inspect_memory(json_output: bool) -> Result<()> {
    let accountant = LinuxAccountant::new();
    let mem = accountant.get_system_memory()?;
    let pressure = accountant.get_pressure_metrics()?;

    if json_output {
        let report = MemoryInspectionReport {
            memory: mem,
            pressure,
            note: "System memory values are read directly from /proc/meminfo. Cached memory includes reclaimable page cache and buffer storage.".to_string(),
        };
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| root_core::error::RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    println!("============================================================");
    println!(" ROOT LINUX MEMORY SUBSYSTEM INSPECTION");
    println!("============================================================");
    println!("Kernel Memory Distribution (/proc/meminfo):");
    println!(
        "  Total Physical RAM   : {:>10.2} GiB ({} bytes)",
        mem.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
        mem.total_bytes
    );
    println!(
        "  Available RAM        : {:>10.2} GiB ({} bytes)",
        mem.available_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
        mem.available_bytes
    );
    println!(
        "  Reclaimable Cache    : {:>10.2} GiB ({} bytes)",
        mem.cached_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
        mem.cached_bytes
    );
    println!(
        "  Free RAM (Unmapped)  : {:>10.2} GiB ({} bytes)",
        mem.free_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
        mem.free_bytes
    );

    let swap_used = mem.swap_total_bytes.saturating_sub(mem.swap_free_bytes);
    println!("\nSwap Space Accounting:");
    println!(
        "  Swap Total           : {:>10.2} GiB",
        mem.swap_total_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "  Swap Used            : {:>10.2} GiB",
        swap_used as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "  Swap Free            : {:>10.2} GiB",
        mem.swap_free_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    );

    if let Some(press) = pressure {
        println!("\nPressure Stall Information (/proc/pressure/memory):");
        println!("  Some Stalls (10s)    : {:>6.2}%", press.some_10s_pct);
        println!("  Some Stalls (60s)    : {:>6.2}%", press.some_60s_pct);
        println!("  Some Stalls (300s)   : {:>6.2}%", press.some_300s_pct);
        println!("  Full Thrashing (10s) : {:>6.2}%", press.full_10s_pct);
    } else {
        println!("\nPressure Stall Information: Not available (CONFIG_PSI not enabled)");
    }

    println!("\nTechnical Accounting Invariants:");
    println!("  - Available RAM represents kernel estimate of memory available without swapping.");
    println!(
        "  - Cached memory is not wasted; Linux automatically reclaims it under workload demand."
    );
    println!(
        "  - Naive summation of process RSS overcounts shared page cache and shared libraries."
    );
    println!("============================================================");

    Ok(())
}

pub fn run_inspect_processes(user_only: bool, json_output: bool) -> Result<()> {
    let env = LinuxEnvironment::new();
    let proc_provider = LinuxProcess::new();
    let current_uid = env.current_uid();

    let pids = proc_provider.list_pids()?;
    let mut candidates = Vec::new();

    for pid in pids {
        if let Ok(Some(candidate)) = proc_provider.inspect_process(pid) {
            if user_only && candidate.identity.real_uid != current_uid {
                continue;
            }
            candidates.push(candidate);
        }
    }

    if json_output {
        let report = ProcessInspectionReport {
            invoking_uid: current_uid,
            user_only_filter: user_only,
            total_processes: candidates.len(),
            processes: candidates,
        };
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| root_core::error::RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    println!("====================================================================================================");
    println!(" ROOT LINUX PROCESS INSPECTION (/proc)");
    println!("====================================================================================================");
    println!(
        "Filter Mode : {}",
        if user_only {
            format!("Current User Only (UID {})", current_uid)
        } else {
            "All Accessible Processes".to_string()
        }
    );
    println!("Total Found : {} processes\n", candidates.len());

    println!(
        " {:>6} | {:>6} | {:>4} | {:>10} | {:>10} | {:<20} | {:<12} | {:<20}",
        "PID", "PPID", "UID", "RSS", "PSS", "COMMAND", "STATE", "AGENT / STATUS"
    );
    println!("-------+--------+------+------------+------------+----------------------+--------------+--------------------");

    for c in &candidates {
        let rss_str = format_bytes(c.memory.rss_bytes);
        let pss_str = c
            .memory
            .pss_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "-".to_string());
        let state_str = format!("{:?}", c.state);
        let status_desc = if c.is_abandoned {
            format!(
                "ABANDONED ({})",
                c.associated_agent.as_deref().unwrap_or("Dev Worker")
            )
        } else if let Some(ref agent) = c.associated_agent {
            format!("Active ({})", agent)
        } else if c.is_reparented_to_init {
            "Reparented to PID 1".to_string()
        } else {
            "Active".to_string()
        };

        let cmd_display = if c.identity.name.len() > 20 {
            format!("{}...", &c.identity.name[..17])
        } else {
            c.identity.name.clone()
        };

        println!(
            " {:>6} | {:>6} | {:>4} | {:>10} | {:>10} | {:<20} | {:<12} | {}",
            c.identity.pid,
            c.identity.ppid,
            c.identity.real_uid,
            rss_str,
            pss_str,
            cmd_display,
            state_str,
            status_desc
        );
    }

    println!("====================================================================================================");
    println!("Safety Notice:");
    println!("  - Processes reparented to PID 1 are NOT classified as abandoned without terminal detachment");
    println!("    and corroborated development tool signatures.");
    println!("  - Command arguments are sanitized to prevent credential and token exposure in diagnostic logs.");
    println!(
        "  - Root Guardian strictly prohibits process signaling or termination during Phase 02."
    );
    println!("====================================================================================================");

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GiB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}
