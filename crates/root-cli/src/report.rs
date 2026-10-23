use root_core::{
    error::{Result, RootError},
    model::{FilesystemUsage, PlatformCapabilities, PressureMetrics, SystemMemorySummary},
    DiscoveryContext, DiscoveryEngine, DiscoveryFilter, DiscoverySummary, FindingTarget,
    ProposedAction, ProtectionTier, SafetyDecision,
};
use root_guardian::GuardianPolicy;
use root_platform::{
    traits::{EnvironmentProvider, FilesystemProvider, ProcessProvider, ResourceAccountant},
    NativeAccountant, NativeEnvironment, NativeFilesystem, NativeProcess, TraversalOptions,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::terminal::{format_bytes, format_percent, Style};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveReport {
    pub report_version: String,
    pub timestamp_epoch_secs: i64,
    pub operating_system: String,
    pub kernel_version: String,
    pub invoking_uid: u32,
    pub capabilities: PlatformCapabilities,
    pub memory: SystemMemorySummary,
    pub memory_pressure: Option<PressureMetrics>,
    pub filesystem_usage: FilesystemUsage,
    pub discovery_summary: DiscoverySummary,
    pub safety_guarantees: Vec<String>,
}

pub fn run_report(target_path: Option<PathBuf>, json_output: bool) -> Result<()> {
    let env = NativeEnvironment::new();
    let fs = NativeFilesystem::new();
    let accountant = NativeAccountant::new();
    let proc_provider = NativeProcess::new();
    let policy = GuardianPolicy::new();

    let current_uid = env.current_uid();
    let capabilities = accountant.get_capabilities()?;
    let memory = accountant.get_system_memory()?;
    let memory_pressure = accountant.get_pressure_metrics()?;

    let home = env.home_dir();
    let scan_roots = if let Some(p) = target_path {
        vec![p]
    } else {
        let mut roots = Vec::new();
        for dir in &[".gemini", ".claude", ".cache/openai"] {
            let candidate = home.join(dir);
            if candidate.exists() {
                roots.push(candidate);
            }
        }
        roots
    };

    let fs_target = scan_roots.first().cloned().unwrap_or_else(|| home.clone());
    let fs_usage = fs.get_filesystem_usage(&fs_target).unwrap_or_default();

    // Active processes for correlation
    let mut active_processes = Vec::new();
    if let Ok(pids) = proc_provider.list_pids() {
        for pid in pids {
            if let Ok(Some(candidate)) = proc_provider.inspect_process(pid) {
                active_processes.push(candidate);
            }
        }
    }

    // Defensive traversal
    let traversal_options = TraversalOptions {
        max_depth: 16,
        max_entries: 50_000,
        allow_cross_device: false,
        timeout: Some(std::time::Duration::from_secs(20)),
    };

    let mut all_entries = Vec::new();
    let mut total_skipped = 0u64;
    let mut is_complete = true;
    let mut incomplete_reason = None;

    for root in &scan_roots {
        if let Ok(outcome) = fs.traverse(root, &traversal_options) {
            total_skipped += outcome.metrics.skipped_count;
            if !outcome.metrics.is_complete {
                is_complete = false;
                incomplete_reason = outcome.metrics.incomplete_reason;
            }
            for entry in outcome.entries {
                all_entries.push((entry.path, entry.metadata, entry.dev, entry.ino));
            }
        } else {
            total_skipped += 1;
        }
    }

    let filter = DiscoveryFilter::default();
    let ctx = DiscoveryContext {
        root_paths: scan_roots.clone(),
        filter: &filter,
        current_uid,
        active_processes: &active_processes,
        capabilities: capabilities.clone(),
        skipped_count: total_skipped,
        is_complete,
        incomplete_reason,
    };

    let disc_report =
        DiscoveryEngine::evaluate_findings(&all_entries, &ctx, &|target: &FindingTarget,
                                                                 tier: ProtectionTier,
                                                                 action: ProposedAction,
                                                                 uid: u32|
         -> SafetyDecision {
            policy.evaluate(target, tier, action, uid)
        })?;

    let safety_guarantees = vec![
        "Deterministic local-first execution: zero cloud telemetry and zero external LLM runtimes.".to_string(),
        "Production read-only enforcement: all filesystem mutations rejected; quarantine isolated to synthetic fixtures.".to_string(),
        "Least-privilege execution: completely unprivileged user-space operation with zero sudo/root requirements.".to_string(),
        "Strict content privacy: file contents, API credentials, and session histories are never logged or exported.".to_string(),
    ];

    let comp_report = ComprehensiveReport {
        report_version: "1.0.0".to_string(),
        timestamp_epoch_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        operating_system: capabilities.os_name.clone(),
        kernel_version: capabilities.kernel_version.clone(),
        invoking_uid: current_uid,
        capabilities,
        memory,
        memory_pressure,
        filesystem_usage: fs_usage,
        discovery_summary: disc_report.summary,
        safety_guarantees,
    };

    if json_output {
        let json_str = serde_json::to_string_pretty(&comp_report)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    render_comprehensive_terminal(&comp_report, &scan_roots);
    Ok(())
}

fn render_comprehensive_terminal(report: &ComprehensiveReport, scan_roots: &[PathBuf]) {
    println!("================================================================================");
    println!(
        " {}",
        Style::bold("ROOT COMPREHENSIVE RESOURCE AUDIT REPORT")
    );
    println!(
        " Version: v{} | Timestamp: {} (Epoch)",
        report.report_version, report.timestamp_epoch_secs
    );
    println!("================================================================================");

    println!("1. Host Identity & Kernel Platform:");
    println!(
        "   OS / Kernel          : {} (Kernel {})",
        report.operating_system, report.kernel_version
    );
    println!("   Invoking UID         : {}", report.invoking_uid);
    println!(
        "   Available RAM        : {} / Total {}",
        format_bytes(report.memory.available_bytes),
        format_bytes(report.memory.total_bytes)
    );
    if let Some(press) = report.memory_pressure {
        println!(
            "   Memory Pressure (PSI): 10s: {} | 60s: {} | Full: {}",
            format_percent(press.some_10s_pct),
            format_percent(press.some_60s_pct),
            format_percent(press.full_10s_pct)
        );
    }

    println!("\n2. Filesystem Capacity:");
    println!(
        "   Filesystem Total     : {:>10} | Available: {:>10}",
        format_bytes(report.filesystem_usage.total_bytes),
        format_bytes(report.filesystem_usage.available_bytes)
    );
    println!(
        "   Inodes Total / Free  : {} / {}",
        report.filesystem_usage.total_inodes, report.filesystem_usage.free_inodes
    );

    println!("\n3. Agent & Tool Discovery Audit:");
    println!(
        "   Scanned Roots        : {}",
        scan_roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "   Total Findings       : {:>8}",
        report.discovery_summary.total_findings
    );
    println!(
        "   Active In-Use        : {:>8} (Live locks or active processes)",
        report.discovery_summary.active_lifecycle_count
    );
    println!(
        "   Persistent Records   : {:>8} (Session state, credentials, configs)",
        report.discovery_summary.persistent_lifecycle_count
    );
    println!(
        "   Dormant Transient    : {:>8} (Caches, scratchpads, old logs)",
        report.discovery_summary.dormant_transient_count
    );
    println!(
        "   Uncertain Lifecycle  : {:>8} (Defaults to protection)",
        report.discovery_summary.unknown_lifecycle_count
    );
    println!(
        "   Speculative Savings  : {:>8} (Estimated upper bound; not guaranteed recoverable)",
        format_bytes(report.discovery_summary.reclaimable_bytes_estimate)
    );

    println!("\n4. Security Boundaries & Architectural Guarantees:");
    for guarantee in &report.safety_guarantees {
        println!("   - {}", Style::green(guarantee));
    }

    println!("================================================================================");
}
