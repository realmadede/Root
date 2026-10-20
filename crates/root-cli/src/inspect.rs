use root_core::{
    error::{Result, RootError},
    model::{FilesystemUsage, PressureMetrics, ProcessCandidate, SystemMemorySummary},
};
use root_guardian::{JournalRecord, RecoveryJournal, TransactionState};
use root_platform::{
    traits::{EnvironmentProvider, FilesystemProvider, ProcessProvider, ResourceAccountant},
    LinuxAccountant, LinuxEnvironment, LinuxFilesystem, LinuxProcess, TraversalOptions,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::terminal::{format_bytes, format_percent, truncate_middle, Style};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInspectionReport {
    pub memory: SystemMemorySummary,
    pub pressure: Option<PressureMetrics>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInspectionReport {
    pub invoking_uid: u32,
    pub user_only_filter: bool,
    pub total_processes: usize,
    pub processes: Vec<ProcessCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePathAccounting {
    pub target_path: String,
    pub total_entries: u64,
    pub apparent_bytes: u64,
    pub allocated_bytes: u64,
    pub sparse_files_count: u64,
    pub multi_link_files_count: u64,
    pub shared_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageInspectionReport {
    pub target_path: String,
    pub filesystem_usage: FilesystemUsage,
    pub directory_accounting: Option<StoragePathAccounting>,
    pub technical_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInspectionReport {
    pub journal_path: String,
    pub total_records: usize,
    pub interrupted_count: usize,
    pub records: Vec<JournalRecord>,
    pub interrupted_transactions: Vec<JournalRecord>,
    pub safety_policy: String,
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
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    println!("================================================================================");
    println!(" {}", Style::bold("ROOT LINUX MEMORY SUBSYSTEM INSPECTION"));
    println!("================================================================================");
    println!("Kernel Memory Distribution (/proc/meminfo):");
    println!(
        "  Total Physical RAM   : {:>10} ({} bytes)",
        format_bytes(mem.total_bytes),
        mem.total_bytes
    );
    println!(
        "  Available RAM        : {:>10} ({} bytes)",
        format_bytes(mem.available_bytes),
        mem.available_bytes
    );
    println!(
        "  Reclaimable Cache    : {:>10} ({} bytes)",
        format_bytes(mem.cached_bytes),
        mem.cached_bytes
    );
    println!(
        "  Free RAM (Unmapped)  : {:>10} ({} bytes)",
        format_bytes(mem.free_bytes),
        mem.free_bytes
    );

    let swap_used = mem.swap_total_bytes.saturating_sub(mem.swap_free_bytes);
    println!("\nSwap Space Accounting:");
    println!(
        "  Swap Total           : {:>10}",
        format_bytes(mem.swap_total_bytes)
    );
    println!("  Swap Used            : {:>10}", format_bytes(swap_used));
    println!(
        "  Swap Free            : {:>10}",
        format_bytes(mem.swap_free_bytes)
    );

    if let Some(press) = pressure {
        println!("\nPressure Stall Information (/proc/pressure/memory):");
        println!(
            "  Some Stalls (10s)    : {:>6}",
            format_percent(press.some_10s_pct)
        );
        println!(
            "  Some Stalls (60s)    : {:>6}",
            format_percent(press.some_60s_pct)
        );
        println!(
            "  Some Stalls (300s)   : {:>6}",
            format_percent(press.some_300s_pct)
        );
        println!(
            "  Full Thrashing (10s) : {:>6}",
            format_percent(press.full_10s_pct)
        );
    } else {
        println!("\nPressure Stall Information: Not available (CONFIG_PSI not enabled)");
    }

    println!("\nTechnical Accounting Invariants:");
    println!(
        "  - Available RAM represents the kernel estimate of memory available without swapping."
    );
    println!(
        "  - Cached memory is not wasted; Linux automatically reclaims it under workload demand."
    );
    println!(
        "  - Naive summation of process RSS overcounts shared page cache and dynamic libraries."
    );
    println!("================================================================================");

    Ok(())
}

pub fn run_inspect_processes(user_only: bool, json_output: bool) -> Result<()> {
    let env = LinuxEnvironment::new();
    let proc_provider = LinuxProcess::new();
    let invoking_uid = env.current_uid();

    let pids = proc_provider.list_pids()?;
    let mut processes = Vec::new();

    for pid in pids {
        if let Ok(Some(candidate)) = proc_provider.inspect_process(pid) {
            if user_only && candidate.identity.real_uid != invoking_uid {
                continue;
            }
            processes.push(candidate);
        }
    }

    processes.sort_by_key(|p| p.identity.pid);

    if json_output {
        let report = ProcessInspectionReport {
            invoking_uid,
            user_only_filter: user_only,
            total_processes: processes.len(),
            processes,
        };
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    println!("================================================================================");
    println!(" {}", Style::bold("ROOT RUNNING PROCESS INSPECTION"));
    println!(
        " Filter       : {}",
        if user_only {
            "Current User Only"
        } else {
            "All Readable Processes"
        }
    );
    println!(" Total Found  : {}", processes.len());
    println!("================================================================================");
    println!(
        " {:>7} | {:>7} | {:>6} | {:<22} | {:>9} | {:<16}",
        "PID", "PPID", "UID", "Process Name", "RSS", "State"
    );
    println!("--------+---------+--------+------------------------+-----------+-----------------");

    for p in &processes {
        let rss_str = format_bytes(p.memory.rss_bytes);
        let name_trunc = truncate_middle(&p.identity.name, 22);
        let state_str = format!("{:?}", p.state);

        println!(
            " {:>7} | {:>7} | {:>6} | {:<22} | {:>9} | {:<16}",
            p.identity.pid, p.identity.ppid, p.identity.real_uid, name_trunc, rss_str, state_str
        );
    }

    println!("================================================================================");
    println!(" Technical Note: PSS/USS granular memory metrics require reading /proc/[pid]/smaps_rollup.");
    println!(" Reparented processes (PPID 1) are not automatically abandoned without lifecycle corroboration.");
    println!("================================================================================");

    Ok(())
}

pub fn run_inspect_storage(target_path: Option<PathBuf>, json_output: bool) -> Result<()> {
    let fs = LinuxFilesystem::new();
    let env = LinuxEnvironment::new();

    let path =
        target_path.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| env.home_dir()));

    if !path.exists() {
        return Err(RootError::InvalidPath(format!(
            "Specified path '{}' does not exist.",
            path.display()
        )));
    }

    let fs_usage = fs.get_filesystem_usage(&path)?;

    // If path is a directory, compute bounded storage breakdown
    let directory_accounting = if path.is_dir() {
        let options = TraversalOptions {
            max_depth: 16,
            max_entries: 50_000,
            allow_cross_device: false,
            timeout: Some(std::time::Duration::from_secs(15)),
        };

        if let Ok(outcome) = fs.traverse(&path, &options) {
            let mut apparent_bytes = 0u64;
            let mut allocated_bytes = 0u64;
            let mut sparse_count = 0u64;
            let mut multi_link_count = 0u64;
            let mut shared_bytes = 0u64;

            for entry in &outcome.entries {
                apparent_bytes += entry.metadata.storage.bytes;
                allocated_bytes += entry.metadata.storage.allocated_bytes;
                if entry.metadata.storage.is_sparse {
                    sparse_count += 1;
                }
                if entry.metadata.storage.is_multi_link {
                    multi_link_count += 1;
                    shared_bytes += entry.metadata.storage.shared_bytes;
                }
            }

            Some(StoragePathAccounting {
                target_path: path.display().to_string(),
                total_entries: outcome.entries.len() as u64,
                apparent_bytes,
                allocated_bytes,
                sparse_files_count: sparse_count,
                multi_link_files_count: multi_link_count,
                shared_bytes,
            })
        } else {
            None
        }
    } else {
        None
    };

    let technical_notes = vec![
        "Filesystem capacity and free space are read via kernel statvfs syscall.".to_string(),
        "Apparent (logical) size represents byte length; allocated size represents actual disk blocks.".to_string(),
        "Hard-linked files sharing an inode are tracked separately to avoid double-counting shared storage.".to_string(),
        "Speculative reclaimable estimates are upper bounds and not guaranteed recoverable space.".to_string(),
    ];

    let report = StorageInspectionReport {
        target_path: path.display().to_string(),
        filesystem_usage: fs_usage,
        directory_accounting,
        technical_notes,
    };

    if json_output {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    render_storage_terminal(&report);
    Ok(())
}

fn render_storage_terminal(report: &StorageInspectionReport) {
    println!("================================================================================");
    println!(
        " {}",
        Style::bold("ROOT STORAGE & FILESYSTEM ALLOCATION AUDIT")
    );
    println!(" Target Path: {}", report.target_path);
    println!("================================================================================");
    println!("Filesystem Capacity (statvfs):");
    println!(
        "  Total Filesystem Size : {:>10} ({} bytes)",
        format_bytes(report.filesystem_usage.total_bytes),
        report.filesystem_usage.total_bytes
    );
    println!(
        "  Available for User    : {:>10} ({} bytes)",
        format_bytes(report.filesystem_usage.available_bytes),
        report.filesystem_usage.available_bytes
    );
    println!(
        "  Free Disk Blocks      : {:>10} ({} bytes)",
        format_bytes(report.filesystem_usage.free_bytes),
        report.filesystem_usage.free_bytes
    );
    println!(
        "  Total Inodes          : {:>10} | Free Inodes: {:>10}",
        report.filesystem_usage.total_inodes, report.filesystem_usage.free_inodes
    );

    if let Some(ref dir) = report.directory_accounting {
        println!("\nDirectory Tree Accounting (Bounded Traversal):");
        println!("  Inspected Entries     : {:>10}", dir.total_entries);
        println!(
            "  Apparent (Logical)    : {:>10} (Sum of logical file lengths)",
            format_bytes(dir.apparent_bytes)
        );
        println!(
            "  Allocated Disk Blocks : {:>10} (Physical 512-byte blocks allocated)",
            format_bytes(dir.allocated_bytes)
        );
        println!(
            "  Sparse Files Detected : {:>10} (Physical allocation < logical size)",
            dir.sparse_files_count
        );
        println!(
            "  Multi-Link Files      : {:>10} (Sharing inodes across directory entries)",
            dir.multi_link_files_count
        );
        println!(
            "  Shared Inode Storage  : {:>10} (Deduplicated; excluded from individual reclaim)",
            format_bytes(dir.shared_bytes)
        );
    }

    println!("\nTechnical Accounting Invariants:");
    for note in &report.technical_notes {
        println!("  - {}", note);
    }
    println!("================================================================================");
}

pub fn run_inspect_transactions(journal_path: Option<PathBuf>, json_output: bool) -> Result<()> {
    let resolved_journal = if let Some(p) = journal_path {
        p
    } else {
        let default_path = PathBuf::from(".root_journal");
        if default_path.exists() {
            default_path
        } else {
            return Err(RootError::InvalidPath(
                "No journal path provided and default '.root_journal' does not exist in current directory.\nSpecify a synthetic test journal with '--journal-path <path>'.".to_string(),
            ));
        }
    };

    let journal = RecoveryJournal::new(&resolved_journal)?;
    let records = journal.read_all()?;
    let interrupted = journal.get_interrupted_transactions()?;

    let report = TransactionInspectionReport {
        journal_path: resolved_journal.display().to_string(),
        total_records: records.len(),
        interrupted_count: interrupted.len(),
        records: records.clone(),
        interrupted_transactions: interrupted.clone(),
        safety_policy: "Quarantine transactions are restricted to isolated synthetic test fixtures in Phase 05. Production cleanup is disabled.".to_string(),
    };

    if json_output {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    println!("================================================================================");
    println!(" {}", Style::bold("ROOT TRANSACTION JOURNAL DIAGNOSTICS"));
    println!(" Journal Path : {}", report.journal_path);
    println!(" Safety Policy: {}", Style::green(&report.safety_policy));
    println!(" Total Records: {}", report.total_records);
    println!(
        " Interrupted  : {}",
        if report.interrupted_count > 0 {
            Style::yellow(&format!(
                "{} (Intervention Required)",
                report.interrupted_count
            ))
        } else {
            Style::green("0 (All Transactions In Terminal States)")
        }
    );
    println!("================================================================================");
    println!(
        " {:<12} | {:<16} | {:>9} | {:<24} | {:<14}",
        "Transaction", "State", "Size", "Original Path", "Result"
    );
    println!(
        "-------------+------------------+-----------+--------------------------+---------------"
    );

    for r in &records {
        let state_badge = match r.state {
            TransactionState::Verified => Style::green("[VERIFIED]"),
            TransactionState::Restored => Style::green("[RESTORED]"),
            TransactionState::Failed => Style::red("[FAILED]"),
            TransactionState::RecoveryRequired => Style::yellow("[RECOVERY]"),
            _ => Style::cyan(&format!("[{:?}]", r.state)),
        };

        let path_trunc = truncate_middle(&r.original_path.to_string_lossy(), 24);
        let result_str = if let Some(ref fail) = r.failure_reason {
            truncate_middle(fail, 14)
        } else {
            "Success".to_string()
        };

        println!(
            " {:<12} | {:<16} | {:>9} | {:<24} | {:<14}",
            truncate_middle(&r.transaction_id, 12),
            state_badge,
            format_bytes(r.size_bytes),
            path_trunc,
            result_str
        );
    }

    if !interrupted.is_empty() {
        println!("\n{}", Style::yellow("INTERRUPTED TRANSACTIONS DETECTED:"));
        for item in &interrupted {
            println!(
                "  - ID: {} | State: {:?} | Path: {}",
                item.transaction_id,
                item.state,
                item.original_path.display()
            );
        }
    }

    println!("================================================================================");
    println!(" Note: Transaction records are append-only and synchronized via sync_data().");
    println!(" Production mutation remains strictly disabled.");
    println!("================================================================================");

    Ok(())
}
