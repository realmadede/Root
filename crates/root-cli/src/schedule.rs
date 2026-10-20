use root_core::{
    discovery::{DiscoveryContext, DiscoveryEngine, DiscoveryFilter},
    error::{Result, RootError},
    model::{
        validate_executable, FindingTarget, InspectionProfile, ProposedAction, ProtectionTier,
        SafetyDecision, ScheduleConfig, ScheduleHistoryEntry, ScheduleInterval, ScheduleRunStatus,
        ScheduleStatus,
    },
};
use root_guardian::policy::GuardianPolicy;
use root_platform::{
    linux::{
        DesktopNotifier, LinuxAccountant, LinuxEnvironment, LinuxFilesystem, LinuxProcess,
        LinuxScheduler, TraversalOptions,
    },
    traits::{EnvironmentProvider, ProcessProvider, ResourceAccountant},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};

use crate::terminal::Style;

/// Options for enabling periodic background inspections.
#[derive(Debug, Clone)]
pub struct ScheduleEnableOptions {
    pub interval: Option<String>,
    pub profile: Option<String>,
    pub targets: Vec<PathBuf>,
    pub notify: bool,
    pub catch_up: bool,
    pub ac_only: bool,
    pub max_duration: Option<u64>,
    pub max_entries: Option<usize>,
    pub max_depth: Option<usize>,
    pub exec_path: Option<PathBuf>,
    pub non_interactive: bool,
}

fn get_state_dir() -> PathBuf {
    if let Ok(state_home) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(state_home).join("root")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("root")
    } else {
        PathBuf::from("/tmp/root_state")
    }
}

fn get_config_dir() -> PathBuf {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(config_home).join("root")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config").join("root")
    } else {
        PathBuf::from("/tmp/root_config")
    }
}

pub fn get_schedule_config_path() -> PathBuf {
    get_config_dir().join("schedule.json")
}

pub fn get_schedule_history_path() -> PathBuf {
    get_state_dir().join("schedule_history.json")
}

pub fn get_schedule_lock_path() -> PathBuf {
    get_state_dir().join("schedule.lock")
}

/// Loads schedule configuration from disk, returning defaults if absent or malformed.
pub fn load_schedule_config() -> ScheduleConfig {
    let path = get_schedule_config_path();
    if !path.exists() {
        return ScheduleConfig::default();
    }

    match File::open(&path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            match serde_json::from_reader(reader) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!(
                        "Warning: Malformed schedule configuration at '{}': {}. Reverting to defaults.",
                        path.display(),
                        e
                    );
                    ScheduleConfig::default()
                }
            }
        }
        Err(_) => ScheduleConfig::default(),
    }
}

/// Atomically persists schedule configuration to disk with staged writes.
pub fn save_schedule_config(config: &ScheduleConfig) -> Result<()> {
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir).map_err(|e| RootError::Io {
        path: config_dir.clone(),
        source: e,
    })?;

    let path = get_schedule_config_path();
    let serialized = serde_json::to_string_pretty(config)
        .map_err(|e| RootError::Serialization(e.to_string()))?;

    let temp_path = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|e| RootError::Io {
            path: temp_path.clone(),
            source: e,
        })?;

    file.write_all(serialized.as_bytes())
        .map_err(|e| RootError::Io {
            path: temp_path.clone(),
            source: e,
        })?;
    file.sync_all().map_err(|e| RootError::Io {
        path: temp_path.clone(),
        source: e,
    })?;

    fs::rename(&temp_path, &path).map_err(|e| RootError::Io { path, source: e })?;

    Ok(())
}

/// Loads execution history journal from disk, returning an empty list if absent or corrupt.
pub fn load_schedule_history() -> Vec<ScheduleHistoryEntry> {
    let path = get_schedule_history_path();
    if !path.exists() {
        return Vec::new();
    }

    match File::open(&path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            match serde_json::from_reader(reader) {
                Ok(entries) => entries,
                Err(e) => {
                    eprintln!(
                        "Warning: Malformed schedule history at '{}': {}. Preserving corrupt file and starting fresh.",
                        path.display(),
                        e
                    );
                    let corrupt_backup = path.with_extension("corrupt");
                    let _ = fs::rename(&path, &corrupt_backup);
                    Vec::new()
                }
            }
        }
        Err(_) => Vec::new(),
    }
}

/// Appends an entry to schedule history, pruning records exceeding retention bounds.
pub fn append_schedule_history(entry: ScheduleHistoryEntry) -> Result<()> {
    let state_dir = get_state_dir();
    fs::create_dir_all(&state_dir).map_err(|e| RootError::Io {
        path: state_dir.clone(),
        source: e,
    })?;

    let mut history = load_schedule_history();
    history.push(entry);

    // Prune history to 50 most recent records
    const MAX_HISTORY_RECORDS: usize = 50;
    if history.len() > MAX_HISTORY_RECORDS {
        let drain_count = history.len() - MAX_HISTORY_RECORDS;
        history.drain(0..drain_count);
    }

    let path = get_schedule_history_path();
    let serialized = serde_json::to_string_pretty(&history)
        .map_err(|e| RootError::Serialization(e.to_string()))?;

    let temp_path = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|e| RootError::Io {
            path: temp_path.clone(),
            source: e,
        })?;

    file.write_all(serialized.as_bytes())
        .map_err(|e| RootError::Io {
            path: temp_path.clone(),
            source: e,
        })?;
    file.sync_all().map_err(|e| RootError::Io {
        path: temp_path.clone(),
        source: e,
    })?;

    fs::rename(&temp_path, &path).map_err(|e| RootError::Io { path, source: e })?;

    Ok(())
}

/// Queries current status of Mode B scheduled inspections.
pub fn get_schedule_status() -> ScheduleStatus {
    let config = load_schedule_config();
    let scheduler = LinuxScheduler::new();
    let history = load_schedule_history();

    let systemd_accessible = scheduler.is_systemd_user_available();
    let timer_active = scheduler.is_timer_active();
    let next_trigger_utc = scheduler.query_next_trigger();

    let last_entry = history.last();
    let last_attempt_epoch_secs = last_entry.map(|e| e.timestamp_epoch_secs);
    let last_success_epoch_secs = history
        .iter()
        .rev()
        .find(|e| e.status == ScheduleRunStatus::Completed)
        .map(|e| e.timestamp_epoch_secs);
    let last_failure_reason = history
        .iter()
        .rev()
        .find(|e| {
            e.status == ScheduleRunStatus::Failed || e.status == ScheduleRunStatus::Incomplete
        })
        .and_then(|e| e.error_message.clone());

    ScheduleStatus {
        enabled: config.enabled,
        interval: config.interval,
        profile: config.profile,
        budget: config.budget,
        targets: config.targets,
        notifications: config.notifications,
        catch_up: config.catch_up,
        ac_power_only: config.ac_power_only,
        systemd_accessible,
        timer_active,
        next_trigger_utc,
        last_attempt_epoch_secs,
        last_success_epoch_secs,
        last_failure_reason,
        safety_policy: "Production Read-Only (Quarantine & Process Termination Prohibited)"
            .to_string(),
    }
}

/// Displays scheduled inspection status in the terminal.
pub fn run_schedule_status(json_output: bool) -> Result<()> {
    let status = get_schedule_status();

    if json_output {
        let json_str = serde_json::to_string_pretty(&status)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    render_schedule_status_terminal(&status);
    Ok(())
}

fn render_schedule_status_terminal(status: &ScheduleStatus) {
    println!("================================================================================");
    println!(
        " {}",
        Style::bold("ROOT SCHEDULED INSPECTION STATUS (MODE B)")
    );
    println!("================================================================================");
    println!(
        "  Schedule State        : {}",
        if status.enabled {
            Style::green("[ACTIVE]")
        } else {
            Style::dim("[DISABLED by default]")
        }
    );
    println!(
        "  Inspection Profile    : {}",
        status.profile.display_badge()
    );
    println!(
        "  Calendar Interval     : {}",
        status.interval.display_badge()
    );
    println!(
        "  Catch-Up on Resume    : {}",
        if status.catch_up {
            "Enabled"
        } else {
            "Disabled (Default)"
        }
    );
    println!(
        "  Power Policy          : {}",
        if status.ac_power_only {
            "AC Power Only (Skip on battery)"
        } else {
            "Any Power Source"
        }
    );
    println!(
        "  systemd User Manager  : {}",
        if status.systemd_accessible {
            Style::green("Accessible")
        } else {
            Style::red("Unavailable / Inactive")
        }
    );
    println!(
        "  Timer Unit Status     : {}",
        if status.timer_active {
            Style::green("Active (root-inspect.timer)")
        } else {
            Style::yellow("Inactive / Stopped")
        }
    );
    println!(
        "  Next Scheduled Run    : {}",
        status
            .next_trigger_utc
            .as_deref()
            .unwrap_or("None scheduled / timer disabled")
    );
    println!(
        "  Desktop Notifications : {}",
        if status.notifications {
            "Enabled"
        } else {
            "Disabled"
        }
    );

    println!("\nResource Budgets (Profile Limits):");
    println!("  Max Traversal Depth   : {}", status.budget.max_depth);
    println!("  Max Scanned Entries   : {}", status.budget.max_entries);
    println!(
        "  Execution Timeout     : {}s",
        status.budget.max_duration_secs
    );
    if let Some(mem) = status.budget.max_memory_bytes {
        println!("  Memory Limit (RSS)    : {} MiB", mem / (1024 * 1024));
    }

    println!("\nConfigured Target Paths:");
    if status.targets.is_empty() {
        println!("  (No targets configured; run 'root schedule enable --targets <path>')");
    } else {
        for target in &status.targets {
            let exists_badge = if target.exists() {
                Style::green("[EXISTS]")
            } else {
                Style::red("[MISSING]")
            };
            println!("  - {} {}", target.display(), exists_badge);
        }
    }

    println!("\nRecent Scheduled Execution:");
    if let Some(epoch) = status.last_attempt_epoch_secs {
        println!("  Last Execution Time   : Epoch {}s", epoch);
    } else {
        println!("  Last Execution Time   : (No scheduled runs recorded)");
    }
    if let Some(epoch) = status.last_success_epoch_secs {
        println!("  Last Successful Run   : Epoch {}s", epoch);
    }
    if let Some(ref reason) = status.last_failure_reason {
        println!("  Last Anomaly Reason   : {}", Style::yellow(reason));
    }

    println!("\nSafety Governance:");
    println!(
        "  Policy Invariant      : {}",
        Style::green(&status.safety_policy)
    );
    println!("  Disable Command       : Run 'root schedule disable' to stop future runs");
    println!("================================================================================");
}

/// Lists configured inspection targets and parameters.
pub fn run_schedule_list() -> Result<()> {
    let config = load_schedule_config();

    println!("================================================================================");
    println!(" {}", Style::bold("ROOT SCHEDULED INSPECTION PROFILES"));
    println!("================================================================================");
    println!(
        "  Active State          : {}",
        if config.enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!(
        "  Profile               : {}",
        config.profile.display_badge()
    );
    println!(
        "  Interval              : {}",
        config.interval.display_badge()
    );
    println!(
        "  Catch-Up on Wake      : {}",
        if config.catch_up {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!(
        "  Power Policy          : {}",
        if config.ac_power_only {
            "AC Only"
        } else {
            "Any"
        }
    );
    println!(
        "  Notifications         : {}",
        if config.notifications {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!(
        "  Timeout Limit         : {}s",
        config.budget.max_duration_secs
    );
    println!("  Entry Limit           : {}", config.budget.max_entries);
    println!("  Depth Limit           : {}", config.budget.max_depth);
    println!("\nConfigured Target Paths:");
    if config.targets.is_empty() {
        println!("  (No targets configured)");
    } else {
        for t in &config.targets {
            println!("  - {}", t.display());
        }
    }
    println!("================================================================================");

    Ok(())
}

/// Removes all Root systemd user units and deletes schedule configuration.
pub fn run_schedule_remove() -> Result<()> {
    let scheduler = LinuxScheduler::new();
    let _ = scheduler.disable_timer();
    let _ = scheduler.uninstall_units();

    let config_path = get_schedule_config_path();
    if config_path.exists() {
        let _ = fs::remove_file(&config_path);
    }

    println!(
        "{}",
        Style::green("Root systemd user units and schedule configuration completely removed.")
    );

    Ok(())
}

/// Enables periodic scheduled inspections with explicit parameters and validation.
pub fn run_schedule_enable(opts: ScheduleEnableOptions) -> Result<()> {
    let mut config = load_schedule_config();

    // 1. Resolve interval
    let interval = if let Some(ref s) = opts.interval {
        ScheduleInterval::from_filter(s).ok_or_else(|| {
            RootError::ScheduleError(format!(
                "Invalid interval '{}'. Expected 'hourly', 'daily', 'weekly', or valid OnCalendar spec.",
                s
            ))
        })?
    } else if config.interval != ScheduleInterval::Daily {
        config.interval.clone()
    } else {
        ScheduleInterval::Daily
    };

    // 2. Resolve profile
    let profile = if let Some(ref p) = opts.profile {
        InspectionProfile::from_str_name(p).ok_or_else(|| {
            RootError::ScheduleError(format!(
                "Invalid profile '{}'. Expected 'lightweight', 'standard', or 'comprehensive'.",
                p
            ))
        })?
    } else {
        config.profile
    };

    // 3. Resolve resource budget
    let mut budget = profile.default_budget();
    if let Some(dur) = opts.max_duration {
        budget.max_duration_secs = dur;
    }
    if let Some(entries) = opts.max_entries {
        budget.max_entries = entries;
    }
    if let Some(depth) = opts.max_depth {
        budget.max_depth = depth;
    }

    // 4. Resolve approved targets (do not automatically expand or invent targets)
    let resolved_targets = if !opts.targets.is_empty() {
        opts.targets
    } else if !config.targets.is_empty() {
        config.targets.clone()
    } else {
        return Err(RootError::ScheduleError(
            "Cannot enable scheduled inspection without explicit approved target directories. Supply at least one target directory via '--targets <path>'."
                .to_string(),
        ));
    };

    // Validate all targets
    for target in &resolved_targets {
        ScheduleConfig::validate_target(target)?;
    }

    // 5. Resolve and validate executable path
    let exec_path = if let Some(ref p) = opts.exec_path {
        validate_executable(p)?
    } else {
        let current = std::env::current_exe().map_err(|e| RootError::Io {
            path: PathBuf::from("current_exe"),
            source: e,
        })?;
        validate_executable(&current)?
    };

    // 6. Pre-activation confirmation
    if !opts.non_interactive {
        println!(
            "================================================================================"
        );
        println!(
            " {}",
            Style::bold("CONFIRM SCHEDULED INSPECTION ACTIVATION (MODE B)")
        );
        println!(
            "================================================================================"
        );
        println!("Configuration Preview:");
        println!("  Inspection Profile    : {}", profile.display_badge());
        println!("  Frequency Interval    : {}", interval.display_badge());
        println!(
            "  Notifications         : {}",
            if opts.notify { "Enabled" } else { "Disabled" }
        );
        println!(
            "  Catch-Up on Wake      : {}",
            if opts.catch_up {
                "Enabled"
            } else {
                "Disabled (Default)"
            }
        );
        println!(
            "  Power Policy          : {}",
            if opts.ac_only {
                "AC Power Only"
            } else {
                "Any Power Source"
            }
        );
        println!("  Max Traversal Depth   : {}", budget.max_depth);
        println!("  Max Inspected Entries : {}", budget.max_entries);
        println!(
            "  Execution Timeout     : {} seconds",
            budget.max_duration_secs
        );
        println!("  Validated Executable  : {}", exec_path.display());
        println!(
            "  History Storage       : {}",
            get_schedule_history_path().display()
        );
        println!("\nTarget Directories to Inspect:");
        for t in &resolved_targets {
            println!("  - {}", t.display());
        }
        println!("\nSafety Guarantees:");
        println!("  - Scheduled inspections are strictly READ-ONLY.");
        println!(
            "  - Root Guardian unconditionally rejects all mutations and process termination."
        );
        println!("  - Unprivileged execution; zero permanent background daemons.");
        println!("  - Disable at any time using: root schedule disable");
        println!(
            "================================================================================"
        );
    }

    // 7. Update configuration
    config.enabled = true;
    config.interval = interval;
    config.profile = profile;
    config.budget = budget;
    config.targets = resolved_targets;
    config.notifications = opts.notify;
    config.catch_up = opts.catch_up;
    config.ac_power_only = opts.ac_only;
    config.executable_path = Some(exec_path.clone());
    config.last_modified_epoch_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    config.validate()?;
    save_schedule_config(&config)?;

    // 8. Transactional unit installation
    let scheduler = LinuxScheduler::new();
    scheduler.install_units_transactional(
        &exec_path,
        &config.interval,
        config.catch_up,
        config.ac_power_only,
    )?;

    if scheduler.is_systemd_user_available() {
        scheduler.enable_timer()?;
        println!(
            "{}",
            Style::green(
                "Mode B scheduled inspection successfully enabled and timer activated (root-inspect.timer)."
            )
        );
    } else {
        println!(
            "{}",
            Style::yellow(
                "Notice: systemd user manager is not active in this session. Units generated successfully."
            )
        );
    }

    Ok(())
}

/// Disables periodic background inspections.
pub fn run_schedule_disable() -> Result<()> {
    let mut config = load_schedule_config();
    config.enabled = false;
    config.last_modified_epoch_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    save_schedule_config(&config)?;

    let scheduler = LinuxScheduler::new();
    let _ = scheduler.disable_timer();

    println!(
        "{}",
        Style::green(
            "Scheduled inspections disabled. Systemd user timer stopped. Config preserved."
        )
    );

    Ok(())
}

/// Executes a scheduled inspection pass (called by systemd user service or manually).
pub fn run_schedule_run(dry_run: bool, notify: bool) -> Result<()> {
    let start_time = Instant::now();
    let mut config = load_schedule_config();

    if !config.enabled && !dry_run {
        println!("Notice: Scheduling is currently disabled. Exiting.");
        return Ok(());
    }

    // 1. Concurrency control: acquire non-blocking lock to prevent overlapping runs
    let state_dir = get_state_dir();
    let _ = fs::create_dir_all(&state_dir);
    let lock_path = get_schedule_lock_path();

    let lock_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| RootError::Io {
            path: lock_path.clone(),
            source: e,
        })?;

    // Try acquiring flock without blocking
    unsafe {
        if libc::flock(
            std::os::unix::io::AsRawFd::as_raw_fd(&lock_file),
            libc::LOCK_EX | libc::LOCK_NB,
        ) != 0
        {
            println!("Notice: Another Root scheduled inspection is already running. Skipping overlapping execution.");
            record_history_entry(HistoryRecordParams {
                status: ScheduleRunStatus::Deferred,
                profile: config.profile,
                targets: &config.targets,
                total_inspected: 0,
                total_findings: 0,
                reclaimable_bytes: 0,
                start_time,
                notification_sent: false,
                error_message: Some(
                    "Skipped: Concurrently running scheduled inspection (lock contention)"
                        .to_string(),
                ),
            });
            return Ok(());
        }
    }

    // 2. Preflight check: Battery awareness
    if config.ac_power_only && !LinuxScheduler::is_ac_power_connected() {
        println!("Notice: System running on battery power and AC-only scheduling is configured. Deferring scan.");
        record_history_entry(HistoryRecordParams {
            status: ScheduleRunStatus::Deferred,
            profile: config.profile,
            targets: &config.targets,
            total_inspected: 0,
            total_findings: 0,
            reclaimable_bytes: 0,
            start_time,
            notification_sent: false,
            error_message: Some(
                "Deferred: System running on battery power (AC-only mode)".to_string(),
            ),
        });
        return Ok(());
    }

    // 3. Preflight check: System memory pressure
    if let Some(threshold) = config.max_memory_pressure_pct {
        if LinuxScheduler::is_memory_pressure_high(threshold) {
            println!("Notice: System memory pressure exceeds safe threshold. Deferring scan.");
            record_history_entry(HistoryRecordParams {
                status: ScheduleRunStatus::Deferred,
                profile: config.profile,
                targets: &config.targets,
                total_inspected: 0,
                total_findings: 0,
                reclaimable_bytes: 0,
                start_time,
                notification_sent: false,
                error_message: Some(
                    "Deferred: Host memory pressure exceeds safe operational threshold".to_string(),
                ),
            });
            return Ok(());
        }
    }

    let targets = if !config.targets.is_empty() {
        config.targets.clone()
    } else {
        let env = LinuxEnvironment::new();
        vec![env.home_dir()]
    };

    let env = LinuxEnvironment::new();
    let fs = LinuxFilesystem::new();
    let proc_provider = LinuxProcess::new();
    let accountant = LinuxAccountant::new();
    let policy = GuardianPolicy::new();

    let current_uid = env.current_uid();
    let capabilities = match accountant.get_capabilities() {
        Ok(c) => c,
        Err(e) => {
            record_history_entry(HistoryRecordParams {
                status: ScheduleRunStatus::Failed,
                profile: config.profile,
                targets: &targets,
                total_inspected: 0,
                total_findings: 0,
                reclaimable_bytes: 0,
                start_time,
                notification_sent: false,
                error_message: Some(format!("Platform capabilities query failed: {}", e)),
            });
            return Err(e);
        }
    };

    // Filter non-existent targets gracefully (Deleted target handling)
    let mut valid_targets = Vec::new();
    for t in &targets {
        if t.exists() {
            valid_targets.push(t.clone());
        } else {
            eprintln!(
                "Notice: Scheduled target '{}' no longer exists; skipping.",
                t.display()
            );
        }
    }

    if valid_targets.is_empty() {
        let err_msg = "All configured scheduled targets are missing or deleted.".to_string();
        record_history_entry(HistoryRecordParams {
            status: ScheduleRunStatus::Failed,
            profile: config.profile,
            targets: &targets,
            total_inspected: 0,
            total_findings: 0,
            reclaimable_bytes: 0,
            start_time,
            notification_sent: false,
            error_message: Some(err_msg),
        });
        if config.notifications || notify {
            let _ = DesktopNotifier::dispatch(
                "Root Scheduled Inspection Failed",
                "Configured target directories were missing or deleted.",
                "normal",
            );
        }
        return Ok(());
    }

    let traversal_options = TraversalOptions {
        max_depth: config.budget.max_depth,
        max_entries: config.budget.max_entries,
        allow_cross_device: false,
        timeout: Some(Duration::from_secs(config.budget.max_duration_secs)),
    };

    let mut all_entries = Vec::new();
    let mut total_skipped = 0u64;
    let mut is_complete = true;
    let mut incomplete_reason = None;

    for root in &valid_targets {
        match fs.traverse(root, &traversal_options) {
            Ok(outcome) => {
                total_skipped += outcome.metrics.skipped_count;
                if !outcome.metrics.is_complete {
                    is_complete = false;
                    incomplete_reason = outcome.metrics.incomplete_reason;
                }
                for entry in outcome.entries {
                    all_entries.push((entry.path, entry.metadata, entry.dev, entry.ino));
                }
            }
            Err(e) => {
                total_skipped += 1;
                eprintln!(
                    "Notice: Skipping inaccessible path {}: {}",
                    root.display(),
                    e
                );
            }
        }
    }

    // Check memory budget where supported
    if let Some(max_mem) = config.budget.max_memory_bytes {
        if let Ok(Some(self_proc)) = proc_provider.inspect_process(std::process::id()) {
            if self_proc.memory.rss_bytes > max_mem {
                is_complete = false;
                incomplete_reason = Some(format!(
                    "Memory budget exceeded: resident memory {} bytes exceeds limit {}",
                    self_proc.memory.rss_bytes, max_mem
                ));
            }
        }
    }

    let mut active_processes = Vec::new();
    if let Ok(pids) = proc_provider.list_pids() {
        for pid in pids {
            if let Ok(Some(candidate)) = proc_provider.inspect_process(pid) {
                active_processes.push(candidate);
            }
        }
    }

    let filter = DiscoveryFilter::default();
    let ctx = DiscoveryContext {
        root_paths: valid_targets.clone(),
        filter: &filter,
        current_uid,
        active_processes: &active_processes,
        capabilities,
        skipped_count: total_skipped,
        is_complete,
        incomplete_reason: incomplete_reason.clone(),
    };

    let disc_report =
        match DiscoveryEngine::evaluate_findings(&all_entries, &ctx, &|target: &FindingTarget,
                                                                       tier: ProtectionTier,
                                                                       action: ProposedAction,
                                                                       uid: u32|
         -> SafetyDecision {
            policy.evaluate(target, tier, action, uid)
        }) {
            Ok(r) => r,
            Err(e) => {
                record_history_entry(HistoryRecordParams {
                    status: ScheduleRunStatus::Failed,
                    profile: config.profile,
                    targets: &valid_targets,
                    total_inspected: 0,
                    total_findings: 0,
                    reclaimable_bytes: 0,
                    start_time,
                    notification_sent: false,
                    error_message: Some(format!("Discovery evaluation failed: {}", e)),
                });
                return Err(e);
            }
        };

    // Determine status: Partial scans are strictly reported as Incomplete, never Complete
    let status = if is_complete {
        ScheduleRunStatus::Completed
    } else {
        ScheduleRunStatus::Incomplete
    };

    let duration_millis = start_time.elapsed().as_millis() as u64;

    // Notification handling with privacy-safe deduplication
    let mut notification_sent = false;
    if config.notifications || notify {
        let current_fingerprint = DesktopNotifier::compute_fingerprint(
            status,
            disc_report.summary.total_inspected,
            disc_report.findings.len(),
        );

        if config.last_notification_fingerprint.as_deref() == Some(&current_fingerprint) {
            println!("Notice: Inspection findings unchanged since last run; suppressing duplicate notification.");
        } else {
            let (title, body) = match status {
                ScheduleRunStatus::Completed => (
                    "Root Inspection Completed",
                    format!(
                        "Examined {} resources across {} targets with zero mutations.",
                        disc_report.summary.total_inspected,
                        valid_targets.len()
                    ),
                ),
                ScheduleRunStatus::Incomplete => (
                    "Root Inspection Incomplete",
                    format!(
                        "Scan halted early ({}).",
                        incomplete_reason
                            .as_deref()
                            .unwrap_or("resource budget limits reached")
                    ),
                ),
                ScheduleRunStatus::Deferred => (
                    "Root Inspection Deferred",
                    "Inspection postponed due to battery or system pressure preflight check."
                        .to_string(),
                ),
                ScheduleRunStatus::Failed => (
                    "Root Scheduled Inspection Failed",
                    "Review local audit log for failure diagnostics.".to_string(),
                ),
            };

            let _ = DesktopNotifier::dispatch(title, &body, "normal");
            notification_sent = true;

            // Persist updated notification fingerprint
            config.last_notification_fingerprint = Some(current_fingerprint);
            let _ = save_schedule_config(&config);
        }
    }

    record_history_entry(HistoryRecordParams {
        status,
        profile: config.profile,
        targets: &valid_targets,
        total_inspected: disc_report.summary.total_inspected,
        total_findings: disc_report.findings.len(),
        reclaimable_bytes: disc_report.summary.reclaimable_bytes_estimate,
        start_time,
        notification_sent,
        error_message: incomplete_reason,
    });

    println!(
        "Scheduled inspection run complete: {} findings across {} inspected resources ({:?}) in {}ms.",
        disc_report.findings.len(),
        disc_report.summary.total_inspected,
        status,
        duration_millis
    );

    Ok(())
}

struct HistoryRecordParams<'a> {
    pub status: ScheduleRunStatus,
    pub profile: InspectionProfile,
    pub targets: &'a [PathBuf],
    pub total_inspected: u64,
    pub total_findings: usize,
    pub reclaimable_bytes: u64,
    pub start_time: Instant,
    pub notification_sent: bool,
    pub error_message: Option<String>,
}

fn record_history_entry(params: HistoryRecordParams) {
    let entry = ScheduleHistoryEntry {
        id: format!(
            "run-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        timestamp_epoch_secs: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        duration_millis: params.start_time.elapsed().as_millis() as u64,
        status: params.status,
        profile: params.profile,
        targets_scanned: params.targets.to_vec(),
        total_inspected: params.total_inspected,
        total_findings: params.total_findings,
        reclaimable_bytes_estimate: params.reclaimable_bytes,
        notification_sent: params.notification_sent,
        error_message: params.error_message,
    };
    let _ = append_schedule_history(entry);
}

/// Displays recent scheduled inspection history records.
pub fn run_schedule_history(limit: Option<usize>, json_output: bool) -> Result<()> {
    let mut history = load_schedule_history();
    let max_count = limit.unwrap_or(20);

    if history.len() > max_count {
        let drain_count = history.len() - max_count;
        history.drain(0..drain_count);
    }

    if json_output {
        let json_str = serde_json::to_string_pretty(&history)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    println!("================================================================================");
    println!(" {}", Style::bold("ROOT SCHEDULED INSPECTION HISTORY"));
    println!("================================================================================");

    if history.is_empty() {
        println!("  (No scheduled inspection history recorded yet)");
        println!(
            "================================================================================"
        );
        return Ok(());
    }

    println!(
        " {:<12} | {:<14} | {:>8} | {:>8} | {:>10} | {:<18}",
        "Run ID", "Status", "Inspected", "Findings", "Duration", "Timestamp"
    );
    println!(
        "-------------+----------------+----------+----------+------------+-------------------"
    );

    for h in history.iter().rev() {
        let status_badge = match h.status {
            ScheduleRunStatus::Completed => Style::green(h.status.display_badge()),
            ScheduleRunStatus::Incomplete => Style::yellow(h.status.display_badge()),
            ScheduleRunStatus::Deferred => Style::yellow(h.status.display_badge()),
            ScheduleRunStatus::Failed => Style::red(h.status.display_badge()),
        };

        println!(
            " {:<12} | {:<14} | {:>8} | {:>8} | {:>8}ms | Epoch {}s",
            h.id,
            status_badge,
            h.total_inspected,
            h.total_findings,
            h.duration_millis,
            h.timestamp_epoch_secs
        );
    }

    println!("================================================================================");
    Ok(())
}
