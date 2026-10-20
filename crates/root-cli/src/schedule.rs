use root_core::{
    error::{Result, RootError},
    model::{
        FindingTarget, ProposedAction, ProtectionTier, SafetyDecision, ScheduleConfig,
        ScheduleHistoryEntry, ScheduleInterval, ScheduleRunStatus, ScheduleStatus,
    },
    DiscoveryContext, DiscoveryEngine, DiscoveryFilter,
};
use root_guardian::GuardianPolicy;
use root_platform::{
    traits::{EnvironmentProvider, ProcessProvider, ResourceAccountant},
    DesktopNotifier, LinuxAccountant, LinuxEnvironment, LinuxFilesystem, LinuxProcess,
    LinuxScheduler, TraversalOptions,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};

use crate::terminal::Style;

const MAX_HISTORY_RECORDS: usize = 50;

/// Resolves the configuration directory for Root (`$XDG_CONFIG_HOME/root` or `~/.config/root`).
pub fn get_config_dir() -> PathBuf {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(config_home).join("root")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config").join("root")
    } else {
        PathBuf::from("/tmp/root_config")
    }
}

/// Resolves the state directory for Root (`$XDG_STATE_HOME/root` or `~/.local/state/root`).
pub fn get_state_dir() -> PathBuf {
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

pub fn get_schedule_config_path() -> PathBuf {
    get_config_dir().join("schedule.json")
}

pub fn get_schedule_history_path() -> PathBuf {
    get_state_dir().join("schedule_history.json")
}

pub fn get_schedule_lock_path() -> PathBuf {
    get_state_dir().join("schedule.lock")
}

/// Loads scheduling configuration from disk, recovering gracefully from malformed state.
pub fn load_schedule_config() -> ScheduleConfig {
    let path = get_schedule_config_path();
    if !path.exists() {
        return ScheduleConfig::default();
    }

    match fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<ScheduleConfig>(&content) {
            Ok(config) => config,
            Err(e) => {
                eprintln!(
                    "Notice: Schedule configuration at '{}' is malformed ({}). Restoring defaults.",
                    path.display(),
                    e
                );
                let _ = fs::rename(&path, path.with_extension("json.corrupt"));
                ScheduleConfig::default()
            }
        },
        Err(_) => ScheduleConfig::default(),
    }
}

/// Persists scheduling configuration with restrictive `0o600` permissions.
pub fn save_schedule_config(config: &ScheduleConfig) -> Result<()> {
    let dir = get_config_dir();
    fs::create_dir_all(&dir).map_err(|e| RootError::Io {
        path: dir.clone(),
        source: e,
    })?;

    let path = get_schedule_config_path();
    let serialized = serde_json::to_string_pretty(config)
        .map_err(|e| RootError::Serialization(e.to_string()))?;

    // Write to a temporary file in the same directory and atomically rename
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

    fs::rename(&temp_path, &path).map_err(|e| RootError::Io {
        path: path.clone(),
        source: e,
    })?;

    Ok(())
}

/// Loads historical scheduled inspection records with malformed state resilience.
pub fn load_schedule_history() -> Vec<ScheduleHistoryEntry> {
    let path = get_schedule_history_path();
    if !path.exists() {
        return Vec::new();
    }

    match fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<Vec<ScheduleHistoryEntry>>(&content) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!(
                    "Notice: Schedule history log at '{}' is malformed ({}). Resetting log.",
                    path.display(),
                    e
                );
                let _ = fs::rename(&path, path.with_extension("json.corrupt"));
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

/// Appends a run entry to the schedule history log, enforcing retention limits.
pub fn append_schedule_history(entry: ScheduleHistoryEntry) -> Result<()> {
    let dir = get_state_dir();
    fs::create_dir_all(&dir).map_err(|e| RootError::Io {
        path: dir.clone(),
        source: e,
    })?;

    let mut history = load_schedule_history();
    history.push(entry);

    // Enforce retention: keep only the newest entries
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

    fs::rename(&temp_path, &path).map_err(|e| RootError::Io {
        path: path.clone(),
        source: e,
    })?;

    Ok(())
}

/// Displays the current runtime status of scheduled inspections.
pub fn run_schedule_status(json_output: bool) -> Result<()> {
    let config = load_schedule_config();
    let history = load_schedule_history();
    let scheduler = LinuxScheduler::new();

    let systemd_accessible = scheduler.is_systemd_user_available();
    let timer_active = scheduler.is_timer_active();
    let next_trigger = scheduler.query_next_trigger();

    let last_attempt = history.last().map(|h| h.timestamp_epoch_secs);
    let last_success = history
        .iter()
        .rev()
        .find(|h| h.status == ScheduleRunStatus::Completed)
        .map(|h| h.timestamp_epoch_secs);
    let last_failure = history
        .iter()
        .rev()
        .find(|h| h.status == ScheduleRunStatus::Failed)
        .and_then(|h| h.error_message.clone());

    let status = ScheduleStatus {
        enabled: config.enabled,
        interval: config.interval.clone(),
        targets: config.targets.clone(),
        notifications: config.notifications,
        systemd_accessible,
        timer_active,
        next_trigger_utc: next_trigger,
        last_attempt_epoch_secs: last_attempt,
        last_success_epoch_secs: last_success,
        last_failure_reason: last_failure,
        safety_policy: "Production Read-Only (Scheduled mutations strictly prohibited)".to_string(),
    };

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
            Style::green("[ENABLED]")
        } else {
            Style::dim("[DISABLED by default]")
        }
    );
    println!(
        "  Calendar Interval     : {}",
        status.interval.display_badge()
    );
    println!(
        "  systemd User Manager  : {}",
        if status.systemd_accessible {
            Style::green("Accessible")
        } else {
            Style::yellow("Unavailable / Not running")
        }
    );
    println!(
        "  Timer Unit Status     : {}",
        if status.timer_active {
            Style::green("Active (root-inspect.timer)")
        } else {
            Style::dim("Inactive / Stopped")
        }
    );

    if let Some(ref next) = status.next_trigger_utc {
        println!("  Next Trigger          : {}", next);
    } else {
        println!("  Next Trigger          : None scheduled");
    }

    println!(
        "  Desktop Notifications : {}",
        if status.notifications {
            Style::green("Enabled")
        } else {
            Style::dim("Disabled (Opt-in only)")
        }
    );

    println!("\nApproved Inspection Targets:");
    if status.targets.is_empty() {
        println!("  (No targets configured. Run 'root schedule enable' to configure targets.)");
    } else {
        for target in &status.targets {
            println!("  - {}", target.display());
        }
    }

    println!("\nExecution History Summary:");
    if let Some(epoch) = status.last_attempt_epoch_secs {
        println!("  Last Attempted Scan   : Epoch {}s", epoch);
    } else {
        println!("  Last Attempted Scan   : No recorded executions");
    }

    if let Some(epoch) = status.last_success_epoch_secs {
        println!("  Last Successful Scan  : Epoch {}s", epoch);
    } else {
        println!("  Last Successful Scan  : None");
    }

    if let Some(ref fail) = status.last_failure_reason {
        println!("  Last Failure Reason   : {}", Style::red(fail));
    }

    println!("\nSafety Governance:");
    println!(
        "  Policy Invariant      : {}",
        Style::green(&status.safety_policy)
    );
    println!("  Disable Command       : Run 'root schedule disable' to stop future runs");
    println!("================================================================================");
}

/// Enables periodic scheduled inspections after explicit confirmation.
pub fn run_schedule_enable(
    interval_str: Option<String>,
    targets: Vec<PathBuf>,
    notify: bool,
    non_interactive: bool,
) -> Result<()> {
    let mut config = load_schedule_config();

    // 1. Resolve interval
    let interval = if let Some(ref s) = interval_str {
        ScheduleInterval::from_filter(s).ok_or_else(|| {
            RootError::ScheduleError(format!(
                "Invalid interval '{}'. Supported intervals: 'daily', 'weekly', or valid OnCalendar expression.",
                s
            ))
        })?
    } else {
        ScheduleInterval::Daily
    };

    // 2. Resolve targets
    let resolved_targets = if !targets.is_empty() {
        targets
    } else if !config.targets.is_empty() {
        config.targets.clone()
    } else {
        // Fall back to auto-detected local agent roots
        let env = LinuxEnvironment::new();
        let home = env.home_dir();
        let mut candidates = Vec::new();
        for dir in &[".gemini", ".claude", ".cache/openai"] {
            let p = home.join(dir);
            if p.exists() {
                candidates.push(p);
            }
        }
        if candidates.is_empty() {
            if let Ok(cwd) = std::env::current_dir() {
                candidates.push(cwd);
            }
        }
        candidates
    };

    if resolved_targets.is_empty() {
        return Err(RootError::ScheduleError(
            "No scan targets specified. Supply at least one target directory via '--targets <path>'."
                .to_string(),
        ));
    }

    // Validate all targets
    for target in &resolved_targets {
        ScheduleConfig::validate_target(target)?;
    }

    // 3. Pre-activation confirmation
    if !non_interactive {
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
        println!("  Frequency Interval    : {}", interval.display_badge());
        println!(
            "  Notifications         : {}",
            if notify { "Enabled" } else { "Disabled" }
        );
        println!("  Max Traversal Depth   : 16");
        println!("  Max Inspected Entries : 50,000");
        println!("  Execution Timeout     : 60 seconds");
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
        println!("  - Root Guardian will reject any attempt to mutate files or kill processes.");
        println!("  - No system daemon or superuser privileges are required.");
        println!("  - Disable at any time using: root schedule disable");
        println!(
            "================================================================================"
        );
    }

    // 4. Update configuration
    config.enabled = true;
    config.interval = interval;
    config.targets = resolved_targets;
    config.notifications = notify;
    config.last_modified_epoch_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    config.validate()?;
    save_schedule_config(&config)?;

    // 5. Install systemd user units
    let exec_path = std::env::current_exe().map_err(|e| RootError::Io {
        path: PathBuf::from("current_exe"),
        source: e,
    })?;

    let scheduler = LinuxScheduler::new();
    scheduler.install_units(&exec_path, &config.interval)?;

    if scheduler.is_systemd_user_available() {
        scheduler.enable_timer()?;
        println!(
            "{}",
            Style::green("Scheduled inspections successfully enabled and timer activated.")
        );
    } else {
        println!(
            "{}",
            Style::yellow(
                "Notice: systemd user manager not reachable. Unit files written to ~/.config/systemd/user/ for manual activation."
            )
        );
    }

    Ok(())
}

/// Disables periodic scheduled inspections.
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
            "Scheduled inspections disabled. Future runs stopped. Historical reports preserved."
        )
    );

    Ok(())
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
        "  Interval              : {}",
        config.interval.display_badge()
    );
    println!(
        "  Notifications         : {}",
        if config.notifications {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!("  Timeout Limit         : {}s", config.timeout_secs);
    println!("  Entry Limit           : {}", config.max_entries);
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

/// Executes a scheduled inspection run (called by systemd user service or manually).
pub fn run_schedule_run(dry_run: bool, notify: bool) -> Result<()> {
    let start_time = Instant::now();
    let config = load_schedule_config();

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
            record_failure("Platform capabilities query failed", &targets, start_time);
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
        record_failure(&err_msg, &targets, start_time);
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
        max_depth: config.max_depth,
        max_entries: config.max_entries,
        allow_cross_device: false,
        timeout: Some(Duration::from_secs(config.timeout_secs)),
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
                record_failure(
                    &format!("Discovery evaluation failed: {}", e),
                    &valid_targets,
                    start_time,
                );
                return Err(e);
            }
        };

    let duration_millis = start_time.elapsed().as_millis() as u64;
    let status = if is_complete {
        ScheduleRunStatus::Completed
    } else {
        ScheduleRunStatus::Incomplete
    };

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
        duration_millis,
        status,
        targets_scanned: valid_targets,
        total_inspected: disc_report.summary.total_inspected,
        total_findings: disc_report.findings.len(),
        reclaimable_bytes_estimate: disc_report.summary.reclaimable_bytes_estimate,
        notification_sent: config.notifications || notify,
        error_message: incomplete_reason.clone(),
    };

    let _ = append_schedule_history(entry);

    // Desktop notification dispatch (if enabled)
    if config.notifications || notify {
        let (title, body) = match status {
            ScheduleRunStatus::Completed => (
                "Root Inspection Completed",
                format!(
                    "Examined {} resources with zero mutations.",
                    disc_report.summary.total_inspected
                ),
            ),
            ScheduleRunStatus::Incomplete => (
                "Root Inspection Incomplete",
                format!(
                    "Scan halted early ({}).",
                    incomplete_reason
                        .as_deref()
                        .unwrap_or("traversal bounds reached")
                ),
            ),
            ScheduleRunStatus::Failed => (
                "Root Scheduled Inspection Failed",
                "Review local report at ~/.local/state/root/schedule_history.json.".to_string(),
            ),
        };

        let _ = DesktopNotifier::dispatch(title, &body, "normal");
    }

    println!(
        "Scheduled inspection run complete: {} findings across {} inspected resources ({:?}) in {}ms.",
        disc_report.findings.len(),
        disc_report.summary.total_inspected,
        status,
        duration_millis
    );

    Ok(())
}

fn record_failure(error_msg: &str, targets: &[PathBuf], start_time: Instant) {
    let entry = ScheduleHistoryEntry {
        id: format!(
            "run-err-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ),
        timestamp_epoch_secs: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        duration_millis: start_time.elapsed().as_millis() as u64,
        status: ScheduleRunStatus::Failed,
        targets_scanned: targets.to_vec(),
        total_inspected: 0,
        total_findings: 0,
        reclaimable_bytes_estimate: 0,
        notification_sent: false,
        error_message: Some(error_msg.to_string()),
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
