use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Result, RootError};

/// Lifecycle state of a live monitoring session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MonitorSessionState {
    #[default]
    Created,
    Starting,
    Running,
    Degraded,
    Stopping,
    Stopped,
    Failed,
}

impl MonitorSessionState {
    pub fn display_badge(&self) -> &'static str {
        match self {
            Self::Created => "[CREATED]",
            Self::Starting => "[STARTING]",
            Self::Running => "[RUNNING]",
            Self::Degraded => "[DEGRADED]",
            Self::Stopping => "[STOPPING]",
            Self::Stopped => "[STOPPED]",
            Self::Failed => "[FAILED]",
        }
    }
}

/// Explicit reason explaining why a monitoring session became degraded or incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedReason {
    /// Inotify event queue overflowed; some events were lost.
    QueueOverflow(String),
    /// Max active watch descriptors limit was reached.
    WatchLimitExceeded(usize),
    /// Permission denied attempting to watch path.
    PermissionDenied(PathBuf),
    /// A watched target directory was unlinked or moved.
    WatchedDirectoryRemoved(PathBuf),
    /// Kernel inotify or /proc interface unavailable.
    KernelInterfaceUnavailable(String),
    /// Session resource budget exceeded (e.g. event queue or RSS limit).
    ResourceBudgetExceeded(String),
    /// High memory pressure detected during monitoring.
    MemoryPressureElevated(String),
}

impl DegradedReason {
    pub fn display_message(&self) -> String {
        match self {
            Self::QueueOverflow(details) => format!("Kernel inotify queue overflowed: {}", details),
            Self::WatchLimitExceeded(limit) => {
                format!("Active inotify watch budget exceeded (limit: {})", limit)
            }
            Self::PermissionDenied(path) => {
                format!("Permission denied watching path '{}'", path.display())
            }
            Self::WatchedDirectoryRemoved(path) => {
                format!(
                    "Monitored target path was removed or renamed: '{}'",
                    path.display()
                )
            }
            Self::KernelInterfaceUnavailable(err) => {
                format!("Required kernel monitoring interface unavailable: {}", err)
            }
            Self::ResourceBudgetExceeded(reason) => {
                format!("Monitoring resource budget limit reached: {}", reason)
            }
            Self::MemoryPressureElevated(details) => {
                format!("System memory pressure elevated: {}", details)
            }
        }
    }
}

/// Category of filesystem mutation observed by inotify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveFsEventKind {
    Created,
    Modified,
    Deleted,
    MovedFrom,
    MovedTo,
    DirCreated,
    DirDeleted,
}

impl LiveFsEventKind {
    pub fn display_badge(&self) -> &'static str {
        match self {
            Self::Created => "[CREATE]",
            Self::Modified => "[MODIFY]",
            Self::Deleted => "[DELETE]",
            Self::MovedFrom => "[MOVE_OUT]",
            Self::MovedTo => "[MOVE_IN]",
            Self::DirCreated => "[DIR_CREATE]",
            Self::DirDeleted => "[DIR_DELETE]",
        }
    }
}

/// Filesystem event emitted during live monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveFsEvent {
    pub path: PathBuf,
    pub kind: LiveFsEventKind,
    pub is_directory: bool,
    pub timestamp_epoch_secs: i64,
    pub matched_agent: Option<String>,
}

/// Process lifecycle event category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEventKind {
    Spawned,
    Exited,
}

impl ProcessEventKind {
    pub fn display_badge(&self) -> &'static str {
        match self {
            Self::Spawned => "[PROC_SPAWN]",
            Self::Exited => "[PROC_EXIT]",
        }
    }
}

/// Lightweight snapshot of an observed active or terminated process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessObservation {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub binary_name: String,
    pub start_time_ticks: u64,
    pub rss_bytes: u64,
    pub associated_agent: Option<String>,
}

/// Periodic snapshot of host system memory metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryObservation {
    pub total_ram_bytes: u64,
    pub available_ram_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub psi_memory_10s_pct: Option<f64>,
}

/// Strict resource budgets constraining a live monitoring session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorBudget {
    /// Maximum directory trees permitted to be actively monitored simultaneously.
    pub max_monitored_paths: usize,
    /// Maximum inotify watch descriptors allocated across all monitored trees.
    pub max_watches: usize,
    /// Maximum live events retained in the bounded in-memory buffer.
    pub max_queued_events: usize,
    /// Optional session wall-clock timeout in seconds.
    pub max_duration_secs: Option<u64>,
    /// Maximum resident memory (RSS bytes) allowed for the Root process before degrading.
    pub max_memory_rss_bytes: Option<u64>,
    /// Minimum allowed sampling interval in milliseconds (prevents high-frequency thrashing).
    pub sampling_interval_millis: u64,
}

impl Default for MonitorBudget {
    fn default() -> Self {
        Self {
            max_monitored_paths: 32,
            max_watches: 512,
            max_queued_events: 5_000,
            max_duration_secs: None,
            max_memory_rss_bytes: Some(256 * 1024 * 1024), // 256 MiB limit
            sampling_interval_millis: 1_000,               // 1.0s default
        }
    }
}

/// Configuration defining the scope of an explicit live monitoring session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MonitorScope {
    /// Explicit target directories approved for inotify watching.
    pub paths: Vec<PathBuf>,
    /// Optional filter restricting observation to a specific agent (e.g. "antigravity").
    pub agent_filter: Option<String>,
    /// Whether process lifecycle events should be sampled.
    pub observe_processes: bool,
    /// Whether system memory metrics should be sampled.
    pub observe_memory: bool,
    /// Operational resource budgets.
    pub budget: MonitorBudget,
}

impl MonitorScope {
    /// Validates the monitoring scope against security invariants.
    pub fn validate(&self) -> Result<()> {
        if self.paths.is_empty()
            && self.agent_filter.is_none()
            && !self.observe_processes
            && !self.observe_memory
        {
            return Err(RootError::InvalidPath(
                "Cannot start monitoring without an explicit target scope. Specify at least one directory path (--path) or observation filter (--agent, --processes, --memory).".to_string(),
            ));
        }

        if self.paths.len() > self.budget.max_monitored_paths {
            return Err(RootError::PolicyViolation {
                reason: format!(
                    "Monitored paths count ({}) exceeds maximum allowed budget ({})",
                    self.paths.len(),
                    self.budget.max_monitored_paths
                ),
            });
        }

        // Validate each target path
        for path in &self.paths {
            Self::validate_monitor_target(path)?;
        }

        // Enforce minimum sampling interval (>= 250ms)
        if self.budget.sampling_interval_millis < 250 {
            return Err(RootError::PolicyViolation {
                reason: "Sampling interval must be at least 250 milliseconds to prevent kernel event thrashing".to_string(),
            });
        }

        Ok(())
    }

    /// Validates a single directory path target for live monitoring.
    pub fn validate_monitor_target(path: &Path) -> Result<()> {
        let path_str = path.to_string_lossy();

        if path_str.contains('\n') || path_str.contains('\r') || path_str.contains('\0') {
            return Err(RootError::UnsafeScheduleTarget {
                path: path.to_path_buf(),
                reason: "Target path contains illegal control characters or newlines".to_string(),
            });
        }

        if path == Path::new("/") {
            return Err(RootError::UnsafeScheduleTarget {
                path: path.to_path_buf(),
                reason: "Refusing to monitor host root ('/')".to_string(),
            });
        }

        // Prohibit pseudo-filesystems
        let pseudo_prefixes = ["/proc", "/sys", "/dev", "/run"];
        for prefix in &pseudo_prefixes {
            if path_str == *prefix || path_str.starts_with(&format!("{}/", prefix)) {
                return Err(RootError::UnsafeScheduleTarget {
                    path: path.to_path_buf(),
                    reason: format!("Refusing to monitor pseudo-filesystem '{}'", prefix),
                });
            }
        }

        // Prohibit sensitive system hierarchies
        let system_prefixes = ["/etc", "/boot", "/usr", "/var", "/lib", "/lib64", "/opt"];
        for prefix in &system_prefixes {
            if path_str == *prefix || path_str.starts_with(&format!("{}/", prefix)) {
                return Err(RootError::UnsafeScheduleTarget {
                    path: path.to_path_buf(),
                    reason: format!(
                        "Refusing to monitor protected system directory '{}'",
                        prefix
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Unified live event emitted by the monitoring engine (serializable for JSON Lines).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MonitorEvent {
    Fs(LiveFsEvent),
    Process {
        kind: ProcessEventKind,
        process: ProcessObservation,
    },
    Memory(MemoryObservation),
    Status {
        state: MonitorSessionState,
        reason: Option<DegradedReason>,
    },
}

/// Final summary documenting the execution of a live monitoring session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorSessionSummary {
    pub session_id: String,
    pub started_epoch_secs: i64,
    pub duration_millis: u64,
    pub final_state: MonitorSessionState,
    pub degraded_reasons: Vec<DegradedReason>,
    pub total_fs_events: u64,
    pub total_process_events: u64,
    pub total_memory_samples: u64,
    pub monitored_paths: Vec<PathBuf>,
}
