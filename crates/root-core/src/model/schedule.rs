use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Result, RootError};

/// Calendar interval for periodic scheduled inspections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleInterval {
    Hourly,
    #[default]
    Daily,
    Weekly,
    Custom(String),
}

impl ScheduleInterval {
    /// Parses an interval string into a `ScheduleInterval`.
    pub fn from_filter(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "hourly" | "hour" => Some(Self::Hourly),
            "daily" | "day" => Some(Self::Daily),
            "weekly" | "week" => Some(Self::Weekly),
            custom if !custom.is_empty() => Some(Self::Custom(custom.to_string())),
            _ => None,
        }
    }

    /// Converts the interval into a validated systemd OnCalendar specification.
    ///
    /// Validates characters to prevent shell injection or unit parsing corruption.
    pub fn to_calendar_spec(&self) -> Result<String> {
        match self {
            Self::Hourly => Ok("hourly".to_string()),
            Self::Daily => Ok("daily".to_string()),
            Self::Weekly => Ok("weekly".to_string()),
            Self::Custom(spec) => {
                let trimmed = spec.trim();
                // Strictly disallow shell metacharacters, control characters, or newlines
                for ch in trimmed.chars() {
                    if ch == '\n'
                        || ch == '\r'
                        || ch == '\0'
                        || ch == ';'
                        || ch == '&'
                        || ch == '|'
                        || ch == '$'
                        || ch == '`'
                        || ch == '"'
                        || ch == '\''
                        || ch == '<'
                        || ch == '>'
                        || ch == '\\'
                    {
                        return Err(RootError::ScheduleError(format!(
                            "Custom OnCalendar interval contains illegal character '{}': {}",
                            ch, trimmed
                        )));
                    }
                }

                if trimmed.is_empty() || trimmed.len() > 100 {
                    return Err(RootError::ScheduleError(
                        "Custom OnCalendar interval must be between 1 and 100 characters"
                            .to_string(),
                    ));
                }

                Ok(trimmed.to_string())
            }
        }
    }

    pub fn display_badge(&self) -> &'static str {
        match self {
            Self::Hourly => "Hourly",
            Self::Daily => "Daily",
            Self::Weekly => "Weekly",
            Self::Custom(_) => "Custom",
        }
    }
}

/// Deterministic inspection profile with explicit scope and resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InspectionProfile {
    Lightweight,
    #[default]
    Standard,
    Comprehensive,
}

impl InspectionProfile {
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "lightweight" | "light" | "quick" => Some(Self::Lightweight),
            "standard" | "default" => Some(Self::Standard),
            "comprehensive" | "deep" | "full" => Some(Self::Comprehensive),
            _ => None,
        }
    }

    pub fn display_badge(&self) -> &'static str {
        match self {
            Self::Lightweight => "[LIGHTWEIGHT]",
            Self::Standard => "[STANDARD]",
            Self::Comprehensive => "[COMPREHENSIVE]",
        }
    }

    pub fn default_budget(&self) -> InspectionBudget {
        match self {
            Self::Lightweight => InspectionBudget {
                max_duration_secs: 15,
                max_entries: 10_000,
                max_depth: 4,
                max_memory_bytes: Some(256 * 1024 * 1024),
                cpu_limit_percent: Some(30),
            },
            Self::Standard => InspectionBudget {
                max_duration_secs: 60,
                max_entries: 50_000,
                max_depth: 16,
                max_memory_bytes: Some(512 * 1024 * 1024),
                cpu_limit_percent: Some(60),
            },
            Self::Comprehensive => InspectionBudget {
                max_duration_secs: 120,
                max_entries: 150_000,
                max_depth: 32,
                max_memory_bytes: Some(1024 * 1024 * 1024),
                cpu_limit_percent: Some(90),
            },
        }
    }
}

/// Configurable resource budget governing an inspection run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectionBudget {
    /// Maximum wall-clock execution duration in seconds.
    pub max_duration_secs: u64,
    /// Maximum entries scanned across all target trees.
    pub max_entries: usize,
    /// Maximum directory traversal depth.
    pub max_depth: usize,
    /// Maximum allowed memory consumption (RSS bytes) where supported.
    pub max_memory_bytes: Option<u64>,
    /// CPU utilization limit percentage where supported.
    pub cpu_limit_percent: Option<u32>,
}

impl Default for InspectionBudget {
    fn default() -> Self {
        InspectionProfile::Standard.default_budget()
    }
}

/// Persistent user configuration for Mode B scheduled inspections.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Whether periodic scheduling is enabled (disabled by default).
    pub enabled: bool,
    /// Calendar recurrence interval.
    pub interval: ScheduleInterval,
    /// Inspection profile defining scope and resource limits.
    #[serde(default)]
    pub profile: InspectionProfile,
    /// Explicit resource budget.
    #[serde(default)]
    pub budget: InspectionBudget,
    /// Explicit target directories approved for scheduled scanning.
    pub targets: Vec<PathBuf>,
    /// Whether desktop notifications are dispatched upon inspection completion.
    pub notifications: bool,
    /// Whether missed timer executions catch up immediately upon workstation resume (disabled by default).
    #[serde(default)]
    pub catch_up: bool,
    /// Whether scheduled runs are restricted to AC power only.
    #[serde(default)]
    pub ac_power_only: bool,
    /// Maximum memory pressure stall percentage (10s window) above which scans are deferred.
    #[serde(default)]
    pub max_memory_pressure_pct: Option<f64>,
    /// Privacy-safe aggregate fingerprint of the last notification sent (used for deduplication).
    #[serde(default)]
    pub last_notification_fingerprint: Option<String>,
    /// Explicitly validated path to the installed Root binary.
    #[serde(default)]
    pub executable_path: Option<PathBuf>,
    /// Days to retain historical scheduled scan logs.
    pub history_retention_days: u32,
    /// Epoch timestamp when this configuration was last modified.
    pub last_modified_epoch_secs: i64,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        let profile = InspectionProfile::Standard;
        Self {
            enabled: false,
            interval: ScheduleInterval::Daily,
            profile,
            budget: profile.default_budget(),
            targets: Vec::new(),
            notifications: false,
            catch_up: false,
            ac_power_only: false,
            max_memory_pressure_pct: Some(60.0),
            last_notification_fingerprint: None,
            executable_path: None,
            history_retention_days: 30,
            last_modified_epoch_secs: 0,
        }
    }
}

impl ScheduleConfig {
    /// Validates the scheduling configuration against security boundaries.
    pub fn validate(&self) -> Result<()> {
        self.interval.to_calendar_spec()?;

        if self.enabled && self.targets.is_empty() {
            return Err(RootError::ScheduleError(
                "Cannot enable scheduling without at least one approved scan target directory"
                    .to_string(),
            ));
        }

        for target in &self.targets {
            Self::validate_target(target)?;
        }

        if self.budget.max_duration_secs == 0 || self.budget.max_duration_secs > 3600 {
            return Err(RootError::ScheduleError(
                "Timeout must be between 1 and 3600 seconds".to_string(),
            ));
        }

        if self.budget.max_entries == 0 || self.budget.max_entries > 1_000_000 {
            return Err(RootError::ScheduleError(
                "Max entries must be between 1 and 1,000,000".to_string(),
            ));
        }

        if self.budget.max_depth == 0 || self.budget.max_depth > 64 {
            return Err(RootError::ScheduleError(
                "Max depth must be between 1 and 64".to_string(),
            ));
        }

        if let Some(ref exec) = self.executable_path {
            validate_executable(exec)?;
        }

        Ok(())
    }

    /// Validates that a single target path is safe for scheduled inspection.
    ///
    /// Rejects host root ('/'), operating system pseudo-filesystems, system configuration
    /// directories, and invalid characters.
    pub fn validate_target(path: &Path) -> Result<()> {
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
                reason: "Refusing to schedule scans of host root ('/')".to_string(),
            });
        }

        // Prohibit pseudo-filesystems
        let pseudo_prefixes = ["/proc", "/sys", "/dev", "/run"];
        for prefix in &pseudo_prefixes {
            if path_str == *prefix || path_str.starts_with(&format!("{}/", prefix)) {
                return Err(RootError::UnsafeScheduleTarget {
                    path: path.to_path_buf(),
                    reason: format!("Target path resides within pseudo-filesystem '{}'", prefix),
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
                        "Target path resides within protected system directory '{}'",
                        prefix
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Validates and canonicalizes the Root executable path.
///
/// Ensures the path exists, is a regular file, has Unix executable permissions,
/// and is not an arbitrary script or shell interpreter.
pub fn validate_executable(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        return Err(RootError::ScheduleError(format!(
            "Root executable path does not exist: {}",
            path.display()
        )));
    }

    let canonical = path.canonicalize().map_err(|e| RootError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let metadata = std::fs::metadata(&canonical).map_err(|e| RootError::Io {
        path: canonical.clone(),
        source: e,
    })?;

    if !metadata.is_file() {
        return Err(RootError::ScheduleError(format!(
            "Root executable path is not a regular file: {}",
            canonical.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(RootError::ScheduleError(format!(
                "Root executable path lacks execution permissions (mode: {:o}): {}",
                mode,
                canonical.display()
            )));
        }
    }

    // Verify it is not a shell or interpreter invocation
    let file_name = canonical.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if file_name == "sh" || file_name == "bash" || file_name == "python" || file_name == "python3" {
        return Err(RootError::ScheduleError(format!(
            "Refusing to configure shell or interpreter binary as Root executable: {}",
            file_name
        )));
    }

    Ok(canonical)
}

/// Execution status of a scheduled inspection run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleRunStatus {
    Completed,
    Incomplete,
    Deferred,
    Failed,
}

impl ScheduleRunStatus {
    pub fn display_badge(&self) -> &'static str {
        match self {
            Self::Completed => "[COMPLETED]",
            Self::Incomplete => "[INCOMPLETE]",
            Self::Deferred => "[DEFERRED]",
            Self::Failed => "[FAILED]",
        }
    }
}

/// Audit log record documenting a single execution of a scheduled inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleHistoryEntry {
    pub id: String,
    pub timestamp_epoch_secs: i64,
    pub duration_millis: u64,
    pub status: ScheduleRunStatus,
    #[serde(default)]
    pub profile: InspectionProfile,
    pub targets_scanned: Vec<PathBuf>,
    pub total_inspected: u64,
    pub total_findings: usize,
    pub reclaimable_bytes_estimate: u64,
    pub notification_sent: bool,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Consolidated runtime status of Root's scheduled inspection system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleStatus {
    pub enabled: bool,
    pub interval: ScheduleInterval,
    pub profile: InspectionProfile,
    pub budget: InspectionBudget,
    pub targets: Vec<PathBuf>,
    pub notifications: bool,
    pub catch_up: bool,
    pub ac_power_only: bool,
    pub systemd_accessible: bool,
    pub timer_active: bool,
    pub next_trigger_utc: Option<String>,
    pub last_attempt_epoch_secs: Option<i64>,
    pub last_success_epoch_secs: Option<i64>,
    pub last_failure_reason: Option<String>,
    pub safety_policy: String,
}
