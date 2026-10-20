use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Result, RootError};

/// Calendar interval for periodic scheduled inspections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleInterval {
    #[default]
    Daily,
    Weekly,
    Custom(String),
}

impl ScheduleInterval {
    /// Parses an interval string into a `ScheduleInterval`.
    pub fn from_filter(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
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
            Self::Daily => "Daily",
            Self::Weekly => "Weekly",
            Self::Custom(_) => "Custom",
        }
    }
}

/// Persistent user configuration for Mode B scheduled inspections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Whether periodic scheduling is enabled (disabled by default).
    pub enabled: bool,
    /// Calendar recurrence interval.
    pub interval: ScheduleInterval,
    /// Explicit target directories approved for scheduled scanning.
    pub targets: Vec<PathBuf>,
    /// Whether desktop notifications are dispatched upon inspection completion.
    pub notifications: bool,
    /// Maximum directory traversal depth.
    pub max_depth: usize,
    /// Maximum filesystem entries inspected per scan pass.
    pub max_entries: usize,
    /// Wall-clock execution timeout in seconds.
    pub timeout_secs: u64,
    /// Days to retain historical scheduled scan logs.
    pub history_retention_days: u32,
    /// Epoch timestamp when this configuration was last modified.
    pub last_modified_epoch_secs: i64,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: ScheduleInterval::Daily,
            targets: Vec::new(),
            notifications: false,
            max_depth: 16,
            max_entries: 50_000,
            timeout_secs: 60,
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

        if self.timeout_secs == 0 || self.timeout_secs > 3600 {
            return Err(RootError::ScheduleError(
                "Timeout must be between 1 and 3600 seconds".to_string(),
            ));
        }

        if self.max_entries == 0 || self.max_entries > 1_000_000 {
            return Err(RootError::ScheduleError(
                "Max entries must be between 1 and 1,000,000".to_string(),
            ));
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

/// Execution status of a scheduled inspection run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleRunStatus {
    Completed,
    Incomplete,
    Failed,
}

impl ScheduleRunStatus {
    pub fn display_badge(&self) -> &'static str {
        match self {
            Self::Completed => "[COMPLETED]",
            Self::Incomplete => "[INCOMPLETE]",
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
    pub targets_scanned: Vec<PathBuf>,
    pub total_inspected: u64,
    pub total_findings: usize,
    pub reclaimable_bytes_estimate: u64,
    pub notification_sent: bool,
    pub error_message: Option<String>,
}

/// Consolidated runtime status of Root's scheduled inspection system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleStatus {
    pub enabled: bool,
    pub interval: ScheduleInterval,
    pub targets: Vec<PathBuf>,
    pub notifications: bool,
    pub systemd_accessible: bool,
    pub timer_active: bool,
    pub next_trigger_utc: Option<String>,
    pub last_attempt_epoch_secs: Option<i64>,
    pub last_success_epoch_secs: Option<i64>,
    pub last_failure_reason: Option<String>,
    pub safety_policy: String,
}
