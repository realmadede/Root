use root_core::model::{
    InspectionProfile, ScheduleConfig, ScheduleHistoryEntry, ScheduleInterval, ScheduleRunStatus,
};
use root_platform::{traits::Scheduler, NativeScheduler};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

/// Formatted history entry row for the scheduled inspections table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleHistoryRow {
    pub timestamp_rfc3339: String,
    pub duration_display: String,
    pub status: ScheduleRunStatus,
    pub status_label: &'static str,
    pub status_css: &'static str,
    pub examined_count: usize,
    pub targets_summary: String,
}

impl ScheduleHistoryRow {
    pub fn from_entry(entry: &ScheduleHistoryEntry) -> Self {
        let (label, css) = match entry.status {
            ScheduleRunStatus::Completed => ("COMPLETED", "badge-completed"),
            ScheduleRunStatus::Incomplete => ("INCOMPLETE", "badge-incomplete"),
            ScheduleRunStatus::Deferred => ("DEFERRED", "badge-deferred"),
            ScheduleRunStatus::Failed => ("FAILED", "badge-failed"),
        };

        let duration_secs = entry.duration_millis as f64 / 1000.0;
        let targets_str = entry
            .targets_scanned
            .iter()
            .map(|p| p.to_string_lossy())
            .collect::<Vec<_>>()
            .join(", ");

        Self {
            timestamp_rfc3339: format!("{}s", entry.timestamp_epoch_secs),
            duration_display: format!("{:.2}s", duration_secs),
            status: entry.status,
            status_label: label,
            status_css: css,
            examined_count: entry.total_inspected as usize,
            targets_summary: targets_str,
        }
    }
}

/// View-model managing Mode B scheduled inspections configuration and history.
#[derive(Debug, Clone)]
pub struct ScheduleViewModel {
    pub enabled: bool,
    pub interval: ScheduleInterval,
    pub profile: InspectionProfile,
    pub targets: Vec<PathBuf>,
    pub notifications_enabled: bool,
    pub ac_power_only: bool,
    pub catch_up: bool,
    pub next_trigger_display: Option<String>,
    pub last_run_summary: Option<String>,
    pub history_rows: Vec<ScheduleHistoryRow>,
    pub systemd_available: bool,
}

impl Default for ScheduleViewModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ScheduleViewModel {
    pub fn new() -> Self {
        Self {
            enabled: false,
            interval: ScheduleInterval::Daily,
            profile: InspectionProfile::Standard,
            targets: Vec::new(),
            notifications_enabled: true,
            ac_power_only: true,
            catch_up: false,
            next_trigger_display: None,
            last_run_summary: None,
            history_rows: Vec::new(),
            systemd_available: true,
        }
    }

    /// Loads schedule status from the platform scheduler and configuration.
    pub fn refresh_from_system(&mut self) {
        let scheduler = NativeScheduler::new();
        self.systemd_available = scheduler.backend_available();
        self.next_trigger_display = scheduler.next_trigger();

        // 1. Load config if present
        let config_path = Self::get_config_path();
        if config_path.exists() {
            if let Ok(file) = File::open(&config_path) {
                let reader = BufReader::new(file);
                if let Ok(config) = serde_json::from_reader::<_, ScheduleConfig>(reader) {
                    self.enabled = config.enabled;
                    self.interval = config.interval;
                    self.profile = config.profile;
                    self.targets = config.targets;
                    self.notifications_enabled = config.notifications;
                    self.ac_power_only = config.ac_power_only;
                    self.catch_up = config.catch_up;
                }
            }
        }

        // 2. Load history if present
        let history_path = Self::get_history_path();
        if history_path.exists() {
            if let Ok(file) = File::open(&history_path) {
                let reader = BufReader::new(file);
                if let Ok(entries) = serde_json::from_reader::<_, Vec<ScheduleHistoryEntry>>(reader)
                {
                    if let Some(latest) = entries.first() {
                        self.last_run_summary = Some(format!(
                            "{:?} — {} examined in {}ms",
                            latest.status, latest.total_inspected, latest.duration_millis
                        ));
                    }
                    self.history_rows =
                        entries.iter().map(ScheduleHistoryRow::from_entry).collect();
                }
            }
        }
    }

    /// Explicitly authorizes and enables scheduled inspections.
    pub fn authorize_and_enable(
        &mut self,
        interval: ScheduleInterval,
        profile: InspectionProfile,
        targets: Vec<PathBuf>,
        notify: bool,
        ac_only: bool,
    ) -> Result<ScheduleConfig, String> {
        let config = ScheduleConfig {
            enabled: true,
            interval: interval.clone(),
            profile,
            budget: profile.default_budget(),
            targets,
            notifications: notify,
            catch_up: false,
            ac_power_only: ac_only,
            max_memory_pressure_pct: Some(60.0),
            last_notification_fingerprint: None,
            executable_path: None,
            history_retention_days: 30,
            last_modified_epoch_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        };

        config.validate().map_err(|e| e.to_string())?;

        self.enabled = true;
        self.interval = interval;
        self.profile = profile;
        self.targets = config.targets.clone();
        self.notifications_enabled = notify;
        self.ac_power_only = ac_only;

        Ok(config)
    }

    /// Disables scheduled inspections.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    fn get_config_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME").unwrap_or_default();
                PathBuf::from(home).join(".config")
            });
        base.join("root").join("schedule.json")
    }

    fn get_history_path() -> PathBuf {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME").unwrap_or_default();
                PathBuf::from(home).join(".local/state")
            });
        base.join("root").join("schedule_history.json")
    }
}
