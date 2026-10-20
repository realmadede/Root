use root_core::error::{Result, RootError};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

/// Summary record of a completed scan or discovery pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanHistoryRecord {
    pub timestamp_epoch_secs: i64,
    pub scan_root: String,
    pub total_scanned: u64,
    pub total_findings: usize,
    pub is_complete: bool,
    pub command_source: String,
}

/// Resolves the canonical path for Root's state file in accordance with the XDG Base Directory specification.
pub fn get_history_file_path() -> PathBuf {
    if let Ok(state_home) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(state_home)
            .join("root")
            .join("last_scan.json")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("root")
            .join("last_scan.json")
    } else {
        PathBuf::from("/tmp/root_last_scan.json")
    }
}

/// Records the summary of a completed scan or discovery run.
pub fn save_last_scan(
    scan_root: &Path,
    total_scanned: u64,
    total_findings: usize,
    is_complete: bool,
    command_source: &str,
) -> Result<()> {
    let path = get_history_file_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let record = ScanHistoryRecord {
        timestamp_epoch_secs: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        scan_root: scan_root.display().to_string(),
        total_scanned,
        total_findings,
        is_complete,
        command_source: command_source.to_string(),
    };

    let serialized = serde_json::to_string_pretty(&record)
        .map_err(|e| RootError::Serialization(e.to_string()))?;

    fs::write(&path, serialized).map_err(|e| RootError::Io { path, source: e })?;

    Ok(())
}

/// Loads the most recent scan summary from persistent state, if available.
pub fn load_last_scan() -> Option<ScanHistoryRecord> {
    let path = get_history_file_path();
    if !path.exists() {
        return None;
    }

    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}
