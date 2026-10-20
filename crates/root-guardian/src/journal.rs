use root_core::error::{Result, RootError};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use crate::transaction::TransactionState;

/// An immutable, auditable log entry recorded during quarantine or restoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    pub transaction_id: String,
    pub timestamp_epoch_secs: i64,
    pub state: TransactionState,
    pub original_path: PathBuf,
    pub quarantine_path: Option<PathBuf>,
    pub device_id: u64,
    pub inode: u64,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub reason: String,
    pub failure_reason: Option<String>,
}

/// A durable, append-only JSONL recovery journal tracking transactional operations.
#[derive(Debug)]
pub struct RecoveryJournal {
    journal_path: PathBuf,
}

impl RecoveryJournal {
    pub fn new(journal_path: &Path) -> Result<Self> {
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RootError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        Ok(Self {
            journal_path: journal_path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.journal_path
    }

    /// Appends a new journal record and synchronizes to disk.
    pub fn append(&mut self, record: &JournalRecord) -> Result<()> {
        let serialized =
            serde_json::to_string(record).map_err(|e| RootError::Serialization(e.to_string()))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .map_err(|e| RootError::Io {
                path: self.journal_path.clone(),
                source: e,
            })?;

        writeln!(file, "{}", serialized).map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        // Synchronize data to physical storage for crash resilience
        file.sync_data().map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        Ok(())
    }

    /// Reads and parses all journal records in chronological sequence.
    ///
    /// Reports an explicit `RootError::JournalError` if a line is malformed or corrupted.
    pub fn read_all(&self) -> Result<Vec<JournalRecord>> {
        if !self.journal_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.journal_path).map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| RootError::Io {
                path: self.journal_path.clone(),
                source: e,
            })?;

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let record: JournalRecord =
                serde_json::from_str(trimmed).map_err(|e| RootError::JournalError {
                    path: self.journal_path.clone(),
                    reason: format!("Line {} is malformed: {}", idx + 1, e),
                })?;

            records.push(record);
        }

        Ok(records)
    }

    /// Finds the most recent journal record associated with a given transaction ID.
    pub fn find_latest(&self, transaction_id: &str) -> Result<Option<JournalRecord>> {
        let records = self.read_all()?;
        Ok(records
            .into_iter()
            .rev()
            .find(|r| r.transaction_id == transaction_id))
    }

    /// Scans the journal for interrupted transactions that did not reach a terminal or verified state.
    pub fn get_interrupted_transactions(&self) -> Result<Vec<JournalRecord>> {
        let records = self.read_all()?;
        let mut latest_by_id: HashMap<String, JournalRecord> = HashMap::new();

        for record in records {
            latest_by_id.insert(record.transaction_id.clone(), record);
        }

        let mut interrupted = Vec::new();
        for (_id, record) in latest_by_id {
            match record.state {
                TransactionState::Prepared | TransactionState::Quarantined => {
                    interrupted.push(record);
                }
                _ => {}
            }
        }

        Ok(interrupted)
    }
}
