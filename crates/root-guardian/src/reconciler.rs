//! Read-only crash-state reconciliation engine.
//!
//! Conservative inspection and classification of interrupted transactions, partial writes,
//! and filesystem state. Never performs mutations, automatic recovery, deletions, or rollbacks.

use root_core::error::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use crate::{
    crypto::sha256_file,
    journal::{JournalFormat, JournalRecord, RecoveryJournal},
    transaction::TransactionState,
};

/// Explicit, conservative classification of transaction crash recovery state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ReconciliationOutcome {
    /// Operation was definitely not performed. Source is intact; destination is absent.
    KnownNotPerformed,
    /// Operation was definitely performed. Destination has the object; source is absent (or recreated).
    KnownPerformed,
    /// Ambiguous evidence. Both exist, neither exists, or identities do not match.
    Uncertain { reason: String },
    /// Journal itself is invalid (corrupt record, unknown version, bad CRC, invalid framing).
    JournalInvalid { reason: String },
    /// Inconsistent state requiring human operator decision.
    RecoveryRequired { reason: String },
}

/// Individual transaction reconciliation result produced by `JournalReconciler`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReconciliation {
    pub transaction_id: String,
    pub tail_state: TransactionState,
    pub outcome: ReconciliationOutcome,
    pub source_path: PathBuf,
    pub destination_path: Option<PathBuf>,
    pub source_exists: bool,
    pub destination_exists: bool,
    pub identity_match: Option<bool>,
    pub explanation: String,
}

/// Comprehensive crash-state reconciliation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub journal_path: PathBuf,
    pub journal_format: JournalFormat,
    pub total_records_scanned: usize,
    pub total_transactions: usize,
    pub torn_write_detected: bool,
    pub unrecoverable_corruption: Option<String>,
    pub transactions: Vec<TransactionReconciliation>,
    pub count_known_not_performed: usize,
    pub count_known_performed: usize,
    pub count_uncertain: usize,
    pub count_journal_invalid: usize,
    pub count_recovery_required: usize,
}

/// Metadata probe of a filesystem path without modifying or following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathProbe {
    exists: bool,
    is_symlink: bool,
    is_file: bool,
    device_id: u64,
    inode: u64,
    size_bytes: u64,
}

fn probe_path(path: &Path) -> PathProbe {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            let (dev, ino) = {
                use std::os::unix::fs::MetadataExt;
                (meta.dev(), meta.ino())
            };
            #[cfg(not(unix))]
            let (dev, ino) = (0, 0);

            PathProbe {
                exists: true,
                is_symlink: meta.file_type().is_symlink(),
                is_file: meta.file_type().is_file(),
                device_id: dev,
                inode: ino,
                size_bytes: meta.len(),
            }
        }
        Err(_) => PathProbe {
            exists: false,
            is_symlink: false,
            is_file: false,
            device_id: 0,
            inode: 0,
            size_bytes: 0,
        },
    }
}

fn check_identity_match(
    probe: &PathProbe,
    path: &Path,
    expected_dev: u64,
    expected_ino: u64,
    expected_size: u64,
    expected_hash: Option<&str>,
) -> bool {
    if !probe.exists {
        return false;
    }

    #[cfg(unix)]
    {
        if expected_dev != 0
            && expected_ino != 0
            && (probe.device_id != expected_dev || probe.inode != expected_ino)
        {
            return false;
        }
    }

    if expected_size > 0 && probe.size_bytes != expected_size {
        return false;
    }

    if let Some(expected_sha) = expected_hash {
        if probe.is_file && !probe.is_symlink {
            if let Ok(actual_sha) = sha256_file(path) {
                if actual_sha != expected_sha {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    true
}

/// The read-only crash-state reconciliation engine.
pub struct JournalReconciler;

impl JournalReconciler {
    /// Reconciles transaction crash state from an open `RecoveryJournal`.
    pub fn reconcile_journal(journal: &RecoveryJournal) -> Result<ReconciliationReport> {
        Self::reconcile_path(journal.path())
    }

    /// Reconciles transaction crash state directly from a journal file path.
    pub fn reconcile_path(journal_path: &Path) -> Result<ReconciliationReport> {
        Self::reconcile_with_interceptor(journal_path, &crate::fault::NoopInterceptor)
    }

    /// Reconciles transaction crash state directly from a journal file path with deterministic fault interception.
    pub fn reconcile_with_interceptor<I: crate::fault::FaultInterceptor>(
        journal_path: &Path,
        interceptor: &I,
    ) -> Result<ReconciliationReport> {
        match interceptor.on_fault_point(
            crate::fault::FaultPoint::DuringReconciliation,
            journal_path.to_str().unwrap_or(""),
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => return Err(err),
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        let journal = RecoveryJournal::new(journal_path)?;
        let scan = journal.scan_records()?;

        let mut report = ReconciliationReport {
            journal_path: journal_path.to_path_buf(),
            journal_format: scan.format,
            total_records_scanned: scan.records.len(),
            total_transactions: 0,
            torn_write_detected: scan.trailing_torn_write.is_some(),
            unrecoverable_corruption: scan
                .unrecoverable_corruption
                .as_ref()
                .map(|c| format!("{:?}", c)),
            transactions: Vec::new(),
            count_known_not_performed: 0,
            count_known_performed: 0,
            count_uncertain: 0,
            count_journal_invalid: 0,
            count_recovery_required: 0,
        };

        // If journal is empty, return empty clean report
        if scan.format == JournalFormat::Empty {
            return Ok(report);
        }

        // If journal has unrecoverable corruption, classify as JournalInvalid
        if let Some(ref corruption) = scan.unrecoverable_corruption {
            let reason = format!("{:?}", corruption);
            report.transactions.push(TransactionReconciliation {
                transaction_id: "<corrupt_journal>".into(),
                tail_state: TransactionState::Failed,
                outcome: ReconciliationOutcome::JournalInvalid {
                    reason: reason.clone(),
                },
                source_path: PathBuf::new(),
                destination_path: None,
                source_exists: false,
                destination_exists: false,
                identity_match: None,
                explanation: format!("Journal file contains unrecoverable corruption: {}", reason),
            });
            report.total_transactions = 1;
            report.count_journal_invalid = 1;
            return Ok(report);
        }

        // Group records chronologically by transaction ID
        let mut tx_order = Vec::new();
        let mut tx_groups: HashMap<String, Vec<JournalRecord>> = HashMap::new();

        for rec in scan.records {
            tx_groups
                .entry(rec.transaction_id.clone())
                .or_insert_with(|| {
                    tx_order.push(rec.transaction_id.clone());
                    Vec::new()
                })
                .push(rec);
        }

        report.total_transactions = tx_order.len();

        for tx_id in tx_order {
            let records = tx_groups.get(&tx_id).expect("transaction records present");
            let recon = Self::evaluate_transaction(&tx_id, records);
            report.transactions.push(recon);
        }

        // Aggregate summary counts
        for tx in &report.transactions {
            match tx.outcome {
                ReconciliationOutcome::KnownNotPerformed => report.count_known_not_performed += 1,
                ReconciliationOutcome::KnownPerformed => report.count_known_performed += 1,
                ReconciliationOutcome::Uncertain { .. } => report.count_uncertain += 1,
                ReconciliationOutcome::JournalInvalid { .. } => report.count_journal_invalid += 1,
                ReconciliationOutcome::RecoveryRequired { .. } => {
                    report.count_recovery_required += 1
                }
            }
        }

        Ok(report)
    }

    fn evaluate_transaction(tx_id: &str, records: &[JournalRecord]) -> TransactionReconciliation {
        if records.is_empty() {
            return TransactionReconciliation {
                transaction_id: tx_id.to_string(),
                tail_state: TransactionState::Failed,
                outcome: ReconciliationOutcome::JournalInvalid {
                    reason: "No records found for transaction".into(),
                },
                source_path: PathBuf::new(),
                destination_path: None,
                source_exists: false,
                destination_exists: false,
                identity_match: None,
                explanation: "No records found for transaction".into(),
            };
        }

        let first = &records[0];
        let tail = records.last().unwrap();
        let source_path = &tail.original_path;
        let dest_path = tail.quarantine_path.as_ref();

        // 1. Transaction internal consistency validation
        // Check for contradictory original paths or device/inode specifications
        for rec in records {
            if rec.original_path != first.original_path {
                return TransactionReconciliation {
                    transaction_id: tx_id.to_string(),
                    tail_state: tail.state,
                    outcome: ReconciliationOutcome::JournalInvalid {
                        reason: "Contradictory original paths in transaction history".into(),
                    },
                    source_path: source_path.clone(),
                    destination_path: dest_path.cloned(),
                    source_exists: false,
                    destination_exists: false,
                    identity_match: None,
                    explanation: "Transaction history contains contradictory original paths".into(),
                };
            }
        }

        // Check for illegal state transitions
        for i in 0..records.len() - 1 {
            if !records[i].state.can_transition_to(&records[i + 1].state) {
                return TransactionReconciliation {
                    transaction_id: tx_id.to_string(),
                    tail_state: tail.state,
                    outcome: ReconciliationOutcome::JournalInvalid {
                        reason: format!(
                            "Illegal transaction state transition: {:?} -> {:?}",
                            records[i].state,
                            records[i + 1].state
                        ),
                    },
                    source_path: source_path.clone(),
                    destination_path: dest_path.cloned(),
                    source_exists: false,
                    destination_exists: false,
                    identity_match: None,
                    explanation: format!(
                        "Illegal state transition {:?} -> {:?}",
                        records[i].state,
                        records[i + 1].state
                    ),
                };
            }
        }

        // Check for out-of-order single initial record that is not an allowable start state
        if records.len() == 1
            && matches!(
                records[0].state,
                TransactionState::Quarantined
                    | TransactionState::Verified
                    | TransactionState::Restored
            )
        {
            return TransactionReconciliation {
                transaction_id: tx_id.to_string(),
                tail_state: tail.state,
                outcome: ReconciliationOutcome::JournalInvalid {
                    reason: format!(
                        "Out-of-order event: transaction starts directly in {:?} without initial Prepared record",
                        records[0].state
                    ),
                },
                source_path: source_path.clone(),
                destination_path: dest_path.cloned(),
                source_exists: false,
                destination_exists: false,
                identity_match: None,
                explanation: "Transaction record history starts in an intermediate or terminal state".into(),
            };
        }

        // 2. Filesystem evidence probing
        let source_probe = probe_path(source_path);
        let dest_probe = match dest_path {
            Some(p) => probe_path(p),
            None => PathProbe {
                exists: false,
                is_symlink: false,
                is_file: false,
                device_id: 0,
                inode: 0,
                size_bytes: 0,
            },
        };

        let expected_dev = tail.device_id;
        let expected_ino = tail.inode;
        let expected_size = tail.size_bytes;
        let expected_hash = tail.sha256.as_deref();

        let source_matches = check_identity_match(
            &source_probe,
            source_path,
            expected_dev,
            expected_ino,
            expected_size,
            expected_hash,
        );

        let dest_matches = match dest_path {
            Some(p) => check_identity_match(
                &dest_probe,
                p,
                expected_dev,
                expected_ino,
                expected_size,
                expected_hash,
            ),
            None => false,
        };

        // 3. Crash-Recovery Matrix Evaluation
        let (outcome, identity_match, explanation) = match tail.state {
            TransactionState::Prepared
            | TransactionState::Proposed
            | TransactionState::Authorized => {
                if source_probe.exists && !dest_probe.exists {
                    if source_matches {
                        // Case 1: Intended; Source exists; Destination absent; Source matches
                        (
                            ReconciliationOutcome::KnownNotPerformed,
                            Some(true),
                            "Transaction was intended but not performed; source file remains intact at original location; no rollback needed.".into(),
                        )
                    } else {
                        (
                            ReconciliationOutcome::Uncertain {
                                reason: "Source exists but identity (inode/size) does not match pre-intent record; destination is absent.".into(),
                            },
                            Some(false),
                            "Source exists with unexpected identity while destination is absent.".into(),
                        )
                    }
                } else if !source_probe.exists && dest_probe.exists {
                    if dest_matches {
                        // Case 2: Intended; Source absent; Destination exists; Destination matches
                        (
                            ReconciliationOutcome::KnownPerformed,
                            Some(true),
                            "Transaction operation completed before journal was updated with committed state; destination contains expected resource.".into(),
                        )
                    } else {
                        // Case 11: Destination exists with unexpected identity
                        (
                            ReconciliationOutcome::RecoveryRequired {
                                reason: "Source is absent and destination exists with unexpected identity; potential collision or corruption.".into(),
                            },
                            Some(false),
                            "Destination exists with unexpected identity while source is absent.".into(),
                        )
                    }
                } else if source_probe.exists && dest_probe.exists {
                    // Case 3: Both exist
                    (
                        ReconciliationOutcome::Uncertain {
                            reason: "Both source and destination exist for uncommitted intent; manual operator investigation required.".into(),
                        },
                        None,
                        "Ambiguous filesystem state: both source and destination exist.".into(),
                    )
                } else {
                    // Case 4: Neither exists
                    (
                        ReconciliationOutcome::Uncertain {
                            reason: "Neither source nor destination exists for uncommitted intent; manual operator investigation required.".into(),
                        },
                        None,
                        "Ambiguous filesystem state: neither source nor destination exists.".into(),
                    )
                }
            }

            TransactionState::Quarantined | TransactionState::Verified => {
                if !source_probe.exists && dest_probe.exists {
                    if dest_matches {
                        // Case 5: Committed; Source absent; Destination exists; Destination matches
                        (
                            ReconciliationOutcome::KnownPerformed,
                            Some(true),
                            "Transaction completed successfully; resource is safely quarantined at destination.".into(),
                        )
                    } else {
                        // Case 11: Destination exists with unexpected identity
                        (
                            ReconciliationOutcome::RecoveryRequired {
                                reason: "Transaction marked committed but destination exists with unexpected identity; quarantined object identity mismatch.".into(),
                            },
                            Some(false),
                            "Destination exists with unexpected identity.".into(),
                        )
                    }
                } else if source_probe.exists && !dest_probe.exists {
                    // Case 6: Committed; Source exists; Destination absent
                    (
                        ReconciliationOutcome::RecoveryRequired {
                            reason: "Transaction marked committed in journal but source path still exists and destination is absent; operator investigation required.".into(),
                        },
                        Some(source_matches),
                        "Source path still exists despite committed relocation; destination is absent.".into(),
                    )
                } else if source_probe.exists && dest_probe.exists {
                    if dest_matches {
                        if source_probe.inode == expected_ino
                            && source_probe.device_id == expected_dev
                        {
                            // Hard link collision
                            (
                                ReconciliationOutcome::Uncertain {
                                    reason: "Both source and destination reference the same inode; hard-link duplication detected.".into(),
                                },
                                Some(true),
                                "Both source and destination exist with the same inode.".into(),
                            )
                        } else {
                            // Case 7: Committed; Destination matches expected, source is a newly recreated object
                            (
                                ReconciliationOutcome::KnownPerformed,
                                Some(true),
                                "Quarantined resource exists at destination with expected identity; source path was recreated as a distinct object after relocation.".into(),
                            )
                        }
                    } else {
                        // Case 11: Destination does not match expected identity
                        (
                            ReconciliationOutcome::RecoveryRequired {
                                reason: "Both source and destination exist, but destination does not match expected identity.".into(),
                            },
                            Some(false),
                            "Ambiguous state: destination identity does not match expected resource.".into(),
                        )
                    }
                } else {
                    // Case 8: Committed; Neither exists
                    (
                        ReconciliationOutcome::RecoveryRequired {
                            reason: "Transaction marked committed in journal but neither source nor destination exists; quarantined object is missing.".into(),
                        },
                        None,
                        "Quarantined object missing: neither source nor destination exists.".into(),
                    )
                }
            }

            TransactionState::Restored => {
                if source_probe.exists && !dest_probe.exists {
                    if source_matches {
                        (
                            ReconciliationOutcome::KnownPerformed,
                            Some(true),
                            "Resource successfully restored back to original location; quarantine location is empty.".into(),
                        )
                    } else {
                        (
                            ReconciliationOutcome::RecoveryRequired {
                                reason: "Resource marked restored but file at original location has unexpected identity.".into(),
                            },
                            Some(false),
                            "Restored resource identity mismatch.".into(),
                        )
                    }
                } else if !source_probe.exists && dest_probe.exists {
                    (
                        ReconciliationOutcome::RecoveryRequired {
                            reason: "Transaction marked restored but resource is still present in quarantine and absent at original path.".into(),
                        },
                        Some(dest_matches),
                        "Restoration incomplete: file still in quarantine.".into(),
                    )
                } else if source_probe.exists && dest_probe.exists {
                    (
                        ReconciliationOutcome::Uncertain {
                            reason: "Both original path and quarantine path exist for restored transaction.".into(),
                        },
                        None,
                        "Both original path and quarantine path exist.".into(),
                    )
                } else {
                    (
                        ReconciliationOutcome::RecoveryRequired {
                            reason: "Neither original path nor quarantine path exists for restored transaction.".into(),
                        },
                        None,
                        "Restored object missing from both locations.".into(),
                    )
                }
            }

            TransactionState::Failed => {
                if source_probe.exists && !dest_probe.exists {
                    if source_matches {
                        (
                            ReconciliationOutcome::KnownNotPerformed,
                            Some(true),
                            "Transaction failed before relocation; source file remains intact at original location.".into(),
                        )
                    } else {
                        (
                            ReconciliationOutcome::Uncertain {
                                reason: "Transaction marked failed; source exists with unexpected identity; destination absent.".into(),
                            },
                            Some(false),
                            "Source exists with unexpected identity for failed transaction.".into(),
                        )
                    }
                } else if !source_probe.exists && dest_probe.exists {
                    (
                        ReconciliationOutcome::RecoveryRequired {
                            reason: "Transaction marked failed but destination file exists and source is absent.".into(),
                        },
                        Some(dest_matches),
                        "Inconsistent state: transaction failed but file moved to destination.".into(),
                    )
                } else {
                    (
                        ReconciliationOutcome::Uncertain {
                            reason: "Transaction marked failed; ambiguous filesystem state.".into(),
                        },
                        None,
                        "Ambiguous state for failed transaction.".into(),
                    )
                }
            }

            TransactionState::RecoveryRequired => (
                ReconciliationOutcome::RecoveryRequired {
                    reason: tail.failure_reason.clone().unwrap_or_else(|| {
                        "Transaction marked as requiring recovery in journal".into()
                    }),
                },
                None,
                "Transaction explicitly marked RecoveryRequired in journal.".into(),
            ),
        };

        TransactionReconciliation {
            transaction_id: tx_id.to_string(),
            tail_state: tail.state,
            outcome,
            source_path: source_path.clone(),
            destination_path: dest_path.cloned(),
            source_exists: source_probe.exists,
            destination_exists: dest_probe.exists,
            identity_match,
            explanation,
        }
    }
}
