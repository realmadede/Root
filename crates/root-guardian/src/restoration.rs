use root_core::error::{Result, RootError};
use root_platform::LinuxFilesystem;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use crate::{
    crypto::sha256_file,
    journal::{JournalRecord, RecoveryJournal},
    sandbox::FixtureSandbox,
    transaction::{TransactionContext, TransactionState},
};

/// Engine handling safe, conflict-aware restoration of quarantined resources.
pub struct RestorationEngine;

impl RestorationEngine {
    /// Restores a previously quarantined resource back to its original path within the sandbox.
    pub fn restore_resource(
        sandbox: &FixtureSandbox,
        journal: &mut RecoveryJournal,
        transaction_id: &str,
    ) -> Result<TransactionContext> {
        // 1. Locate latest transaction record from journal
        let latest_record =
            journal
                .find_latest(transaction_id)?
                .ok_or_else(|| RootError::TransactionFailed {
                    tx_id: transaction_id.to_string(),
                    reason: "No journal record found for transaction".into(),
                })?;

        // State check: Only Verified or RecoveryRequired transactions can be restored
        if latest_record.state != TransactionState::Verified
            && latest_record.state != TransactionState::RecoveryRequired
        {
            return Err(RootError::InvalidStateTransition {
                from: format!("{:?}", latest_record.state),
                to: "Restored".into(),
            });
        }

        let quarantine_path =
            latest_record
                .quarantine_path
                .as_ref()
                .ok_or_else(|| RootError::TransactionFailed {
                    tx_id: transaction_id.to_string(),
                    reason: "Journal record is missing quarantine path".into(),
                })?;

        let original_path = &latest_record.original_path;

        // 2. Validate Sandbox boundaries
        sandbox.assert_within_bounds(original_path)?;

        // 3. Verify quarantined file integrity before attempting restoration
        if !quarantine_path.exists() {
            return Err(RootError::IntegrityVerificationFailed {
                path: quarantine_path.clone(),
                reason: "Quarantined file has disappeared from staging area".into(),
            });
        }

        if let Some(ref expected_sha256) = latest_record.sha256 {
            let actual_sha256 = sha256_file(quarantine_path)?;
            if actual_sha256 != *expected_sha256 {
                return Err(RootError::IntegrityVerificationFailed {
                    path: quarantine_path.clone(),
                    reason: format!(
                        "Quarantine file corruption detected: hash '{}' != expected '{}'",
                        actual_sha256, expected_sha256
                    ),
                });
            }
        }

        // 4. Destination Conflict Check: Never overwrite an existing file!
        if original_path.exists() || fs::symlink_metadata(original_path).is_ok() {
            return Err(RootError::RestorationConflict {
                path: original_path.clone(),
                reason: "Destination path is occupied by an existing file or directory".into(),
            });
        }

        // 5. Ensure parent directory exists
        if let Some(parent) = original_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| RootError::Io {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
        }

        // 6. Perform atomic rename back to original path
        let quat_meta = fs::symlink_metadata(quarantine_path).map_err(|e| RootError::Io {
            path: quarantine_path.clone(),
            source: e,
        })?;

        LinuxFilesystem::atomic_rename_no_replace(quarantine_path, original_path)?;

        // 7. Restore permissions
        let _ = fs::set_permissions(
            original_path,
            fs::Permissions::from_mode(quat_meta.mode() & 0o777),
        );

        // 8. Log restoration record to journal
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let restoration_record = JournalRecord {
            transaction_id: transaction_id.to_string(),
            timestamp_epoch_secs: now,
            state: TransactionState::Restored,
            original_path: original_path.clone(),
            quarantine_path: Some(quarantine_path.clone()),
            device_id: latest_record.device_id,
            inode: latest_record.inode,
            size_bytes: latest_record.size_bytes,
            sha256: latest_record.sha256.clone(),
            reason: "Resource successfully restored to original path".into(),
            failure_reason: None,
        };

        journal.append(&restoration_record)?;

        // Build completed context
        let dummy_candidate = root_core::model::ResourceCandidate {
            id: root_core::model::ResourceId::new(transaction_id),
            location: root_core::model::ResourceLocation::new(
                original_path.clone(),
                None,
                latest_record.device_id,
                latest_record.inode,
            ),
            category: root_core::model::ResourceCategory::BuildArtifact,
            metadata: root_core::model::ResourceMetadata {
                file_type: root_core::model::FileType::RegularFile,
                storage: root_core::model::StorageMeasurement::from_raw(
                    latest_record.size_bytes,
                    1,
                    1,
                ),
                permissions_mode: quat_meta.mode() & 0o777,
                mtime_epoch_secs: now,
                atime_epoch_secs: now,
                ctime_epoch_secs: now,
            },
            ownership: root_core::model::ResourceOwnership {
                uid: sandbox.operator_uid(),
                gid: sandbox.operator_uid(),
                is_current_user: true,
            },
            associated_agent: None,
        };

        let mut ctx = TransactionContext::new(
            dummy_candidate,
            root_core::model::ProposedAction::Quarantine,
        );
        ctx.transaction_id = transaction_id.to_string();
        ctx.state = TransactionState::Restored;
        ctx.quarantine_path = Some(quarantine_path.clone());
        ctx.verified_sha256 = latest_record.sha256;

        Ok(ctx)
    }
}
