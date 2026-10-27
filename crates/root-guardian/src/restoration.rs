use root_core::error::{Result, RootError};
#[cfg(not(target_os = "linux"))]
use root_platform::LinuxFilesystem;
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::PermissionsExt;
use std::{fs, os::unix::fs::MetadataExt};

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
        Self::restore_resource_with_interceptor(
            sandbox,
            journal,
            transaction_id,
            &crate::fault::NoopInterceptor,
        )
    }

    /// Restores a previously quarantined resource with deterministic fault interception.
    pub fn restore_resource_with_interceptor<I: crate::fault::FaultInterceptor>(
        sandbox: &FixtureSandbox,
        journal: &mut RecoveryJournal,
        transaction_id: &str,
        interceptor: &I,
    ) -> Result<TransactionContext> {
        match interceptor
            .on_fault_point(crate::fault::FaultPoint::BeforeRestoration, transaction_id)
        {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => return Err(err),
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

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
        let orig_parent = original_path.parent().ok_or_else(|| {
            RootError::InvalidPath(format!("Original path '{:?}' has no parent", original_path))
        })?;
        let orig_filename = original_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RootError::InvalidPath("Invalid original filename".into()))?;
        let quarantine_filename = quarantine_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RootError::InvalidPath("Invalid quarantine filename".into()))?;

        if !orig_parent.exists() {
            fs::create_dir_all(orig_parent).map_err(|e| RootError::Io {
                path: orig_parent.to_path_buf(),
                source: e,
            })?;
        }

        // 6. Perform descriptor-pinned atomic rename back to original path
        let quat_meta = fs::symlink_metadata(quarantine_path).map_err(|e| RootError::Io {
            path: quarantine_path.clone(),
            source: e,
        })?;

        match interceptor
            .on_fault_point(crate::fault::FaultPoint::DuringRestoration, transaction_id)
        {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => return Err(err),
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        #[cfg(target_os = "linux")]
        {
            let dest_parent_dir = root_platform::PinnedDirectory::open_root(orig_parent)?;
            let quarantine_dir =
                root_platform::PinnedDirectory::open_root(sandbox.quarantine_dir())?;

            if dest_parent_dir.exists_child(orig_filename) {
                return Err(RootError::RestorationConflict {
                    path: original_path.clone(),
                    reason: "Destination path is occupied by an existing file or directory".into(),
                });
            }

            quarantine_dir
                .rename_child_to(quarantine_filename, &dest_parent_dir, orig_filename)
                .map_err(RootError::from)?;

            // 7. Restore permissions
            let _ =
                dest_parent_dir.set_child_permissions_mode(orig_filename, quat_meta.mode() & 0o777);
        }

        #[cfg(not(target_os = "linux"))]
        {
            LinuxFilesystem::atomic_rename_no_replace(quarantine_path, original_path)?;

            // 7. Restore permissions
            let _ = fs::set_permissions(
                original_path,
                fs::Permissions::from_mode(quat_meta.mode() & 0o777),
            );
        }

        match interceptor.on_fault_point(crate::fault::FaultPoint::AfterRestoration, transaction_id)
        {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => return Err(err),
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

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
