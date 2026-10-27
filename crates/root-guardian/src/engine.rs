use root_core::error::{Result, RootError};
use std::{fs, os::unix::fs::MetadataExt};

use crate::{
    authorization::{AuthorizationDecision, AuthorizationEngine, AuthorizationRequest},
    crypto::sha256_file,
    journal::{JournalRecord, RecoveryJournal},
    quarantine::QuarantineStore,
    restoration::RestorationEngine,
    sandbox::FixtureSandbox,
    transaction::{TransactionContext, TransactionState},
};

/// High-level quarantine transaction engine coordinating multi-stage resource quarantine and restoration.
pub struct TransactionEngine;

impl TransactionEngine {
    /// Executes a complete, verified quarantine transaction within the isolated fixture sandbox.
    pub fn quarantine(
        sandbox: &FixtureSandbox,
        journal: &mut RecoveryJournal,
        request: &AuthorizationRequest,
    ) -> Result<TransactionContext> {
        Self::quarantine_with_interceptor(sandbox, journal, request, &crate::fault::NoopInterceptor)
    }

    /// Executes a verified quarantine transaction with deterministic fault interception.
    pub fn quarantine_with_interceptor<I: crate::fault::FaultInterceptor>(
        sandbox: &FixtureSandbox,
        journal: &mut RecoveryJournal,
        request: &AuthorizationRequest,
        interceptor: &I,
    ) -> Result<TransactionContext> {
        let source_path = &request.candidate.location.path;

        // 1. Validate sandbox containment
        sandbox.assert_within_bounds(source_path)?;

        // 2. Initialize Transaction in Proposed state
        let mut ctx = TransactionContext::new(request.candidate.clone(), request.requested_action);

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::BeforeAuthorization,
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        // 3. Evaluate Guardian Authorization Policy
        let auth_decision = AuthorizationEngine::authorize(request);
        let receipt = match auth_decision {
            AuthorizationDecision::Authorized { receipt } => receipt,
            AuthorizationDecision::Denied {
                reason,
                explanation,
            } => {
                ctx.fail(format!(
                    "Authorization denied ({:?}): {}",
                    reason, explanation
                ))?;
                let record = JournalRecord {
                    transaction_id: ctx.transaction_id.clone(),
                    timestamp_epoch_secs: ctx.created_at_epoch_secs,
                    state: TransactionState::Failed,
                    original_path: source_path.to_path_buf(),
                    quarantine_path: None,
                    device_id: request.candidate.location.device_id,
                    inode: request.candidate.location.inode,
                    size_bytes: request.candidate.metadata.storage.bytes,
                    sha256: None,
                    reason: format!("Authorization denied: {:?}", reason),
                    failure_reason: Some(explanation.clone()),
                };
                let _ = journal.append(&record);
                return Err(RootError::PolicyViolation {
                    reason: format!(
                        "Guardian authorization denied ({:?}): {}",
                        reason, explanation
                    ),
                });
            }
        };

        // Transition: Proposed -> Authorized
        ctx.transition_to(TransactionState::Authorized)?;

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::AfterAuthorization,
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::BeforePreflightValidation,
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        // 4. Pre-flight Validation: Stat file and compute snapshot hash
        let meta = fs::symlink_metadata(source_path).map_err(|e| RootError::Io {
            path: source_path.to_path_buf(),
            source: e,
        })?;

        if meta.is_symlink() {
            ctx.fail("Candidate is a symbolic link; symlinks cannot be quarantined directly")?;
            return Err(RootError::PolicyViolation {
                reason: "Symlinks cannot be quarantined".into(),
            });
        }

        if meta.dev() != request.candidate.location.device_id
            || meta.ino() != request.candidate.location.inode
        {
            ctx.fail("Source file identity changed after authorization")?;
            return Err(RootError::PolicyViolation {
                reason: format!(
                    "Source identity revalidation failed after authorization: observed {}:{}, authorized {}:{}",
                    meta.dev(),
                    meta.ino(),
                    request.candidate.location.device_id,
                    request.candidate.location.inode
                ),
            });
        }

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::AfterIdentityValidation,
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        match interceptor
            .on_fault_point(crate::fault::FaultPoint::DuringHashing, &ctx.transaction_id)
        {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        let sha256_hash = sha256_file(source_path)?;

        match interceptor
            .on_fault_point(crate::fault::FaultPoint::AfterHashing, &ctx.transaction_id)
        {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        let size_bytes = meta.len();
        let expected_dev = meta.dev();
        let expected_ino = meta.ino();

        let (expected_parent_dev, expected_parent_ino) = match source_path.parent() {
            Some(p) => {
                let pmeta = fs::symlink_metadata(p).map_err(|e| RootError::Io {
                    path: p.to_path_buf(),
                    source: e,
                })?;
                (Some(pmeta.dev()), Some(pmeta.ino()))
            }
            None => (None, None),
        };

        // Allocate collision-resistant quarantine path
        let quarantine_path = QuarantineStore::allocate_quarantine_path(
            sandbox,
            &ctx.transaction_id,
            source_path,
            expected_ino,
        )?;

        ctx.quarantine_path = Some(quarantine_path.clone());
        ctx.verified_sha256 = Some(sha256_hash.clone());

        // Transition: Authorized -> Prepared
        ctx.transition_to(TransactionState::Prepared)?;

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::BeforeJournalAppend(TransactionState::Prepared),
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        // Write Prepared state to Journal
        let prepared_record = JournalRecord {
            transaction_id: ctx.transaction_id.clone(),
            timestamp_epoch_secs: ctx.created_at_epoch_secs,
            state: TransactionState::Prepared,
            original_path: source_path.to_path_buf(),
            quarantine_path: Some(quarantine_path.clone()),
            device_id: expected_dev,
            inode: expected_ino,
            size_bytes,
            sha256: Some(sha256_hash.clone()),
            reason: receipt.evidence.clone(),
            failure_reason: None,
        };
        journal.append(&prepared_record)?;

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::AfterJournalAppend(TransactionState::Prepared),
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        // 5. TOCTOU Defense: Pin directories and revalidate identity & consent immediately prior to rename
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let source_parent = source_path
            .parent()
            .ok_or_else(|| RootError::InvalidPath("Source has no parent".into()))?;
        let source_filename = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RootError::InvalidPath("Invalid source filename".into()))?;
        let quarantine_filename = quarantine_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RootError::InvalidPath("Invalid quarantine filename".into()))?;

        #[cfg(target_os = "linux")]
        let (source_parent_dir, dest_dir) = {
            let sp_dir = root_platform::PinnedDirectory::open_root(source_parent).map_err(|e| {
                let _ = ctx.fail(format!("Failed to pin source parent directory: {}", e));
                RootError::from(e)
            })?;
            let d_dir = root_platform::PinnedDirectory::open_root(sandbox.quarantine_dir())
                .map_err(|e| {
                    let _ = ctx.fail(format!("Failed to pin quarantine directory: {}", e));
                    RootError::from(e)
                })?;
            (sp_dir, d_dir)
        };

        if let Err(rejection) = AuthorizationEngine::revalidate_full(
            source_path,
            expected_dev,
            expected_ino,
            sandbox.operator_uid(),
            expected_parent_dev,
            expected_parent_ino,
            Some(sandbox.root()),
        ) {
            ctx.fail(format!(
                "Pre-mutation TOCTOU revalidation failed: {:?}",
                rejection
            ))?;
            let fail_record = JournalRecord {
                transaction_id: ctx.transaction_id.clone(),
                timestamp_epoch_secs: ctx.created_at_epoch_secs,
                state: TransactionState::Failed,
                original_path: source_path.to_path_buf(),
                quarantine_path: Some(quarantine_path),
                device_id: expected_dev,
                inode: expected_ino,
                size_bytes,
                sha256: Some(sha256_hash),
                reason: "TOCTOU revalidation failed immediately prior to mutation".into(),
                failure_reason: Some(format!("{:?}", rejection)),
            };
            let _ = journal.append(&fail_record);
            return Err(RootError::PolicyViolation {
                reason: format!("TOCTOU revalidation failed: {:?}", rejection),
            });
        }

        // Revalidate descriptor-pinned identity AND consent expiration!
        #[cfg(target_os = "linux")]
        if let Err(rejection) = AuthorizationEngine::revalidate_pinned(
            &source_parent_dir,
            source_filename,
            expected_dev,
            expected_ino,
            sandbox.operator_uid(),
            request.consent_record.as_ref(),
            now,
        ) {
            ctx.fail(format!(
                "Pre-mutation descriptor revalidation failed: {:?}",
                rejection
            ))?;
            let fail_record = JournalRecord {
                transaction_id: ctx.transaction_id.clone(),
                timestamp_epoch_secs: ctx.created_at_epoch_secs,
                state: TransactionState::Failed,
                original_path: source_path.to_path_buf(),
                quarantine_path: Some(quarantine_path),
                device_id: expected_dev,
                inode: expected_ino,
                size_bytes,
                sha256: Some(sha256_hash),
                reason: "Pre-mutation descriptor revalidation failed".into(),
                failure_reason: Some(format!("{:?}", rejection)),
            };
            let _ = journal.append(&fail_record);
            return Err(RootError::PolicyViolation {
                reason: format!("Pre-mutation revalidation failed: {:?}", rejection),
            });
        }

        // Verify destination does not already exist in destination directory
        #[cfg(target_os = "linux")]
        if dest_dir.exists_child(quarantine_filename) {
            ctx.fail("Destination collision detected in quarantine staging")?;
            let fail_record = JournalRecord {
                transaction_id: ctx.transaction_id.clone(),
                timestamp_epoch_secs: ctx.created_at_epoch_secs,
                state: TransactionState::Failed,
                original_path: source_path.to_path_buf(),
                quarantine_path: Some(quarantine_path.clone()),
                device_id: expected_dev,
                inode: expected_ino,
                size_bytes,
                sha256: Some(sha256_hash),
                reason: "Destination collision in quarantine staging".into(),
                failure_reason: Some("Destination collision".into()),
            };
            let _ = journal.append(&fail_record);
            return Err(RootError::DestinationCollision {
                path: quarantine_path,
            });
        }

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::ImmediatelyBeforeRename,
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        // 6. Perform descriptor-pinned atomic rename
        #[cfg(target_os = "linux")]
        let rename_res = QuarantineStore::relocate_pinned(
            &source_parent_dir,
            source_filename,
            &dest_dir,
            quarantine_filename,
            sandbox.device_id(),
            meta.mode() & 0o777,
        );

        #[cfg(not(target_os = "linux"))]
        let rename_res = QuarantineStore::relocate_into_quarantine(
            source_path,
            &quarantine_path,
            sandbox.device_id(),
        );

        if let Err(e) = rename_res {
            ctx.fail(format!("Relocation into quarantine failed: {}", e))?;
            let fail_record = JournalRecord {
                transaction_id: ctx.transaction_id.clone(),
                timestamp_epoch_secs: ctx.created_at_epoch_secs,
                state: TransactionState::Failed,
                original_path: source_path.to_path_buf(),
                quarantine_path: Some(quarantine_path),
                device_id: expected_dev,
                inode: expected_ino,
                size_bytes,
                sha256: Some(sha256_hash),
                reason: "Atomic rename failed".into(),
                failure_reason: Some(e.to_string()),
            };
            let _ = journal.append(&fail_record);
            return Err(e);
        }

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::ImmediatelyAfterRename,
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        // Transition: Prepared -> Quarantined
        ctx.transition_to(TransactionState::Quarantined)?;

        let quarantined_record = JournalRecord {
            transaction_id: ctx.transaction_id.clone(),
            timestamp_epoch_secs: ctx.created_at_epoch_secs,
            state: TransactionState::Quarantined,
            original_path: source_path.to_path_buf(),
            quarantine_path: Some(quarantine_path.clone()),
            device_id: expected_dev,
            inode: expected_ino,
            size_bytes,
            sha256: Some(sha256_hash.clone()),
            reason: "Atomic move into quarantine completed".into(),
            failure_reason: None,
        };
        journal.append(&quarantined_record)?;

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::BeforePostOperationVerification,
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        // 7. Post-mutation verification (verify integrity and verify source is gone)
        #[cfg(target_os = "linux")]
        let source_still_exists = source_parent_dir.exists_child(source_filename);
        #[cfg(not(target_os = "linux"))]
        let source_still_exists = source_path.exists();

        if source_still_exists {
            ctx.transition_to(TransactionState::RecoveryRequired)?;
            let rec_record = JournalRecord {
                transaction_id: ctx.transaction_id.clone(),
                timestamp_epoch_secs: ctx.created_at_epoch_secs,
                state: TransactionState::RecoveryRequired,
                original_path: source_path.to_path_buf(),
                quarantine_path: Some(quarantine_path),
                device_id: expected_dev,
                inode: expected_ino,
                size_bytes,
                sha256: Some(sha256_hash),
                reason: "Post-mutation anomaly: source path still exists after rename".into(),
                failure_reason: Some("Source path not unlinked".into()),
            };
            let _ = journal.append(&rec_record);
            return Err(RootError::IntegrityVerificationFailed {
                path: source_path.to_path_buf(),
                reason: "Source path still exists after quarantine rename".into(),
            });
        }

        #[cfg(target_os = "linux")]
        {
            let dest_id = dest_dir.stat_child(quarantine_filename).map_err(|e| {
                RootError::IntegrityVerificationFailed {
                    path: quarantine_path.clone(),
                    reason: format!("Failed to stat quarantined destination descriptor: {}", e),
                }
            })?;

            if dest_id.inode != expected_ino || dest_id.device_id != expected_dev {
                ctx.transition_to(TransactionState::RecoveryRequired)?;
                let rec_record = JournalRecord {
                    transaction_id: ctx.transaction_id.clone(),
                    timestamp_epoch_secs: ctx.created_at_epoch_secs,
                    state: TransactionState::RecoveryRequired,
                    original_path: source_path.to_path_buf(),
                    quarantine_path: Some(quarantine_path.clone()),
                    device_id: expected_dev,
                    inode: expected_ino,
                    size_bytes,
                    sha256: Some(sha256_hash.clone()),
                    reason: "Post-mutation anomaly: quarantined inode does not match authorized identity".into(),
                    failure_reason: Some(format!(
                        "Quarantined inode ({}:{}) does not match expected ({}:{})",
                        dest_id.device_id, dest_id.inode, expected_dev, expected_ino
                    )),
                };
                let _ = journal.append(&rec_record);
                return Err(RootError::IntegrityVerificationFailed {
                    path: quarantine_path,
                    reason: format!(
                        "Quarantined inode ({}:{}) does not match authorized candidate ({}:{})",
                        dest_id.device_id, dest_id.inode, expected_dev, expected_ino
                    ),
                });
            }
        }

        if let Err(e) =
            QuarantineStore::verify_quarantined_resource(&quarantine_path, size_bytes, &sha256_hash)
        {
            ctx.transition_to(TransactionState::RecoveryRequired)?;
            let rec_record = JournalRecord {
                transaction_id: ctx.transaction_id.clone(),
                timestamp_epoch_secs: ctx.created_at_epoch_secs,
                state: TransactionState::RecoveryRequired,
                original_path: source_path.to_path_buf(),
                quarantine_path: Some(quarantine_path),
                device_id: expected_dev,
                inode: expected_ino,
                size_bytes,
                sha256: Some(sha256_hash),
                reason: "Post-mutation integrity check failed".into(),
                failure_reason: Some(e.to_string()),
            };
            let _ = journal.append(&rec_record);
            return Err(e);
        }

        match interceptor.on_fault_point(
            crate::fault::FaultPoint::AfterVerification,
            &ctx.transaction_id,
        ) {
            crate::fault::InterceptDecision::Continue => {}
            crate::fault::InterceptDecision::Fail(err) => {
                let _ = ctx.fail(err.to_string());
                return Err(err);
            }
            crate::fault::InterceptDecision::Crash(err) => return Err(err),
        }

        // Transition: Quarantined -> Verified
        ctx.transition_to(TransactionState::Verified)?;

        let verified_record = JournalRecord {
            transaction_id: ctx.transaction_id.clone(),
            timestamp_epoch_secs: ctx.created_at_epoch_secs,
            state: TransactionState::Verified,
            original_path: source_path.to_path_buf(),
            quarantine_path: Some(quarantine_path),
            device_id: expected_dev,
            inode: expected_ino,
            size_bytes,
            sha256: Some(sha256_hash),
            reason: "Quarantine verification succeeded; file intact in staging".into(),
            failure_reason: None,
        };
        journal.append(&verified_record)?;

        Ok(ctx)
    }

    /// Restores a previously verified quarantine transaction.
    pub fn restore(
        sandbox: &FixtureSandbox,
        journal: &mut RecoveryJournal,
        transaction_id: &str,
    ) -> Result<TransactionContext> {
        RestorationEngine::restore_resource(sandbox, journal, transaction_id)
    }

    /// Restores a previously verified quarantine transaction with deterministic fault interception.
    pub fn restore_with_interceptor<I: crate::fault::FaultInterceptor>(
        sandbox: &FixtureSandbox,
        journal: &mut RecoveryJournal,
        transaction_id: &str,
        interceptor: &I,
    ) -> Result<TransactionContext> {
        RestorationEngine::restore_resource_with_interceptor(
            sandbox,
            journal,
            transaction_id,
            interceptor,
        )
    }
}
