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
        let source_path = &request.candidate.location.path;

        // 1. Validate sandbox containment
        sandbox.assert_within_bounds(source_path)?;

        // 2. Initialize Transaction in Proposed state
        let mut ctx = TransactionContext::new(request.candidate.clone(), request.requested_action);

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

        let sha256_hash = sha256_file(source_path)?;
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

        // 5. TOCTOU Defense: Revalidate immediately before physical rename
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

        // 6. Perform same-filesystem atomic rename
        if let Err(e) = QuarantineStore::relocate_into_quarantine(
            source_path,
            &quarantine_path,
            sandbox.device_id(),
        ) {
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

        // 7. Post-mutation verification (verify integrity and verify source is gone)
        if source_path.exists() {
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
}
