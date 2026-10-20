use root_core::{
    error::{Result, RootError},
    model::{ProposedAction, ResourceCandidate},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Explicit, auditable lifecycle states for a Root quarantine transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    /// Initial proposal of an action against an identified resource.
    Proposed,
    /// Evaluated and explicitly approved by Root Guardian authorization policies.
    Authorized,
    /// Pre-flight validation passed; destination allocated; journal record prepared.
    Prepared,
    /// Target file atomically relocated into isolated quarantine staging.
    Quarantined,
    /// Post-mutation verification completed (quarantine integrity verified; source unlinked).
    Verified,
    /// Quarantined resource successfully restored back to its original path.
    Restored,
    /// Transaction aborted or failed due to an error, policy rejection, or collision.
    Failed,
    /// Incomplete or anomalous state requiring operator intervention or recovery replay.
    RecoveryRequired,
}

impl TransactionState {
    /// Validates whether a state transition is legal under Root's transactional safety model.
    pub fn can_transition_to(&self, next: &TransactionState) -> bool {
        match (self, next) {
            // From Proposed
            (TransactionState::Proposed, TransactionState::Authorized) => true,
            (TransactionState::Proposed, TransactionState::Failed) => true,

            // From Authorized
            (TransactionState::Authorized, TransactionState::Prepared) => true,
            (TransactionState::Authorized, TransactionState::Failed) => true,

            // From Prepared
            (TransactionState::Prepared, TransactionState::Quarantined) => true,
            (TransactionState::Prepared, TransactionState::Failed) => true,
            (TransactionState::Prepared, TransactionState::RecoveryRequired) => true,

            // From Quarantined
            (TransactionState::Quarantined, TransactionState::Verified) => true,
            (TransactionState::Quarantined, TransactionState::RecoveryRequired) => true,

            // From Verified
            (TransactionState::Verified, TransactionState::Restored) => true,
            (TransactionState::Verified, TransactionState::RecoveryRequired) => true,

            // From RecoveryRequired
            (TransactionState::RecoveryRequired, TransactionState::Restored) => true,
            (TransactionState::RecoveryRequired, TransactionState::Failed) => true,

            // Self-transitions are disallowed
            _ => false,
        }
    }

    pub fn display_badge(&self) -> &'static str {
        match self {
            TransactionState::Proposed => "[PROPOSED]",
            TransactionState::Authorized => "[AUTHORIZED]",
            TransactionState::Prepared => "[PREPARED]",
            TransactionState::Quarantined => "[QUARANTINED]",
            TransactionState::Verified => "[VERIFIED]",
            TransactionState::Restored => "[RESTORED]",
            TransactionState::Failed => "[FAILED]",
            TransactionState::RecoveryRequired => "[RECOVERY REQUIRED]",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, TransactionState::Restored | TransactionState::Failed)
    }
}

/// In-memory context and state tracking for a single resource transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionContext {
    pub transaction_id: String,
    pub created_at_epoch_secs: i64,
    pub candidate: ResourceCandidate,
    pub action: ProposedAction,
    pub state: TransactionState,
    pub original_path: PathBuf,
    pub quarantine_path: Option<PathBuf>,
    pub verified_sha256: Option<String>,
    pub failure_reason: Option<String>,
}

impl TransactionContext {
    /// Constructs a new transaction in the Proposed state.
    pub fn new(candidate: ResourceCandidate, action: ProposedAction) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let random_suffix = format!("{:08x}", now as u32 ^ (candidate.location.inode as u32));
        let transaction_id = format!("tx_{}_{}", now, random_suffix);
        let original_path = candidate.location.path.clone();

        Self {
            transaction_id,
            created_at_epoch_secs: now,
            candidate,
            action,
            state: TransactionState::Proposed,
            original_path,
            quarantine_path: None,
            verified_sha256: None,
            failure_reason: None,
        }
    }

    /// Transitions the transaction to the next validated state.
    pub fn transition_to(&mut self, next: TransactionState) -> Result<()> {
        if !self.state.can_transition_to(&next) {
            return Err(RootError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: format!("{:?}", next),
            });
        }
        self.state = next;
        Ok(())
    }

    /// Marks the transaction as Failed with an explicit diagnostic reason.
    pub fn fail(&mut self, reason: impl Into<String>) -> Result<()> {
        let reason_str = reason.into();
        self.failure_reason = Some(reason_str.clone());

        // Any state except terminal can fail
        if self.state != TransactionState::Failed && self.state != TransactionState::Restored {
            self.state = TransactionState::Failed;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use root_core::model::{
        FileType, ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata,
        ResourceOwnership, StorageMeasurement,
    };

    fn make_test_candidate() -> ResourceCandidate {
        ResourceCandidate {
            id: ResourceId::new("test-res"),
            location: ResourceLocation::new(PathBuf::from("/tmp/test.tmp"), None, 1, 100),
            category: ResourceCategory::PackageCache,
            metadata: ResourceMetadata {
                file_type: FileType::RegularFile,
                storage: StorageMeasurement::from_raw(1024, 2, 1),
                permissions_mode: 0o644,
                mtime_epoch_secs: 1000,
                atime_epoch_secs: 1000,
                ctime_epoch_secs: 1000,
            },
            ownership: ResourceOwnership {
                uid: 1000,
                gid: 1000,
                is_current_user: true,
            },
            associated_agent: None,
        }
    }

    #[test]
    fn test_valid_transaction_lifecycle_transitions() {
        let mut ctx = TransactionContext::new(make_test_candidate(), ProposedAction::Quarantine);
        assert_eq!(ctx.state, TransactionState::Proposed);

        ctx.transition_to(TransactionState::Authorized).unwrap();
        assert_eq!(ctx.state, TransactionState::Authorized);

        ctx.transition_to(TransactionState::Prepared).unwrap();
        assert_eq!(ctx.state, TransactionState::Prepared);

        ctx.transition_to(TransactionState::Quarantined).unwrap();
        assert_eq!(ctx.state, TransactionState::Quarantined);

        ctx.transition_to(TransactionState::Verified).unwrap();
        assert_eq!(ctx.state, TransactionState::Verified);

        ctx.transition_to(TransactionState::Restored).unwrap();
        assert_eq!(ctx.state, TransactionState::Restored);
        assert!(ctx.state.is_terminal());
    }

    #[test]
    fn test_invalid_transaction_transitions_rejected() {
        let mut ctx = TransactionContext::new(make_test_candidate(), ProposedAction::Quarantine);

        // Cannot skip directly from Proposed to Quarantined
        assert!(ctx.transition_to(TransactionState::Quarantined).is_err());

        // Cannot skip directly from Proposed to Restored
        assert!(ctx.transition_to(TransactionState::Restored).is_err());
    }
}
