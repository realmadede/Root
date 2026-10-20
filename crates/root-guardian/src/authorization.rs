use root_core::model::{
    ProposedAction, ProtectionTier, RejectionReason, ResourceCandidate, ResourceId,
};
use serde::{Deserialize, Serialize};
use std::{os::unix::fs::MetadataExt, path::Path};

/// Cryptographically traceable or unique receipt confirming explicit authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationReceipt {
    pub receipt_id: String,
    pub timestamp_epoch_secs: i64,
    pub resource_id: ResourceId,
    pub allowed_action: ProposedAction,
    pub classification: ProtectionTier,
    pub operator_uid: u32,
    pub evidence: String,
}

/// The outcome of an authorization evaluation by Root Guardian.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Authorized {
        receipt: AuthorizationReceipt,
    },
    Denied {
        reason: RejectionReason,
        explanation: String,
    },
}

impl AuthorizationDecision {
    pub fn is_authorized(&self) -> bool {
        matches!(self, AuthorizationDecision::Authorized { .. })
    }

    pub fn receipt(&self) -> Option<&AuthorizationReceipt> {
        match self {
            AuthorizationDecision::Authorized { receipt } => Some(receipt),
            _ => None,
        }
    }
}

/// Parameters submitted to request mutation authorization.
pub struct AuthorizationRequest {
    pub candidate: ResourceCandidate,
    pub requested_action: ProposedAction,
    pub classification: ProtectionTier,
    pub invoking_uid: u32,
    pub explicit_user_consent: bool,
}

/// Guardian authorization engine enforcing explicit, multi-factor safety policies.
pub struct AuthorizationEngine;

impl AuthorizationEngine {
    /// Evaluates an authorization request against Root's 8 mandatory security requirements.
    pub fn authorize(request: &AuthorizationRequest) -> AuthorizationDecision {
        let path = &request.candidate.location.path;

        // 1. Explicitly Identified Resource
        if request.candidate.id.as_str().is_empty() || path.as_os_str().is_empty() {
            return AuthorizationDecision::Denied {
                reason: RejectionReason::UnknownResource,
                explanation: "Resource identifier or path is empty or undefined".into(),
            };
        }

        // 2. Verified Ownership
        if request.candidate.ownership.uid != request.invoking_uid
            || !request.candidate.ownership.is_current_user
        {
            return AuthorizationDecision::Denied {
                reason: RejectionReason::OwnershipMismatch,
                explanation: format!(
                    "Resource UID {} does not match invoking operator UID {}",
                    request.candidate.ownership.uid, request.invoking_uid
                ),
            };
        }

        // 3. Verified Filesystem Identity (Symlink Non-Follow Invariant)
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::InvalidPath,
                    explanation: format!(
                        "Failed to stat candidate path '{}': {}",
                        path.display(),
                        e
                    ),
                };
            }
        };

        if meta.is_symlink() {
            return AuthorizationDecision::Denied {
                reason: RejectionReason::SymlinkJailEscape,
                explanation:
                    "Target is a symbolic link; Root refuses to follow or mutate symlinks directly"
                        .into(),
            };
        }

        if meta.dev() != request.candidate.location.device_id
            || meta.ino() != request.candidate.location.inode
        {
            return AuthorizationDecision::Denied {
                reason: RejectionReason::FilesystemIdentityChanged,
                explanation: format!(
                    "Observed inode ({}:{}) does not match candidate snapshot ({}:{})",
                    meta.dev(),
                    meta.ino(),
                    request.candidate.location.device_id,
                    request.candidate.location.inode
                ),
            };
        }

        // 4. Permitted Protection Classification
        match request.classification {
            ProtectionTier::StrictlyProtected => {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::TierStrictlyProtected,
                    explanation:
                        "Tier 1 (Strictly Protected) resources can never be authorized for mutation"
                            .into(),
                };
            }
            ProtectionTier::NonActionable => {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::UnknownResource,
                    explanation:
                        "Non-actionable or unrecognized resources default to strict protection"
                            .into(),
                };
            }
            ProtectionTier::UserConfirmRequired => {
                if !request.explicit_user_consent {
                    return AuthorizationDecision::Denied {
                        reason: RejectionReason::UserConfirmationMissing,
                        explanation: "Tier 2 resources require explicit interactive user confirmation before authorization".into(),
                    };
                }
            }
            ProtectionTier::ObsoleteTransient | ProtectionTier::SafeRecoverable => {}
        }

        // 5. Supported Operation in Phase 04
        match request.requested_action {
            ProposedAction::Quarantine => {}
            ProposedAction::Inspect | ProposedAction::Ignore => {}
            ProposedAction::Prune | ProposedAction::TerminateGraceful => {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::Phase04UnsupportedAction,
                    explanation: format!(
                        "Action '{:?}' is permanently prohibited in Phase 04; only sandboxed quarantine is supported",
                        request.requested_action
                    ),
                };
            }
        }

        // 6. Generate Authorization Receipt
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let receipt_id = format!("rcpt_{}_{:08x}", now, meta.ino() as u32);
        let evidence = format!(
            "Verified UID={}, dev={}, ino={}, classification={:?}",
            request.invoking_uid,
            meta.dev(),
            meta.ino(),
            request.classification
        );

        AuthorizationDecision::Authorized {
            receipt: AuthorizationReceipt {
                receipt_id,
                timestamp_epoch_secs: now,
                resource_id: request.candidate.id.clone(),
                allowed_action: request.requested_action,
                classification: request.classification,
                operator_uid: request.invoking_uid,
                evidence,
            },
        }
    }

    /// Revalidates filesystem identity immediately prior to physical rename (TOCTOU defense).
    pub fn revalidate_before_mutation(
        path: &Path,
        expected_dev: u64,
        expected_ino: u64,
        expected_uid: u32,
    ) -> Result<(), RejectionReason> {
        let meta = std::fs::symlink_metadata(path).map_err(|_| RejectionReason::InvalidPath)?;

        if meta.is_symlink() {
            return Err(RejectionReason::SymlinkJailEscape);
        }
        if meta.dev() != expected_dev || meta.ino() != expected_ino {
            return Err(RejectionReason::FilesystemIdentityChanged);
        }
        if meta.uid() != expected_uid {
            return Err(RejectionReason::OwnershipMismatch);
        }

        Ok(())
    }
}
