use root_core::model::{
    FileIdentity, ProposedAction, ProtectionTier, RejectionReason, ResourceCandidate, ResourceId,
};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// Structured consent record authorizing an action against an identified resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub consent_id: String,
    pub resource_id: ResourceId,
    pub nonce: String,
    pub created_at_epoch_secs: i64,
    pub expires_at_epoch_secs: i64,
    pub approved_action: ProposedAction,
    pub target_path: PathBuf,
    pub target_identity: Option<FileIdentity>,
}

impl ConsentRecord {
    /// Creates a new consent record with standard 300-second TTL.
    pub fn new(
        resource_id: ResourceId,
        action: ProposedAction,
        target_path: PathBuf,
        nonce: String,
        ttl_secs: u64,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self::with_explicit_time(resource_id, action, target_path, nonce, now, ttl_secs)
    }

    /// Creates a consent record with explicit timestamps for deterministic testing.
    pub fn with_explicit_time(
        resource_id: ResourceId,
        action: ProposedAction,
        target_path: PathBuf,
        nonce: String,
        created_at: i64,
        ttl_secs: u64,
    ) -> Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        nonce.hash(&mut hasher);
        let id_hash = hasher.finish();

        Self {
            consent_id: format!("csnt_{}_{:08x}", created_at, id_hash as u32),
            resource_id,
            nonce,
            created_at_epoch_secs: created_at,
            expires_at_epoch_secs: created_at + ttl_secs as i64,
            approved_action: action,
            target_path,
            target_identity: None,
        }
    }

    /// Validates whether the consent record is active and not expired at `now_epoch_secs`.
    pub fn is_valid_at(&self, now_epoch_secs: i64) -> bool {
        now_epoch_secs >= self.created_at_epoch_secs && now_epoch_secs < self.expires_at_epoch_secs
    }
}

/// Unique receipt confirming explicit authorization.
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
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub candidate: ResourceCandidate,
    pub requested_action: ProposedAction,
    pub classification: ProtectionTier,
    pub invoking_uid: u32,
    pub explicit_user_consent: bool,
    pub consent_record: Option<ConsentRecord>,
    pub sandbox_root: Option<PathBuf>,
    pub allow_multi_link: bool,
}

impl AuthorizationRequest {
    pub fn new(
        candidate: ResourceCandidate,
        requested_action: ProposedAction,
        classification: ProtectionTier,
        invoking_uid: u32,
    ) -> Self {
        Self {
            candidate,
            requested_action,
            classification,
            invoking_uid,
            explicit_user_consent: false,
            consent_record: None,
            sandbox_root: None,
            allow_multi_link: false,
        }
    }

    pub fn with_consent(mut self, consent: ConsentRecord) -> Self {
        self.explicit_user_consent = true;
        self.consent_record = Some(consent);
        self
    }

    pub fn with_sandbox_root(mut self, root: PathBuf) -> Self {
        self.sandbox_root = Some(root);
        self
    }

    pub fn with_multi_link(mut self, allow: bool) -> Self {
        self.allow_multi_link = allow;
        self
    }
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

        // 3. Sandbox Scope Containment
        if let Some(ref root) = request.sandbox_root {
            let escaped = if let (Ok(canon_root), Ok(canon_path)) =
                (root.canonicalize(), path.canonicalize())
            {
                !canon_path.starts_with(&canon_root)
            } else {
                !path.starts_with(root)
            };
            if escaped {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::ScopeEscape,
                    explanation: format!(
                        "Path '{}' escapes authorized sandbox boundary '{}'",
                        path.display(),
                        root.display()
                    ),
                };
            }
        }

        // 4. Verified Filesystem Identity (Symlink Non-Follow Invariant)
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

        // 4. Multi-link shared storage protection
        if meta.nlink() > 1 && !request.allow_multi_link {
            return AuthorizationDecision::Denied {
                reason: RejectionReason::HardLinkShared,
                explanation: format!(
                    "Resource has {} hard links; shared inode mutation is prohibited without explicit authorization",
                    meta.nlink()
                ),
            };
        }

        // 5. Permitted Protection Classification
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
            ProtectionTier::UserConfirmRequired
            | ProtectionTier::ObsoleteTransient
            | ProtectionTier::SafeRecoverable => {}
        }

        // 6. Explicit Consent Record Validation
        if let Some(ref consent) = request.consent_record {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            if !consent.is_valid_at(now) {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::ConsentExpired,
                    explanation: format!(
                        "Consent record has expired (expires at {}, current {})",
                        consent.expires_at_epoch_secs, now
                    ),
                };
            }

            if consent.resource_id != request.candidate.id {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::ConsentNonceMismatch,
                    explanation: format!(
                        "Consent record resource ID '{}' does not match candidate ID '{}'",
                        consent.resource_id.as_str(),
                        request.candidate.id.as_str()
                    ),
                };
            }

            if consent.approved_action != request.requested_action {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::ConsentNonceMismatch,
                    explanation: format!(
                        "Consent record approved action '{:?}' does not match requested action '{:?}'",
                        consent.approved_action, request.requested_action
                    ),
                };
            }

            if consent.target_path != request.candidate.location.path {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::ConsentNonceMismatch,
                    explanation: format!(
                        "Consent target path '{}' does not match candidate path '{}'",
                        consent.target_path.display(),
                        request.candidate.location.path.display()
                    ),
                };
            }
        } else if request.classification == ProtectionTier::UserConfirmRequired
            && !request.explicit_user_consent
        {
            return AuthorizationDecision::Denied {
                reason: RejectionReason::UserConfirmationMissing,
                explanation: "Tier 2 resources require explicit interactive user confirmation before authorization".into(),
            };
        }

        // 8. Supported Operation in Phase 11 Sandbox
        match request.requested_action {
            ProposedAction::Quarantine => {}
            ProposedAction::Inspect | ProposedAction::Ignore => {}
            ProposedAction::Prune | ProposedAction::TerminateGraceful => {
                return AuthorizationDecision::Denied {
                    reason: RejectionReason::Phase04UnsupportedAction,
                    explanation: format!(
                        "Action '{:?}' is permanently prohibited in Phase 11; only sandboxed quarantine is supported",
                        request.requested_action
                    ),
                };
            }
        }

        // Generate Authorization Receipt
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
        Self::revalidate_full(
            path,
            expected_dev,
            expected_ino,
            expected_uid,
            None,
            None,
            None,
        )
    }

    /// Comprehensive pre-mutation revalidation checking file identity, ownership, parent directory, and sandbox scope.
    pub fn revalidate_full(
        path: &Path,
        expected_dev: u64,
        expected_ino: u64,
        expected_uid: u32,
        expected_parent_dev: Option<u64>,
        expected_parent_ino: Option<u64>,
        sandbox_root: Option<&Path>,
    ) -> Result<(), RejectionReason> {
        let meta = std::fs::symlink_metadata(path).map_err(|_| RejectionReason::InvalidPath)?;

        if meta.is_symlink() {
            return Err(RejectionReason::SymlinkJailEscape);
        }
        if meta.is_dir() {
            return Err(RejectionReason::FilesystemIdentityChanged);
        }
        if meta.dev() != expected_dev || meta.ino() != expected_ino {
            return Err(RejectionReason::FilesystemIdentityChanged);
        }
        if meta.uid() != expected_uid {
            return Err(RejectionReason::OwnershipMismatch);
        }

        // Parent directory identity revalidation
        if let (Some(exp_pdev), Some(exp_pino)) = (expected_parent_dev, expected_parent_ino) {
            if let Some(parent) = path.parent() {
                let pmeta =
                    std::fs::symlink_metadata(parent).map_err(|_| RejectionReason::InvalidPath)?;
                if pmeta.is_symlink() {
                    return Err(RejectionReason::SymlinkJailEscape);
                }
                if pmeta.dev() != exp_pdev || pmeta.ino() != exp_pino {
                    return Err(RejectionReason::ParentDirectoryChanged);
                }
            }
        }

        // Sandbox root containment revalidation
        if let Some(root) = sandbox_root {
            if let Ok(canon_root) = root.canonicalize() {
                if let Ok(canon_path) = path.canonicalize() {
                    if !canon_path.starts_with(&canon_root) {
                        return Err(RejectionReason::ScopeEscape);
                    }
                }
            }
        }

        Ok(())
    }
}
