use serde::{Deserialize, Serialize};

/// Deterministic 4-tier classification hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionTier {
    /// Tier 1: Personal files, active credentials, uncommitted Git work, session transcripts. NEVER ELIGIBLE.
    StrictlyProtected = 1,
    /// Tier 2: Large build outputs, dormant virtual environments, closed scratchpads. Requires explicit user consent.
    UserConfirmRequired = 2,
    /// Tier 3: Stale logs past retention, empty UUID dirs, crash reports, orphaned test traces. Batch eligible with preview.
    ObsoleteTransient = 3,
    /// Tier 4: Upstream package caches (npm, pip, cargo .crate) bit-for-bit fetchable from public registries.
    SafeRecoverable = 4,
    /// Informational or active resource where no recovery action is proposed or sensible.
    NonActionable = 5,
}

impl ProtectionTier {
    pub fn is_protected(&self) -> bool {
        matches!(
            self,
            ProtectionTier::StrictlyProtected | ProtectionTier::NonActionable
        )
    }

    pub fn display_badge(&self) -> &'static str {
        match self {
            ProtectionTier::StrictlyProtected => "[PROTECTED]",
            ProtectionTier::UserConfirmRequired => "[CONFIRM REQUIRED]",
            ProtectionTier::ObsoleteTransient => "[OBSOLETE TRANSIENT]",
            ProtectionTier::SafeRecoverable => "[SAFE RECOVERABLE]",
            ProtectionTier::NonActionable => "[NON-ACTIONABLE]",
        }
    }
}

/// The action proposed for an identified candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposedAction {
    /// Relocate into quarantine staging directory with rollback journal.
    Quarantine,
    /// Permanent unlinking (only for empty directories or unlinked temporary files).
    Prune,
    /// Graceful process termination via `pidfd_send_signal(SIGTERM)`.
    TerminateGraceful,
    /// Flag for detailed user inspection.
    Inspect,
    /// Do not perform any action; preserve in place.
    Ignore,
}

/// Explicit reason for rejecting a proposed operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Strict Phase 01 safety invariant: all destructive operations are disabled.
    Phase01ReadOnlyPolicy,
    /// Strict Phase 02 safety invariant: all destructive operations and mutations are prohibited.
    Phase02ReadOnlyPolicy,
    /// Strict Phase 03 safety invariant: discovery is strictly read-only; destructive operations and mutations are prohibited.
    Phase03ReadOnlyPolicy,
    /// The resource is classified as Tier 1 (Strictly Protected).
    TierStrictlyProtected,
    /// Path resides in a protected location (e.g. system directory, SSH keys, user documents).
    ProtectedLocation,
    /// Resource UID does not match current unprivileged user UID.
    OwnershipMismatch,
    /// Symbolic link attempts to escape the root boundary.
    SymlinkJailEscape,
    /// Path resides on a different filesystem device.
    CrossDeviceBoundary,
    /// Repository contains uncommitted or dirty working tree state.
    UncommittedGitState,
    /// Inactive session or abandonment could not be proven with sufficient evidence.
    InsufficientLifecycleEvidence,
    /// Resource identity is unknown or ambiguous; default to protected.
    UnknownResource,
    /// Invalid, malformed, or unsafe lexical path.
    InvalidPath,
}

/// The outcome of evaluating a candidate against Root Guardian safety policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SafetyDecision {
    /// Operation complies with all safety policies.
    Allowed,
    /// Operation rejected by safety policy with explicit justification.
    Rejected {
        reason: RejectionReason,
        explanation: String,
    },
}

impl SafetyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, SafetyDecision::Allowed)
    }

    pub fn reject(reason: RejectionReason, explanation: impl Into<String>) -> Self {
        SafetyDecision::Rejected {
            reason,
            explanation: explanation.into(),
        }
    }
}
