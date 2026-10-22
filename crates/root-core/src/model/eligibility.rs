//! Explicit resource eligibility model separating observation from authorization.
//!
//! Discovering that a resource is a candidate does not automatically authorize an operation.
//! Root models eligibility as a distinct evaluation stage in an 11-stage decision pipeline.

use serde::{Deserialize, Serialize};

use super::classification::{ProtectionTier, RejectionReason};

/// The 11 distinct stages of resource evaluation and mutation lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStage {
    /// 1. Resource metadata observed during traversal.
    Observed = 1,
    /// 2. Candidate classified into a protection tier.
    Classified = 2,
    /// 3. Resource evaluated for cleanup consideration.
    ConsideredForCleanup = 3,
    /// 4. Resource determined to be protected or excluded.
    ProtectedOrExcluded = 4,
    /// 5. Resource proposed action presented to operator.
    PresentedToUser = 5,
    /// 6. Operator grants explicit authorization for this resource.
    UserAuthorized = 6,
    /// 7. Guardian validates the authorization request against all policies.
    GuardianValidated = 7,
    /// 8. Staging allocated and transaction intent recorded in journal.
    Prepared = 8,
    /// 9. TOCTOU identity revalidated and atomic move executed in test sandbox.
    ExecutedInTestEnv = 9,
    /// 10. Destination content hash and source unlink verified.
    ResultVerified = 10,
    /// 11. Rollback or recovery capability confirmed.
    RestorationEvaluated = 11,
}

impl DecisionStage {
    pub fn display_badge(&self) -> &'static str {
        match self {
            DecisionStage::Observed => "[1. OBSERVED]",
            DecisionStage::Classified => "[2. CLASSIFIED]",
            DecisionStage::ConsideredForCleanup => "[3. CONSIDERED]",
            DecisionStage::ProtectedOrExcluded => "[4. EXCLUDED]",
            DecisionStage::PresentedToUser => "[5. PRESENTED]",
            DecisionStage::UserAuthorized => "[6. USER AUTHORIZED]",
            DecisionStage::GuardianValidated => "[7. GUARDIAN VALIDATED]",
            DecisionStage::Prepared => "[8. PREPARED]",
            DecisionStage::ExecutedInTestEnv => "[9. EXECUTED IN TEST ENV]",
            DecisionStage::ResultVerified => "[10. VERIFIED]",
            DecisionStage::RestorationEvaluated => "[11. RESTORATION EVALUATED]",
        }
    }
}

/// Explicit determination of whether a candidate is eligible for cleanup consideration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EligibilityStatus {
    /// Resource is eligible for user presentation and consideration.
    Eligible {
        tier: ProtectionTier,
        reason: String,
    },
    /// Resource is permanently ineligible and protected from cleanup consideration.
    Ineligible {
        reason: RejectionReason,
        explanation: String,
    },
}

impl EligibilityStatus {
    pub fn is_eligible(&self) -> bool {
        matches!(self, EligibilityStatus::Eligible { .. })
    }

    pub fn tier(&self) -> Option<ProtectionTier> {
        match self {
            EligibilityStatus::Eligible { tier, .. } => Some(*tier),
            _ => None,
        }
    }
}
