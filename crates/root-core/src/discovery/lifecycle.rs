use serde::{Deserialize, Serialize};

use crate::model::ConfidenceLevel;

/// Operational lifecycle state of an inspected filesystem or process resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Actively attached to a running process, socket lock, or active presence marker.
    Active,
    /// Intentionally persistent user configuration, credentials, or session history.
    Persistent,
    /// Ephemeral or temporary artifact that is dormant and unheld by active processes.
    DormantTransient,
    /// Insufficient or contradictory evidence to establish lifecycle status.
    Unknown,
}

impl LifecycleState {
    pub fn display_badge(&self) -> &'static str {
        match self {
            LifecycleState::Active => "[ACTIVE]",
            LifecycleState::Persistent => "[PERSISTENT]",
            LifecycleState::DormantTransient => "[DORMANT TRANSIENT]",
            LifecycleState::Unknown => "[UNKNOWN LIFECYCLE]",
        }
    }
}

/// Audit assessment detailing the lifecycle classification and supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleAssessment {
    pub state: LifecycleState,
    pub confidence: ConfidenceLevel,
    pub reasoning: String,
    pub associated_pid: Option<u32>,
    pub last_activity_epoch_secs: Option<i64>,
}

impl LifecycleAssessment {
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            state: LifecycleState::Unknown,
            confidence: ConfidenceLevel::LowConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: None,
        }
    }

    pub fn active(reason: impl Into<String>, pid: Option<u32>) -> Self {
        Self {
            state: LifecycleState::Active,
            confidence: ConfidenceLevel::HighConfidence,
            reasoning: reason.into(),
            associated_pid: pid,
            last_activity_epoch_secs: None,
        }
    }

    pub fn persistent(reason: impl Into<String>) -> Self {
        Self {
            state: LifecycleState::Persistent,
            confidence: ConfidenceLevel::HighConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: None,
        }
    }

    pub fn dormant_transient(reason: impl Into<String>, mtime: i64) -> Self {
        Self {
            state: LifecycleState::DormantTransient,
            confidence: ConfidenceLevel::MediumConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: Some(mtime),
        }
    }
}
