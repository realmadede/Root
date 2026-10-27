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

/// Nature and certainty of process association to a discovered resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessAttribution {
    /// Directly observed: running process command line explicitly references this path or an ancestor/child boundary.
    Direct,
    /// Inferred: matching agent or specialized tool process is running, but lacks direct path proof.
    Inferred,
    /// Inconclusive: ambiguous arguments, generic runtime match without path correlation, or conflicting indicators.
    Inconclusive,
    /// Unavailable: process enumeration or procfs was inaccessible or permission-restricted.
    Unavailable,
    /// None: process inspection succeeded and no correlated processes were identified.
    #[default]
    None,
}

impl ProcessAttribution {
    pub fn display_badge(&self) -> &'static str {
        match self {
            ProcessAttribution::Direct => "[DIRECT]",
            ProcessAttribution::Inferred => "[INFERRED]",
            ProcessAttribution::Inconclusive => "[INCONCLUSIVE]",
            ProcessAttribution::Unavailable => "[UNAVAILABLE]",
            ProcessAttribution::None => "[NONE]",
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
    #[serde(default)]
    pub attribution: ProcessAttribution,
}

impl LifecycleAssessment {
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            state: LifecycleState::Unknown,
            confidence: ConfidenceLevel::LowConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: None,
            attribution: ProcessAttribution::None,
        }
    }

    pub fn unknown_with_attribution(
        reason: impl Into<String>,
        attribution: ProcessAttribution,
    ) -> Self {
        Self {
            state: LifecycleState::Unknown,
            confidence: ConfidenceLevel::LowConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: None,
            attribution,
        }
    }

    pub fn active(reason: impl Into<String>, pid: Option<u32>) -> Self {
        Self {
            state: LifecycleState::Active,
            confidence: ConfidenceLevel::HighConfidence,
            reasoning: reason.into(),
            associated_pid: pid,
            last_activity_epoch_secs: None,
            attribution: ProcessAttribution::Direct,
        }
    }

    pub fn active_direct(reason: impl Into<String>, pid: Option<u32>) -> Self {
        Self {
            state: LifecycleState::Active,
            confidence: ConfidenceLevel::HighConfidence,
            reasoning: reason.into(),
            associated_pid: pid,
            last_activity_epoch_secs: None,
            attribution: ProcessAttribution::Direct,
        }
    }

    pub fn active_inferred(reason: impl Into<String>, pid: Option<u32>) -> Self {
        Self {
            state: LifecycleState::Active,
            confidence: ConfidenceLevel::MediumConfidence,
            reasoning: reason.into(),
            associated_pid: pid,
            last_activity_epoch_secs: None,
            attribution: ProcessAttribution::Inferred,
        }
    }

    pub fn persistent(reason: impl Into<String>) -> Self {
        Self {
            state: LifecycleState::Persistent,
            confidence: ConfidenceLevel::HighConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: None,
            attribution: ProcessAttribution::None,
        }
    }

    pub fn persistent_with_attribution(
        reason: impl Into<String>,
        attribution: ProcessAttribution,
    ) -> Self {
        Self {
            state: LifecycleState::Persistent,
            confidence: ConfidenceLevel::HighConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: None,
            attribution,
        }
    }

    pub fn dormant_transient(reason: impl Into<String>, mtime: i64) -> Self {
        Self {
            state: LifecycleState::DormantTransient,
            confidence: ConfidenceLevel::MediumConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: Some(mtime),
            attribution: ProcessAttribution::None,
        }
    }

    pub fn dormant_transient_with_attribution(
        reason: impl Into<String>,
        mtime: i64,
        attribution: ProcessAttribution,
    ) -> Self {
        Self {
            state: LifecycleState::DormantTransient,
            confidence: ConfidenceLevel::MediumConfidence,
            reasoning: reason.into(),
            associated_pid: None,
            last_activity_epoch_secs: Some(mtime),
            attribution,
        }
    }
}
