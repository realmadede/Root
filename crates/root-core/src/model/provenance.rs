use serde::{Deserialize, Serialize};

/// The origin and verification status of a piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    /// Empirically verified fact obtained directly from an OS system call or virtual filesystem.
    VerifiedFact,
    /// Direct inspection of a filesystem entity's metadata or directory presence.
    DirectInspection,
    /// Structural match against known software conventions (e.g. `target/`, `node_modules/`).
    StructuralMatch,
    /// Heuristically derived fact (e.g. dormancy inferred from timestamps or session inactivity).
    HeuristicDerivation,
    /// Signature fingerprint matching known agent or developer tooling binaries.
    ToolFingerprint,
}

/// Degree of confidence in a finding or classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    /// 100% verified fact; zero inference.
    VerifiedFact = 4,
    /// High confidence based on multiple corroborating attributes.
    HighConfidence = 3,
    /// Moderate confidence; plausible but subject to edge cases.
    MediumConfidence = 2,
    /// Low confidence; weak heuristic or unconfirmed indicator.
    LowConfidence = 1,
    /// Unknown confidence; unverified or contradictory indicators.
    Unknown = 0,
}

/// A discrete unit of evidence supporting a scan finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingEvidence {
    /// Human-readable explanation of the observed fact or inference.
    pub description: String,
    /// Provenance origin of this evidence.
    pub provenance: EvidenceProvenance,
    /// Confidence level in this evidence.
    pub confidence: ConfidenceLevel,
}

impl FindingEvidence {
    pub fn verified(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            provenance: EvidenceProvenance::VerifiedFact,
            confidence: ConfidenceLevel::VerifiedFact,
        }
    }

    pub fn inspection(description: impl Into<String>, confidence: ConfidenceLevel) -> Self {
        Self {
            description: description.into(),
            provenance: EvidenceProvenance::DirectInspection,
            confidence,
        }
    }

    pub fn structural(description: impl Into<String>, confidence: ConfidenceLevel) -> Self {
        Self {
            description: description.into(),
            provenance: EvidenceProvenance::StructuralMatch,
            confidence,
        }
    }

    pub fn heuristic(description: impl Into<String>, confidence: ConfidenceLevel) -> Self {
        Self {
            description: description.into(),
            provenance: EvidenceProvenance::HeuristicDerivation,
            confidence,
        }
    }
}
