use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{
    lifecycle::LifecycleAssessment,
    target::{DiscoveryTargetId, TargetKind},
};
use crate::model::{
    ConfidenceLevel, PlatformCapabilities, ProposedAction, ProtectionTier, ResourceCategory,
    ResourceLocation, ResourceMetadata, SafetyDecision,
};

/// A single discovered resource with full provenance, lifecycle assessment, and Guardian safety decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryFinding {
    pub target_id: DiscoveryTargetId,
    pub target_name: String,
    pub target_kind: TargetKind,
    pub rule_id: String,
    pub location: ResourceLocation,
    pub category: ResourceCategory,
    pub metadata: ResourceMetadata,
    pub protection_tier: ProtectionTier,
    pub proposed_action: ProposedAction,
    pub lifecycle: LifecycleAssessment,
    pub confidence: ConfidenceLevel,
    pub evidence_explanation: String,
    pub safety_decision: SafetyDecision,
    pub limitations: String,
}

/// Metrics summary for a discovery pass.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DiscoverySummary {
    pub total_inspected: u64,
    pub total_findings: usize,
    pub protected_count: usize,
    pub confirm_required_count: usize,
    pub transient_count: usize,
    pub recoverable_count: usize,
    pub non_actionable_count: usize,
    pub active_lifecycle_count: usize,
    pub persistent_lifecycle_count: usize,
    pub dormant_transient_count: usize,
    pub unknown_lifecycle_count: usize,
    pub reclaimable_bytes_estimate: u64,
    pub skipped_count: u64,
    pub is_complete: bool,
    pub incomplete_reason: Option<String>,
}

/// Consolidated, auditable report emitted by the Discovery Engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReport {
    pub timestamp_epoch_secs: i64,
    pub target_filter: Option<String>,
    pub root_paths: Vec<PathBuf>,
    pub findings: Vec<DiscoveryFinding>,
    pub summary: DiscoverySummary,
    pub capabilities: PlatformCapabilities,
}
