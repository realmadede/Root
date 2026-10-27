use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use super::{
    classifier::ResourceClassifier,
    finding::{DiscoveryReport, DiscoverySummary},
    lifecycle::LifecycleState,
    target::{DiscoveryTargetId, TargetKind},
};
use crate::{
    error::Result,
    model::{FindingTarget, PlatformCapabilities, ProposedAction, ProtectionTier, SafetyDecision},
};

/// High-level filter configuration for a discovery pass.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryFilter {
    pub target_id: Option<DiscoveryTargetId>,
    pub kind: Option<TargetKind>,
}

impl DiscoveryFilter {
    pub fn matches(&self, target_id: DiscoveryTargetId) -> bool {
        if let Some(specific) = self.target_id {
            if specific != target_id {
                return false;
            }
        }
        if let Some(kind) = self.kind {
            if target_id.kind() != kind {
                return false;
            }
        }
        true
    }
}

/// Contextual configuration and runtime environment for evaluating discovery findings.
#[derive(Clone)]
pub struct DiscoveryContext<'a> {
    pub root_paths: Vec<PathBuf>,
    pub filter: &'a DiscoveryFilter,
    pub current_uid: u32,
    pub active_processes: &'a [crate::model::ProcessCandidate],
    pub capabilities: PlatformCapabilities,
    pub skipped_count: u64,
    pub is_complete: bool,
    pub incomplete_reason: Option<String>,
}

impl<'a> DiscoveryContext<'a> {
    pub fn new(
        root_paths: Vec<PathBuf>,
        filter: &'a DiscoveryFilter,
        current_uid: u32,
        active_processes: &'a [crate::model::ProcessCandidate],
        capabilities: PlatformCapabilities,
    ) -> Self {
        Self {
            root_paths,
            filter,
            current_uid,
            active_processes,
            capabilities,
            skipped_count: 0,
            is_complete: true,
            incomplete_reason: None,
        }
    }
}

/// The core discovery engine coordinating rule evaluation, lifecycle assessment, and Guardian safety.
pub struct DiscoveryEngine;

impl DiscoveryEngine {
    /// Evaluates discovered entries against the discovery rule registry and Guardian safety policy.
    pub fn evaluate_findings(
        entries: &[(PathBuf, crate::model::ResourceMetadata, u64, u64)],
        ctx: &DiscoveryContext,
        policy: &dyn Fn(&FindingTarget, ProtectionTier, ProposedAction, u32) -> SafetyDecision,
    ) -> Result<DiscoveryReport> {
        let mut findings = Vec::new();
        let mut counted_inodes = HashSet::new();

        // Pre-count occurrences of physical inodes to determine if multi-link files
        // have all references contained within the inspected scope.
        let mut observed_inodes = HashMap::new();
        for (_, _, dev, ino) in entries {
            if *dev != 0 || *ino != 0 {
                *observed_inodes.entry((*dev, *ino)).or_insert(0usize) += 1;
            }
        }

        let mut summary = DiscoverySummary {
            total_inspected: entries.len() as u64,
            skipped_count: ctx.skipped_count,
            is_complete: ctx.is_complete,
            incomplete_reason: ctx.incomplete_reason.clone(),
            ..Default::default()
        };

        for (path, metadata, dev, ino) in entries {
            let finding = ResourceClassifier::classify_entry_with_capabilities(
                path,
                metadata,
                *dev,
                *ino,
                ctx.current_uid,
                ctx.active_processes,
                Some(&ctx.capabilities),
                policy,
            );

            // Apply filter
            if !ctx.filter.matches(finding.target_id) {
                continue;
            }

            let is_candidate_tier = matches!(
                finding.protection_tier,
                ProtectionTier::UserConfirmRequired
                    | ProtectionTier::ObsoleteTransient
                    | ProtectionTier::SafeRecoverable
            );

            // Candidate estimate eligibility: only inactive candidate files qualify.
            // Active sessions, directory dentry tables, and symlinks do not represent
            // guaranteed or candidate unlinked file bytes.
            let is_eligible_for_estimate = is_candidate_tier
                && finding.lifecycle.state != LifecycleState::Active
                && finding.metadata.file_type != crate::model::FileType::Directory
                && finding.metadata.file_type != crate::model::FileType::Symlink;

            let is_new_inode = if *dev != 0 || *ino != 0 {
                counted_inodes.insert((*dev, *ino))
            } else {
                true
            };

            let reclaimable_bytes = if is_eligible_for_estimate && is_new_inode {
                if finding.metadata.storage.is_multi_link {
                    let observed_count = observed_inodes.get(&(*dev, *ino)).copied().unwrap_or(1);
                    // If all links referencing this inode are accounted for within this scan,
                    // unlinking all candidate references would release the physical allocated blocks.
                    // If observed_count < link_count, external links exist and unlinking candidate
                    // references frees zero physical disk blocks while external links remain.
                    if observed_count >= finding.metadata.storage.link_count as usize {
                        if finding.metadata.storage.is_sparse {
                            finding.metadata.storage.allocated_bytes
                        } else {
                            finding.metadata.storage.bytes
                        }
                    } else {
                        0
                    }
                } else if finding.metadata.storage.is_sparse {
                    finding.metadata.storage.allocated_bytes
                } else {
                    finding.metadata.storage.bytes
                }
            } else {
                0
            };

            // Tally metrics
            summary.total_findings += 1;
            match finding.protection_tier {
                ProtectionTier::StrictlyProtected => summary.protected_count += 1,
                ProtectionTier::UserConfirmRequired => {
                    summary.confirm_required_count += 1;
                    summary.reclaimable_bytes_estimate += reclaimable_bytes;
                }
                ProtectionTier::ObsoleteTransient => {
                    summary.transient_count += 1;
                    summary.reclaimable_bytes_estimate += reclaimable_bytes;
                }
                ProtectionTier::SafeRecoverable => {
                    summary.recoverable_count += 1;
                    summary.reclaimable_bytes_estimate += reclaimable_bytes;
                }
                ProtectionTier::NonActionable => summary.non_actionable_count += 1,
            }

            match finding.lifecycle.state {
                LifecycleState::Active => summary.active_lifecycle_count += 1,
                LifecycleState::Persistent => summary.persistent_lifecycle_count += 1,
                LifecycleState::DormantTransient => summary.dormant_transient_count += 1,
                LifecycleState::Unknown => summary.unknown_lifecycle_count += 1,
            }

            findings.push(finding);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let filter_description = if let Some(target) = ctx.filter.target_id {
            Some(target.name().to_string())
        } else if let Some(kind) = ctx.filter.kind {
            match kind {
                TargetKind::Agent => Some("All AI Coding Agents".to_string()),
                TargetKind::Tool => Some("All Development Tooling".to_string()),
            }
        } else {
            None
        };

        Ok(DiscoveryReport {
            timestamp_epoch_secs: timestamp,
            target_filter: filter_description,
            root_paths: ctx.root_paths.clone(),
            findings,
            summary,
            capabilities: ctx.capabilities.clone(),
        })
    }
}
