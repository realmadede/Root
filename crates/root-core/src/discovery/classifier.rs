use std::path::Path;

use super::{
    finding::DiscoveryFinding, lifecycle::LifecycleAssessment, rules::RuleRegistry,
    target::DiscoveryTargetId,
};
use crate::model::{
    ConfidenceLevel, FindingTarget, ProcessCandidate, ProposedAction, ProtectionTier,
    ResourceCandidate, ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata,
    ResourceOwnership, SafetyDecision,
};

pub struct ResourceClassifier;

impl ResourceClassifier {
    /// Classifies an inspected path, applying rule matching, lifecycle analysis, and Guardian policy.
    pub fn classify_entry(
        path: &Path,
        metadata: &ResourceMetadata,
        dev: u64,
        ino: u64,
        current_uid: u32,
        active_processes: &[ProcessCandidate],
        policy: &dyn Fn(&FindingTarget, ProtectionTier, ProposedAction, u32) -> SafetyDecision,
    ) -> DiscoveryFinding {
        let path_str = path.to_string_lossy();
        let matched_rule = RuleRegistry::match_path(&path_str);

        let (
            target_id,
            target_name,
            target_kind,
            rule_id,
            category,
            tier,
            action,
            confidence,
            limitations,
            evidence_explanation,
        ) = if let Some(rule) = matched_rule {
            (
                rule.target_id,
                rule.target_id.name().to_string(),
                rule.target_id.kind(),
                rule.rule_id.clone(),
                rule.category,
                rule.default_tier,
                rule.default_action,
                rule.confidence,
                rule.known_limitations.clone(),
                format!(
                    "Matched rule '{}' via pattern '{}' ({})",
                    rule.rule_id, rule.pattern_description, rule.evidence_source
                ),
            )
        } else {
            (
                DiscoveryTargetId::Git, // Placeholder fallback target
                "Unknown / General".to_string(),
                super::target::TargetKind::Tool,
                "default-unknown".to_string(),
                ResourceCategory::Unknown,
                ProtectionTier::NonActionable,
                ProposedAction::Inspect,
                ConfidenceLevel::LowConfidence,
                "Unrecognized resource pattern; preserved in place by default".to_string(),
                "No specific agent or tool discovery rule matched path".to_string(),
            )
        };

        // Multi-factor Lifecycle Assessment
        let lifecycle =
            Self::assess_lifecycle(path, metadata, target_id, tier, category, active_processes);

        let location = ResourceLocation::new(path.to_path_buf(), None, dev, ino);
        let id = ResourceId::from_path_and_inode(path, dev, ino);

        let candidate = ResourceCandidate {
            id,
            location: location.clone(),
            category,
            metadata: metadata.clone(),
            ownership: ResourceOwnership {
                uid: current_uid,
                gid: current_uid,
                is_current_user: true,
            },
            associated_agent: Some(target_id.name().to_string()),
        };

        let target = FindingTarget::Filesystem(candidate);
        let safety_decision = policy(&target, tier, action, current_uid);

        DiscoveryFinding {
            target_id,
            target_name,
            target_kind,
            rule_id,
            location,
            category,
            metadata: metadata.clone(),
            protection_tier: tier,
            proposed_action: action,
            lifecycle,
            confidence,
            evidence_explanation,
            safety_decision,
            limitations,
        }
    }

    fn assess_lifecycle(
        path: &Path,
        metadata: &ResourceMetadata,
        target_id: DiscoveryTargetId,
        tier: ProtectionTier,
        category: ResourceCategory,
        active_processes: &[ProcessCandidate],
    ) -> LifecycleAssessment {
        // 1. Check if associated agent or tool process is currently running
        let running_proc = active_processes.iter().find(|p| match target_id {
            DiscoveryTargetId::Antigravity => {
                p.identity.name.contains("agy")
                    || p.identity.name.contains("antigravity")
                    || p.associated_agent.as_deref() == Some("Google Antigravity")
            }
            DiscoveryTargetId::ClaudeCode => {
                p.identity.name.contains("claude")
                    || p.associated_agent.as_deref() == Some("Claude Code")
            }
            DiscoveryTargetId::OpenAiCodex => {
                p.identity.name.contains("codex") || p.identity.name.contains("openai")
            }
            DiscoveryTargetId::GeminiCli => p.identity.name.contains("gemini"),
            DiscoveryTargetId::Aider => p.identity.name.contains("aider"),
            DiscoveryTargetId::NodeNpm => {
                p.identity.name.contains("npm") || p.identity.name.contains("node")
            }
            DiscoveryTargetId::Pnpm => p.identity.name.contains("pnpm"),
            DiscoveryTargetId::RustCargo => {
                p.identity.name.contains("cargo") || p.identity.name.contains("rustc")
            }
            DiscoveryTargetId::Python => p.identity.name.contains("python"),
            DiscoveryTargetId::Git => p.identity.name.contains("git"),
            DiscoveryTargetId::LanguageServers => {
                p.identity.name.contains("rust-analyzer")
                    || p.identity.name.contains("clangd")
                    || p.identity.name.contains("tsserver")
                    || p.identity.name.contains("pyright")
                    || p.identity.name.contains("gopls")
            }
            DiscoveryTargetId::DevServers => {
                p.identity.name.contains("vite")
                    || p.identity.name.contains("next")
                    || p.identity.name.contains("webpack")
                    || p.identity.name.contains("uvicorn")
                    || p.identity.name.contains("flask")
            }
        });

        if let Some(proc) = running_proc {
            return LifecycleAssessment::active(
                format!(
                    "Associated tool process '{}' (PID {}) is currently active",
                    proc.identity.name, proc.identity.pid
                ),
                Some(proc.identity.pid),
            );
        }

        // 2. Check for active presence markers on disk
        let path_str = path.to_string_lossy();
        if path_str.contains("presence/session_active.lock") {
            return LifecycleAssessment::active(
                "Active presence lockfile indicates running agent session".to_string(),
                None,
            );
        }

        // 2. Persistent credentials, history, and keys are permanent session records
        if tier == ProtectionTier::StrictlyProtected
            || category == ResourceCategory::SessionState
            || category == ResourceCategory::SystemFile
        {
            return LifecycleAssessment::persistent(
                "Persistent configuration, conversation history, or authentication record",
            );
        }

        // 3. Transient scratchpads, logs, or build caches
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let age_secs = now.saturating_sub(metadata.mtime_epoch_secs);

        // If older than 48 hours and no process running: Dormant Transient
        if age_secs > 48 * 3600 {
            LifecycleAssessment::dormant_transient(
                format!(
                    "No active {} process detected and mtime is older than 48h (age: {}h)",
                    target_id.name(),
                    age_secs / 3600
                ),
                metadata.mtime_epoch_secs,
            )
        } else if age_secs < 3600 {
            // Recent file (less than 1 hour old): may be active or mid-flight
            LifecycleAssessment::unknown(
                "Resource modified within the last hour; cannot confirm session closure without live process telemetry",
            )
        } else {
            // Indeterminate lifecycle
            LifecycleAssessment::unknown(
                "No active process detected, but lifecycle evidence remains inconclusive",
            )
        }
    }
}
