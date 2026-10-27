use std::path::Path;

use super::{
    finding::DiscoveryFinding,
    lifecycle::{LifecycleAssessment, ProcessAttribution},
    rules::RuleRegistry,
    target::{DiscoveryTargetId, TargetKind},
};
use crate::model::{
    CapabilityStatus, ConfidenceLevel, FindingTarget, PlatformCapabilities, ProcessCandidate,
    ProposedAction, ProtectionTier, ResourceCandidate, ResourceCategory, ResourceId,
    ResourceLocation, ResourceMetadata, ResourceOwnership, SafetyDecision,
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
        Self::classify_entry_with_capabilities(
            path,
            metadata,
            dev,
            ino,
            current_uid,
            active_processes,
            None,
            policy,
        )
    }

    /// Classifies an inspected path with platform capabilities context for accurate telemetry assessment.
    #[allow(clippy::too_many_arguments)]
    pub fn classify_entry_with_capabilities(
        path: &Path,
        metadata: &ResourceMetadata,
        dev: u64,
        ino: u64,
        current_uid: u32,
        active_processes: &[ProcessCandidate],
        capabilities: Option<&PlatformCapabilities>,
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
        let lifecycle = Self::assess_lifecycle(
            path,
            metadata,
            target_id,
            tier,
            category,
            active_processes,
            capabilities,
        );

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
        capabilities: Option<&PlatformCapabilities>,
    ) -> LifecycleAssessment {
        // 1. Presence locks on disk guarantee active session status
        let path_str_normalized = path.to_string_lossy().replace('\\', "/");
        if path_str_normalized.contains("presence/session_active.lock")
            || path_str_normalized.ends_with("session_active.lock")
        {
            return LifecycleAssessment::active_direct(
                "Active presence lockfile indicates running agent session",
                None,
            );
        }

        // 2. Persistent credentials, history, and system records
        if tier == ProtectionTier::StrictlyProtected
            || category == ResourceCategory::SessionState
            || category == ResourceCategory::SystemFile
        {
            return LifecycleAssessment::persistent_with_attribution(
                "Persistent configuration, conversation history, or authentication record",
                ProcessAttribution::None,
            );
        }

        // 3. Process telemetry availability verification
        if let Some(caps) = capabilities {
            if caps.process_enumeration == CapabilityStatus::PermissionRestricted
                || caps.process_enumeration == CapabilityStatus::Unavailable
                || caps.process_enumeration == CapabilityStatus::Unsupported
                || caps.proc_fs == CapabilityStatus::PermissionRestricted
            {
                return LifecycleAssessment::unknown_with_attribution(
                    "Process telemetry is inaccessible or restricted; active process usage cannot be verified",
                    ProcessAttribution::Unavailable,
                );
            }
        }

        // 4. Direct process correlation: check for processes directly referencing this path in arguments
        let direct_proc = active_processes.iter().find(|p| {
            process_matches_target(p, target_id)
                && p.identity
                    .cmdline
                    .iter()
                    .any(|arg| match_path_in_arg(path, arg))
        });

        if let Some(proc) = direct_proc {
            return LifecycleAssessment::active_direct(
                format!(
                    "Associated process '{}' (PID {}) is actively operating on this path",
                    proc.identity.name, proc.identity.pid
                ),
                Some(proc.identity.pid),
            );
        }

        // 5. Candidate processes matching target signature without direct path correlation
        let running_proc = active_processes
            .iter()
            .find(|p| process_matches_target(p, target_id));

        if let Some(proc) = running_proc {
            if is_generic_runtime(target_id) {
                // Generic development runtime (node, python):
                // A generic interpreter running on the host cannot prove this specific resource is active.
                // Do not mark active; record inconclusive attribution.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let age_secs = now.saturating_sub(metadata.mtime_epoch_secs);

                if age_secs > 48 * 3600 && is_transient_category(category) {
                    return LifecycleAssessment::dormant_transient_with_attribution(
                        format!(
                            "No active process correlated to path (generic runtime '{}' PID {} running without path reference) and mtime older than 48h (age: {}h)",
                            proc.identity.name, proc.identity.pid, age_secs / 3600
                        ),
                        metadata.mtime_epoch_secs,
                        ProcessAttribution::Inconclusive,
                    );
                } else {
                    return LifecycleAssessment::unknown_with_attribution(
                        format!(
                            "Generic runtime process '{}' (PID {}) is running on system, but lacks path correlation to this resource; cannot confirm activity",
                            proc.identity.name, proc.identity.pid
                        ),
                        ProcessAttribution::Inconclusive,
                    );
                }
            } else {
                // Target is an AI coding agent or specialized tool (e.g. Antigravity, Claude, Cargo, Vite, LSP)
                // Active on system, but arguments lack direct path reference (inferred activity).
                let label = if target_id.kind() == TargetKind::Agent {
                    format!(
                        "Associated agent process '{}' (PID {}) is active on system (inferred activity; unverified on this specific path)",
                        proc.identity.name, proc.identity.pid
                    )
                } else {
                    format!(
                        "Associated tool process '{}' (PID {}) is active on system (inferred activity; unverified on this specific path)",
                        proc.identity.name, proc.identity.pid
                    )
                };
                return LifecycleAssessment::active_inferred(label, Some(proc.identity.pid));
            }
        }

        // 6. No matching candidate processes detected
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let age_secs = now.saturating_sub(metadata.mtime_epoch_secs);

        // Unknown / unclassified resources never become DormantTransient based on age
        if category == ResourceCategory::Unknown {
            return LifecycleAssessment::unknown_with_attribution(
                "Unrecognized resource pattern; preserved in place by default",
                ProcessAttribution::None,
            );
        }

        if age_secs > 48 * 3600 {
            if is_transient_category(category) {
                LifecycleAssessment::dormant_transient_with_attribution(
                    format!(
                        "No active {} process detected and mtime is older than 48h (age: {}h)",
                        target_id.name(),
                        age_secs / 3600
                    ),
                    metadata.mtime_epoch_secs,
                    ProcessAttribution::None,
                )
            } else {
                LifecycleAssessment::persistent_with_attribution(
                    format!(
                        "Non-transient resource category ({:?}) preserved regardless of age",
                        category
                    ),
                    ProcessAttribution::None,
                )
            }
        } else if age_secs < 3600 {
            LifecycleAssessment::unknown_with_attribution(
                "Resource modified within the last hour; cannot confirm session closure without live process telemetry",
                ProcessAttribution::None,
            )
        } else {
            LifecycleAssessment::unknown_with_attribution(
                format!(
                    "No active {} process linked to path, and resource age ({}h) is within the 1h-48h indeterminate window",
                    target_id.name(),
                    age_secs / 3600
                ),
                ProcessAttribution::None,
            )
        }
    }
}

/// Boundary-aware, privacy-safe path matcher for process command-line arguments.
fn match_path_in_arg(path: &Path, raw_arg: &str) -> bool {
    // 1. Ignore redaction and truncation placeholders
    if raw_arg == "[REDACTED]" || raw_arg == "[TRUNCATED]" {
        return false;
    }

    // 2. Extract value from option flags (e.g. "--flag=value" or "-o=value")
    let arg_val = if let Some(stripped) = raw_arg.strip_prefix("--") {
        if let Some((_flag, val)) = stripped.split_once('=') {
            val
        } else {
            // Flag name only (e.g. "--target", "--build") is not a filesystem path
            return false;
        }
    } else if let Some(stripped) = raw_arg.strip_prefix('-') {
        if let Some((_flag, val)) = stripped.split_once('=') {
            val
        } else {
            // Short flag name only is not a filesystem path
            return false;
        }
    } else {
        raw_arg
    };

    // Strip surrounding quotes
    let val_trimmed = arg_val.trim_matches('\'').trim_matches('"');
    if val_trimmed.is_empty() || val_trimmed == "/" {
        return false;
    }

    // Normalize separators
    let norm_arg = val_trimmed.replace('\\', "/");
    let norm_arg = norm_arg.trim_end_matches('/');

    let path_str = path.to_string_lossy().replace('\\', "/");
    let norm_path = path_str.trim_end_matches('/');

    if norm_arg.is_empty() || norm_path.is_empty() {
        return false;
    }

    // Exact path match
    if norm_arg == norm_path {
        return true;
    }

    // Argument targets a child path within the resource directory
    if norm_arg.starts_with(&format!("{}/", norm_path)) {
        return true;
    }

    // Resource is located within an argument target directory
    if norm_path.starts_with(&format!("{}/", norm_arg)) {
        return true;
    }

    // If resource path is relative, match trailing path component boundary
    if !path.is_absolute()
        && (norm_arg.ends_with(&format!("/{}", norm_path)) || norm_arg == norm_path)
    {
        return true;
    }

    false
}

fn is_transient_category(category: ResourceCategory) -> bool {
    matches!(
        category,
        ResourceCategory::PackageCache
            | ResourceCategory::BuildArtifact
            | ResourceCategory::AgentScratchpad
            | ResourceCategory::DiagnosticLog
    )
}

fn is_generic_runtime(target_id: DiscoveryTargetId) -> bool {
    matches!(
        target_id,
        DiscoveryTargetId::NodeNpm | DiscoveryTargetId::Python
    )
}

fn process_matches_target(p: &ProcessCandidate, target_id: DiscoveryTargetId) -> bool {
    match target_id {
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
    }
}
