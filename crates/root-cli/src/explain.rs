use root_core::{
    error::{Result, RootError},
    model::{
        ConfidenceLevel, FindingEvidence, FindingTarget, ProposedAction, ProtectionTier,
        ResourceCandidate, ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata,
        ResourceOwnership, SafetyDecision, StorageMeasurement,
    },
    DiscoveryRule, RuleRegistry,
};
use root_guardian::GuardianPolicy;
use root_platform::{
    traits::{EnvironmentProvider, FilesystemProvider},
    LinuxEnvironment, LinuxFilesystem,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::terminal::{format_bytes, format_tier_badge, Style};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainReport {
    pub query_identifier: String,
    pub target_name: String,
    pub matched_rule_id: String,
    pub rule_version: u32,
    pub category: ResourceCategory,
    pub pattern_description: String,
    pub observed_details: String,
    pub supporting_evidence: Vec<FindingEvidence>,
    pub confidence: ConfidenceLevel,
    pub lifecycle_uncertainty: String,
    pub protection_tier: ProtectionTier,
    pub guardian_decision: String,
    pub permitted_actions: Vec<String>,
    pub rejected_actions: Vec<String>,
    pub known_limitations: String,
}

pub fn run_explain(identifier: &str, json_output: bool) -> Result<()> {
    let report = generate_explanation(identifier)?;

    if json_output {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    render_explain_terminal(&report);
    Ok(())
}

pub fn generate_explanation(identifier: &str) -> Result<ExplainReport> {
    let env = LinuxEnvironment::new();
    let fs = LinuxFilesystem::new();
    let policy = GuardianPolicy::new();
    let current_uid = env.current_uid();

    // 1. Check if the identifier is a rule_id directly
    if let Some(rule) = RuleRegistry::get_rule(identifier) {
        return build_rule_explanation(&rule, &policy, current_uid, identifier);
    }

    // 2. Parse potential path or resource_id (which could be path:dev:ino)
    let candidate_path_str = if let Some(idx) = identifier.find(':') {
        &identifier[..idx]
    } else {
        identifier
    };

    let candidate_path = PathBuf::from(candidate_path_str);

    // 3. Match path against rule registry
    if let Some(rule) = RuleRegistry::match_path(candidate_path_str) {
        let meta_opt = fs.symlink_metadata(&candidate_path).ok();
        return build_path_explanation(
            &rule,
            &candidate_path,
            meta_opt,
            &policy,
            current_uid,
            identifier,
        );
    }

    // 4. If path exists on disk but didn't match a specialized agent rule
    if candidate_path.exists() {
        let meta = fs.symlink_metadata(&candidate_path)?;
        return build_generic_path_explanation(
            &candidate_path,
            meta,
            &policy,
            current_uid,
            identifier,
        );
    }

    // 5. No match found
    let available_rules = RuleRegistry::all_rules()
        .into_iter()
        .map(|r| r.rule_id)
        .take(8)
        .collect::<Vec<_>>()
        .join(", ");

    Err(RootError::InvalidPath(format!(
        "No matching discovery rule or filesystem resource found for identifier '{}'.\nAvailable rule identifiers include: {} (or run 'root discover' to locate resources).",
        identifier, available_rules
    )))
}

fn build_rule_explanation(
    rule: &DiscoveryRule,
    policy: &GuardianPolicy,
    current_uid: u32,
    query: &str,
) -> Result<ExplainReport> {
    let dummy_path = PathBuf::from(&rule.nominal_base);
    let dummy_candidate = ResourceCandidate {
        id: ResourceId::new(&rule.rule_id),
        location: ResourceLocation::new(dummy_path.clone(), None, 1, 1),
        category: rule.category,
        metadata: ResourceMetadata {
            file_type: root_core::model::FileType::RegularFile,
            storage: StorageMeasurement::zero(),
            permissions_mode: 0o644,
            mtime_epoch_secs: 0,
            atime_epoch_secs: 0,
            ctime_epoch_secs: 0,
        },
        ownership: ResourceOwnership {
            uid: current_uid,
            gid: current_uid,
            is_current_user: true,
        },
        associated_agent: Some(rule.target_id.name().to_string()),
    };

    let target = FindingTarget::Filesystem(dummy_candidate);
    let inspect_decision = policy.evaluate(
        &target,
        rule.default_tier,
        ProposedAction::Inspect,
        current_uid,
    );
    let quarantine_decision = policy.evaluate(
        &target,
        rule.default_tier,
        ProposedAction::Quarantine,
        current_uid,
    );
    let prune_decision = policy.evaluate(
        &target,
        rule.default_tier,
        ProposedAction::Prune,
        current_uid,
    );

    let mut permitted = Vec::new();
    let mut rejected = Vec::new();

    if inspect_decision.is_allowed() {
        permitted.push("Inspect (Read-Only)".to_string());
    } else {
        rejected.push(format!("Inspect: {}", format_rejection(&inspect_decision)));
    }

    if quarantine_decision.is_allowed() {
        permitted.push("Quarantine (Multi-Factor Authorized in Fixtures Only)".to_string());
    } else {
        rejected.push(format!(
            "Quarantine: {}",
            format_rejection(&quarantine_decision)
        ));
    }

    if prune_decision.is_allowed() {
        permitted.push("Prune (Never permitted directly; quarantine required)".to_string());
    } else {
        rejected.push(format!("Prune: {}", format_rejection(&prune_decision)));
    }
    rejected.push("Delete: Direct unquarantined deletion is architecturally forbidden".to_string());

    let evidence = vec![
        FindingEvidence::structural(
            format!(
                "Structural path pattern match: '{}'",
                rule.pattern_description
            ),
            rule.confidence,
        ),
        FindingEvidence::inspection(
            format!("Rule provenance source: '{}'", rule.evidence_source),
            rule.confidence,
        ),
    ];

    Ok(ExplainReport {
        query_identifier: query.to_string(),
        target_name: rule.target_id.name().to_string(),
        matched_rule_id: rule.rule_id.clone(),
        rule_version: rule.rule_version,
        category: rule.category,
        pattern_description: rule.pattern_description.clone(),
        observed_details: format!("Target nominal base: '{}' for target '{}'", rule.nominal_base, rule.target_id.name()),
        supporting_evidence: evidence,
        confidence: rule.confidence,
        lifecycle_uncertainty: format!(
            "Lifecycle uncertainty exists: {}. A classification does not imply automatic deletion safety.",
            rule.known_limitations
        ),
        protection_tier: rule.default_tier,
        guardian_decision: format!(
            "Default Tier: {:?}. In Phase 05, all production mutations are rejected.",
            rule.default_tier
        ),
        permitted_actions: permitted,
        rejected_actions: rejected,
        known_limitations: rule.known_limitations.clone(),
    })
}

fn build_path_explanation(
    rule: &DiscoveryRule,
    path: &Path,
    metadata: Option<ResourceMetadata>,
    policy: &GuardianPolicy,
    current_uid: u32,
    query: &str,
) -> Result<ExplainReport> {
    let mut evidence = vec![FindingEvidence::structural(
        format!(
            "Matched rule '{}' for pattern '{}'",
            rule.rule_id, rule.pattern_description
        ),
        rule.confidence,
    )];

    let observed_details = if let Some(ref meta) = metadata {
        evidence.push(FindingEvidence::verified(format!(
            "Physical disk allocation: apparent {} vs allocated {}",
            format_bytes(meta.storage.bytes),
            format_bytes(meta.storage.allocated_bytes)
        )));
        format!(
            "Path '{}' exists on disk. Apparent size: {}, allocated: {}, sparse: {}, link_count: {}",
            path.display(),
            format_bytes(meta.storage.bytes),
            format_bytes(meta.storage.allocated_bytes),
            meta.storage.is_sparse,
            meta.storage.link_count
        )
    } else {
        format!(
            "Path '{}' matched structural pattern, but does not currently exist on disk.",
            path.display()
        )
    };

    let candidate = ResourceCandidate {
        id: ResourceId::new(path.display().to_string()),
        location: ResourceLocation::new(path.to_path_buf(), None, 1, 1),
        category: rule.category,
        metadata: metadata.unwrap_or(ResourceMetadata {
            file_type: root_core::model::FileType::RegularFile,
            storage: StorageMeasurement::zero(),
            permissions_mode: 0o644,
            mtime_epoch_secs: 0,
            atime_epoch_secs: 0,
            ctime_epoch_secs: 0,
        }),
        ownership: ResourceOwnership {
            uid: current_uid,
            gid: current_uid,
            is_current_user: true,
        },
        associated_agent: Some(rule.target_id.name().to_string()),
    };

    let target = FindingTarget::Filesystem(candidate);
    let inspect_dec = policy.evaluate(
        &target,
        rule.default_tier,
        ProposedAction::Inspect,
        current_uid,
    );
    let quar_dec = policy.evaluate(
        &target,
        rule.default_tier,
        ProposedAction::Quarantine,
        current_uid,
    );
    let prune_dec = policy.evaluate(
        &target,
        rule.default_tier,
        ProposedAction::Prune,
        current_uid,
    );

    let mut permitted = Vec::new();
    let mut rejected = Vec::new();

    if inspect_dec.is_allowed() {
        permitted.push("Inspect (Read-Only)".to_string());
    } else {
        rejected.push(format!("Inspect: {}", format_rejection(&inspect_dec)));
    }

    if quar_dec.is_allowed() {
        permitted.push("Quarantine (Multi-Factor Authorized in Fixtures Only)".to_string());
    } else {
        rejected.push(format!("Quarantine: {}", format_rejection(&quar_dec)));
    }

    if prune_dec.is_allowed() {
        permitted.push("Prune (Never permitted directly)".to_string());
    } else {
        rejected.push(format!("Prune: {}", format_rejection(&prune_dec)));
    }
    rejected.push("Delete: Direct unquarantined deletion is architecturally forbidden".to_string());

    Ok(ExplainReport {
        query_identifier: query.to_string(),
        target_name: rule.target_id.name().to_string(),
        matched_rule_id: rule.rule_id.clone(),
        rule_version: rule.rule_version,
        category: rule.category,
        pattern_description: rule.pattern_description.clone(),
        observed_details,
        supporting_evidence: evidence,
        confidence: rule.confidence,
        lifecycle_uncertainty: format!(
            "Lifecycle uncertainty: {}. Classification does not guarantee absence of active session references.",
            rule.known_limitations
        ),
        protection_tier: rule.default_tier,
        guardian_decision: format!(
            "Guardian Policy: {:?}. Phase 05 enforces production read-only safety.",
            rule.default_tier
        ),
        permitted_actions: permitted,
        rejected_actions: rejected,
        known_limitations: rule.known_limitations.clone(),
    })
}

fn build_generic_path_explanation(
    path: &Path,
    meta: ResourceMetadata,
    policy: &GuardianPolicy,
    current_uid: u32,
    query: &str,
) -> Result<ExplainReport> {
    let candidate = ResourceCandidate {
        id: ResourceId::new(path.display().to_string()),
        location: ResourceLocation::new(path.to_path_buf(), None, 1, 1),
        category: ResourceCategory::Unknown,
        metadata: meta.clone(),
        ownership: ResourceOwnership {
            uid: current_uid,
            gid: current_uid,
            is_current_user: true,
        },
        associated_agent: None,
    };

    let target = FindingTarget::Filesystem(candidate);
    let tier = ProtectionTier::StrictlyProtected;
    let inspect_dec = policy.evaluate(&target, tier, ProposedAction::Inspect, current_uid);
    let quar_dec = policy.evaluate(&target, tier, ProposedAction::Quarantine, current_uid);

    let mut permitted = Vec::new();
    let mut rejected = Vec::new();

    if inspect_dec.is_allowed() {
        permitted.push("Inspect (Read-Only)".to_string());
    }
    if !quar_dec.is_allowed() {
        rejected.push(format!("Quarantine: {}", format_rejection(&quar_dec)));
    }
    rejected.push("Delete: Direct unquarantined deletion is architecturally forbidden".to_string());

    Ok(ExplainReport {
        query_identifier: query.to_string(),
        target_name: "Generic Filesystem Resource".to_string(),
        matched_rule_id: "generic-unclassified".to_string(),
        rule_version: 1,
        category: ResourceCategory::Unknown,
        pattern_description: "Unclassified filesystem path".to_string(),
        observed_details: format!(
            "Path '{}' observed. Apparent size: {}, allocated: {}, permissions: {:o}",
            path.display(),
            format_bytes(meta.storage.bytes),
            format_bytes(meta.storage.allocated_bytes),
            meta.permissions_mode & 0o777
        ),
        supporting_evidence: vec![FindingEvidence::inspection(
            "Direct lstat metadata inspection",
            ConfidenceLevel::VerifiedFact,
        )],
        confidence: ConfidenceLevel::HighConfidence,
        lifecycle_uncertainty: "Unclassified resources default to Tier 1 Strict Protection; zero heuristic deletion.".to_string(),
        protection_tier: tier,
        guardian_decision: "Strictly protected by default. Root Guardian prohibits actions against unclassified resources.".to_string(),
        permitted_actions: permitted,
        rejected_actions: rejected,
        known_limitations: "No agent or tool signature detected. Root will not touch unclassified paths.".to_string(),
    })
}

fn format_rejection(decision: &SafetyDecision) -> String {
    match decision {
        SafetyDecision::Allowed => "Allowed".to_string(),
        SafetyDecision::Rejected { explanation, .. } => explanation.clone(),
    }
}

fn render_explain_terminal(report: &ExplainReport) {
    println!("================================================================================");
    println!(" {}", Style::bold("ROOT RESOURCE FINDING EXPLANATION"));
    println!("================================================================================");
    println!("Finding Identity:");
    println!("  Query Identifier      : {}", report.query_identifier);
    println!(
        "  Associated Target     : {}",
        Style::bold(&report.target_name)
    );
    println!(
        "  Matched Rule ID       : {} (v{})",
        report.matched_rule_id, report.rule_version
    );
    println!("  Resource Category     : {:?}", report.category);
    println!("  Pattern Description   : {}", report.pattern_description);

    println!("\nObserved Facts & Evidence Provenance:");
    println!("  {}", report.observed_details);
    for ev in &report.supporting_evidence {
        println!(
            "  - [{:?}] {} (Confidence: {:?})",
            ev.provenance, ev.description, ev.confidence
        );
    }

    println!("\nLifecycle Assessment & Uncertainty:");
    println!("  {}", report.lifecycle_uncertainty);
    println!("  Known Limitations     : {}", report.known_limitations);

    println!("\nProtection Status & Guardian Safety Policy:");
    println!(
        "  Protection Tier       : {}",
        format_tier_badge(report.protection_tier)
    );
    println!("  Guardian Invariant    : {}", report.guardian_decision);

    println!("\nPermitted Operations:");
    for act in &report.permitted_actions {
        println!("  - {}", Style::green(act));
    }

    println!("\nRejected Operations (Safety Guardrails):");
    for act in &report.rejected_actions {
        println!("  - {}", Style::red(act));
    }

    println!("================================================================================");
    println!(" Technical Note: A classification finding is an explanation of observed provenance.");
    println!(
        " It does not constitute proof of cleanup safety or authorization for host modification."
    );
    println!("================================================================================");
}
