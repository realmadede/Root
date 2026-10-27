use root_core::{
    discovery::{DiscoveryFinding, LifecycleAssessment, RuleRegistry},
    error::{Result, RootError},
    model::{
        ConfidenceLevel, FindingEvidence, FindingTarget, ProposedAction, ProtectionTier,
        ResourceCandidate, ResourceCategory, ResourceId, ResourceLocation, ScanFinding, ScanReport,
        ScanSummary,
    },
};
use root_guardian::GuardianPolicy;
use root_platform::{
    traits::{EnvironmentProvider, ResourceAccountant},
    DiscoveredEntry, NativeAccountant, NativeEnvironment, NativeFilesystem, TraversalOptions,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub fn run_scan(
    target_path: Option<PathBuf>,
    _dry_run: bool,
    json_output: bool,
    interactive: bool,
) -> Result<()> {
    let env = NativeEnvironment::new();
    let fs = NativeFilesystem::new();
    let accountant = NativeAccountant::new();
    let policy = GuardianPolicy::new();

    let current_uid = env.current_uid();
    let capabilities = accountant.get_capabilities()?;

    // Explicit target selection: reject execution if no target path was supplied
    let scan_root = match target_path {
        Some(p) => p,
        None => {
            return Err(RootError::InvalidPath(
                "No target path supplied. Specify a directory to scan using '--path <DIRECTORY>', or use 'root discover' for automated agent footprint discovery.".into(),
            ));
        }
    };

    // Traversal options with defensive defaults (max 64 depth, 250k entries, no cross-device)
    let options = TraversalOptions::default();
    let outcome = fs.traverse(&scan_root, &options)?;

    let mut findings = Vec::new();
    let mut discovery_findings = Vec::new();
    let mut seen_inodes = HashSet::new();
    let mut summary = ScanSummary {
        total_scanned: outcome.metrics.total_inspected,
        skipped_count: outcome.metrics.skipped_count,
        permission_denied_count: outcome.metrics.permission_denied_count,
        disappeared_count: outcome.metrics.disappeared_count,
        unsupported_count: outcome.metrics.unsupported_count,
        is_complete: outcome.metrics.is_complete,
        incomplete_reason: outcome.metrics.incomplete_reason.clone(),
        ..Default::default()
    };

    let mut observed_inodes = HashMap::new();
    for entry in &outcome.entries {
        if entry.dev != 0 || entry.ino != 0 {
            *observed_inodes
                .entry((entry.dev, entry.ino))
                .or_insert(0usize) += 1;
        }
    }

    for entry in &outcome.entries {
        classify_and_record_entry(
            entry,
            current_uid,
            &policy,
            &mut findings,
            &mut discovery_findings,
            &mut summary,
            &mut seen_inodes,
            &observed_inodes,
        );
    }

    let report = ScanReport {
        timestamp_epoch_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        root_paths: vec![scan_root.clone()],
        findings,
        summary,
        capabilities,
    };

    let _ = crate::history::save_last_scan(
        &scan_root,
        report.summary.total_scanned,
        report.findings.len(),
        report.summary.is_complete,
        "scan",
    );

    if json_output {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
    } else {
        render_terminal_report(&scan_root, &report);
        if interactive {
            crate::interactive::run_interactive_browser(&discovery_findings);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn classify_and_record_entry(
    entry: &DiscoveredEntry,
    current_uid: u32,
    policy: &GuardianPolicy,
    findings: &mut Vec<ScanFinding>,
    discovery_findings: &mut Vec<DiscoveryFinding>,
    summary: &mut ScanSummary,
    seen_inodes: &mut HashSet<(u64, u64)>,
    observed_inodes: &HashMap<(u64, u64), usize>,
) {
    let path_str = entry.path.to_string_lossy();
    let matched_rule = RuleRegistry::match_path(&path_str);

    let (target_id, target_name, target_kind, rule_id, category, tier, action, explanation) =
        if let Some(rule) = matched_rule {
            (
                rule.target_id,
                rule.target_id.name().to_string(),
                rule.target_id.kind(),
                rule.rule_id.clone(),
                rule.category,
                rule.default_tier,
                rule.default_action,
                format!(
                    "Matched discovery rule '{}': {}",
                    rule.rule_id, rule.pattern_description
                ),
            )
        } else {
            (
                root_core::discovery::DiscoveryTargetId::Git,
                "Unknown / General".to_string(),
                root_core::discovery::TargetKind::Tool,
                "default-unknown".to_string(),
                ResourceCategory::Unknown,
                ProtectionTier::NonActionable,
                ProposedAction::Inspect,
                "General filesystem entity; preserved in place".to_string(),
            )
        };

    let is_candidate_tier = matches!(
        tier,
        ProtectionTier::UserConfirmRequired
            | ProtectionTier::ObsoleteTransient
            | ProtectionTier::SafeRecoverable
    );

    let is_eligible_for_estimate = is_candidate_tier
        && entry.metadata.file_type != root_core::model::FileType::Directory
        && entry.metadata.file_type != root_core::model::FileType::Symlink;

    let is_new_inode = if entry.dev != 0 || entry.ino != 0 {
        seen_inodes.insert((entry.dev, entry.ino))
    } else {
        true
    };

    let reclaimable_bytes = if is_eligible_for_estimate && is_new_inode {
        if entry.metadata.storage.is_multi_link {
            let observed_count = observed_inodes
                .get(&(entry.dev, entry.ino))
                .copied()
                .unwrap_or(1);
            if observed_count >= entry.metadata.storage.link_count as usize {
                if entry.metadata.storage.is_sparse {
                    entry.metadata.storage.allocated_bytes
                } else {
                    entry.metadata.storage.bytes
                }
            } else {
                0
            }
        } else if entry.metadata.storage.is_sparse {
            entry.metadata.storage.allocated_bytes
        } else {
            entry.metadata.storage.bytes
        }
    } else {
        0
    };

    match tier {
        ProtectionTier::StrictlyProtected => summary.protected_count += 1,
        ProtectionTier::UserConfirmRequired => {
            summary.confirm_required_count += 1;
            summary.reclaimable_storage_bytes += reclaimable_bytes;
        }
        ProtectionTier::ObsoleteTransient => {
            summary.transient_count += 1;
            summary.reclaimable_storage_bytes += reclaimable_bytes;
        }
        ProtectionTier::SafeRecoverable => {
            summary.recoverable_count += 1;
            summary.reclaimable_storage_bytes += reclaimable_bytes;
        }
        ProtectionTier::NonActionable => summary.non_actionable_count += 1,
    }

    let location = ResourceLocation::new(entry.path.clone(), None, entry.dev, entry.ino);
    let id = ResourceId::from_path_and_inode(&entry.path, entry.dev, entry.ino);

    let candidate = ResourceCandidate {
        id,
        location: location.clone(),
        category,
        metadata: entry.metadata.clone(),
        ownership: root_core::model::ResourceOwnership {
            uid: entry.uid,
            gid: entry.gid,
            is_current_user: entry.uid == current_uid,
        },
        associated_agent: Some(target_name.clone()),
    };

    let target = FindingTarget::Filesystem(candidate);
    let safety_decision = policy.evaluate(&target, tier, action, current_uid);

    let finding = ScanFinding {
        target,
        protection_tier: tier,
        proposed_action: action,
        evidence_list: vec![FindingEvidence::inspection(
            "Filesystem metadata and discovery rule match",
            ConfidenceLevel::HighConfidence,
        )],
        confidence: ConfidenceLevel::HighConfidence,
        explanation: explanation.clone(),
        safety_decision: safety_decision.clone(),
    };

    discovery_findings.push(DiscoveryFinding {
        target_id,
        target_name,
        target_kind,
        rule_id,
        location,
        category,
        metadata: entry.metadata.clone(),
        protection_tier: tier,
        proposed_action: action,
        lifecycle: LifecycleAssessment::unknown("Direct filesystem scan"),
        confidence: ConfidenceLevel::HighConfidence,
        evidence_explanation: explanation,
        safety_decision,
        limitations: String::new(),
    });

    findings.push(finding);
}

fn render_terminal_report(root_path: &Path, report: &ScanReport) {
    println!("\n==========================================================================================");
    println!(" ROOT INSPECTION & SAFETY AUDIT REPORT (DRY-RUN)");
    println!(" Scanned Path: {}", root_path.display());
    println!("==========================================================================================");
    println!(
        "{:<20} | {:>10} | {:<22} | {:<12} | {:<24}",
        "Classification", "Size", "Candidate Path", "Action", "Guardian Safety Decision"
    );
    println!("------------------------------------------------------------------------------------------");

    for finding in &report.findings {
        let size_str = match &finding.target {
            FindingTarget::Filesystem(res) => format_bytes(res.metadata.storage.bytes),
            FindingTarget::Process(proc) => format_bytes(proc.memory.rss_bytes),
        };

        let raw_name = finding.target.display_name().replace('\n', "\\n");
        let truncated_name = truncate_middle(&raw_name, 22);

        let action_str = match finding.proposed_action {
            ProposedAction::Quarantine => "Quarantine",
            ProposedAction::Prune => "Prune",
            ProposedAction::TerminateGraceful => "Terminate",
            ProposedAction::Inspect => "Inspect",
            ProposedAction::Ignore => "Ignore",
        };

        let decision_str = match &finding.safety_decision {
            root_core::model::SafetyDecision::Allowed => "Allowed".to_string(),
            root_core::model::SafetyDecision::Rejected { reason, .. } => {
                format!("REJECT: {:?}", reason)
            }
        };

        println!(
            "{:<20} | {:>10} | {:<22} | {:<12} | {:<24}",
            finding.protection_tier.display_badge(),
            size_str,
            truncated_name,
            action_str,
            truncate_middle(&decision_str, 24)
        );
    }

    println!("==========================================================================================");
    println!(" AUDIT SUMMARY METRICS");
    println!("==========================================================================================");
    println!(
        "  Total Entities Inspected    : {:>10}",
        report.summary.total_scanned
    );
    println!(
        "  Skipped (Safety Policies)   : {:>10}",
        report.summary.skipped_count
    );
    println!(
        "  Permission Denied Paths     : {:>10}",
        report.summary.permission_denied_count
    );
    println!(
        "  Disappeared During Scan     : {:>10}",
        report.summary.disappeared_count
    );
    println!(
        "  Tier 1: Strictly Protected  : {:>10} (Excluded from recovery)",
        report.summary.protected_count
    );
    println!(
        "  Tier 2: Confirm Required    : {:>10} (Build outputs / scratchpads)",
        report.summary.confirm_required_count
    );
    println!(
        "  Tier 3: Obsolete Transient  : {:>10} (Logs / tempfiles / empty dirs)",
        report.summary.transient_count
    );
    println!(
        "  Tier 4: Safe Recoverable    : {:>10} (Package caches)",
        report.summary.recoverable_count
    );
    println!(
        "  Non-Actionable Files        : {:>10}",
        report.summary.non_actionable_count
    );
    println!(
        "  Estimated Candidate Storage : {:>10} (Upper bound; subject to active session and link verification)",
        format_bytes(report.summary.reclaimable_storage_bytes)
    );
    println!(
        "  Scan Completeness Status    : {}",
        if report.summary.is_complete {
            "COMPLETE (100% of bounded tree traversed)".to_string()
        } else {
            format!(
                "INCOMPLETE ({})",
                report
                    .summary
                    .incomplete_reason
                    .as_deref()
                    .unwrap_or("Halted early")
            )
        }
    );
    println!(
        "\n  Guardian Policy Invariant   : ALL MUTATIONS REJECTED (Phase 02 Read-Only Enforcement)"
    );
    println!("  Audit Conclusion            : 0 files moved. 0 files modified. Host completely untouched.");
    println!("==========================================================================================");
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GiB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}

fn truncate_middle(text: &str, max_chars: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        return text.to_string();
    }
    if max_chars <= 3 {
        return chars[..max_chars].iter().collect();
    }
    let keep = (max_chars - 3) / 2;
    let end_start = chars.len() - (max_chars - 3 - keep);
    let start_part: String = chars[..keep].iter().collect();
    let end_part: String = chars[end_start..].iter().collect();
    format!("{}...{}", start_part, end_part)
}
