use root_core::{
    error::Result,
    model::{
        FindingEvidence, FindingTarget, ProposedAction, ProtectionTier, ResourceCandidate,
        ResourceCategory, ResourceId, ResourceLocation, ScanFinding, ScanReport, ScanSummary,
    },
    SyntheticFixture,
};
use root_guardian::GuardianPolicy;
use root_platform::{
    traits::{EnvironmentProvider, FilesystemProvider, ResourceAccountant},
    LinuxAccountant, LinuxEnvironment, LinuxFilesystem,
};
use std::path::{Path, PathBuf};

pub fn run_scan(target_path: Option<PathBuf>, json_output: bool) -> Result<()> {
    let env = LinuxEnvironment::new();
    let fs = LinuxFilesystem::new();
    let accountant = LinuxAccountant::new();
    let policy = GuardianPolicy::new();

    let current_uid = env.current_uid();
    let capabilities = accountant.get_capabilities()?;

    // If no path was explicitly supplied, generate and scan an isolated synthetic fixture tree
    let (scan_root, _synthetic_guard) = if let Some(p) = target_path {
        (p, None)
    } else {
        if !json_output {
            println!("No target path supplied. Generating synthetic sandboxed fixture tree...");
        } else {
            eprintln!("No target path supplied. Generating synthetic sandboxed fixture tree...");
        }
        let fixture = SyntheticFixture::create()?;
        let path = fixture.path().to_path_buf();
        (path, Some(fixture))
    };

    let mut findings = Vec::new();
    let mut summary = ScanSummary::default();

    traverse_and_classify(
        &fs,
        &scan_root,
        &scan_root,
        current_uid,
        &policy,
        &mut findings,
        &mut summary,
    )?;

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

    if json_output {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| root_core::error::RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
    } else {
        render_terminal_report(&scan_root, &report);
    }

    Ok(())
}

fn traverse_and_classify(
    fs: &LinuxFilesystem,
    _root: &Path,
    current_dir: &Path,
    current_uid: u32,
    policy: &GuardianPolicy,
    findings: &mut Vec<ScanFinding>,
    summary: &mut ScanSummary,
) -> Result<()> {
    let entries = match fs.read_dir(current_dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for path in entries {
        let meta = match fs.symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        summary.total_scanned += 1;

        let path_str = path.to_string_lossy();
        let (category, tier, action, explanation) = classify_path(&path_str, meta.storage.bytes);

        match tier {
            ProtectionTier::StrictlyProtected => summary.protected_count += 1,
            ProtectionTier::UserConfirmRequired => {
                summary.confirm_required_count += 1;
                summary.reclaimable_storage_bytes += meta.storage.bytes;
            }
            ProtectionTier::ObsoleteTransient => {
                summary.transient_count += 1;
                summary.reclaimable_storage_bytes += meta.storage.bytes;
            }
            ProtectionTier::SafeRecoverable => {
                summary.recoverable_count += 1;
                summary.reclaimable_storage_bytes += meta.storage.bytes;
            }
            ProtectionTier::NonActionable => summary.non_actionable_count += 1,
        }

        let dev_id = fs.get_device_id(&path).unwrap_or(0);
        let inode = fs.get_inode(&path).unwrap_or(0);

        let location = ResourceLocation::new(path.clone(), None, dev_id, inode);
        let id = ResourceId::from_path_and_inode(&path, dev_id, inode);

        let candidate = ResourceCandidate {
            id,
            location,
            category,
            metadata: meta,
            ownership: root_core::model::ResourceOwnership {
                uid: current_uid,
                gid: current_uid,
                is_current_user: true,
            },
            associated_agent: None,
        };

        let target = FindingTarget::Filesystem(candidate);
        let safety_decision = policy.evaluate(&target, tier, action, current_uid);

        let finding = ScanFinding {
            target,
            protection_tier: tier,
            proposed_action: action,
            evidence_list: vec![FindingEvidence::inspection(
                "Filesystem metadata and lexical pattern match",
                root_core::model::ConfidenceLevel::HighConfidence,
            )],
            confidence: root_core::model::ConfidenceLevel::HighConfidence,
            explanation,
            safety_decision,
        };

        findings.push(finding);

        // Recurse into directories (unless symlink)
        if path.is_dir() && !path.is_symlink() {
            let _ = traverse_and_classify(fs, _root, &path, current_uid, policy, findings, summary);
        }
    }

    Ok(())
}

fn classify_path(
    path_str: &str,
    _bytes: u64,
) -> (ResourceCategory, ProtectionTier, ProposedAction, String) {
    if path_str.contains("/.ssh")
        || path_str.contains("/.gnupg")
        || path_str.ends_with(".bashrc")
        || path_str.ends_with("transcript.jsonl")
        || path_str.ends_with("oauth_creds.json")
        || path_str.ends_with(".key")
    {
        (
            ResourceCategory::SessionState,
            ProtectionTier::StrictlyProtected,
            ProposedAction::Ignore,
            "Protected credentials, user configuration, or conversation transcripts".to_string(),
        )
    } else if path_str.contains("/target/") || path_str.contains("/node_modules/") {
        (
            ResourceCategory::BuildArtifact,
            ProtectionTier::UserConfirmRequired,
            ProposedAction::Quarantine,
            "Development build outputs / dependency vendor directory".to_string(),
        )
    } else if path_str.contains("/scratch/")
        || path_str.contains("/log/")
        || path_str.ends_with(".tmp")
        || path_str.contains("session-env")
    {
        (
            ResourceCategory::AgentScratchpad,
            ProtectionTier::ObsoleteTransient,
            ProposedAction::Quarantine,
            "Transient diagnostic logs, agent scratchpads, or temporary files".to_string(),
        )
    } else if path_str.contains("cache") {
        (
            ResourceCategory::PackageCache,
            ProtectionTier::SafeRecoverable,
            ProposedAction::Quarantine,
            "Package download cache; bit-for-bit re-fetchable from registries".to_string(),
        )
    } else {
        (
            ResourceCategory::Unknown,
            ProtectionTier::NonActionable,
            ProposedAction::Inspect,
            "General filesystem entity; preserved in place".to_string(),
        )
    }
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
        "  Total Entities Scanned      : {:>10}",
        report.summary.total_scanned
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
        "  Potential Reclaimable Space : {:>10}",
        format_bytes(report.summary.reclaimable_storage_bytes)
    );
    println!(
        "\n  Guardian Policy Invariant   : ALL MUTATIONS REJECTED (Phase 01 Read-Only Enforcement)"
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
