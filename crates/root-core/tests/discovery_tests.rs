use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use root_core::{
    discovery::{
        DiscoveryContext, DiscoveryEngine, DiscoveryFilter, DiscoveryTargetId, LifecycleState,
        RuleRegistry, TargetKind,
    },
    fixtures::SyntheticFixture,
    model::{
        ConfidenceLevel, FileType, FindingTarget, MemoryMeasurement, PlatformCapabilities,
        ProcessCandidate, ProcessIdentity, ProcessState, ProposedAction, ProtectionTier,
        RejectionReason, ResourceCandidate, ResourceId, ResourceMetadata, ResourceOwnership,
        SafetyDecision, StorageMeasurement,
    },
};
use root_guardian::GuardianPolicy;

#[cfg(unix)]
fn extract_metadata(meta: &std::fs::Metadata) -> (ResourceMetadata, u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let file_type = if meta.is_dir() {
        FileType::Directory
    } else if meta.is_symlink() {
        FileType::Symlink
    } else {
        FileType::RegularFile
    };

    let metadata = ResourceMetadata {
        file_type,
        storage: StorageMeasurement::from_raw(meta.len(), meta.blocks(), 1),
        permissions_mode: meta.mode(),
        mtime_epoch_secs: meta.mtime(),
        atime_epoch_secs: meta.atime(),
        ctime_epoch_secs: meta.ctime(),
    };

    (metadata, meta.dev(), meta.ino())
}

#[cfg(windows)]
fn extract_metadata(meta: &std::fs::Metadata) -> (ResourceMetadata, u64, u64) {
    let file_type = if meta.is_dir() {
        FileType::Directory
    } else if meta.is_symlink() {
        FileType::Symlink
    } else {
        FileType::RegularFile
    };

    let epoch_secs = |t: std::io::Result<SystemTime>| {
        t.ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };

    let metadata = ResourceMetadata {
        file_type,
        storage: StorageMeasurement::from_raw(meta.len(), (meta.len() + 511) / 512, 1),
        permissions_mode: 0,
        mtime_epoch_secs: epoch_secs(meta.modified()),
        atime_epoch_secs: epoch_secs(meta.accessed()),
        ctime_epoch_secs: epoch_secs(meta.created()),
    };

    (metadata, 0, 0)
}

fn collect_fixture_entries(dir: &Path, out: &mut Vec<(PathBuf, ResourceMetadata, u64, u64)>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = entry.metadata() {
                let (metadata, dev, ino) = extract_metadata(&meta);
                out.push((path.clone(), metadata, dev, ino));

                if meta.is_dir() && !path.is_symlink() {
                    collect_fixture_entries(&path, out);
                }
            }
        }
    }
}

#[test]
fn test_discovery_all_12_targets_detected_on_synthetic_fixture() {
    let fixture = SyntheticFixture::create().expect("Failed to create synthetic fixture");
    let mut entries = Vec::new();
    collect_fixture_entries(fixture.path(), &mut entries);

    let policy = GuardianPolicy::new();
    let capabilities = PlatformCapabilities::unknown();
    let filter = DiscoveryFilter::default();

    let ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &filter,
        1000,
        &[],
        capabilities,
    );

    let report = DiscoveryEngine::evaluate_findings(
        &entries,
        &ctx,
        &|target: &FindingTarget, tier: ProtectionTier, action: ProposedAction, uid: u32| {
            policy.evaluate(target, tier, action, uid)
        },
    )
    .expect("Discovery evaluation failed");

    assert!(
        report.findings.len() > 10,
        "Expected multiple findings across fixture, got {}",
        report.findings.len()
    );

    // Verify detection of all 12 discovery targets
    let expected_targets = [
        DiscoveryTargetId::Antigravity,
        DiscoveryTargetId::ClaudeCode,
        DiscoveryTargetId::OpenAiCodex,
        DiscoveryTargetId::GeminiCli,
        DiscoveryTargetId::Aider,
        DiscoveryTargetId::NodeNpm,
        DiscoveryTargetId::Pnpm,
        DiscoveryTargetId::RustCargo,
        DiscoveryTargetId::Python,
        DiscoveryTargetId::Git,
        DiscoveryTargetId::LanguageServers,
        DiscoveryTargetId::DevServers,
    ];

    for expected in &expected_targets {
        let found = report.findings.iter().any(|f| f.target_id == *expected);
        assert!(
            found,
            "Target '{}' ({}) was not detected in synthetic fixture findings",
            expected.name(),
            expected.slug()
        );
    }
}

#[test]
fn test_discovery_filtering_agents_and_tools() {
    let fixture = SyntheticFixture::create().expect("Failed to create synthetic fixture");
    let mut entries = Vec::new();
    collect_fixture_entries(fixture.path(), &mut entries);

    let policy = GuardianPolicy::new();
    let capabilities = PlatformCapabilities::unknown();

    // 1. Agents only filter
    let agents_filter = DiscoveryFilter {
        target_id: None,
        kind: Some(TargetKind::Agent),
    };
    let agents_ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &agents_filter,
        1000,
        &[],
        capabilities.clone(),
    );
    let agents_report =
        DiscoveryEngine::evaluate_findings(&entries, &agents_ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");

    assert!(!agents_report.findings.is_empty());
    for finding in &agents_report.findings {
        assert_eq!(
            finding.target_kind,
            TargetKind::Agent,
            "Finding '{}' unexpectedly included under --agents filter",
            finding.target_name
        );
    }

    // 2. Tools only filter
    let tools_filter = DiscoveryFilter {
        target_id: None,
        kind: Some(TargetKind::Tool),
    };
    let tools_ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &tools_filter,
        1000,
        &[],
        capabilities.clone(),
    );
    let tools_report =
        DiscoveryEngine::evaluate_findings(&entries, &tools_ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");

    assert!(!tools_report.findings.is_empty());
    for finding in &tools_report.findings {
        assert_eq!(
            finding.target_kind,
            TargetKind::Tool,
            "Finding '{}' unexpectedly included under --tools filter",
            finding.target_name
        );
    }

    // 3. Specific agent filter: Claude Code
    let claude_filter = DiscoveryFilter {
        target_id: Some(DiscoveryTargetId::ClaudeCode),
        kind: None,
    };
    let claude_ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &claude_filter,
        1000,
        &[],
        capabilities.clone(),
    );
    let claude_report =
        DiscoveryEngine::evaluate_findings(&entries, &claude_ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");

    assert!(!claude_report.findings.is_empty());
    for finding in &claude_report.findings {
        assert_eq!(finding.target_id, DiscoveryTargetId::ClaudeCode);
    }

    // 4. Specific tool filter: Rust & Cargo
    let cargo_filter = DiscoveryFilter {
        target_id: Some(DiscoveryTargetId::RustCargo),
        kind: None,
    };
    let cargo_ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &cargo_filter,
        1000,
        &[],
        capabilities,
    );
    let cargo_report =
        DiscoveryEngine::evaluate_findings(&entries, &cargo_ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");

    assert!(!cargo_report.findings.is_empty());
    for finding in &cargo_report.findings {
        assert_eq!(finding.target_id, DiscoveryTargetId::RustCargo);
    }
}

#[test]
fn test_discovery_lifecycle_assessment_transitions() {
    let fixture = SyntheticFixture::create().expect("Failed to create synthetic fixture");
    let mut entries = Vec::new();
    collect_fixture_entries(fixture.path(), &mut entries);

    let policy = GuardianPolicy::new();
    let capabilities = PlatformCapabilities::unknown();

    // 1. Active Process Correlation
    let mock_proc = ProcessCandidate {
        identity: ProcessIdentity {
            pid: 4488,
            ppid: 1,
            real_uid: 1000,
            name: "cargo".to_string(),
            executable: Some(PathBuf::from("/usr/bin/cargo")),
            cmdline: vec!["cargo".to_string(), "build".to_string()],
            start_time_ticks: 10000,
            tty_nr: 0,
        },
        state: ProcessState::Running,
        memory: MemoryMeasurement::new(50_000_000, None, None, None),
        is_reparented_to_init: false,
        is_abandoned: false,
        associated_agent: None,
    };

    let cargo_filter = DiscoveryFilter {
        target_id: Some(DiscoveryTargetId::RustCargo),
        kind: None,
    };
    let cargo_ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &cargo_filter,
        1000,
        std::slice::from_ref(&mock_proc),
        capabilities.clone(),
    );
    let report_with_proc =
        DiscoveryEngine::evaluate_findings(&entries, &cargo_ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");

    let cargo_finding = report_with_proc
        .findings
        .iter()
        .find(|f| f.target_id == DiscoveryTargetId::RustCargo)
        .expect("No Cargo finding found");

    assert_eq!(cargo_finding.lifecycle.state, LifecycleState::Active);
    assert_eq!(cargo_finding.lifecycle.associated_pid, Some(4488));

    // 2. Presence Lockfile Indicator
    let antigravity_filter = DiscoveryFilter {
        target_id: Some(DiscoveryTargetId::Antigravity),
        kind: None,
    };
    let antigravity_ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &antigravity_filter,
        1000,
        &[],
        capabilities.clone(),
    );
    let report_antigravity =
        DiscoveryEngine::evaluate_findings(&entries, &antigravity_ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");

    let presence_finding = report_antigravity
        .findings
        .iter()
        .find(|f| {
            f.location
                .path
                .to_string_lossy()
                .contains("session_active.lock")
        })
        .expect("Presence lockfile finding not found");

    assert_eq!(presence_finding.lifecycle.state, LifecycleState::Active);

    // 3. Persistent Credentials & Keys
    let claude_filter = DiscoveryFilter {
        target_id: Some(DiscoveryTargetId::ClaudeCode),
        kind: None,
    };
    let claude_ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &claude_filter,
        1000,
        &[],
        capabilities.clone(),
    );
    let report_claude =
        DiscoveryEngine::evaluate_findings(&entries, &claude_ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");

    let key_finding = report_claude
        .findings
        .iter()
        .find(|f| f.location.path.to_string_lossy().ends_with(".key"))
        .expect("Claude session key finding not found");

    assert_eq!(
        key_finding.lifecycle.state,
        LifecycleState::Persistent,
        "Session key must be classified as Persistent lifecycle"
    );

    // 4. Dormant Transient vs Recent Unknown via synthetic entries
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let dormant_meta = ResourceMetadata {
        file_type: FileType::RegularFile,
        storage: StorageMeasurement::from_raw(4096, 8, 1),
        permissions_mode: 0o644,
        mtime_epoch_secs: now - (72 * 3600), // 72 hours ago
        atime_epoch_secs: now - (72 * 3600),
        ctime_epoch_secs: now - (72 * 3600),
    };

    let recent_meta = ResourceMetadata {
        file_type: FileType::RegularFile,
        storage: StorageMeasurement::from_raw(4096, 8, 1),
        permissions_mode: 0o644,
        mtime_epoch_secs: now - 300, // 5 minutes ago
        atime_epoch_secs: now - 300,
        ctime_epoch_secs: now - 300,
    };

    let test_entries = vec![
        (
            PathBuf::from("/tmp/app/__pycache__/mod.cpython-312.pyc"),
            dormant_meta,
            1,
            201,
        ),
        (
            PathBuf::from("/tmp/app2/__pycache__/recent.cpython-312.pyc"),
            recent_meta,
            1,
            202,
        ),
    ];

    let default_filter = DiscoveryFilter::default();
    let time_ctx = DiscoveryContext::new(
        vec![PathBuf::from("/tmp")],
        &default_filter,
        1000,
        &[],
        capabilities,
    );
    let time_report =
        DiscoveryEngine::evaluate_findings(&test_entries, &time_ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");

    let dormant_finding = &time_report.findings[0];
    let recent_finding = &time_report.findings[1];

    assert_eq!(
        dormant_finding.lifecycle.state,
        LifecycleState::DormantTransient
    );
    assert_eq!(recent_finding.lifecycle.state, LifecycleState::Unknown);
}

#[test]
fn test_discovery_guardian_rejection_of_mutations() {
    let fixture = SyntheticFixture::create().expect("Failed to create synthetic fixture");
    let mut entries = Vec::new();
    collect_fixture_entries(fixture.path(), &mut entries);

    let policy = GuardianPolicy::new();
    let capabilities = PlatformCapabilities::unknown();
    let filter = DiscoveryFilter::default();

    let ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &filter,
        1000,
        &[],
        capabilities,
    );

    let report =
        DiscoveryEngine::evaluate_findings(&entries, &ctx, &|target, tier, action, uid| {
            policy.evaluate(target, tier, action, uid)
        })
        .expect("Discovery failed");

    // All findings in Phase 03 must strictly reject mutating operations
    for finding in &report.findings {
        let dummy_target = FindingTarget::Filesystem(ResourceCandidate {
            id: ResourceId::from_path_and_inode(
                &finding.location.path,
                finding.location.device_id,
                finding.location.inode,
            ),
            location: finding.location.clone(),
            category: finding.category,
            metadata: finding.metadata.clone(),
            ownership: ResourceOwnership {
                uid: 1000,
                gid: 1000,
                is_current_user: true,
            },
            associated_agent: Some(finding.target_name.clone()),
        });

        // Mutating actions must fail under Phase 03 policy
        let quarantine_decision = policy.evaluate(
            &dummy_target,
            finding.protection_tier,
            ProposedAction::Quarantine,
            1000,
        );
        match quarantine_decision {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(
                    reason,
                    RejectionReason::Phase03ReadOnlyPolicy,
                    "Phase 03 Guardian must reject Quarantine for '{}'",
                    finding.location.path.display()
                );
            }
            SafetyDecision::Allowed => panic!("Phase 03 Guardian must reject Quarantine"),
        }

        let prune_decision = policy.evaluate(
            &dummy_target,
            finding.protection_tier,
            ProposedAction::Prune,
            1000,
        );
        match prune_decision {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(
                    reason,
                    RejectionReason::Phase03ReadOnlyPolicy,
                    "Phase 03 Guardian must reject Prune for '{}'",
                    finding.location.path.display()
                );
            }
            SafetyDecision::Allowed => panic!("Phase 03 Guardian must reject Prune"),
        }

        let terminate_decision = policy.evaluate(
            &dummy_target,
            finding.protection_tier,
            ProposedAction::TerminateGraceful,
            1000,
        );
        match terminate_decision {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(
                    reason,
                    RejectionReason::Phase03ReadOnlyPolicy,
                    "Phase 03 Guardian must reject TerminateGraceful for '{}'",
                    finding.location.path.display()
                );
            }
            SafetyDecision::Allowed => panic!("Phase 03 Guardian must reject TerminateGraceful"),
        }
    }
}

#[test]
fn test_discovery_pnpm_store_protection() {
    let fixture = SyntheticFixture::create().expect("Failed to create synthetic fixture");
    let mut entries = Vec::new();
    collect_fixture_entries(fixture.path(), &mut entries);

    let policy = GuardianPolicy::new();
    let capabilities = PlatformCapabilities::unknown();
    let filter = DiscoveryFilter {
        target_id: Some(DiscoveryTargetId::Pnpm),
        kind: None,
    };

    let ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &filter,
        1000,
        &[],
        capabilities,
    );

    let report = DiscoveryEngine::evaluate_findings(&entries, &ctx, &|t, tier, a, uid| {
        policy.evaluate(t, tier, a, uid)
    })
    .expect("Evaluation failed");

    assert!(!report.findings.is_empty(), "No pnpm findings detected");

    for finding in &report.findings {
        assert_eq!(
            finding.protection_tier,
            ProtectionTier::StrictlyProtected,
            "pnpm store must be StrictlyProtected due to shared hard links"
        );
        assert_eq!(
            finding.proposed_action,
            ProposedAction::Ignore,
            "pnpm store proposed action must be Ignore"
        );
        assert!(
            finding.limitations.contains("hard-link") || finding.limitations.contains("Shared"),
            "pnpm finding must document hard link danger in limitations"
        );
    }
}

#[test]
fn test_discovery_no_content_inspection_and_privacy() {
    let fixture = SyntheticFixture::create().expect("Failed to create synthetic fixture");
    let mut entries = Vec::new();
    collect_fixture_entries(fixture.path(), &mut entries);

    let policy = GuardianPolicy::new();
    let capabilities = PlatformCapabilities::unknown();
    let filter = DiscoveryFilter::default();

    let ctx = DiscoveryContext::new(
        vec![fixture.path().to_path_buf()],
        &filter,
        1000,
        &[],
        capabilities,
    );

    let report = DiscoveryEngine::evaluate_findings(&entries, &ctx, &|t, tier, a, uid| {
        policy.evaluate(t, tier, a, uid)
    })
    .expect("Evaluation failed");

    let json_report = serde_json::to_string_pretty(&report).expect("Serialization failed");

    // Invariant 5: Root operates on file metadata only.
    // Content bytes written into synthetic fixtures must never appear in report output.
    assert!(
        !json_report.contains("sk-synthetic-dummy-key-never-leak"),
        "API key content leaked into discovery report!"
    );
    assert!(
        !json_report.contains("SYNTHETIC_DUMMY_TOKEN"),
        "OAuth credentials content leaked into discovery report!"
    );
    assert!(
        !json_report.contains("Synthetic prompt"),
        "Transcript prompt content leaked into discovery report!"
    );
    assert!(
        !json_report.contains("SYNTHETIC_ENCRYPTION_KEY_BYTES"),
        "Session encryption key leaked into discovery report!"
    );
    assert!(
        !json_report.contains("Confidential business plan"),
        "User document content leaked into discovery report!"
    );
}

#[test]
fn test_discovery_rule_registry_invariants() {
    let rules = RuleRegistry::all_rules();
    assert!(
        rules.len() >= 20,
        "Rule registry should contain extensive rules (got {})",
        rules.len()
    );

    for rule in &rules {
        assert!(!rule.rule_id.is_empty(), "Rule ID must not be empty");
        assert!(rule.rule_version >= 1, "Rule version must be at least 1");
        assert!(
            !rule.nominal_base.is_empty(),
            "Nominal base path must not be empty"
        );
        assert!(
            !rule.evidence_source.is_empty(),
            "Evidence source must be documented"
        );
        assert!(
            !rule.known_limitations.is_empty(),
            "Known limitations must be documented"
        );
        assert!(
            rule.confidence == ConfidenceLevel::HighConfidence
                || rule.confidence == ConfidenceLevel::MediumConfidence,
            "Rules must have high or medium confidence"
        );
    }
}
