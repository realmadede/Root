use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use root_core::{
    discovery::{
        DiscoveryContext, DiscoveryEngine, DiscoveryFilter, DiscoveryTargetId, LifecycleState,
        ProcessAttribution, ResourceClassifier, RuleRegistry, TargetKind,
    },
    fixtures::SyntheticFixture,
    model::{
        CapabilityStatus, ConfidenceLevel, FileType, FindingTarget, MemoryMeasurement,
        PlatformCapabilities, ProcessCandidate, ProcessIdentity, ProcessState, ProposedAction,
        ProtectionTier, RejectionReason, ResourceCandidate, ResourceId, ResourceMetadata,
        ResourceOwnership, SafetyDecision, StorageMeasurement,
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

#[test]
fn test_phase13_rule_precedence_and_credential_protection() {
    // 1. Antigravity presence lock must take precedence over general antigravity state
    let presence_path = "/home/user/.gemini/antigravity-cli/presence/session_active.lock";
    let matched = RuleRegistry::match_path(presence_path).expect("Presence lock must match a rule");
    assert_eq!(matched.rule_id, "antigravity-presence");
    assert_eq!(matched.default_tier, ProtectionTier::StrictlyProtected);

    // 2. Dev server cache inside node_modules (.vite) must take precedence over node_modules
    let vite_path = "/home/user/project/node_modules/.vite/deps/react.js";
    let matched_vite = RuleRegistry::match_path(vite_path).expect("Vite cache must match a rule");
    assert_eq!(matched_vite.rule_id, "dev-server-cache");
    assert_eq!(matched_vite.default_tier, ProtectionTier::ObsoleteTransient);

    // Standard node_modules still matches node-modules rule
    let standard_nm = "/home/user/project/node_modules/lodash/index.js";
    let matched_nm = RuleRegistry::match_path(standard_nm).expect("Node modules must match");
    assert_eq!(matched_nm.rule_id, "node-modules");
    assert_eq!(matched_nm.default_tier, ProtectionTier::UserConfirmRequired);

    // 3. Cargo credentials must be strictly protected, never classified as cargo-cache
    let cargo_creds = "/home/user/.cargo/credentials.toml";
    let matched_creds =
        RuleRegistry::match_path(cargo_creds).expect("Cargo credentials must match a rule");
    assert_eq!(matched_creds.rule_id, "cargo-credentials");
    assert_eq!(
        matched_creds.default_tier,
        ProtectionTier::StrictlyProtected
    );

    let cargo_config = "/home/user/.cargo/config.toml";
    let matched_config =
        RuleRegistry::match_path(cargo_config).expect("Cargo config must match a rule");
    assert_eq!(matched_config.rule_id, "cargo-credentials");
    assert_eq!(
        matched_config.default_tier,
        ProtectionTier::StrictlyProtected
    );

    // Cargo binaries must never match cargo-cache
    let cargo_bin = "/home/user/.cargo/bin/cargo";
    assert!(RuleRegistry::match_path(cargo_bin).is_none());

    // Legitimate cargo cache matches cargo-cache
    let cargo_crate = "/home/user/.cargo/registry/cache/crates.io-1234/serde-1.0.crate";
    let matched_crate = RuleRegistry::match_path(cargo_crate).expect("Cargo cache must match");
    assert_eq!(matched_crate.rule_id, "cargo-cache");
    assert_eq!(matched_crate.default_tier, ProtectionTier::SafeRecoverable);

    // 4. npm credentials (.npmrc) must be strictly protected
    let npmrc_path = "/home/user/.npmrc";
    let matched_npmrc = RuleRegistry::match_path(npmrc_path).expect("npmrc must match a rule");
    assert_eq!(matched_npmrc.rule_id, "npm-credentials");
    assert_eq!(
        matched_npmrc.default_tier,
        ProtectionTier::StrictlyProtected
    );

    // Arbitrary paths containing 'npm' must NOT match npm-cache
    let non_npm_cache = "/home/user/my-project/src/npm/client.rs";
    assert!(RuleRegistry::match_path(non_npm_cache).is_none());

    // Legitimate npm cache matches npm-cache
    let npm_cache_path = "/home/user/.npm/_cacache/content-v2/sha512/ab/cd";
    let matched_npm_cache = RuleRegistry::match_path(npm_cache_path).expect("npm cache must match");
    assert_eq!(matched_npm_cache.rule_id, "npm-cache");
    assert_eq!(
        matched_npm_cache.default_tier,
        ProtectionTier::SafeRecoverable
    );
}

fn make_test_meta(mtime: i64, bytes: u64, blocks: u64, nlink: u64) -> ResourceMetadata {
    ResourceMetadata {
        file_type: FileType::RegularFile,
        storage: StorageMeasurement::from_raw(bytes, blocks, nlink),
        permissions_mode: 0o644,
        mtime_epoch_secs: mtime,
        atime_epoch_secs: mtime,
        ctime_epoch_secs: mtime,
    }
}

#[test]
fn test_phase13_lifecycle_refinements() {
    let policy = GuardianPolicy::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // 1. Presence lockfile is always Active even with no processes running
    let presence_meta = make_test_meta(now - 3600 * 100, 0, 0, 1);
    let finding_lock = ResourceClassifier::classify_entry(
        std::path::Path::new("/home/user/.gemini/antigravity-cli/presence/session_active.lock"),
        &presence_meta,
        1,
        1,
        1000,
        &[],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(finding_lock.lifecycle.state, LifecycleState::Active);

    // 2. StrictlyProtected credentials are always Persistent, never Dormant
    let creds_meta = make_test_meta(now - 3600 * 200, 100, 1, 1);
    let finding_creds = ResourceClassifier::classify_entry(
        std::path::Path::new("/home/user/.cargo/credentials.toml"),
        &creds_meta,
        1,
        2,
        1000,
        &[],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(finding_creds.lifecycle.state, LifecycleState::Persistent);

    // 3. Process directly targeting path via cmdline produces Active with direct operation reasoning
    let target_path = std::path::Path::new("/home/user/project/target/debug/app");
    let proc_direct = ProcessCandidate {
        identity: ProcessIdentity {
            pid: 9999,
            ppid: 1,
            real_uid: 1000,
            name: "cargo".to_string(),
            executable: Some(PathBuf::from("/usr/bin/cargo")),
            cmdline: vec![
                "cargo".to_string(),
                "build".to_string(),
                "--manifest-path".to_string(),
                "/home/user/project/target/debug/app".to_string(),
            ],
            start_time_ticks: 1000,
            tty_nr: 0,
        },
        state: ProcessState::Running,
        memory: MemoryMeasurement::new(1000, None, None, None),
        is_reparented_to_init: false,
        is_abandoned: false,
        associated_agent: None,
    };
    let meta_transient = make_test_meta(now - 3600 * 10, 1024, 2, 1);
    let finding_direct = ResourceClassifier::classify_entry(
        target_path,
        &meta_transient,
        1,
        3,
        1000,
        &[proc_direct],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(finding_direct.lifecycle.state, LifecycleState::Active);
    assert!(finding_direct
        .lifecycle
        .reasoning
        .contains("actively operating on this path"));

    // 4. Inconclusive 1h-48h window with no running process
    let finding_indeterminate = ResourceClassifier::classify_entry(
        target_path,
        &meta_transient,
        1,
        4,
        1000,
        &[],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(
        finding_indeterminate.lifecycle.state,
        LifecycleState::Unknown
    );
    assert!(finding_indeterminate
        .lifecycle
        .reasoning
        .contains("indeterminate window"));

    // 5. Older than 48h with no running process -> DormantTransient
    let meta_old = make_test_meta(now - 3600 * 72, 1024, 2, 1);
    let finding_dormant = ResourceClassifier::classify_entry(
        target_path,
        &meta_old,
        1,
        5,
        1000,
        &[],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(
        finding_dormant.lifecycle.state,
        LifecycleState::DormantTransient
    );
}

#[test]
fn test_phase13_resource_accounting_accuracy() {
    let policy = GuardianPolicy::new();
    let capabilities = PlatformCapabilities::unknown();
    let filter = DiscoveryFilter::default();

    // Case 1: Multi-link file (hard link count 3) must contribute 0 unique bytes
    let multi_link_meta = make_test_meta(1000, 10_000, 20, 3);
    assert!(multi_link_meta.storage.is_multi_link);
    assert_eq!(multi_link_meta.storage.unique_bytes, 0);

    let entries_multi = vec![(
        PathBuf::from("/home/user/project/target/debug/lib1.a"),
        multi_link_meta,
        1,
        100,
    )];
    let ctx_multi = DiscoveryContext::new(
        vec![PathBuf::from("/home/user/project")],
        &filter,
        1000,
        &[],
        capabilities.clone(),
    );
    let report_multi =
        DiscoveryEngine::evaluate_findings(&entries_multi, &ctx_multi, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");
    assert_eq!(report_multi.summary.reclaimable_bytes_estimate, 0);

    // Case 2: Sparse file (apparent bytes 10MB, allocated 4KB) must contribute physical allocated bytes
    let sparse_meta = make_test_meta(1000, 10_485_760, 8, 1);
    assert!(sparse_meta.storage.is_sparse);
    assert_eq!(sparse_meta.storage.allocated_bytes, 4096);

    let entries_sparse = vec![(
        PathBuf::from("/home/user/project/target/debug/sparse.bin"),
        sparse_meta,
        1,
        200,
    )];
    let report_sparse =
        DiscoveryEngine::evaluate_findings(&entries_sparse, &ctx_multi, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");
    assert_eq!(report_sparse.summary.reclaimable_bytes_estimate, 4096);

    // Case 3: Duplicate inode visited twice must be counted only once
    let normal_meta = make_test_meta(1000, 5000, 10, 1);
    let entries_dup = vec![
        (
            PathBuf::from("/home/user/project/target/debug/a.o"),
            normal_meta.clone(),
            1,
            300,
        ),
        (
            PathBuf::from("/home/user/project/target/debug/b.o"),
            normal_meta,
            1,
            300,
        ),
    ];
    let report_dup =
        DiscoveryEngine::evaluate_findings(&entries_dup, &ctx_multi, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");
    assert_eq!(report_dup.summary.total_findings, 2);
    assert_eq!(report_dup.summary.reclaimable_bytes_estimate, 5000);
}

#[test]
fn test_phase14_evidence_quality_and_process_attribution() {
    let policy = GuardianPolicy::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // 1. Direct path association in process cmdline yields Active with Direct attribution
    let proc_direct = ProcessCandidate {
        identity: ProcessIdentity {
            pid: 5120,
            ppid: 1,
            real_uid: 1000,
            name: "python3".to_string(),
            executable: Some(PathBuf::from("/usr/bin/python3")),
            cmdline: vec![
                "python3".to_string(),
                "/home/user/myproject/venv/bin/activate_this.py".to_string(),
            ],
            start_time_ticks: 1000,
            tty_nr: 0,
        },
        state: ProcessState::Running,
        memory: MemoryMeasurement::new(20_000_000, None, None, None),
        is_reparented_to_init: false,
        is_abandoned: false,
        associated_agent: None,
    };
    let venv_meta = make_test_meta(now - 7200, 1024, 2, 1);
    let finding_direct = ResourceClassifier::classify_entry(
        Path::new("/home/user/myproject/venv"),
        &venv_meta,
        1,
        101,
        1000,
        &[proc_direct],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(finding_direct.lifecycle.state, LifecycleState::Active);
    assert_eq!(
        finding_direct.lifecycle.attribution,
        ProcessAttribution::Direct
    );
    assert_eq!(finding_direct.confidence, ConfidenceLevel::HighConfidence);
    assert!(finding_direct
        .lifecycle
        .reasoning
        .contains("actively operating on this path"));

    // 2. Generic python runtime on host without path correlation must NOT mark unrelated venv as Active
    let proc_generic_python = ProcessCandidate {
        identity: ProcessIdentity {
            pid: 7777,
            ppid: 1,
            real_uid: 1000,
            name: "python3".to_string(),
            executable: Some(PathBuf::from("/usr/bin/python3")),
            cmdline: vec![
                "python3".to_string(),
                "/usr/share/unrelated/system_daemon.py".to_string(),
            ],
            start_time_ticks: 2000,
            tty_nr: 0,
        },
        state: ProcessState::Running,
        memory: MemoryMeasurement::new(15_000_000, None, None, None),
        is_reparented_to_init: false,
        is_abandoned: false,
        associated_agent: None,
    };
    let finding_generic = ResourceClassifier::classify_entry(
        Path::new("/home/user/other_project/.venv"),
        &venv_meta,
        1,
        102,
        1000,
        &[proc_generic_python],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    // Preserves uncertainty: generic runtime match is Inconclusive, never Active!
    assert_eq!(finding_generic.lifecycle.state, LifecycleState::Unknown);
    assert_eq!(
        finding_generic.lifecycle.attribution,
        ProcessAttribution::Inconclusive
    );
    assert!(finding_generic
        .lifecycle
        .reasoning
        .contains("Generic runtime process 'python3'"));

    // 3. Ambiguous substring match (e.g. argument "--target" must not match resource path "target")
    let proc_flag = ProcessCandidate {
        identity: ProcessIdentity {
            pid: 8888,
            ppid: 1,
            real_uid: 1000,
            name: "cargo".to_string(),
            executable: Some(PathBuf::from("/usr/bin/cargo")),
            cmdline: vec![
                "cargo".to_string(),
                "build".to_string(),
                "--target".to_string(),
                "x86_64-unknown-linux-gnu".to_string(),
            ],
            start_time_ticks: 3000,
            tty_nr: 0,
        },
        state: ProcessState::Running,
        memory: MemoryMeasurement::new(50_000_000, None, None, None),
        is_reparented_to_init: false,
        is_abandoned: false,
        associated_agent: None,
    };
    // Testing path "target" against "--target" flag - must not match as a direct path argument!
    let target_meta = make_test_meta(now - 7200, 4096, 8, 1);
    let finding_flag = ResourceClassifier::classify_entry(
        Path::new("/home/user/rust_project/target"),
        &target_meta,
        1,
        103,
        1000,
        &[proc_flag],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    // Since cmdline does not reference "/home/user/rust_project/target", it is Inferred, not Direct!
    assert_eq!(finding_flag.lifecycle.state, LifecycleState::Active);
    assert_eq!(
        finding_flag.lifecycle.attribution,
        ProcessAttribution::Inferred
    );
    assert_eq!(
        finding_flag.lifecycle.confidence,
        ConfidenceLevel::MediumConfidence
    );

    // 4. Inaccessible process telemetry preserves uncertainty (Unknown + Unavailable attribution)
    let mut restricted_caps = PlatformCapabilities::unknown();
    restricted_caps.process_enumeration = CapabilityStatus::PermissionRestricted;
    let finding_restricted = ResourceClassifier::classify_entry_with_capabilities(
        Path::new("/home/user/project/target/debug/app"),
        &target_meta,
        1,
        104,
        1000,
        &[],
        Some(&restricted_caps),
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(finding_restricted.lifecycle.state, LifecycleState::Unknown);
    assert_eq!(
        finding_restricted.lifecycle.attribution,
        ProcessAttribution::Unavailable
    );
    assert!(finding_restricted
        .lifecycle
        .reasoning
        .contains("Process telemetry is inaccessible or restricted"));

    // 5. Unrecognized resource (default-unknown) older than 48h must remain Unknown, never DormantTransient
    let unknown_meta = make_test_meta(now - 3600 * 100, 2048, 4, 1);
    let finding_unknown = ResourceClassifier::classify_entry(
        Path::new("/home/user/unrecognized_directory_xyz/file.dat"),
        &unknown_meta,
        1,
        105,
        1000,
        &[],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(finding_unknown.lifecycle.state, LifecycleState::Unknown);
    assert_eq!(
        finding_unknown.protection_tier,
        ProtectionTier::NonActionable
    );

    // 6. Non-transient resource category (e.g. SessionState, UserDocument) older than 48h does not degrade to DormantTransient
    let session_meta = make_test_meta(now - 3600 * 200, 4096, 8, 1);
    let finding_session = ResourceClassifier::classify_entry(
        Path::new("/home/user/.claude/sessions/session-1.json"),
        &session_meta,
        1,
        106,
        1000,
        &[],
        &|t, tier, a, uid| policy.evaluate(t, tier, a, uid),
    );
    assert_eq!(finding_session.lifecycle.state, LifecycleState::Persistent);
}

#[test]
fn test_phase14_storage_accounting_integrity_and_hard_links() {
    let policy = GuardianPolicy::new();
    let capabilities = PlatformCapabilities::unknown();
    let filter = DiscoveryFilter::default();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // 1. Sparse file with 0 physical blocks allocated must contribute 0 bytes (not apparent size)
    let hollow_sparse = make_test_meta(1000, 10_000_000, 0, 1);
    assert!(hollow_sparse.storage.is_sparse);
    assert_eq!(hollow_sparse.storage.allocated_bytes, 0);

    let entries_hollow = vec![(
        PathBuf::from("/home/user/project/target/debug/hollow.bin"),
        hollow_sparse,
        1,
        501,
    )];
    let ctx = DiscoveryContext::new(
        vec![PathBuf::from("/home/user/project")],
        &filter,
        1000,
        &[],
        capabilities.clone(),
    );
    let report_hollow =
        DiscoveryEngine::evaluate_findings(&entries_hollow, &ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");
    assert_eq!(report_hollow.summary.reclaimable_bytes_estimate, 0);

    // 2. Multi-link file with 2 links where only ONE link is within scan boundary
    // External link exists outside scan scope -> unlinking the candidate link frees 0 physical blocks
    let multi_meta = make_test_meta(1000, 8192, 16, 2);
    let entries_partial_multi = vec![(
        PathBuf::from("/home/user/project/target/debug/link1.o"),
        multi_meta.clone(),
        1,
        502,
    )];
    let report_partial =
        DiscoveryEngine::evaluate_findings(&entries_partial_multi, &ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");
    assert_eq!(report_partial.summary.reclaimable_bytes_estimate, 0);

    // 3. Multi-link file where BOTH links are within scan boundary
    // All 2 references accounted for in this scan -> unlinking all candidate references releases physical blocks
    let entries_all_multi = vec![
        (
            PathBuf::from("/home/user/project/target/debug/link1.o"),
            multi_meta.clone(),
            1,
            503,
        ),
        (
            PathBuf::from("/home/user/project/target/debug/link2.o"),
            multi_meta,
            1,
            503,
        ),
    ];
    let report_all_multi =
        DiscoveryEngine::evaluate_findings(&entries_all_multi, &ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");
    assert_eq!(report_all_multi.summary.total_findings, 2);
    // Contributed exactly once (8192 bytes, not double-counted as 16384)
    assert_eq!(report_all_multi.summary.reclaimable_bytes_estimate, 8192);

    // 4. Directory entry (4096 bytes dentry) must not be counted in candidate file storage estimate
    let mut dir_meta = make_test_meta(1000, 4096, 8, 2);
    dir_meta.file_type = FileType::Directory;
    let file_meta = make_test_meta(1000, 2048, 4, 1);
    let entries_dir_and_file = vec![
        (
            PathBuf::from("/home/user/project/target/debug"),
            dir_meta,
            1,
            504,
        ),
        (
            PathBuf::from("/home/user/project/target/debug/output.bin"),
            file_meta,
            1,
            505,
        ),
    ];
    let report_dir =
        DiscoveryEngine::evaluate_findings(&entries_dir_and_file, &ctx, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");
    assert_eq!(report_dir.summary.total_findings, 2);
    // Only the regular file (2048 bytes) is counted, directory table (4096) is excluded from candidate storage
    assert_eq!(report_dir.summary.reclaimable_bytes_estimate, 2048);

    // 5. Active resource (held by running process) must contribute 0 bytes to candidate storage estimate
    let active_proc = ProcessCandidate {
        identity: ProcessIdentity {
            pid: 9191,
            ppid: 1,
            real_uid: 1000,
            name: "cargo".to_string(),
            executable: Some(PathBuf::from("/usr/bin/cargo")),
            cmdline: vec![
                "cargo".to_string(),
                "build".to_string(),
                "/home/user/project/target/debug/active.bin".to_string(),
            ],
            start_time_ticks: 1000,
            tty_nr: 0,
        },
        state: ProcessState::Running,
        memory: MemoryMeasurement::new(50_000_000, None, None, None),
        is_reparented_to_init: false,
        is_abandoned: false,
        associated_agent: None,
    };
    let active_meta = make_test_meta(now - 100, 65536, 128, 1);
    let entries_active = vec![(
        PathBuf::from("/home/user/project/target/debug/active.bin"),
        active_meta,
        1,
        506,
    )];
    let active_procs = [active_proc];
    let ctx_active = DiscoveryContext::new(
        vec![PathBuf::from("/home/user/project")],
        &filter,
        1000,
        &active_procs,
        capabilities,
    );
    let report_active =
        DiscoveryEngine::evaluate_findings(&entries_active, &ctx_active, &|t, tier, a, uid| {
            policy.evaluate(t, tier, a, uid)
        })
        .expect("Evaluation failed");
    assert_eq!(report_active.summary.active_lifecycle_count, 1);
    assert_eq!(report_active.summary.reclaimable_bytes_estimate, 0);
}
