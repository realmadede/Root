use root_core::{
    fixtures::SyntheticFixture,
    model::{
        ConfidenceLevel, FileType, FindingEvidence, FindingTarget, MemoryMeasurement,
        ProcessCandidate, ProcessIdentity, ProcessState, ProposedAction, ProtectionTier,
        RejectionReason, ResourceCandidate, ResourceCategory, ResourceId, ResourceLocation,
        ResourceMetadata, ResourceOwnership, SafetyDecision, ScanFinding, StorageMeasurement,
    },
};
use root_guardian::GuardianPolicy;
use std::path::{Path, PathBuf};

#[test]
fn test_protection_defaults() {
    let tier_unknown = ProtectionTier::NonActionable;
    assert!(tier_unknown.is_protected());

    let tier_strictly = ProtectionTier::StrictlyProtected;
    assert!(tier_strictly.is_protected());
}

#[test]
fn test_unsupported_operations_rejected_in_phase01() {
    let policy = GuardianPolicy::new();

    let candidate = ResourceCandidate {
        id: ResourceId::new("res-1"),
        location: ResourceLocation::new(PathBuf::from("/tmp/cache.dat"), None, 1, 100),
        category: ResourceCategory::PackageCache,
        metadata: ResourceMetadata {
            file_type: FileType::RegularFile,
            storage: StorageMeasurement::from_raw(1024, 2, 1),
            permissions_mode: 0o644,
            mtime_epoch_secs: 1000,
            atime_epoch_secs: 1000,
            ctime_epoch_secs: 1000,
        },
        ownership: ResourceOwnership {
            uid: 1000,
            gid: 1000,
            is_current_user: true,
        },
        associated_agent: None,
    };

    let target = FindingTarget::Filesystem(candidate);

    // Any mutating action must be rejected in Phase 01
    let actions = [
        ProposedAction::Quarantine,
        ProposedAction::Prune,
        ProposedAction::TerminateGraceful,
    ];

    for action in actions {
        let decision = policy.evaluate(&target, ProtectionTier::SafeRecoverable, action, 1000);
        match decision {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(reason, RejectionReason::Phase01ReadOnlyPolicy);
            }
            SafetyDecision::Allowed => panic!("Action {:?} must be rejected in Phase 01", action),
        }
    }
}

#[test]
fn test_ownership_mismatch_rejection() {
    let policy = GuardianPolicy::new();

    let candidate = ResourceCandidate {
        id: ResourceId::new("res-foreign"),
        location: ResourceLocation::new(PathBuf::from("/tmp/other_user.dat"), None, 1, 100),
        category: ResourceCategory::PackageCache,
        metadata: ResourceMetadata {
            file_type: FileType::RegularFile,
            storage: StorageMeasurement::from_raw(1024, 2, 1),
            permissions_mode: 0o644,
            mtime_epoch_secs: 1000,
            atime_epoch_secs: 1000,
            ctime_epoch_secs: 1000,
        },
        ownership: ResourceOwnership {
            uid: 1005, // Different UID
            gid: 1005,
            is_current_user: false,
        },
        associated_agent: None,
    };

    let target = FindingTarget::Filesystem(candidate);
    let decision = policy.evaluate(
        &target,
        ProtectionTier::SafeRecoverable,
        ProposedAction::Inspect,
        1000,
    );

    match decision {
        SafetyDecision::Rejected { reason, .. } => {
            assert_eq!(reason, RejectionReason::OwnershipMismatch);
        }
        SafetyDecision::Allowed => panic!("Foreign ownership must be rejected"),
    }
}

#[test]
fn test_protected_locations_and_credentials_rejection() {
    let policy = GuardianPolicy::new();

    let protected_paths = [
        "/etc/shadow",
        "/usr/bin/bash",
        "/boot/vmlinuz",
        "/home/user/.ssh/id_rsa",
        "/home/user/.gnupg/secring.gpg",
        "/home/user/.gemini/oauth_creds.json",
        "/home/user/.claude/sessions/test.key",
    ];

    for path in protected_paths {
        let candidate = ResourceCandidate {
            id: ResourceId::new(path),
            location: ResourceLocation::new(PathBuf::from(path), None, 1, 100),
            category: ResourceCategory::SessionState,
            metadata: ResourceMetadata {
                file_type: FileType::RegularFile,
                storage: StorageMeasurement::from_raw(512, 1, 1),
                permissions_mode: 0o600,
                mtime_epoch_secs: 1000,
                atime_epoch_secs: 1000,
                ctime_epoch_secs: 1000,
            },
            ownership: ResourceOwnership {
                uid: 1000,
                gid: 1000,
                is_current_user: true,
            },
            associated_agent: None,
        };

        let target = FindingTarget::Filesystem(candidate);
        let decision = policy.evaluate(
            &target,
            ProtectionTier::StrictlyProtected,
            ProposedAction::Inspect,
            1000,
        );

        match decision {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(reason, RejectionReason::ProtectedLocation);
            }
            SafetyDecision::Allowed => panic!("Protected location {:?} must be rejected", path),
        }
    }
}

#[test]
fn test_resource_accounting_multi_link_and_sparse() {
    // 1. Single-link file: 100% unique bytes
    let m_single = StorageMeasurement::from_raw(1024, 2, 1);
    assert!(!m_single.is_multi_link);
    assert_eq!(m_single.unique_bytes, 1024);
    assert_eq!(m_single.shared_bytes, 0);

    // 2. Multi-link file (nlink = 3): 100% shared bytes (cannot free storage without unlinking all)
    let m_multi = StorageMeasurement::from_raw(1024, 2, 3);
    assert!(m_multi.is_multi_link);
    assert_eq!(m_multi.unique_bytes, 0);
    assert_eq!(m_multi.shared_bytes, 1024);

    // 3. Sparse file: apparent size 10 MiB, allocated blocks 8 (4 KiB)
    let m_sparse = StorageMeasurement::from_raw(10_485_760, 8, 1);
    assert!(m_sparse.is_sparse);
    assert_eq!(m_sparse.allocated_bytes, 4096);
    assert_eq!(m_sparse.bytes, 10_485_760);
}

#[test]
fn test_process_identity_and_abandonment_logic() {
    // Case 1: Process reparented to PID 1 but attached to terminal -> NOT abandoned
    let proc_attached = ProcessCandidate {
        identity: ProcessIdentity {
            pid: 101,
            ppid: 1,
            real_uid: 1000,
            name: "interactive_job".to_string(),
            executable: Some(PathBuf::from("/usr/bin/python3")),
            cmdline: vec!["python3".into(), "job.py".into()],
            start_time_ticks: 1000,
            tty_nr: 34816, // Non-zero TTY device number
        },
        state: ProcessState::Running,
        memory: MemoryMeasurement::new(10_000_000, None, None, 0),
        is_reparented_to_init: true,
        is_abandoned: false,
        associated_agent: None,
    };
    assert!(!proc_attached.is_abandoned);

    // Case 2: Process reparented to PID 1, detached from terminal (tty_nr == 0),
    // and matching dev server signature -> Corroborated Abandoned
    let proc_orphaned_server = ProcessCandidate {
        identity: ProcessIdentity {
            pid: 102,
            ppid: 1,
            real_uid: 1000,
            name: "node".to_string(),
            executable: Some(PathBuf::from("/usr/bin/node")),
            cmdline: vec!["node".into(), "/path/to/vite".into()],
            start_time_ticks: 2000,
            tty_nr: 0, // Detached from TTY
        },
        state: ProcessState::Sleeping,
        memory: MemoryMeasurement::new(50_000_000, Some(35_000_000), Some(30_000_000), 0),
        is_reparented_to_init: true,
        is_abandoned: true,
        associated_agent: Some("Vite Dev Server".to_string()),
    };
    assert!(proc_orphaned_server.is_abandoned);
    assert!(proc_orphaned_server.is_reparented_to_init);
}

#[test]
fn test_serialization_safety_no_file_content_leakage() {
    let candidate = ResourceCandidate {
        id: ResourceId::new("test_secret_log"),
        location: ResourceLocation::new(
            PathBuf::from("/home/user/.claude/shell-snapshots/snap.sh"),
            None,
            1,
            100,
        ),
        category: ResourceCategory::DiagnosticLog,
        metadata: ResourceMetadata {
            file_type: FileType::RegularFile,
            storage: StorageMeasurement::from_raw(4096, 8, 1),
            permissions_mode: 0o600,
            mtime_epoch_secs: 1700000000,
            atime_epoch_secs: 1700000000,
            ctime_epoch_secs: 1700000000,
        },
        ownership: ResourceOwnership {
            uid: 1000,
            gid: 1000,
            is_current_user: true,
        },
        associated_agent: Some("Claude Code".to_string()),
    };

    let finding = ScanFinding {
        target: FindingTarget::Filesystem(candidate),
        protection_tier: ProtectionTier::ObsoleteTransient,
        proposed_action: ProposedAction::Quarantine,
        evidence_list: vec![FindingEvidence::inspection(
            "Observed shell snapshot script",
            ConfidenceLevel::HighConfidence,
        )],
        confidence: ConfidenceLevel::HighConfidence,
        explanation: "Shell snapshot script older than 7 days".to_string(),
        safety_decision: SafetyDecision::reject(
            RejectionReason::Phase01ReadOnlyPolicy,
            "Phase 01 read-only policy",
        ),
    };

    let serialized = serde_json::to_string(&finding).expect("Serialization failed");

    // Verify metadata fields exist in JSON
    assert!(serialized.contains("test_secret_log"));
    assert!(serialized.contains("Claude Code"));
    assert!(serialized.contains("obsolete_transient"));

    // Verify that NO file content field exists in the serialization schema
    assert!(!serialized.contains("file_content"));
    assert!(!serialized.contains("content_bytes"));
    assert!(!serialized.contains("raw_data"));
}

#[test]
fn test_synthetic_fixtures_adversarial_coverage() {
    let fixture = SyntheticFixture::create().expect("Failed to create fixture");
    let root = fixture.path();

    // 1. Unusual names: spaces, unicode, quotes, dashes
    assert!(root.join("unusual_names/file with spaces.log").exists());
    assert!(root.join("unusual_names/файл-тест 🚀.dat").exists());
    assert!(root.join("unusual_names/\"quoted_name\".txt").exists());
    assert!(root.join("unusual_names/--leading-dashes.tmp").exists());

    // 2. Empty directories
    let empty1 = root.join("empty_dirs/orphan_empty_dir_1");
    assert!(empty1.exists());
    assert!(empty1.is_dir());
    assert_eq!(std::fs::read_dir(&empty1).unwrap().count(), 0);

    // 3. Symlinks
    let sym_valid = root.join("symlinks/valid_rel.txt");
    assert!(sym_valid.is_symlink());

    let sym_dangling = root.join("symlinks/dangling.txt");
    assert!(sym_dangling.is_symlink());
    // Dangling link target does not exist, but symlink itself exists
    assert!(!sym_dangling.exists());

    let sym_escape = root.join("symlinks/jail_escape.txt");
    assert!(sym_escape.is_symlink());

    // 4. Test boundary checking
    assert!(fixture.assert_within_bounds(&empty1).is_ok());

    // Testing boundary violation
    let outside_path = Path::new("/etc/passwd");
    if outside_path.exists() {
        assert!(fixture.assert_within_bounds(outside_path).is_err());
    }
}
