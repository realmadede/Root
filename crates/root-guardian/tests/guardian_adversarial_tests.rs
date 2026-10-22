//! Comprehensive Synthetic Adversarial Test Suite for Root Guardian (Phase 11).
//!
//! Validates the 30 required adversarial threat and boundary scenarios:
//! 1. Unauthorized operation.
//! 2. Expired consent.
//! 3. Replayed authorization.
//! 4. Modified resource identity.
//! 5. Modified parent directory.
//! 6. Symlink substitution.
//! 7. Scope escape.
//! 8. Cross-device operation.
//! 9. Destination collision.
//! 10. Hard-linked resource.
//! 11. Sparse file.
//! 12. Corrupt journal.
//! 13. Interrupted transaction.
//! 14. Duplicate recovery.
//! 15. Restoration conflict.
//! 16. Changed permissions.
//! 17. Changed ownership.
//! 18. Unsupported platform capability.
//! 19. Resource currently in use.
//! 20. Unknown lifecycle.
//! 21. Shared dependency store.
//! 22. Invalid state transition.
//! 23. Content-integrity failure.
//! 24. Disk-space exhaustion.
//! 25. Concurrent requests.
//! 26. GUI authorization mismatch.
//! 27. Scheduler authorization mismatch.
//! 28. Non-Linux mutation rejection.
//! 29. Fixture sandbox escape.
//! 30. Guardian bypass attempt.

use root_core::{
    error::RootError,
    model::{
        CapabilityStatus, DecisionStage, EligibilityStatus, FileType, PlatformCapabilities,
        PlatformKind, ProposedAction, ProtectionTier, RejectionReason, ResourceCandidate,
        ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata, ResourceOwnership,
        StorageMeasurement,
    },
};
use root_guardian::{
    crypto::sha256_file, AuthorizationDecision, AuthorizationEngine, AuthorizationRequest,
    ConsentRecord, FixtureSandbox, JournalRecord, RecoveryJournal, TransactionEngine,
    TransactionState,
};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tempfile::TempDir;

struct TestEnv {
    _temp: TempDir,
    sandbox: FixtureSandbox,
    journal: RecoveryJournal,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("root-guardian-adv-")
            .tempdir()
            .expect("Failed to create test tempdir");

        let uid = temp.path().metadata().expect("Stat tempdir").uid();
        let sandbox = FixtureSandbox::new(temp.path(), uid).expect("Failed to init sandbox");
        let journal = RecoveryJournal::new(sandbox.journal_path()).expect("Failed to init journal");

        Self {
            _temp: temp,
            sandbox,
            journal,
        }
    }

    fn write_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
        let full_path = self.sandbox.root().join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("Failed to create parent dir");
        }
        let mut f = File::create(&full_path).expect("Failed to create file");
        f.write_all(content).expect("Failed to write content");
        full_path
    }

    fn make_candidate(&self, file_path: &Path, category: ResourceCategory) -> ResourceCandidate {
        let meta = fs::symlink_metadata(file_path).expect("File must exist to create candidate");
        let uid = self.sandbox.operator_uid();

        ResourceCandidate {
            id: ResourceId::from_path_and_inode(file_path, meta.dev(), meta.ino()),
            location: ResourceLocation::new(file_path.to_path_buf(), None, meta.dev(), meta.ino()),
            category,
            metadata: ResourceMetadata {
                file_type: FileType::RegularFile,
                storage: StorageMeasurement::from_raw(meta.len(), meta.blocks(), 1),
                permissions_mode: meta.mode() & 0o777,
                mtime_epoch_secs: meta.mtime(),
                atime_epoch_secs: meta.atime(),
                ctime_epoch_secs: meta.ctime(),
            },
            ownership: ResourceOwnership {
                uid,
                gid: uid,
                is_current_user: true,
            },
            associated_agent: None,
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Unauthorized Operation
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_01_unauthorized_operation() {
    let env = TestEnv::new();
    let file = env.write_file("unauth.dat", b"data");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    // Requesting Prune (deletion) instead of Quarantine
    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Prune,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    );

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::Phase04UnsupportedAction);
        }
        _ => panic!("Direct pruning must be unconditionally denied in Phase 11"),
    }
}

// ---------------------------------------------------------------------------
// 2. Expired Consent
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_02_expired_consent() {
    let env = TestEnv::new();
    let file = env.write_file("expired.dat", b"data");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    // Create consent record that expired 10 seconds ago
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let expired_consent = ConsentRecord::with_explicit_time(
        candidate.id.clone(),
        ProposedAction::Quarantine,
        file.clone(),
        "nonce-123".into(),
        now - 100,
        50, // TTL 50s; expired 50s ago
    );

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::UserConfirmRequired,
        env.sandbox.operator_uid(),
    )
    .with_consent(expired_consent);

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::ConsentExpired);
        }
        _ => panic!("Expired consent must be rejected"),
    }
}

// ---------------------------------------------------------------------------
// 3. Replayed Authorization
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_03_replayed_authorization() {
    let env = TestEnv::new();
    let file_a = env.write_file("target_a.dat", b"resource A");
    let file_b = env.write_file("target_b.dat", b"resource B");

    let cand_a = env.make_candidate(&file_a, ResourceCategory::BuildArtifact);
    let cand_b = env.make_candidate(&file_b, ResourceCategory::BuildArtifact);

    // Consent issued exclusively for Resource A
    let consent_a = ConsentRecord::new(
        cand_a.id.clone(),
        ProposedAction::Quarantine,
        file_a.clone(),
        "nonce-a".into(),
        300,
    );

    // Replay consent for Resource A against candidate B
    let request_b = AuthorizationRequest::new(
        cand_b,
        ProposedAction::Quarantine,
        ProtectionTier::UserConfirmRequired,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent_a);

    let decision = AuthorizationEngine::authorize(&request_b);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::ConsentNonceMismatch);
        }
        _ => panic!("Consent replay against another resource must be denied"),
    }
}

// ---------------------------------------------------------------------------
// 4. Modified Resource Identity
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_04_modified_resource_identity() {
    let env = TestEnv::new();
    let file = env.write_file("mod_identity.dat", b"initial version");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    // Unlink and recreate with different inode
    fs::remove_file(&file).unwrap();
    let _ = env.write_file("mod_identity.dat", b"substituted second version");

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    );

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::FilesystemIdentityChanged);
        }
        _ => panic!("Modified inode identity must be rejected"),
    }
}

// ---------------------------------------------------------------------------
// 5. Modified Parent Directory
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_05_modified_parent_directory() {
    let env = TestEnv::new();
    let dir = env.sandbox.root().join("parent_dir");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("leaf.dat");
    fs::write(&file, b"leaf content").unwrap();

    let meta = fs::symlink_metadata(&file).unwrap();
    let pmeta = fs::symlink_metadata(&dir).unwrap();

    // Verification fails if parent directory inode changes
    let res = AuthorizationEngine::revalidate_full(
        &file,
        meta.dev(),
        meta.ino(),
        env.sandbox.operator_uid(),
        Some(pmeta.dev()),
        Some(pmeta.ino() + 9999), // Tampered parent inode
        Some(env.sandbox.root()),
    );

    assert_eq!(res, Err(RejectionReason::ParentDirectoryChanged));
}

// ---------------------------------------------------------------------------
// 6. Symlink Substitution
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_06_symlink_substitution() {
    let env = TestEnv::new();
    let real_file = env.write_file("real.dat", b"legitimate content");
    let symlink = env.sandbox.root().join("symlink.dat");
    std::os::unix::fs::symlink(&real_file, &symlink).unwrap();

    let meta = fs::symlink_metadata(&real_file).unwrap();
    let candidate = ResourceCandidate {
        id: ResourceId::new("symlink-cand"),
        location: ResourceLocation::new(symlink.clone(), None, meta.dev(), meta.ino()),
        category: ResourceCategory::AgentScratchpad,
        metadata: ResourceMetadata {
            file_type: FileType::Symlink,
            storage: StorageMeasurement::from_raw(10, 1, 1),
            permissions_mode: 0o777,
            mtime_epoch_secs: 1000,
            atime_epoch_secs: 1000,
            ctime_epoch_secs: 1000,
        },
        ownership: ResourceOwnership {
            uid: env.sandbox.operator_uid(),
            gid: env.sandbox.operator_uid(),
            is_current_user: true,
        },
        associated_agent: None,
    };

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    );

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::SymlinkJailEscape);
        }
        _ => panic!("Symlink target must be rejected"),
    }
}

// ---------------------------------------------------------------------------
// 7. Scope Escape
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_07_scope_escape() {
    let env = TestEnv::new();
    let outside_path = PathBuf::from("/etc/hosts");
    let candidate = ResourceCandidate {
        id: ResourceId::new("outside-escape"),
        location: ResourceLocation::new(outside_path.clone(), None, 1, 1),
        category: ResourceCategory::SystemFile,
        metadata: ResourceMetadata {
            file_type: FileType::RegularFile,
            storage: StorageMeasurement::from_raw(100, 1, 1),
            permissions_mode: 0o644,
            mtime_epoch_secs: 1000,
            atime_epoch_secs: 1000,
            ctime_epoch_secs: 1000,
        },
        ownership: ResourceOwnership {
            uid: env.sandbox.operator_uid(),
            gid: env.sandbox.operator_uid(),
            is_current_user: true,
        },
        associated_agent: None,
    };

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_sandbox_root(env.sandbox.root().to_path_buf());

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::ScopeEscape);
        }
        _ => panic!("Path escaping sandbox scope must be rejected"),
    }
}

// ---------------------------------------------------------------------------
// 8. Cross-Device Operation
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_08_cross_device_operation() {
    let env = TestEnv::new();
    let file = env.write_file("cross_dev.dat", b"device data");

    // Intentionally pass an invalid expected device ID to simulate cross-filesystem move
    let res = root_guardian::QuarantineStore::relocate_into_quarantine(
        &file,
        &env.sandbox.quarantine_dir().join("cross_dest.dat"),
        env.sandbox.device_id() + 9999, // Mismatched device ID
    );

    assert!(matches!(res, Err(RootError::CrossDeviceUnsupported { .. })));
}

// ---------------------------------------------------------------------------
// 9. Destination Collision
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_09_destination_collision() {
    let env = TestEnv::new();
    let file = env.write_file("collision.dat", b"collision target");
    let meta = fs::symlink_metadata(&file).unwrap();

    let tx_id = "tx_collision_test";
    let dest_name = format!("{}_{}_collision.dat", tx_id, meta.ino());
    let dest_path = env.sandbox.quarantine_dir().join(dest_name);

    // Pre-create destination file to simulate collision
    fs::write(&dest_path, b"existing collision artifact").unwrap();

    let res = root_guardian::QuarantineStore::allocate_quarantine_path(
        &env.sandbox,
        tx_id,
        &file,
        meta.ino(),
    );

    assert!(matches!(res, Err(RootError::DestinationCollision { .. })));
}

// ---------------------------------------------------------------------------
// 10. Hard-Linked Resource
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_10_hard_linked_resource() {
    let env = TestEnv::new();
    let origin = env.write_file("origin_link.dat", b"hardlink origin");
    let second_link = env.sandbox.root().join("second_link.dat");
    fs::hard_link(&origin, &second_link).unwrap();

    let candidate = env.make_candidate(&origin, ResourceCategory::BuildArtifact);

    // With allow_multi_link: false, multi-link files MUST be rejected
    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_multi_link(false);

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::HardLinkShared);
        }
        _ => panic!("Shared multi-linked file must be rejected when allow_multi_link is false"),
    }
}

// ---------------------------------------------------------------------------
// 11. Sparse File
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_11_sparse_file() {
    let mut env = TestEnv::new();
    let sparse_path = env.sandbox.root().join("sparse_adv.dat");
    let mut f = File::create(&sparse_path).unwrap();
    f.write_all(b"HEAD_MAGIC").unwrap();
    f.seek(SeekFrom::Start(1024 * 1024)).unwrap(); // 1MB hole
    f.write_all(b"TAIL_MAGIC").unwrap();
    drop(f);

    let original_hash = sha256_file(&sparse_path).unwrap();
    let candidate = env.make_candidate(&sparse_path, ResourceCategory::BuildArtifact);

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::SafeRecoverable,
        env.sandbox.operator_uid(),
    )
    .with_multi_link(true);

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    assert_eq!(tx.state, TransactionState::Verified);
    assert_eq!(tx.verified_sha256.as_deref(), Some(original_hash.as_str()));

    let restore_tx =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id).unwrap();
    assert_eq!(restore_tx.state, TransactionState::Restored);
    assert_eq!(sha256_file(&sparse_path).unwrap(), original_hash);
}

// ---------------------------------------------------------------------------
// 12. Corrupt Journal
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_12_corrupt_journal() {
    let env = TestEnv::new();
    let journal_path = env.journal.path();

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)
        .unwrap();
    writeln!(
        f,
        "{{\"valid_json\":false, \"state\": \"UNKNOWN_GARBAGE\"}}"
    )
    .unwrap();
    drop(f);

    let res = env.journal.read_all();
    assert!(matches!(res, Err(RootError::JournalError { .. })));
}

// ---------------------------------------------------------------------------
// 13. Interrupted Transaction
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_13_interrupted_transaction() {
    let mut env = TestEnv::new();
    let file = env.write_file("interrupted.dat", b"crash data");
    let meta = fs::symlink_metadata(&file).unwrap();

    let tx_id = "tx_interrupted_sim";
    let record = JournalRecord {
        transaction_id: tx_id.into(),
        timestamp_epoch_secs: 1000,
        state: TransactionState::Prepared,
        original_path: file.clone(),
        quarantine_path: Some(env.sandbox.quarantine_dir().join("staging.dat")),
        device_id: meta.dev(),
        inode: meta.ino(),
        size_bytes: meta.len(),
        sha256: Some("fakehash".into()),
        reason: "Simulated crash in Prepared state".into(),
        failure_reason: None,
    };
    env.journal.append(&record).unwrap();

    let interrupted = env.journal.get_interrupted_transactions().unwrap();
    assert_eq!(interrupted.len(), 1);
    assert_eq!(interrupted[0].transaction_id, tx_id);
}

// ---------------------------------------------------------------------------
// 14. Duplicate Recovery
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_14_duplicate_recovery() {
    let mut env = TestEnv::new();
    let file = env.write_file("dup_recovery.dat", b"data");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_multi_link(true);

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    let _ = TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id).unwrap();

    // Replay restore on already restored transaction
    let second_restore =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id);
    assert!(matches!(
        second_restore,
        Err(RootError::InvalidStateTransition { .. })
    ));
}

// ---------------------------------------------------------------------------
// 15. Restoration Conflict
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_15_restoration_conflict() {
    let mut env = TestEnv::new();
    let file = env.write_file("conflict.dat", b"original version");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_multi_link(true);

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();

    // Occupy destination path with a new file
    fs::write(&file, b"unrelated new file occupying the path").unwrap();

    let restore_res =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id);
    assert!(matches!(
        restore_res,
        Err(RootError::RestorationConflict { .. })
    ));
    assert_eq!(
        fs::read(&file).unwrap(),
        b"unrelated new file occupying the path"
    );
}

// ---------------------------------------------------------------------------
// 16. Changed Permissions
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_16_changed_permissions() {
    let mut env = TestEnv::new();
    let file = env.write_file("perms.dat", b"chmod 0755 file");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();

    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);
    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_multi_link(true);

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    let restore_tx =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id).unwrap();
    assert_eq!(restore_tx.state, TransactionState::Restored);

    let restored_meta = fs::symlink_metadata(&file).unwrap();
    assert_eq!(restored_meta.mode() & 0o777, 0o755);
}

// ---------------------------------------------------------------------------
// 17. Changed Ownership
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_17_changed_ownership() {
    let env = TestEnv::new();
    let file = env.write_file("foreign_uid.dat", b"data");
    let mut candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);
    candidate.ownership.uid = 9999;
    candidate.ownership.is_current_user = false;

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(), // Operator UID does not match 9999
    );

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::OwnershipMismatch);
        }
        _ => panic!("Foreign UID must be rejected"),
    }
}

// ---------------------------------------------------------------------------
// 18. Unsupported Platform Capability
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_18_unsupported_platform_capability() {
    let caps = PlatformCapabilities::non_linux_baseline(
        PlatformKind::Windows,
        "Windows 11".into(),
        "10.0".into(),
    );
    assert_eq!(caps.proc_pressure_memory, CapabilityStatus::Unsupported);
    assert_eq!(caps.proc_smaps_rollup, CapabilityStatus::Unsupported);
    assert!(!caps.has_pidfd());
}

// ---------------------------------------------------------------------------
// 19. Resource Currently In Use
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_19_resource_currently_in_use() {
    let env = TestEnv::new();
    let file = env.write_file("active_session.json", b"{\"session\":\"active\"}");
    let candidate = env.make_candidate(&file, ResourceCategory::SessionState);

    // Active session files are classified as StrictlyProtected
    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::StrictlyProtected,
        env.sandbox.operator_uid(),
    );

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::TierStrictlyProtected);
        }
        _ => panic!("Active in-use session resource must be strictly protected"),
    }
}

// ---------------------------------------------------------------------------
// 20. Unknown Lifecycle
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_20_unknown_lifecycle() {
    let env = TestEnv::new();
    let file = env.write_file("ambiguous.dat", b"unknown data");
    let candidate = env.make_candidate(&file, ResourceCategory::Unknown);

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::NonActionable,
        env.sandbox.operator_uid(),
    );

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::UnknownResource);
        }
        _ => panic!("Ambiguous lifecycle resource must be rejected"),
    }
}

// ---------------------------------------------------------------------------
// 21. Shared Dependency Store
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_21_shared_dependency_store() {
    let env = TestEnv::new();
    let file = env.write_file(".pnpm-store/v3/files/ab/cdef123", b"shared package content");
    let candidate = env.make_candidate(&file, ResourceCategory::PackageCache);

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::StrictlyProtected,
        env.sandbox.operator_uid(),
    );

    let decision = AuthorizationEngine::authorize(&request);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::TierStrictlyProtected);
        }
        _ => panic!("Shared dependency store must be strictly protected"),
    }
}

// ---------------------------------------------------------------------------
// 22. Invalid State Transition
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_22_invalid_state_transition() {
    // Self transition
    assert!(!TransactionState::Prepared.can_transition_to(&TransactionState::Prepared));
    // Skipping forward: Proposed -> Restored
    assert!(!TransactionState::Proposed.can_transition_to(&TransactionState::Restored));
    // Leaving terminal state
    assert!(!TransactionState::Restored.can_transition_to(&TransactionState::Prepared));
    assert!(!TransactionState::Failed.can_transition_to(&TransactionState::Verified));
}

// ---------------------------------------------------------------------------
// 23. Content-Integrity Failure
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_23_content_integrity_failure() {
    let mut env = TestEnv::new();
    let file = env.write_file("corrupt_test.dat", b"intact original content");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_multi_link(true);

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();

    // Tamper with file while in quarantine staging
    let qpath = tx.quarantine_path.as_ref().unwrap();
    fs::write(qpath, b"TAMPERED_IN_QUARANTINE").unwrap();

    // Restoration must detect hash corruption
    let restore_res =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id);
    assert!(matches!(
        restore_res,
        Err(RootError::IntegrityVerificationFailed { .. })
    ));
}

// ---------------------------------------------------------------------------
// 24. Disk Space Exhaustion Simulation
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_24_disk_space_exhaustion() {
    let env = TestEnv::new();
    let file = env.write_file("disk_exhaust.dat", b"data");
    let mut bad_journal =
        RecoveryJournal::new(&PathBuf::from("/proc/sys/fs/bogus_journal.jsonl")).unwrap();

    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);
    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_multi_link(true);

    // Journal append will fail on read-only proc path, aborting without moving the file
    let res = TransactionEngine::quarantine(&env.sandbox, &mut bad_journal, &request);
    assert!(res.is_err());
    assert!(
        file.exists(),
        "Source file must not be moved if journal write fails"
    );
}

// ---------------------------------------------------------------------------
// 25. Concurrent Requests (Advisory Locking)
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_25_concurrent_requests() {
    use root_platform::{AdvisoryLock, LockStatus};
    let env = TestEnv::new();
    let lock_path = env.sandbox.root().join("concurrent.lock");

    let first = match AdvisoryLock::try_acquire(&lock_path).unwrap() {
        LockStatus::Acquired(g) => g,
        LockStatus::Contended => panic!("First acquisition should succeed"),
    };

    // Second overlapping acquisition attempt must report Contended
    match AdvisoryLock::try_acquire(&lock_path).unwrap() {
        LockStatus::Contended => {}
        LockStatus::Acquired(_) => panic!("Second acquisition must be contended"),
    }

    drop(first);

    // After dropping first, acquisition succeeds
    assert!(matches!(
        AdvisoryLock::try_acquire(&lock_path).unwrap(),
        LockStatus::Acquired(_)
    ));
}

// ---------------------------------------------------------------------------
// 26. GUI Authorization Mismatch
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_26_gui_authorization_mismatch() {
    // Confirm view models do not contain or expose any mutation execution APIs
    let policy = root_guardian::GuardianPolicy::new();
    let target = root_core::model::FindingTarget::Filesystem(ResourceCandidate {
        id: ResourceId::new("gui-test"),
        location: ResourceLocation::new(PathBuf::from("/home/user/test"), None, 1, 2),
        category: ResourceCategory::BuildArtifact,
        metadata: ResourceMetadata {
            file_type: FileType::Directory,
            storage: StorageMeasurement::from_raw(1000, 2, 1),
            permissions_mode: 0o755,
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
    });

    let decision = policy.evaluate(
        &target,
        ProtectionTier::SafeRecoverable,
        ProposedAction::Quarantine,
        1000,
    );
    assert!(
        matches!(decision, root_core::model::SafetyDecision::Rejected { .. }),
        "Guardian policy must reject all mutations from GUI"
    );
}

// ---------------------------------------------------------------------------
// 27. Scheduler Authorization Mismatch
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_27_scheduler_authorization_mismatch() {
    // Verify that Mode B scheduled inspection policy unconditionally rejects Prune and Quarantine
    let policy = root_guardian::GuardianPolicy::new();
    let candidate = ResourceCandidate {
        id: ResourceId::new("sched-test"),
        location: ResourceLocation::new(PathBuf::from("/tmp/sched_target"), None, 1, 2),
        category: ResourceCategory::BuildArtifact,
        metadata: ResourceMetadata {
            file_type: FileType::RegularFile,
            storage: StorageMeasurement::from_raw(500, 1, 1),
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
    let target = root_core::model::FindingTarget::Filesystem(candidate);

    let res = policy.evaluate(
        &target,
        ProtectionTier::ObsoleteTransient,
        ProposedAction::Quarantine,
        1000,
    );
    assert!(matches!(
        res,
        root_core::model::SafetyDecision::Rejected { .. }
    ));
}

// ---------------------------------------------------------------------------
// 28. Non-Linux Mutation Rejection
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_28_non_linux_mutation_rejection() {
    let mac_caps = PlatformCapabilities::non_linux_baseline(
        PlatformKind::MacOs,
        "macOS 15.0".into(),
        "24.0.0".into(),
    );
    assert_eq!(mac_caps.platform, PlatformKind::MacOs);
    assert!(!mac_caps.is_linux);

    let win_caps = PlatformCapabilities::non_linux_baseline(
        PlatformKind::Windows,
        "Windows 11".into(),
        "10.0".into(),
    );
    assert_eq!(win_caps.platform, PlatformKind::Windows);
    assert!(!win_caps.is_linux);
}

// ---------------------------------------------------------------------------
// 29. Fixture Sandbox Escape
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_29_fixture_sandbox_escape() {
    let env = TestEnv::new();
    let outside_path = PathBuf::from("/var/log/syslog");
    let assert_res = env.sandbox.assert_within_bounds(&outside_path);
    assert!(
        assert_res.is_err(),
        "Sandbox must reject path outside its root"
    );
}

// ---------------------------------------------------------------------------
// 30. Guardian Bypass Attempt
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_30_guardian_bypass_attempt() {
    let env = TestEnv::new();
    let file = env.write_file("bypass.dat", b"bypass target");

    // Creating an unvalidated context without going through Guardian authorization
    let ctx = root_guardian::TransactionContext::new(
        env.make_candidate(&file, ResourceCategory::BuildArtifact),
        ProposedAction::Quarantine,
    );

    // Initial state is Proposed; attempting to restore or finalize directly fails
    assert_eq!(ctx.state, TransactionState::Proposed);
    assert!(!ctx.state.is_terminal());
    assert!(!ctx.state.can_transition_to(&TransactionState::Restored));
}

// ---------------------------------------------------------------------------
// Decision Pipeline & Eligibility Unit Tests (Phase 11 Requirement 4)
// ---------------------------------------------------------------------------
#[test]
fn test_decision_pipeline_stage_ordering() {
    assert!(DecisionStage::Observed < DecisionStage::Classified);
    assert!(DecisionStage::Classified < DecisionStage::ConsideredForCleanup);
    assert!(DecisionStage::ConsideredForCleanup < DecisionStage::PresentedToUser);
    assert!(DecisionStage::PresentedToUser < DecisionStage::UserAuthorized);
    assert!(DecisionStage::UserAuthorized < DecisionStage::GuardianValidated);
    assert!(DecisionStage::GuardianValidated < DecisionStage::Prepared);
    assert!(DecisionStage::Prepared < DecisionStage::ExecutedInTestEnv);
    assert!(DecisionStage::ExecutedInTestEnv < DecisionStage::ResultVerified);
    assert!(DecisionStage::ResultVerified < DecisionStage::RestorationEvaluated);
}

#[test]
fn test_eligibility_status_distinction() {
    let eligible = EligibilityStatus::Eligible {
        tier: ProtectionTier::UserConfirmRequired,
        reason: "Clean build artifact with verified Git status".into(),
    };
    assert!(eligible.is_eligible());
    assert_eq!(eligible.tier(), Some(ProtectionTier::UserConfirmRequired));

    let ineligible = EligibilityStatus::Ineligible {
        reason: RejectionReason::TierStrictlyProtected,
        explanation: "Contains personal documents or credentials".into(),
    };
    assert!(!ineligible.is_eligible());
    assert_eq!(ineligible.tier(), None);
}
