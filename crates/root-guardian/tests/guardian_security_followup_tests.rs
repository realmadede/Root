#![cfg(target_os = "linux")]
use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

use root_core::{
    error::RootError,
    model::{
        FileType, ProposedAction, ProtectionTier, RejectionReason, ResourceCandidate,
        ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata, ResourceOwnership,
        StorageMeasurement,
    },
};
use root_guardian::{
    crypto::sha256_file, sha256_hex, AuthorizationDecision, AuthorizationEngine,
    AuthorizationRequest, ConsentRecord, FixtureSandbox, JournalRecord, RecoveryJournal,
    TransactionEngine, TransactionState,
};

struct TestEnv {
    _temp: TempDir,
    sandbox: FixtureSandbox,
    journal: RecoveryJournal,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("root-security-followup-")
            .tempdir()
            .expect("Create tempdir");
        let uid = temp.path().metadata().expect("Stat tempdir").uid();
        let sandbox = FixtureSandbox::new(temp.path(), uid).expect("Init sandbox");
        let journal = RecoveryJournal::new(sandbox.journal_path()).expect("Init journal");
        Self {
            _temp: temp,
            sandbox,
            journal,
        }
    }

    fn write_file(&self, rel_path: &str, content: &[u8]) -> PathBuf {
        let full = self.sandbox.root().join(rel_path);
        if let Some(p) = full.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(&full, content).unwrap();
        full
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

#[test]
fn test_followup_sandbox_containment_relative_traversal() {
    let env = TestEnv::new();
    let outside_path = env.sandbox.root().join("subdir/../../outside.txt");
    assert!(env.sandbox.assert_within_bounds(&outside_path).is_err());
}

#[test]
fn test_followup_directory_replacement_symlink_race() {
    let mut env = TestEnv::new();
    let real_file = env.write_file("real.txt", b"payload");
    let meta = fs::symlink_metadata(&real_file).unwrap();

    let link_path = env.sandbox.root().join("link_swap.txt");
    std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

    let candidate = ResourceCandidate {
        id: ResourceId::new("link-swap"),
        location: ResourceLocation::new(link_path.clone(), None, meta.dev(), meta.ino()),
        category: ResourceCategory::AgentScratchpad,
        metadata: ResourceMetadata {
            file_type: FileType::Symlink,
            storage: StorageMeasurement::from_raw(10, 1, 1),
            permissions_mode: 0o777,
            mtime_epoch_secs: 100,
            atime_epoch_secs: 100,
            ctime_epoch_secs: 100,
        },
        ownership: ResourceOwnership {
            uid: env.sandbox.operator_uid(),
            gid: env.sandbox.operator_uid(),
            is_current_user: true,
        },
        associated_agent: None,
    };

    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::UserConfirmRequired,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: true,
        consent_record: None,
        sandbox_root: None,
        allow_multi_link: false,
    };

    let auth_res = AuthorizationEngine::authorize(&request);
    assert!(
        !auth_res.is_authorized(),
        "Symlinks must be rejected by authorization"
    );

    let quar_res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    assert!(quar_res.is_err(), "Transaction engine must refuse symlink");
}

#[test]
fn test_followup_journal_durability_and_chronological_ordering() {
    let temp = TempDir::new().unwrap();
    let journal_path = temp.path().join(".root_journal");
    let mut journal = RecoveryJournal::new(&journal_path).unwrap();

    for i in 1..=5 {
        let rec = JournalRecord {
            transaction_id: format!("tx-{:03}", i),
            timestamp_epoch_secs: 1700000000 + i,
            state: TransactionState::Prepared,
            original_path: temp.path().join(format!("file_{}.txt", i)),
            quarantine_path: None,
            device_id: 1,
            inode: 100 + i as u64,
            size_bytes: 512 * i as u64,
            sha256: Some(sha256_hex(format!("content-{}", i).as_bytes())),
            reason: "Durability test".to_string(),
            failure_reason: None,
        };
        journal.append(&rec).unwrap();
    }

    let records = journal.read_all().unwrap();
    assert_eq!(records.len(), 5);
    for (idx, rec) in records.iter().enumerate() {
        assert_eq!(rec.transaction_id, format!("tx-{:03}", idx + 1));
    }
}

#[test]
fn test_followup_recovery_ordering_interrupted_detection() {
    let temp = TempDir::new().unwrap();
    let journal_path = temp.path().join(".root_journal");
    let mut journal = RecoveryJournal::new(&journal_path).unwrap();

    // tx-01 completes Verified
    journal
        .append(&JournalRecord {
            transaction_id: "tx-01".into(),
            timestamp_epoch_secs: 100,
            state: TransactionState::Prepared,
            original_path: temp.path().join("a.txt"),
            quarantine_path: None,
            device_id: 1,
            inode: 10,
            size_bytes: 10,
            sha256: None,
            reason: "Test".into(),
            failure_reason: None,
        })
        .unwrap();

    journal
        .append(&JournalRecord {
            transaction_id: "tx-01".into(),
            timestamp_epoch_secs: 101,
            state: TransactionState::Verified,
            original_path: temp.path().join("a.txt"),
            quarantine_path: Some(temp.path().join("q_a.txt")),
            device_id: 1,
            inode: 10,
            size_bytes: 10,
            sha256: None,
            reason: "Test".into(),
            failure_reason: None,
        })
        .unwrap();

    // tx-02 stops at Prepared (Interrupted)
    journal
        .append(&JournalRecord {
            transaction_id: "tx-02".into(),
            timestamp_epoch_secs: 102,
            state: TransactionState::Prepared,
            original_path: temp.path().join("b.txt"),
            quarantine_path: None,
            device_id: 1,
            inode: 20,
            size_bytes: 20,
            sha256: None,
            reason: "Test".into(),
            failure_reason: None,
        })
        .unwrap();

    let interrupted = journal.get_interrupted_transactions().unwrap();
    assert_eq!(interrupted.len(), 1);
    assert_eq!(interrupted[0].transaction_id, "tx-02");
}

#[test]
fn test_followup_sha256_comprehensive_edge_coverage() {
    let temp = TempDir::new().unwrap();

    // 1. Empty file (0 bytes)
    let empty_path = temp.path().join("empty.txt");
    File::create(&empty_path).unwrap();
    assert_eq!(
        sha256_file(&empty_path).unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // 2. Exact 64-byte block (internal SHA block size)
    let block64 = vec![b'A'; 64];
    let path64 = temp.path().join("block64.txt");
    fs::write(&path64, &block64).unwrap();
    assert_eq!(sha256_file(&path64).unwrap(), sha256_hex(&block64));

    // 3. Exact 65-byte block (forces secondary chunk padding)
    let block65 = vec![b'B'; 65];
    let path65 = temp.path().join("block65.txt");
    fs::write(&path65, &block65).unwrap();
    assert_eq!(sha256_file(&path65).unwrap(), sha256_hex(&block65));

    // 4. Multi-buffer stream (128 KiB)
    let large_data = vec![0x42u8; 128 * 1024];
    let path_large = temp.path().join("large.bin");
    fs::write(&path_large, &large_data).unwrap();
    assert_eq!(sha256_file(&path_large).unwrap(), sha256_hex(&large_data));
}

#[test]
fn test_followup_authorization_boundaries_unconditional_denial() {
    let env = TestEnv::new();
    let protected_file = env.write_file("session_key.key", b"key_data");
    let meta = fs::symlink_metadata(&protected_file).unwrap();

    let candidate = ResourceCandidate {
        id: ResourceId::new("key-candidate"),
        location: ResourceLocation::new(protected_file, None, meta.dev(), meta.ino()),
        category: ResourceCategory::SessionState,
        metadata: ResourceMetadata {
            file_type: FileType::RegularFile,
            storage: StorageMeasurement::from_raw(8, 1, 1),
            permissions_mode: 0o600,
            mtime_epoch_secs: 100,
            atime_epoch_secs: 100,
            ctime_epoch_secs: 100,
        },
        ownership: ResourceOwnership {
            uid: env.sandbox.operator_uid(),
            gid: env.sandbox.operator_uid(),
            is_current_user: true,
        },
        associated_agent: None,
    };

    // 1. Tier 1 must be unconditionally denied even if user_consent is true
    let req_tier1 = AuthorizationRequest {
        candidate: candidate.clone(),
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::StrictlyProtected,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: true,
        consent_record: None,
        sandbox_root: None,
        allow_multi_link: false,
    };
    let decision = AuthorizationEngine::authorize(&req_tier1);
    assert!(
        !decision.is_authorized(),
        "Tier 1 must be unconditionally denied"
    );

    // 2. Foreign UID must be unconditionally denied
    let req_foreign = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::UserConfirmRequired,
        invoking_uid: 9999, // Foreign UID
        explicit_user_consent: true,
        consent_record: None,
        sandbox_root: None,
        allow_multi_link: false,
    };
    let decision_foreign = AuthorizationEngine::authorize(&req_foreign);
    assert!(
        !decision_foreign.is_authorized(),
        "Foreign UID must be rejected"
    );
}

#[test]
fn test_followup_parent_directory_swap_detection() {
    let env = TestEnv::new();
    let parent_a = env.sandbox.root().join("parent_a");
    fs::create_dir_all(&parent_a).unwrap();
    let file = parent_a.join("data.txt");
    fs::write(&file, b"sample content").unwrap();

    let meta = fs::symlink_metadata(&file).unwrap();
    let pmeta_a = fs::symlink_metadata(&parent_a).unwrap();

    // Revalidation with matching parent succeeds
    let ok_res = AuthorizationEngine::revalidate_full(
        &file,
        meta.dev(),
        meta.ino(),
        env.sandbox.operator_uid(),
        Some(pmeta_a.dev()),
        Some(pmeta_a.ino()),
        Some(env.sandbox.root()),
    );
    assert!(ok_res.is_ok());

    // Create a replacement directory with a distinct inode
    let parent_b = env.sandbox.root().join("parent_b");
    fs::create_dir_all(&parent_b).unwrap();
    let pmeta_b = fs::symlink_metadata(&parent_b).unwrap();
    assert_ne!(pmeta_a.ino(), pmeta_b.ino());

    // Swap directory: rename parent_a out, move parent_b to parent_a
    let parent_a_bak = env.sandbox.root().join("parent_a_bak");
    fs::rename(&parent_a, &parent_a_bak).unwrap();
    fs::rename(&parent_b, &parent_a).unwrap();

    // Recreate the target file inside the swapped parent
    fs::write(&file, b"sample content").unwrap();
    let new_meta = fs::symlink_metadata(&file).unwrap();

    // Pre-mutation revalidation must catch the altered parent inode
    let err_res = AuthorizationEngine::revalidate_full(
        &file,
        new_meta.dev(),
        new_meta.ino(),
        env.sandbox.operator_uid(),
        Some(pmeta_a.dev()),
        Some(pmeta_a.ino()), // Old parent inode expectation
        Some(env.sandbox.root()),
    );
    assert_eq!(err_res, Err(RejectionReason::ParentDirectoryChanged));
}

#[test]
fn test_followup_parent_directory_symlink_swap_detection() {
    let env = TestEnv::new();
    let real_parent = env.sandbox.root().join("real_parent");
    fs::create_dir_all(&real_parent).unwrap();
    let file = real_parent.join("target.bin");
    fs::write(&file, b"binary payload").unwrap();

    let meta = fs::symlink_metadata(&file).unwrap();
    let pmeta_real = fs::symlink_metadata(&real_parent).unwrap();

    // Setup symlink pointing to parent
    let sym_parent = env.sandbox.root().join("sym_parent");
    std::os::unix::fs::symlink(&real_parent, &sym_parent).unwrap();
    let sym_file = sym_parent.join("target.bin");

    // Pre-mutation revalidation against a path traversing a symlink parent must reject
    let err_res = AuthorizationEngine::revalidate_full(
        &sym_file,
        meta.dev(),
        meta.ino(),
        env.sandbox.operator_uid(),
        Some(pmeta_real.dev()),
        Some(pmeta_real.ino()),
        Some(env.sandbox.root()),
    );
    assert_eq!(err_res, Err(RejectionReason::SymlinkJailEscape));
}

#[test]
fn test_followup_consent_exact_boundary_conditions() {
    let id = ResourceId::new("boundary-test-candidate");
    let path = PathBuf::from("/tmp/sandbox/leaf.txt");
    let created_at: i64 = 1_000_000;
    let ttl_secs: u64 = 300;
    let expires_at: i64 = created_at + ttl_secs as i64;

    let consent = ConsentRecord::with_explicit_time(
        id,
        ProposedAction::Quarantine,
        path,
        "nonce-test".into(),
        created_at,
        ttl_secs,
    );

    // 1. Prior to creation timestamp — invalid
    assert!(!consent.is_valid_at(created_at - 1));

    // 2. Exact creation timestamp — valid
    assert!(consent.is_valid_at(created_at));

    // 3. Immediately prior to expiration — valid
    assert!(consent.is_valid_at(expires_at - 1));

    // 4. Exact expiration timestamp — invalid (strictly expired)
    assert!(!consent.is_valid_at(expires_at));

    // 5. Subsequent to expiration timestamp — invalid
    assert!(!consent.is_valid_at(expires_at + 1));
}

#[test]
fn test_followup_restoration_conflict_directory_and_dangling_symlink() {
    let mut env = TestEnv::new();
    let file = env.write_file("restore_target.txt", b"essential content");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_multi_link(true);

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    assert!(!file.exists(), "Source file moved into quarantine");

    // Case A: Destination re-occupied by a newly created directory
    fs::create_dir_all(&file).unwrap();
    let res_dir = TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id);
    assert!(
        matches!(res_dir, Err(RootError::RestorationConflict { .. })),
        "Restoration must fail when destination is occupied by a directory"
    );
    fs::remove_dir(&file).unwrap();

    // Case B: Destination re-occupied by a dangling symlink (rejected via sandbox policy or conflict check)
    let nonexistent_target = env.sandbox.root().join("does_not_exist.txt");
    std::os::unix::fs::symlink(&nonexistent_target, &file).unwrap();
    let res_sym = TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id);
    assert!(
        matches!(
            res_sym,
            Err(RootError::PolicyViolation { .. }) | Err(RootError::RestorationConflict { .. })
        ),
        "Restoration must fail when destination is occupied by a dangling symlink"
    );
    fs::remove_file(&file).unwrap();

    // Case C: Clean destination path allows successful restoration
    let res_clean = TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id);
    assert!(
        res_clean.is_ok(),
        "Restoration must succeed once path conflict is resolved"
    );
    assert_eq!(fs::read(&file).unwrap(), b"essential content");
}

#[test]
fn test_followup_hard_link_rejection_and_explicit_allow() {
    let env = TestEnv::new();
    let primary = env.write_file("primary.dat", b"shared inode data");
    let link_path = env.sandbox.root().join("primary_link.dat");
    fs::hard_link(&primary, &link_path).unwrap();

    let candidate = env.make_candidate(&primary, ResourceCategory::BuildArtifact);

    // 1. By default, multi-link resource must be denied authorization
    let req_default = AuthorizationRequest::new(
        candidate.clone(),
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    );
    let decision_default = AuthorizationEngine::authorize(&req_default);
    match decision_default {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::HardLinkShared);
        }
        _ => panic!("Multi-link files must be rejected by default"),
    }

    // 2. Explicit authorization allows proceeding
    let req_allowed = req_default.with_multi_link(true);
    let decision_allowed = AuthorizationEngine::authorize(&req_allowed);
    assert!(
        decision_allowed.is_authorized(),
        "Explicit multi-link flag must permit authorization"
    );
}

#[test]
fn test_followup_consent_mismatched_action() {
    let env = TestEnv::new();
    let file = env.write_file("action_mismatch.txt", b"action test payload");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    let consent = ConsentRecord::new(
        candidate.id.clone(),
        ProposedAction::Quarantine,
        file,
        "nonce-action-guard".into(),
        300,
    );

    // Requesting a different action (e.g. Inspect) with quarantine consent must be denied
    let req = AuthorizationRequest::new(
        candidate,
        ProposedAction::Inspect,
        ProtectionTier::UserConfirmRequired,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent);

    let decision = AuthorizationEngine::authorize(&req);
    match decision {
        AuthorizationDecision::Denied { reason, .. } => {
            assert_eq!(reason, RejectionReason::ConsentNonceMismatch);
        }
        _ => panic!("Mismatched action on consent record must be rejected"),
    }
}
