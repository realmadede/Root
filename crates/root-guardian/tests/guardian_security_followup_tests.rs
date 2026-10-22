#![cfg(target_os = "linux")]
use std::{
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::PathBuf,
};
use tempfile::TempDir;

use root_core::model::{
    FileType, ProposedAction, ProtectionTier, ResourceCandidate, ResourceCategory, ResourceId,
    ResourceLocation, ResourceMetadata, ResourceOwnership, StorageMeasurement,
};
use root_guardian::{
    crypto::sha256_file, sha256_hex, AuthorizationEngine, AuthorizationRequest, FixtureSandbox,
    JournalRecord, RecoveryJournal, TransactionEngine, TransactionState,
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
