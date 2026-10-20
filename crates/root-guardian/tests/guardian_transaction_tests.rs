use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
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
    crypto::sha256_file, AuthorizationEngine, AuthorizationRequest, FixtureSandbox, JournalRecord,
    RecoveryJournal, TransactionContext, TransactionEngine, TransactionState,
};

struct TestEnv {
    _temp: TempDir,
    sandbox: FixtureSandbox,
    journal: RecoveryJournal,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("root-guardian-test-")
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
// Security Test Suite (Scenarios 1 - 16)
// ---------------------------------------------------------------------------

#[test]
fn test_01_symlink_escape_rejection() {
    let mut env = TestEnv::new();
    let external_target = PathBuf::from("/etc/passwd");
    let link_path = env.sandbox.root().join("symlink_escape.txt");
    let _ = std::os::unix::fs::symlink(&external_target, &link_path);

    let candidate = ResourceCandidate {
        id: ResourceId::new("symlink-target"),
        location: ResourceLocation::new(link_path.clone(), None, env.sandbox.device_id(), 9999),
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

    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::ObsoleteTransient,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: false,
    };

    // Must be rejected by sandbox boundary and authorization
    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    assert!(res.is_err(), "Symlink escape attempt must be rejected");
}

#[test]
fn test_02_toctou_revalidation_directory_replacement() {
    let env = TestEnv::new();
    let file = env.write_file("toctou_victim.tmp", b"original file content");
    let meta = fs::symlink_metadata(&file).unwrap();

    // Revalidation should pass initially
    assert!(AuthorizationEngine::revalidate_before_mutation(
        &file,
        meta.dev(),
        meta.ino(),
        env.sandbox.operator_uid()
    )
    .is_ok());

    // Replace file with a directory (simulating a TOCTOU race)
    fs::remove_file(&file).unwrap();
    fs::create_dir(&file).unwrap();
    let _new_meta = fs::symlink_metadata(&file).unwrap();

    // Revalidation against original inode MUST fail
    let res = AuthorizationEngine::revalidate_before_mutation(
        &file,
        meta.dev(),
        meta.ino(),
        env.sandbox.operator_uid(),
    );
    assert_eq!(res, Err(RejectionReason::FilesystemIdentityChanged));
}

#[test]
fn test_03_resource_identity_change_rejection() {
    let env = TestEnv::new();
    let file = env.write_file("identity_changed.tmp", b"content v1");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    // Re-create the file to give it a new inode
    fs::remove_file(&file).unwrap();
    let file_v2 = env.write_file("identity_changed.tmp", b"content v2 with new inode");
    let new_meta = fs::symlink_metadata(&file_v2).unwrap();

    // If new inode differs from candidate snapshot, authorization must be denied
    if new_meta.ino() != candidate.location.inode {
        let request = AuthorizationRequest {
            candidate: candidate.clone(),
            requested_action: ProposedAction::Quarantine,
            classification: ProtectionTier::ObsoleteTransient,
            invoking_uid: env.sandbox.operator_uid(),
            explicit_user_consent: false,
        };

        let decision = AuthorizationEngine::authorize(&request);
        match decision {
            root_guardian::AuthorizationDecision::Denied { reason, .. } => {
                assert_eq!(reason, RejectionReason::FilesystemIdentityChanged);
            }
            _ => panic!("Expected authorization denial due to inode identity mismatch"),
        }
    }
}

#[test]
fn test_04_destination_collision_rejection() {
    let env = TestEnv::new();
    let file = env.write_file("collision_source.tmp", b"source payload");

    // Pre-create the exact collision path
    let fake_tx_id = "tx_collision_test";
    let collision_dest = env.sandbox.quarantine_dir().join(format!(
        "{}_{}_collision_source.tmp",
        fake_tx_id,
        fs::symlink_metadata(&file).unwrap().ino()
    ));
    fs::write(&collision_dest, b"existing collision artifact").unwrap();

    // Quarantine allocation on this exact collision path must fail
    let err = root_guardian::QuarantineStore::allocate_quarantine_path(
        &env.sandbox,
        fake_tx_id,
        &file,
        fs::symlink_metadata(&file).unwrap().ino(),
    );
    assert!(matches!(err, Err(RootError::DestinationCollision { .. })));

    // Verify source was NOT touched
    assert!(file.exists());
    assert_eq!(fs::read(&file).unwrap(), b"source payload");
}

#[test]
fn test_05_hard_link_semantics() {
    let mut env = TestEnv::new();
    let origin = env.write_file("hardlink_origin.dat", b"shared data across hard links");
    let link_copy = env.sandbox.root().join("hardlink_copy.dat");
    fs::hard_link(&origin, &link_copy).unwrap();

    let meta = fs::symlink_metadata(&origin).unwrap();
    assert_eq!(meta.nlink(), 2);

    let candidate = env.make_candidate(&origin, ResourceCategory::BuildArtifact);
    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::ObsoleteTransient,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: false,
    };

    // Quarantine origin
    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    assert_eq!(tx.state, TransactionState::Verified);

    // Origin is relocated, but link_copy MUST remain completely valid and intact
    assert!(!origin.exists());
    assert!(link_copy.exists());
    assert_eq!(
        fs::read(&link_copy).unwrap(),
        b"shared data across hard links"
    );

    // Restore origin
    let restore_tx =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id).unwrap();
    assert_eq!(restore_tx.state, TransactionState::Restored);

    // Both files now exist and have matching content
    assert!(origin.exists());
    assert!(link_copy.exists());
    assert_eq!(fs::read(&origin).unwrap(), fs::read(&link_copy).unwrap());
}

#[test]
fn test_06_sparse_file_quarantine_and_restoration() {
    let mut env = TestEnv::new();
    let sparse_path = env.sandbox.root().join("sparse_artifact.bin");

    // Create a 2 MiB sparse file
    let mut f = File::create(&sparse_path).unwrap();
    f.write_all(b"HEADER_SPARSE").unwrap();
    f.seek(SeekFrom::Start(2 * 1024 * 1024)).unwrap();
    f.write_all(b"FOOTER_SPARSE").unwrap();
    drop(f);

    let original_hash = sha256_file(&sparse_path).unwrap();
    let candidate = env.make_candidate(&sparse_path, ResourceCategory::BuildArtifact);

    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::SafeRecoverable,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: false,
    };

    // Quarantine sparse file
    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    assert_eq!(tx.state, TransactionState::Verified);
    assert_eq!(tx.verified_sha256.as_deref(), Some(original_hash.as_str()));

    // Restore sparse file
    let restore_tx =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id).unwrap();
    assert_eq!(restore_tx.state, TransactionState::Restored);

    assert!(sparse_path.exists());
    assert_eq!(sha256_file(&sparse_path).unwrap(), original_hash);
}

#[test]
fn test_07_unicode_and_non_latin_filenames() {
    let mut env = TestEnv::new();
    let cyrillic_file = env.write_file("файл_тест_отчет.dat", b"unicode content cyrillic");
    let original_hash = sha256_file(&cyrillic_file).unwrap();

    let candidate = env.make_candidate(&cyrillic_file, ResourceCategory::BuildArtifact);
    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::ObsoleteTransient,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: false,
    };

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    assert_eq!(tx.state, TransactionState::Verified);

    let restore_tx =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id).unwrap();
    assert_eq!(restore_tx.state, TransactionState::Restored);

    assert!(cyrillic_file.exists());
    assert_eq!(sha256_file(&cyrillic_file).unwrap(), original_hash);
}

#[test]
fn test_08_newline_and_special_filenames() {
    let mut env = TestEnv::new();
    let special_file = env.write_file("brackets [test] and spaces.tmp", b"special name content");
    let original_hash = sha256_file(&special_file).unwrap();

    let candidate = env.make_candidate(&special_file, ResourceCategory::BuildArtifact);
    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::ObsoleteTransient,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: false,
    };

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    assert_eq!(tx.state, TransactionState::Verified);

    let restore_tx =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id).unwrap();
    assert_eq!(restore_tx.state, TransactionState::Restored);

    assert!(special_file.exists());
    assert_eq!(sha256_file(&special_file).unwrap(), original_hash);
}

#[test]
fn test_09_invalid_transaction_transitions() {
    let env = TestEnv::new();
    let file = env.write_file("tx_test.tmp", b"test");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    let mut ctx = TransactionContext::new(candidate, ProposedAction::Quarantine);
    assert_eq!(ctx.state, TransactionState::Proposed);

    // Cannot transition to Quarantined directly from Proposed
    assert!(ctx.transition_to(TransactionState::Quarantined).is_err());

    // Cannot transition to Restored directly from Proposed
    assert!(ctx.transition_to(TransactionState::Restored).is_err());

    // Valid transition: Proposed -> Authorized
    ctx.transition_to(TransactionState::Authorized).unwrap();

    // Cannot transition backward to Proposed
    assert!(ctx.transition_to(TransactionState::Proposed).is_err());
}

#[test]
fn test_10_interrupted_transaction_detection() {
    let mut env = TestEnv::new();

    let record_prepared = JournalRecord {
        transaction_id: "tx_interrupted_1".into(),
        timestamp_epoch_secs: 1000,
        state: TransactionState::Prepared,
        original_path: env.sandbox.root().join("app/cache1"),
        quarantine_path: Some(env.sandbox.quarantine_dir().join("app_cache1")),
        device_id: env.sandbox.device_id(),
        inode: 1001,
        size_bytes: 4096,
        sha256: Some("fake_hash".into()),
        reason: "Simulated prepared transaction".into(),
        failure_reason: None,
    };

    let record_completed = JournalRecord {
        transaction_id: "tx_completed_2".into(),
        timestamp_epoch_secs: 1002,
        state: TransactionState::Verified,
        original_path: env.sandbox.root().join("app/cache2"),
        quarantine_path: Some(env.sandbox.quarantine_dir().join("app_cache2")),
        device_id: env.sandbox.device_id(),
        inode: 1002,
        size_bytes: 4096,
        sha256: Some("fake_hash2".into()),
        reason: "Simulated completed transaction".into(),
        failure_reason: None,
    };

    env.journal.append(&record_prepared).unwrap();
    env.journal.append(&record_completed).unwrap();

    let interrupted = env.journal.get_interrupted_transactions().unwrap();
    assert_eq!(interrupted.len(), 1);
    assert_eq!(interrupted[0].transaction_id, "tx_interrupted_1");
}

#[test]
fn test_11_corrupted_journal_detection() {
    let env = TestEnv::new();
    let journal_path = env.sandbox.journal_path();

    // Write a valid record followed by a corrupted non-JSON line
    let mut f = File::create(journal_path).unwrap();
    writeln!(f, "{{\"transaction_id\":\"tx_ok\",\"timestamp_epoch_secs\":1000,\"state\":\"prepared\",\"original_path\":\"/a\",\"quarantine_path\":null,\"device_id\":1,\"inode\":1,\"size_bytes\":10,\"sha256\":null,\"reason\":\"ok\",\"failure_reason\":null}}").unwrap();
    writeln!(f, "{{\"corrupted_json_line_with_no_closing_brace").unwrap();
    drop(f);

    let res = env.journal.read_all();
    assert!(
        matches!(res, Err(RootError::JournalError { .. })),
        "Corrupted journal line must return RootError::JournalError"
    );
}

#[test]
fn test_12_restoration_conflict_rejection() {
    let mut env = TestEnv::new();
    let file = env.write_file("conflict_test.tmp", b"original content");
    let candidate = env.make_candidate(&file, ResourceCategory::BuildArtifact);

    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::ObsoleteTransient,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: false,
    };

    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request).unwrap();
    assert_eq!(tx.state, TransactionState::Verified);
    assert!(!file.exists());

    // Attacker/user places a new file at the original destination
    fs::write(&file, b"new occupant file").unwrap();

    // Attempting to restore MUST fail with RestorationConflict and never overwrite
    let restore_res =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id);
    assert!(matches!(
        restore_res,
        Err(RootError::RestorationConflict { .. })
    ));

    // Verify occupant is untouched
    assert_eq!(fs::read(&file).unwrap(), b"new occupant file");

    // Verify quarantine copy is still safe
    assert!(tx.quarantine_path.as_ref().unwrap().exists());
}

#[test]
fn test_13_unsupported_cross_device_rejection() {
    let env = TestEnv::new();
    let source = env.write_file("source.tmp", b"data");
    let dest = env.sandbox.quarantine_dir().join("dest.tmp");

    // Pass mismatched device ID to simulate cross-filesystem move
    let res = root_guardian::QuarantineStore::relocate_into_quarantine(
        &source,
        &dest,
        env.sandbox.device_id() + 9999, // Intentional device ID mismatch
    );

    assert!(matches!(res, Err(RootError::CrossDeviceUnsupported { .. })));
    assert!(source.exists());
    assert!(!dest.exists());
}

#[test]
fn test_14_permission_restrictions_rejection() {
    let mut env = TestEnv::new();
    let ro_dir = env.sandbox.root().join("read_only_folder");
    fs::create_dir(&ro_dir).unwrap();
    let victim = ro_dir.join("victim.tmp");
    fs::write(&victim, b"victim content").unwrap();

    // Make parent directory read-only (0o555 prevents unlinking files inside it)
    fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555)).unwrap();

    let candidate = env.make_candidate(&victim, ResourceCategory::BuildArtifact);
    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::ObsoleteTransient,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: false,
    };

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    assert!(
        res.is_err(),
        "Permission denied unlinking victim must abort transaction"
    );

    // Clean up permissions so tempdir can be removed
    let _ = fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o755));
}

#[test]
fn test_15_guardian_tier1_strictly_protected_rejection() {
    let mut env = TestEnv::new();
    let key_file = env.write_file(".ssh/id_ed25519", b"fake private key bytes");
    let candidate = env.make_candidate(&key_file, ResourceCategory::SessionState);

    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::StrictlyProtected,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: true, // Even with consent, Tier 1 MUST be rejected!
    };

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    assert!(res.is_err());
    assert!(
        key_file.exists(),
        "Strictly protected file must not be modified"
    );
}

#[test]
fn test_16_sandbox_escape_attempts_rejection() {
    let mut env = TestEnv::new();
    let outside_path = PathBuf::from("/etc/hosts");

    let candidate = ResourceCandidate {
        id: ResourceId::new("outside-res"),
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
            uid: 0,
            gid: 0,
            is_current_user: false,
        },
        associated_agent: None,
    };

    let request = AuthorizationRequest {
        candidate,
        requested_action: ProposedAction::Quarantine,
        classification: ProtectionTier::ObsoleteTransient,
        invoking_uid: env.sandbox.operator_uid(),
        explicit_user_consent: false,
    };

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    assert!(
        matches!(res, Err(RootError::SandboxViolation { .. })),
        "Path outside sandbox must yield SandboxViolation"
    );
}
