#![cfg(target_os = "linux")]

use std::{
    fs::{self, File},
    io::Write,
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
    authorization::{AuthorizationEngine, AuthorizationRequest, ConsentRecord},
    quarantine::QuarantineStore,
    sandbox::FixtureSandbox,
    transaction::TransactionState,
    JournalRecord, RecoveryJournal, TransactionEngine,
};
use root_platform::{
    is_openat2_supported, PinnedDirectory, ResolutionError, ResolutionMode, ResolutionOptions,
};

struct TestEnv {
    _temp: TempDir,
    sandbox: FixtureSandbox,
    journal: RecoveryJournal,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("root-guardian-pipeline-test-")
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

    fn make_valid_request(
        &self,
        candidate: &ResourceCandidate,
        ttl_secs: u64,
    ) -> (AuthorizationRequest, ConsentRecord) {
        let consent = ConsentRecord::new(
            candidate.id.clone(),
            ProposedAction::Quarantine,
            candidate.location.path.clone(),
            "valid-nonce-descriptor-pipeline".into(),
            ttl_secs,
        );
        let request = AuthorizationRequest::new(
            candidate.clone(),
            ProposedAction::Quarantine,
            ProtectionTier::ObsoleteTransient,
            self.sandbox.operator_uid(),
        )
        .with_consent(consent.clone())
        .with_sandbox_root(self.sandbox.root().to_path_buf())
        .with_multi_link(true);
        (request, consent)
    }
}

// ---------------------------------------------------------------------------
// Section 7 Deterministic Fault-Injection Tests (Scenarios 1 - 18)
// ---------------------------------------------------------------------------

// 1. Successful descriptor-relative access to an expected synthetic object
#[test]
fn test_01_successful_descriptor_pinned_quarantine_and_restore() {
    let mut env = TestEnv::new();
    let file = env.write_file("sub_project/victim.log", b"audit log payload data");
    let candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);
    let (request, _) = env.make_valid_request(&candidate, 300);

    // Quarantine execution
    let tx = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request)
        .expect("Quarantine must succeed");

    assert_eq!(tx.state, TransactionState::Verified);
    assert!(
        !file.exists(),
        "Source file must be unlinked after quarantine"
    );
    let qpath = tx
        .quarantine_path
        .as_ref()
        .expect("Quarantine path must be present");
    assert!(qpath.exists(), "Quarantined file must exist in staging");

    // Restore execution
    let restored_tx =
        TransactionEngine::restore(&env.sandbox, &mut env.journal, &tx.transaction_id)
            .expect("Restore must succeed");

    assert_eq!(restored_tx.state, TransactionState::Restored);
    assert!(
        file.exists(),
        "Source file must be restored back to original path"
    );
    let content = fs::read(&file).expect("Read restored file");
    assert_eq!(content, b"audit log payload data");
}

// 2. Object replacement after initial inspection (TOCTOU inode change)
#[test]
fn test_02_object_replacement_after_inspection_toctou() {
    let env = TestEnv::new();
    let file = env.write_file("toctou_file.txt", b"original content");
    let candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);
    let expected_dev = candidate.location.device_id;
    let expected_ino = candidate.location.inode;
    let uid = env.sandbox.operator_uid();

    let parent_dir = PinnedDirectory::open_root(file.parent().unwrap()).unwrap();

    // Verify revalidation initially passes
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(AuthorizationEngine::revalidate_pinned(
        &parent_dir,
        "toctou_file.txt",
        expected_dev,
        expected_ino,
        uid,
        None,
        now,
    )
    .is_ok());

    // Injected fault: Replace the file with a newly created file (different inode)
    fs::remove_file(&file).expect("Remove original file");
    let mut f = File::create(&file).expect("Recreate file with new inode");
    f.write_all(b"replacement malicious content")
        .expect("Write replacement content");

    // Revalidation against original expected inode must be refused
    let res = AuthorizationEngine::revalidate_pinned(
        &parent_dir,
        "toctou_file.txt",
        expected_dev,
        expected_ino,
        uid,
        None,
        now,
    );
    assert_eq!(res, Err(RejectionReason::FilesystemIdentityChanged));
}

// 3. Symlink substitution before pre-mutation check
#[test]
fn test_03_symlink_substitution_pre_mutation() {
    let env = TestEnv::new();
    let file = env.write_file("symlink_victim.txt", b"regular file content");
    let candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);
    let expected_dev = candidate.location.device_id;
    let expected_ino = candidate.location.inode;
    let uid = env.sandbox.operator_uid();

    let parent_dir = PinnedDirectory::open_root(file.parent().unwrap()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Injected fault: Replace the file with a symlink pointing elsewhere
    fs::remove_file(&file).expect("Remove file");
    let target = env.sandbox.root().join("dummy_target.txt");
    fs::write(&target, b"target data").expect("Write target");
    std::os::unix::fs::symlink(&target, &file).expect("Create symlink in place of file");

    // Revalidation must refuse symlink with SymlinkJailEscape
    let res = AuthorizationEngine::revalidate_pinned(
        &parent_dir,
        "symlink_victim.txt",
        expected_dev,
        expected_ino,
        uid,
        None,
        now,
    );
    assert_eq!(res, Err(RejectionReason::SymlinkJailEscape));
}

// 4. Parent-directory replacement or namespace substitution
#[test]
fn test_04_parent_directory_replacement() {
    let env = TestEnv::new();
    let sub = env.sandbox.root().join("sub_parent");
    fs::create_dir(&sub).expect("Create parent dir");
    let file = sub.join("inner.txt");
    fs::write(&file, b"content").expect("Write inner file");

    let pmeta = fs::symlink_metadata(&sub).expect("Stat parent");
    let expected_pdev = pmeta.dev();
    let expected_pino = pmeta.ino();

    // Injected fault: Rename sub_parent and recreate with new inode
    let old_sub = env.sandbox.root().join("sub_parent_old");
    fs::rename(&sub, &old_sub).expect("Rename parent dir");
    fs::create_dir(&sub).expect("Recreate parent dir with new inode");
    fs::write(&file, b"content in new parent").expect("Recreate file in new parent");
    let fmeta = fs::symlink_metadata(&file).expect("Stat new file");

    let res = AuthorizationEngine::revalidate_full(
        &file,
        expected_pdev,
        fmeta.ino(),
        env.sandbox.operator_uid(),
        Some(expected_pdev),
        Some(expected_pino),
        Some(env.sandbox.root()),
    );
    assert_eq!(res, Err(RejectionReason::ParentDirectoryChanged));
}

// 5. Destination collision refused
#[test]
fn test_05_destination_collision_refused() {
    let env = TestEnv::new();
    let file = env.write_file("collision_source.txt", b"source payload");
    let candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);
    let (_request, _) = env.make_valid_request(&candidate, 300);

    // Pre-create the destination in quarantine area to trigger collision
    let dest_name = format!("tx_dummy_{}_collision_source.txt", candidate.location.inode);
    let collision_dest = env.sandbox.quarantine_dir().join(&dest_name);
    fs::write(&collision_dest, b"pre-existing colliding payload").expect("Write colliding file");

    // Test QuarantineStore directly
    let err = QuarantineStore::allocate_quarantine_path(
        &env.sandbox,
        "tx_dummy",
        &file,
        candidate.location.inode,
    );
    assert!(matches!(err, Err(RootError::DestinationCollision { .. })));
    assert_eq!(
        fs::read(&collision_dest).unwrap(),
        b"pre-existing colliding payload"
    );
}

// 6. Unexpected destination creation rejected via RENAME_NOREPLACE
#[test]
fn test_06_unexpected_destination_creation() {
    let env = TestEnv::new();
    let src_dir = env.sandbox.root().join("src_test");
    let dst_dir = env.sandbox.root().join("dst_test");
    fs::create_dir(&src_dir).expect("Create src");
    fs::create_dir(&dst_dir).expect("Create dst");

    fs::write(src_dir.join("payload.dat"), b"source data").expect("Write src");
    // Pre-create destination component
    fs::write(dst_dir.join("renamed.dat"), b"pre-existing target").expect("Write dst");

    let src_pinned = PinnedDirectory::open_root(&src_dir).expect("Open src");
    let dst_pinned = PinnedDirectory::open_root(&dst_dir).expect("Open dst");

    // Must be rejected atomically by RENAME_NOREPLACE
    let err = src_pinned.rename_child_to("payload.dat", &dst_pinned, "renamed.dat");
    assert!(matches!(err, Err(ResolutionError::DestinationCollision(_))));

    // Verify existing destination was NOT overwritten
    assert_eq!(
        fs::read(dst_dir.join("renamed.dat")).unwrap(),
        b"pre-existing target"
    );
    assert_eq!(
        fs::read(src_dir.join("payload.dat")).unwrap(),
        b"source data"
    );
}

// 7. Device or inode identity mismatch
#[test]
fn test_07_device_or_inode_identity_mismatch() {
    let mut env = TestEnv::new();
    let file = env.write_file("mismatch.txt", b"data");
    let mut candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);
    // Injected fault: Inode in snapshot differs from physical filesystem
    candidate.location.inode += 9999;

    let (request, _) = env.make_valid_request(&candidate, 300);
    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    assert!(res.is_err());
    let records = env.journal.read_all().unwrap();
    assert_eq!(records.last().unwrap().state, TransactionState::Failed);
}

// 8. Consent expiry before execution
#[test]
fn test_08_consent_expiry_before_execution() {
    let mut env = TestEnv::new();
    let file = env.write_file("expired.txt", b"data");
    let candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);

    // Consent created in the past (expired 10 seconds ago)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expired_consent = ConsentRecord::with_explicit_time(
        candidate.id.clone(),
        ProposedAction::Quarantine,
        file.clone(),
        "expired-nonce".into(),
        now - 100,
        10, // expired at now - 90
    );

    let request = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_consent(expired_consent)
    .with_sandbox_root(env.sandbox.root().to_path_buf());

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    assert!(res.is_err());
    let records = env.journal.read_all().unwrap();
    assert_eq!(records.last().unwrap().state, TransactionState::Failed);
    assert!(records.last().unwrap().reason.contains("ConsentExpired"));
}

// 9. Consent expiry during preflight
#[test]
fn test_09_consent_expiry_during_preflight() {
    let env = TestEnv::new();
    let file = env.write_file("preflight_expiry.txt", b"data");
    let candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);
    let parent_dir = PinnedDirectory::open_root(file.parent().unwrap()).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Consent was created at `now - 5` with TTL 5 (expires at `now`)
    let consent = ConsentRecord::with_explicit_time(
        candidate.id.clone(),
        ProposedAction::Quarantine,
        file.clone(),
        "preflight-nonce".into(),
        now - 5,
        5,
    );

    // At `now`, consent is expired
    let res = AuthorizationEngine::revalidate_pinned(
        &parent_dir,
        "preflight_expiry.txt",
        candidate.location.device_id,
        candidate.location.inode,
        env.sandbox.operator_uid(),
        Some(&consent),
        now + 1, // 1 second after preflight check
    );
    assert_eq!(res, Err(RejectionReason::ConsentExpired));
}

// 10. Authorization associated with wrong object
#[test]
fn test_10_authorization_associated_with_wrong_object() {
    let mut env = TestEnv::new();
    let file_a = env.write_file("file_a.txt", b"data A");
    let file_b = env.write_file("file_b.txt", b"data B");
    let candidate_a = env.make_candidate(&file_a, ResourceCategory::AgentScratchpad);

    // Consent issued for file_b, but submitted with candidate_a
    let consent_b = ConsentRecord::new(
        candidate_a.id.clone(),
        ProposedAction::Quarantine,
        file_b.clone(), // wrong path!
        "nonce-b".into(),
        300,
    );

    let request = AuthorizationRequest::new(
        candidate_a,
        ProposedAction::Quarantine,
        ProtectionTier::ObsoleteTransient,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent_b)
    .with_sandbox_root(env.sandbox.root().to_path_buf());

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    assert!(res.is_err());
    let records = env.journal.read_all().unwrap();
    assert_eq!(records.last().unwrap().state, TransactionState::Failed);
}

// 11. Descriptor acquisition failure
#[test]
fn test_11_descriptor_acquisition_failure() {
    let env = TestEnv::new();
    let restricted_dir = env.sandbox.root().join("restricted");
    fs::create_dir(&restricted_dir).expect("Create dir");
    fs::set_permissions(&restricted_dir, fs::Permissions::from_mode(0o000)).expect("Restrict");

    let res = PinnedDirectory::open_root(&restricted_dir);
    // Restore permissions so cleanup works
    let _ = fs::set_permissions(&restricted_dir, fs::Permissions::from_mode(0o755));

    assert!(matches!(res, Err(ResolutionError::PermissionDenied(_))));
}

// 12. Failure during pre-operation validation (size change)
#[test]
fn test_12_failure_during_pre_operation_validation() {
    let env = TestEnv::new();
    let file = env.write_file("size_victim.txt", b"initial bytes");
    let candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);
    let parent_dir = PinnedDirectory::open_root(file.parent().unwrap()).unwrap();

    // Verify initial check passes
    let pinned_file = parent_dir
        .open_child_file("size_victim.txt", 0, ResolutionOptions::default())
        .unwrap();
    assert_eq!(pinned_file.size_bytes(), candidate.metadata.storage.bytes);
    drop(pinned_file);

    // Mutate file size
    let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
    f.write_all(b" extra bytes appended").unwrap();

    let pinned_after = parent_dir
        .open_child_file("size_victim.txt", 0, ResolutionOptions::default())
        .unwrap();
    assert_ne!(pinned_after.size_bytes(), candidate.metadata.storage.bytes);
}

// 13. Failure during filesystem operation (cross-device rejection)
#[test]
fn test_13_failure_during_filesystem_operation() {
    let env = TestEnv::new();
    let src_dir = env.sandbox.root().join("src_xdev");
    let dst_dir = env.sandbox.root().join("dst_xdev");
    fs::create_dir(&src_dir).unwrap();
    fs::create_dir(&dst_dir).unwrap();
    fs::write(src_dir.join("file.txt"), b"test").unwrap();

    let src_pinned = PinnedDirectory::open_root(&src_dir).unwrap();
    let dst_pinned = PinnedDirectory::open_root(&dst_dir).unwrap();

    // Fake destination device ID to simulate cross-device mismatch
    let err = QuarantineStore::relocate_pinned(
        &src_pinned,
        "file.txt",
        &dst_pinned,
        "file.txt",
        src_pinned.identity().device_id + 1, // device mismatch!
        0o644,
    );
    assert!(matches!(err, Err(RootError::CrossDeviceUnsupported { .. })));
}

// 14. Failure during post-operation verification (integrity corruption)
#[test]
fn test_14_failure_during_post_operation_verification() {
    let env = TestEnv::new();
    let file = env.write_file("corrupt_test.txt", b"original clean payload");

    // Corrupted digest check
    let err = QuarantineStore::verify_quarantined_resource(
        &file,
        22,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert!(matches!(
        err,
        Err(RootError::IntegrityVerificationFailed { .. })
    ));
}

// 15. Journal failure before an operation
#[test]
fn test_15_journal_failure_before_operation() {
    let mut env = TestEnv::new();
    let file = env.write_file("journal_victim.txt", b"source data");
    let candidate = env.make_candidate(&file, ResourceCategory::AgentScratchpad);
    let (request, _) = env.make_valid_request(&candidate, 300);

    // Make journal file read-only to force write failure
    fs::write(env.sandbox.journal_path(), b"").unwrap();
    fs::set_permissions(
        env.sandbox.journal_path(),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &request);
    // Restore permissions so cleanup works
    let _ = fs::set_permissions(
        env.sandbox.journal_path(),
        fs::Permissions::from_mode(0o644),
    );

    assert!(res.is_err(), "Journal write failure must abort transaction");
    assert!(
        file.exists(),
        "Source file must remain in place if journal append fails"
    );
}

// 16. Journal failure after an operation
#[test]
fn test_16_journal_failure_after_operation() {
    let env = TestEnv::new();
    let mut read_only_journal = RecoveryJournal::new(env.sandbox.journal_path()).unwrap();
    fs::write(env.sandbox.journal_path(), b"").unwrap();
    fs::set_permissions(
        env.sandbox.journal_path(),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();

    let record = JournalRecord {
        transaction_id: "tx_post_op".into(),
        timestamp_epoch_secs: 1000,
        state: TransactionState::Quarantined,
        original_path: PathBuf::from("/tmp/dummy"),
        quarantine_path: None,
        device_id: 1,
        inode: 1,
        size_bytes: 10,
        sha256: None,
        reason: "test".into(),
        failure_reason: None,
    };

    let res = read_only_journal.append(&record);
    let _ = fs::set_permissions(
        env.sandbox.journal_path(),
        fs::Permissions::from_mode(0o644),
    );
    assert!(res.is_err());
}

// 17. Unsupported descriptor-resolution capability
#[test]
fn test_17_unsupported_descriptor_capability() {
    let env = TestEnv::new();
    let pinned = PinnedDirectory::open_root(env.sandbox.root()).unwrap();

    if !is_openat2_supported() {
        let opts = ResolutionOptions {
            mode: ResolutionMode::ForceOpenat2,
            allow_mount_crossing: false,
        };
        let res = pinned.open_child_dir("any_dir", opts);
        assert!(matches!(
            res,
            Err(ResolutionError::UnsupportedCapability("openat2"))
        ));
    }
}

// 18. Attempted access beyond intended directory boundary
#[test]
fn test_18_attempted_access_beyond_sandbox_boundary() {
    let env = TestEnv::new();
    let outside_path = PathBuf::from("/etc/passwd");

    // Sandbox containment check refuses outside paths
    let res = env.sandbox.assert_within_bounds(&outside_path);
    assert!(matches!(res, Err(RootError::SandboxViolation { .. })));

    // Relative resolution beneath pinned directory refuses '..'
    let pinned = PinnedDirectory::open_root(env.sandbox.root()).unwrap();
    let err = pinned.resolve_path_beneath(Path::new("../escape"), ResolutionOptions::default());
    assert!(matches!(err, Err(ResolutionError::InvalidComponent(_))));
}
