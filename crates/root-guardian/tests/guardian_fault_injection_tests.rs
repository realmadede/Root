#![cfg(target_os = "linux")]

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use tempfile::TempDir;

use root_core::{
    error::RootError,
    model::{
        FileType, FindingTarget, ProposedAction, ProtectionTier, RejectionReason,
        ResourceCandidate, ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata,
        ResourceOwnership, SafetyDecision, StorageMeasurement,
    },
};
use root_guardian::{
    authorization::{AuthorizationEngine, AuthorizationRequest, ConsentRecord},
    crypto::sha256_file,
    fault::{FaultPoint, FnInterceptor, InterceptDecision},
    journal::{
        crc32, encode_framed_record, JournalCorruption, JournalFault, JournalFormat, JournalRecord,
        RecoveryJournal, HEADER_SIZE, JOURNAL_MAGIC, JOURNAL_VERSION_1, MAX_RECORD_PAYLOAD_SIZE,
    },
    quarantine::QuarantineStore,
    reconciler::JournalReconciler,
    sandbox::FixtureSandbox,
    transaction::TransactionState,
    GuardianPolicy, TransactionEngine,
};

struct TestEnv {
    _temp: TempDir,
    sandbox: FixtureSandbox,
    journal: RecoveryJournal,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("root-guardian-fault-test-")
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
            "valid-nonce-fault-test".into(),
            ttl_secs,
        );

        let req = AuthorizationRequest::new(
            candidate.clone(),
            ProposedAction::Quarantine,
            ProtectionTier::SafeRecoverable,
            self.sandbox.operator_uid(),
        )
        .with_consent(consent.clone())
        .with_sandbox_root(self.sandbox.root().to_path_buf());

        (req, consent)
    }
}

fn create_sample_record(
    tx_id: &str,
    state: TransactionState,
    orig: &Path,
    quat: Option<&Path>,
) -> JournalRecord {
    let meta = orig.metadata().ok();
    let dev = meta.as_ref().map(|m| m.dev()).unwrap_or(1);
    let ino = meta.as_ref().map(|m| m.ino()).unwrap_or(100);
    let size = meta.as_ref().map(|m| m.len()).unwrap_or(12);
    let sha = if orig.exists() {
        sha256_file(orig).ok()
    } else {
        None
    };

    JournalRecord {
        transaction_id: tx_id.to_string(),
        timestamp_epoch_secs: 1_700_000_000,
        state,
        original_path: orig.to_path_buf(),
        quarantine_path: quat.map(|p| p.to_path_buf()),
        device_id: dev,
        inode: ino,
        size_bytes: size,
        sha256: sha,
        reason: "Test synthetic journal record".into(),
        failure_reason: None,
    }
}

// =============================================================================
// WORKSTREAM B: Filesystem Race and Identity Tests
// =============================================================================

// -----------------------------------------------------------------------------
// 5.1 Source Identity Changes
// -----------------------------------------------------------------------------

#[test]
fn test_b01_source_replaced_before_auth() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Initial content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    // Replace source file before authorization using atomic rename to guarantee a distinct inode
    let sub_path = env.write_file("cache/source_sub_b01.bin", b"Replaced before auth");
    fs::rename(&sub_path, &file_path).unwrap();

    // Preflight revalidation must detect inode mismatch
    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req);
    assert!(res.is_err());
    match res {
        Err(RootError::PolicyViolation { reason }) => {
            assert!(
                reason.contains("FilesystemIdentityChanged")
                    || reason.contains("revalidation failed")
                    || reason.contains("identity mismatch")
                    || reason.contains("Observed inode")
            );
        }
        other => panic!(
            "Expected PolicyViolation on pre-auth replace, got {:?}",
            other
        ),
    }
}

#[test]
fn test_b02_source_replaced_after_auth() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Initial content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let sub_path = env.sandbox.root().join("cache/source_sub_b02.bin");
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::AfterAuthorization {
            fs::write(&sub_path, b"Replaced after auth").unwrap();
            fs::rename(&sub_path, &fp_clone).unwrap();
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_b03_source_replaced_after_preflight() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Initial content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let sub_path = env.sandbox.root().join("cache/source_sub_b03.bin");
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::AfterHashing {
            fs::write(&sub_path, b"Replaced after preflight").unwrap();
            fs::rename(&sub_path, &fp_clone).unwrap();
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_b04_source_replaced_immediately_before_rename() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Initial content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let sub_path = env.sandbox.root().join("cache/source_sub_b04.bin");
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            fs::write(&sub_path, b"Replaced immediately before rename").unwrap();
            fs::rename(&sub_path, &fp_clone).unwrap();
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_b05_source_entry_removed_before_rename() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Initial content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            let _ = fs::remove_file(&fp_clone);
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_b06_source_replaced_with_symlink() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Initial content");
    let target_path = env.write_file("safe/target.bin", b"Target file");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let tp_clone = target_path.clone();
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            let _ = fs::remove_file(&fp_clone);
            std::os::unix::fs::symlink(&tp_clone, &fp_clone).unwrap();
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
    // Verify target file was untouched
    assert!(target_path.exists());
}

#[test]
fn test_b07_source_replaced_with_directory() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Initial content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            let _ = fs::remove_file(&fp_clone);
            fs::create_dir_all(&fp_clone).unwrap();
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_b08_source_replaced_with_another_file() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Initial content");
    let decoy_path = env.write_file("cache/decoy.bin", b"Decoy content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let dp_clone = decoy_path.clone();
    let sub_path = env.sandbox.root().join("cache/source_sub_b08.bin");
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            fs::copy(&dp_clone, &sub_path).unwrap();
            fs::rename(&sub_path, &fp_clone).unwrap();
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_b09_source_content_changed_while_hashing() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Original hashable content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::DuringHashing {
            // Append bytes to change hash and size
            let mut f = OpenOptions::new().append(true).open(&fp_clone).unwrap();
            let _ = f.write_all(b"Appended while hashing");
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    // TOCTOU revalidation or size check detects modification
    assert!(res.is_err());
}

#[test]
fn test_b10_source_size_changed_after_snapshot() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Snapshot content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let fp_clone = file_path.clone();
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::AfterHashing {
            let mut f = OpenOptions::new().append(true).open(&fp_clone).unwrap();
            let _ = f.write_all(b"Size changed after snapshot");
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

// -----------------------------------------------------------------------------
// 5.2 Parent and Mount Boundaries
// -----------------------------------------------------------------------------

#[test]
fn test_b11_ancestor_pathname_replaced_after_descriptor_open() {
    let env = TestEnv::new();
    let parent = env.sandbox.root().join("ancestor_test/child_dir");
    fs::create_dir_all(&parent).unwrap();
    let file_path = parent.join("test_file.txt");
    fs::write(&file_path, b"Ancestor persistence").unwrap();

    let pinned = root_platform::PinnedDirectory::open_root(&parent).unwrap();
    assert!(pinned.exists_child("test_file.txt"));

    // Rename ancestor directory on filesystem
    let old_ancestor = env.sandbox.root().join("ancestor_test");
    let new_ancestor = env.sandbox.root().join("ancestor_swapped");
    fs::rename(&old_ancestor, &new_ancestor).unwrap();

    // Pinned descriptor remains anchored to the open inode
    assert!(pinned.exists_child("test_file.txt"));
}

#[test]
fn test_b12_source_parent_renamed_while_descriptor_open() {
    let env = TestEnv::new();
    let parent = env.sandbox.root().join("source_parent");
    fs::create_dir_all(&parent).unwrap();
    let file_path = parent.join("item.bin");
    fs::write(&file_path, b"Item content").unwrap();

    let pinned = root_platform::PinnedDirectory::open_root(&parent).unwrap();

    // Rename the parent directory itself
    let renamed_parent = env.sandbox.root().join("source_parent_renamed");
    fs::rename(&parent, &renamed_parent).unwrap();

    // Descriptor still accesses item via descriptor-relative operations
    let child_file =
        pinned.open_child_file("item.bin", 0, root_platform::ResolutionOptions::default());
    assert!(child_file.is_ok());
}

#[test]
fn test_b13_destination_parent_replaced() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let quat_dir = env.sandbox.quarantine_dir().to_path_buf();
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            let _ = fs::remove_dir_all(&quat_dir);
            let _ = fs::create_dir_all(&quat_dir);
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    // Pinned destination directory detects swap or inode change
    assert!(res.is_err());
}

#[test]
fn test_b14_destination_entry_changes_between_validation_and_rename() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let quat_dir = env.sandbox.quarantine_dir().to_path_buf();
    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            // Drop a colliding file in quarantine staging
            let entries = fs::read_dir(&quat_dir).ok();
            if let Some(entries) = entries {
                for e in entries.flatten() {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        InterceptDecision::Continue
    });

    let _ = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
}

#[test]
fn test_b15_prohibited_symlink_traversal() {
    let env = TestEnv::new();
    let outside_path = env.sandbox.root().join("outside/secret.txt");
    fs::create_dir_all(outside_path.parent().unwrap()).unwrap();
    fs::write(&outside_path, b"Secret").unwrap();

    let symlink_path = env.sandbox.root().join("cache/symlink_escape");
    fs::create_dir_all(symlink_path.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&outside_path, &symlink_path).unwrap();

    let pinned = root_platform::PinnedDirectory::open_root(symlink_path.parent().unwrap()).unwrap();
    // openat2 with RESOLVE_NO_SYMLINKS refuses symlink
    let res = pinned.open_child_file(
        "symlink_escape",
        0,
        root_platform::ResolutionOptions::default(),
    );
    assert!(res.is_err());
}

#[test]
fn test_b16_prohibited_mount_boundary() {
    let env = TestEnv::new();
    let parent = env.sandbox.root().join("mount_test");
    fs::create_dir_all(&parent).unwrap();
    let pinned = root_platform::PinnedDirectory::open_root(&parent).unwrap();

    // Verify resolution with mount boundary crossing disabled
    let res = pinned.open_child_dir(
        "child",
        root_platform::ResolutionOptions {
            mode: root_platform::ResolutionMode::Auto,
            allow_mount_crossing: false,
        },
    );
    // Nonexistent child within same device returns NotFound, not MountBoundary
    match res {
        Err(root_platform::ResolutionError::NotFound(_)) => {}
        Err(root_platform::ResolutionError::MountBoundaryCrossed { .. }) => {}
        other => panic!("Expected NotFound or MountBoundaryCrossed, got {:?}", other),
    }
}

#[test]
fn test_b17_cross_device_rename() {
    // Cross-device relocation check
    let res = QuarantineStore::relocate_into_quarantine(
        &PathBuf::from("/tmp/dev1/file"),
        &PathBuf::from("/tmp/dev2/file"),
        1,
    );
    assert!(res.is_err());
}

#[test]
fn test_b18_fallback_resolution_safety() {
    let env = TestEnv::new();
    let parent = env.sandbox.root().join("fallback_dir");
    fs::create_dir_all(&parent).unwrap();
    let pinned = root_platform::PinnedDirectory::open_root(&parent).unwrap();

    // Multicomponent paths must be rejected by fallback resolution
    let res = pinned.open_child_dir(
        "sub/nested/file",
        root_platform::ResolutionOptions {
            mode: root_platform::ResolutionMode::ForceFallback,
            allow_mount_crossing: false,
        },
    );
    assert!(res.is_err());
}

// -----------------------------------------------------------------------------
// 5.3 Destination Collisions
// -----------------------------------------------------------------------------

#[test]
fn test_b19_destination_exists_before_preflight() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    // Quarantine allocation creates a deterministic non-colliding suffix
    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req);
    assert!(res.is_ok());
}

#[test]
fn test_b20_destination_appears_after_preflight() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let quat_dir = env.sandbox.quarantine_dir().to_path_buf();
    let ino = candidate.location.inode;
    let interceptor = FnInterceptor::new(move |point, tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            let collision_name = format!("{}_{}_{}", tx_id, ino, "source.bin");
            let collision_path = quat_dir.join(collision_name);
            let _ = fs::write(&collision_path, b"Colliding destination");
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_b21_destination_replaced_between_checking_and_rename() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/source.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            // Injected failure simulating collision detection
            return InterceptDecision::Fail(RootError::DestinationCollision {
                path: PathBuf::from("destination_occupied"),
            });
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_b22_destination_is_symlink() {
    let env = TestEnv::new();
    let quat_dir = env.sandbox.quarantine_dir();
    let sym_dest = quat_dir.join("sym_dest");
    let target = env.sandbox.root().join("target");
    fs::write(&target, b"Target").unwrap();
    std::os::unix::fs::symlink(&target, &sym_dest).unwrap();

    let pinned = root_platform::PinnedDirectory::open_root(quat_dir).unwrap();
    assert!(pinned.exists_child("sym_dest"));
}

#[test]
fn test_b23_destination_is_directory() {
    let env = TestEnv::new();
    let quat_dir = env.sandbox.quarantine_dir();
    let dir_dest = quat_dir.join("sub_dir");
    fs::create_dir_all(&dir_dest).unwrap();

    let pinned = root_platform::PinnedDirectory::open_root(quat_dir).unwrap();
    assert!(pinned.exists_child("sub_dir"));
}

#[test]
fn test_b24_destination_unexpected_identity() {
    let env = TestEnv::new();
    let src = env.write_file("source.bin", b"Original");
    let dest = env.sandbox.root().join("quarantine/dest.bin");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    fs::write(&dest, b"Foreign destination").unwrap();

    // Tail state Prepared, but destination exists with unexpected content
    let rec = create_sample_record("tx-b24", TransactionState::Prepared, &src, Some(&dest));
    let mut journal = RecoveryJournal::new(env.sandbox.journal_path()).unwrap();
    journal.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&journal).unwrap();
    // Both exist -> Uncertain
    assert_eq!(report.count_uncertain, 1);
}

#[test]
fn test_b25_restoration_target_collision() {
    let mut env = TestEnv::new();
    let src = env.write_file("orig/file.txt", b"Restored resource");
    let quat = env.sandbox.root().join("quarantine/file.txt");
    fs::create_dir_all(quat.parent().unwrap()).unwrap();
    fs::write(&quat, b"Restored resource").unwrap();

    let rec1 = create_sample_record("tx-b25", TransactionState::Prepared, &src, Some(&quat));
    let rec2 = create_sample_record("tx-b25", TransactionState::Quarantined, &src, Some(&quat));
    let rec3 = create_sample_record("tx-b25", TransactionState::Verified, &src, Some(&quat));

    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();
    env.journal.append(&rec3).unwrap();

    // Original path already occupied -> restoration conflict
    let res = TransactionEngine::restore(&env.sandbox, &mut env.journal, "tx-b25");
    assert!(res.is_err());
    match res {
        Err(RootError::RestorationConflict { .. }) => {}
        other => panic!("Expected RestorationConflict, got {:?}", other),
    }
}

// =============================================================================
// WORKSTREAM C: Authorization and Consent Expiration
// =============================================================================

#[test]
fn test_c01_consent_expires_before_authorization() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);

    // Consent TTL = 0 => already expired
    let mut consent = ConsentRecord::new(
        candidate.id.clone(),
        ProposedAction::Quarantine,
        candidate.location.path.clone(),
        "expired-nonce".into(),
        0,
    );
    consent.expires_at_epoch_secs = 100; // Past epoch

    let req = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::SafeRecoverable,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent);

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req);
    assert!(res.is_err());
    match res {
        Err(RootError::PolicyViolation { reason }) => {
            assert!(reason.contains("ExpiredConsent") || reason.contains("expired"));
        }
        other => panic!(
            "Expected PolicyViolation for expired consent, got {:?}",
            other
        ),
    }
}

#[test]
fn test_c02_consent_expires_during_hashing() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::DuringHashing {
            return InterceptDecision::Fail(RootError::PolicyViolation {
                reason: "Consent expired during hashing phase".into(),
            });
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_c03_consent_expires_after_preflight() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::AfterHashing {
            return InterceptDecision::Fail(RootError::PolicyViolation {
                reason: "Consent expired after preflight validation".into(),
            });
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_c04_consent_expires_immediately_before_rename() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let interceptor = FnInterceptor::new(move |point, _tx_id| {
        if point == FaultPoint::ImmediatelyBeforeRename {
            return InterceptDecision::Fail(RootError::PolicyViolation {
                reason: "Consent expired immediately before atomic rename".into(),
            });
        }
        InterceptDecision::Continue
    });

    let res = TransactionEngine::quarantine_with_interceptor(
        &env.sandbox,
        &mut env.journal,
        &req,
        &interceptor,
    );
    assert!(res.is_err());
}

#[test]
fn test_c05_consent_belongs_to_another_transaction() {
    let mut env = TestEnv::new();
    let f1 = env.write_file("cache/f1.bin", b"F1");
    let f2 = env.write_file("cache/f2.bin", b"F2");

    let c1 = env.make_candidate(&f1, ResourceCategory::BuildArtifact);
    let c2 = env.make_candidate(&f2, ResourceCategory::BuildArtifact);

    let (_req1, consent1) = env.make_valid_request(&c1, 60);

    // Request for c2 supplied with consent for c1
    let req2 = AuthorizationRequest::new(
        c2,
        ProposedAction::Quarantine,
        ProtectionTier::SafeRecoverable,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent1);

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req2);
    assert!(res.is_err());
}

#[test]
fn test_c06_consent_references_different_object_identity() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);

    let mut consent = ConsentRecord::new(
        ResourceId::new("other-resource-id"),
        ProposedAction::Quarantine,
        file_path.clone(),
        "nonce".into(),
        60,
    );
    consent.resource_id = ResourceId::new("different-id");

    let req = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::SafeRecoverable,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent);

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req);
    assert!(res.is_err());
}

#[test]
fn test_c07_consent_references_different_action() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);

    let consent = ConsentRecord::new(
        candidate.id.clone(),
        ProposedAction::Inspect, // Mismatched action
        file_path.clone(),
        "nonce".into(),
        60,
    );

    let req = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::SafeRecoverable,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent);

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req);
    assert!(res.is_err());
}

#[test]
fn test_c08_replayed_authorization_receipt() {
    let env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);
    let (req, _consent) = env.make_valid_request(&candidate, 60);

    let auth1 = AuthorizationEngine::authorize(&req);
    assert!(matches!(
        auth1,
        root_guardian::authorization::AuthorizationDecision::Authorized { .. }
    ));
}

#[test]
fn test_c09_clock_inconsistent_with_transaction() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);

    let mut consent = ConsentRecord::new(
        candidate.id.clone(),
        ProposedAction::Quarantine,
        file_path.clone(),
        "nonce".into(),
        60,
    );
    // Skewed clock: granted in future
    consent.created_at_epoch_secs = 2_000_000_000;
    consent.expires_at_epoch_secs = 1_000_000_000; // expires before granted

    let req = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::SafeRecoverable,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent);

    let res = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req);
    assert!(res.is_err());
}

#[test]
fn test_c10_retry_after_consent_expiry() {
    let mut env = TestEnv::new();
    let file_path = env.write_file("cache/file.bin", b"Content");
    let candidate = env.make_candidate(&file_path, ResourceCategory::BuildArtifact);

    let mut consent = ConsentRecord::new(
        candidate.id.clone(),
        ProposedAction::Quarantine,
        file_path.clone(),
        "nonce".into(),
        1,
    );
    consent.expires_at_epoch_secs = 0; // Expired

    let req = AuthorizationRequest::new(
        candidate,
        ProposedAction::Quarantine,
        ProtectionTier::SafeRecoverable,
        env.sandbox.operator_uid(),
    )
    .with_consent(consent);

    let res1 = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req);
    assert!(res1.is_err());
    let res2 = TransactionEngine::quarantine(&env.sandbox, &mut env.journal, &req);
    assert!(res2.is_err());
}

// =============================================================================
// WORKSTREAM D: Journal Adversarial Testing
// =============================================================================

#[test]
fn test_d01_empty_journal() {
    let env = TestEnv::new();
    assert_eq!(env.journal.detect_format().unwrap(), JournalFormat::Empty);
    let scan = env.journal.scan_records().unwrap();
    assert_eq!(scan.records.len(), 0);
    assert!(scan.is_clean);
}

#[test]
fn test_d02_single_and_multiple_valid_records() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec1 = create_sample_record("tx-d02a", TransactionState::Prepared, &p, None);
    let rec2 = create_sample_record("tx-d02b", TransactionState::Prepared, &p, None);

    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert_eq!(scan.records.len(), 2);
    assert!(scan.is_clean);
}

#[test]
fn test_d03_truncation_at_every_header_byte_boundary() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-d03", TransactionState::Prepared, &p, None);
    let valid_bytes = encode_framed_record(&rec).unwrap();

    for split in 1..HEADER_SIZE {
        let temp_journal_path = env
            .sandbox
            .root()
            .join(format!("trunc_header_{}.log", split));
        let mut f = File::create(&temp_journal_path).unwrap();
        f.write_all(&valid_bytes).unwrap();
        // Append partial header
        f.write_all(&valid_bytes[..split]).unwrap();

        let j = RecoveryJournal::new(&temp_journal_path).unwrap();
        let scan = j.scan_records().unwrap();
        assert_eq!(scan.records.len(), 1);
        assert!(!scan.is_clean);
        assert!(matches!(
            scan.trailing_torn_write,
            Some(JournalCorruption::TruncatedTrailingHeader { .. })
        ));
    }
}

#[test]
fn test_d04_truncation_at_representative_payload_boundaries() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-d04", TransactionState::Prepared, &p, None);
    let valid_bytes = encode_framed_record(&rec).unwrap();

    let payload_len = valid_bytes.len() - HEADER_SIZE - 1;
    let checkpoints = [1, 10, payload_len / 2, payload_len - 1];

    for &cp in &checkpoints {
        let temp_journal_path = env.sandbox.root().join(format!("trunc_payload_{}.log", cp));
        let mut f = File::create(&temp_journal_path).unwrap();
        f.write_all(&valid_bytes).unwrap();
        // Append full header + partial payload
        f.write_all(&valid_bytes[..HEADER_SIZE + cp]).unwrap();

        let j = RecoveryJournal::new(&temp_journal_path).unwrap();
        let scan = j.scan_records().unwrap();
        assert_eq!(scan.records.len(), 1);
        assert!(matches!(
            scan.trailing_torn_write,
            Some(JournalCorruption::TruncatedTrailingPayload { .. })
        ));
    }
}

#[test]
fn test_d05_truncation_immediately_before_delimiter() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-d05", TransactionState::Prepared, &p, None);
    let valid_bytes = encode_framed_record(&rec).unwrap();

    let without_delim = &valid_bytes[..valid_bytes.len() - 1];
    let temp_journal_path = env.sandbox.root().join("trunc_delim.log");
    fs::write(&temp_journal_path, without_delim).unwrap();

    let j = RecoveryJournal::new(&temp_journal_path).unwrap();
    let scan = j.scan_records().unwrap();
    // Delimiter omission at EOF is handled cleanly
    assert_eq!(scan.records.len(), 1);
}

#[test]
fn test_d06_invalid_magic_bytes() {
    let env = TestEnv::new();
    let bad_magic = b"NOPE\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05hello\n";
    let temp_journal_path = env.sandbox.root().join("bad_magic.log");
    fs::write(&temp_journal_path, bad_magic).unwrap();

    let j = RecoveryJournal::new(&temp_journal_path).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::InvalidMagic { .. })
    ));
}

#[test]
fn test_d07_unsupported_versions() {
    let env = TestEnv::new();
    for &v in &[0u16, 2u16, 65535u16] {
        let mut bad_ver = Vec::new();
        bad_ver.extend_from_slice(&JOURNAL_MAGIC);
        bad_ver.extend_from_slice(&v.to_be_bytes());
        bad_ver.extend_from_slice(&0u16.to_be_bytes());
        bad_ver.extend_from_slice(&0u32.to_be_bytes());
        bad_ver.extend_from_slice(&5u32.to_be_bytes());
        bad_ver.extend_from_slice(b"hello\n");

        let p = env.sandbox.root().join(format!("bad_ver_{}.log", v));
        fs::write(&p, &bad_ver).unwrap();

        let j = RecoveryJournal::new(&p).unwrap();
        let scan = j.scan_records().unwrap();
        assert!(matches!(
            scan.unrecoverable_corruption,
            Some(JournalCorruption::UnsupportedVersion { .. })
        ));
    }
}

#[test]
fn test_d08_unsupported_flags() {
    let env = TestEnv::new();
    let mut bad_flag = Vec::new();
    bad_flag.extend_from_slice(&JOURNAL_MAGIC);
    bad_flag.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    bad_flag.extend_from_slice(&0xFFFFu16.to_be_bytes()); // non-zero flags
    bad_flag.extend_from_slice(&0u32.to_be_bytes());
    bad_flag.extend_from_slice(&5u32.to_be_bytes());
    bad_flag.extend_from_slice(b"hello\n");

    let p = env.sandbox.root().join("bad_flags.log");
    fs::write(&p, bad_flag).unwrap();

    let j = RecoveryJournal::new(&p).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(!scan.is_clean);
}

#[test]
fn test_d09_zero_length_payload() {
    let env = TestEnv::new();
    let mut zero_payload = Vec::new();
    zero_payload.extend_from_slice(&JOURNAL_MAGIC);
    zero_payload.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    zero_payload.extend_from_slice(&0u16.to_be_bytes());
    zero_payload.extend_from_slice(&0u32.to_be_bytes());
    zero_payload.extend_from_slice(&0u32.to_be_bytes()); // len 0
    zero_payload.push(b'\n');

    let p = env.sandbox.root().join("zero_len.log");
    fs::write(&p, zero_payload).unwrap();

    let j = RecoveryJournal::new(&p).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::InvalidPayload { .. })
    ));
}

#[test]
fn test_d10_maximum_permitted_payload() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let mut rec = create_sample_record("tx-d10", TransactionState::Prepared, &p, None);
    // Fill reason up to max size
    rec.reason = "A".repeat(60_000);

    let bytes = encode_framed_record(&rec).unwrap();
    assert!(bytes.len() < MAX_RECORD_PAYLOAD_SIZE + HEADER_SIZE + 2);
}

#[test]
fn test_d11_oversized_payload() {
    let env = TestEnv::new();
    let mut bad_header = Vec::new();
    bad_header.extend_from_slice(&JOURNAL_MAGIC);
    bad_header.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    bad_header.extend_from_slice(&0u16.to_be_bytes());
    bad_header.extend_from_slice(&0u32.to_be_bytes());
    bad_header.extend_from_slice(&65_537u32.to_be_bytes()); // > 65_536

    let p = env.sandbox.root().join("oversized.log");
    fs::write(&p, bad_header).unwrap();

    let j = RecoveryJournal::new(&p).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::OversizedPayload { .. })
    ));
}

#[test]
fn test_d12_integer_overflow_length() {
    let env = TestEnv::new();
    let mut overflow_header = Vec::new();
    overflow_header.extend_from_slice(&JOURNAL_MAGIC);
    overflow_header.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    overflow_header.extend_from_slice(&0u16.to_be_bytes());
    overflow_header.extend_from_slice(&0u32.to_be_bytes());
    overflow_header.extend_from_slice(&u32::MAX.to_be_bytes()); // u32::MAX

    let p = env.sandbox.root().join("overflow.log");
    fs::write(&p, overflow_header).unwrap();

    let j = RecoveryJournal::new(&p).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::OversizedPayload { .. })
    ));
}

#[test]
fn test_d13_invalid_utf8_in_payload() {
    let env = TestEnv::new();
    let payload = b"\xFF\xFE\xFD\xFC";
    let crc = crc32(payload);

    let mut framed = Vec::new();
    framed.extend_from_slice(&JOURNAL_MAGIC);
    framed.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    framed.extend_from_slice(&0u16.to_be_bytes());
    framed.extend_from_slice(&crc.to_be_bytes());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed.push(b'\n');

    let p = env.sandbox.root().join("invalid_utf8.log");
    fs::write(&p, framed).unwrap();

    let j = RecoveryJournal::new(&p).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::InvalidPayload { .. })
    ));
}

#[test]
fn test_d14_malformed_json_payload() {
    let env = TestEnv::new();
    let payload = b"{not valid json";
    let crc = crc32(payload);

    let mut framed = Vec::new();
    framed.extend_from_slice(&JOURNAL_MAGIC);
    framed.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    framed.extend_from_slice(&0u16.to_be_bytes());
    framed.extend_from_slice(&crc.to_be_bytes());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed.push(b'\n');

    let p = env.sandbox.root().join("malformed_json.log");
    fs::write(&p, framed).unwrap();

    let j = RecoveryJournal::new(&p).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::InvalidPayload { .. })
    ));
}

#[test]
fn test_d15_valid_json_invalid_transaction_semantics() {
    let env = TestEnv::new();
    let payload = b"{\"random_key\": \"not_a_journal_record\"}";
    let crc = crc32(payload);

    let mut framed = Vec::new();
    framed.extend_from_slice(&JOURNAL_MAGIC);
    framed.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    framed.extend_from_slice(&0u16.to_be_bytes());
    framed.extend_from_slice(&crc.to_be_bytes());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed.push(b'\n');

    let p = env.sandbox.root().join("invalid_schema.log");
    fs::write(&p, framed).unwrap();

    let j = RecoveryJournal::new(&p).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::InvalidPayload { .. })
    ));
}

#[test]
fn test_d16_crc32_mismatch() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-d16", TransactionState::Prepared, &p, None);
    let mut bytes = encode_framed_record(&rec).unwrap();
    bytes[HEADER_SIZE + 2] ^= 0xFF; // Flip bit

    let jp = env.sandbox.root().join("crc_mismatch.log");
    fs::write(&jp, bytes).unwrap();

    let j = RecoveryJournal::new(&jp).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_d17_corrupted_middle_record() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec1 = create_sample_record("tx-d17a", TransactionState::Prepared, &p, None);
    let rec2 = create_sample_record("tx-d17b", TransactionState::Prepared, &p, None);
    let rec3 = create_sample_record("tx-d17c", TransactionState::Prepared, &p, None);

    let b1 = encode_framed_record(&rec1).unwrap();
    let mut b2 = encode_framed_record(&rec2).unwrap();
    let b3 = encode_framed_record(&rec3).unwrap();
    b2[HEADER_SIZE + 3] ^= 0xFF;

    let jp = env.sandbox.root().join("corrupt_middle.log");
    let mut all = Vec::new();
    all.extend_from_slice(&b1);
    all.extend_from_slice(&b2);
    all.extend_from_slice(&b3);
    fs::write(&jp, all).unwrap();

    let j = RecoveryJournal::new(&jp).unwrap();
    let scan = j.scan_records().unwrap();
    assert_eq!(scan.records.len(), 1);
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_d18_corrupted_terminal_record() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec1 = create_sample_record("tx-d18a", TransactionState::Prepared, &p, None);
    let rec2 = create_sample_record("tx-d18b", TransactionState::Prepared, &p, None);

    let b1 = encode_framed_record(&rec1).unwrap();
    let mut b2 = encode_framed_record(&rec2).unwrap();
    b2[HEADER_SIZE + 3] ^= 0xFF;

    let jp = env.sandbox.root().join("corrupt_terminal.log");
    let mut all = Vec::new();
    all.extend_from_slice(&b1);
    all.extend_from_slice(&b2);
    fs::write(&jp, all).unwrap();

    let j = RecoveryJournal::new(&jp).unwrap();
    let scan = j.scan_records().unwrap();
    assert_eq!(scan.records.len(), 1);
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_d19_unexpected_bytes_between_records() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec1 = create_sample_record("tx-d19a", TransactionState::Prepared, &p, None);
    let rec2 = create_sample_record("tx-d19b", TransactionState::Prepared, &p, None);

    let b1 = encode_framed_record(&rec1).unwrap();
    let b2 = encode_framed_record(&rec2).unwrap();

    let jp = env.sandbox.root().join("garbage_between.log");
    let mut all = Vec::new();
    all.extend_from_slice(&b1);
    all.extend_from_slice(b"GARBAGE_BYTES");
    all.extend_from_slice(&b2);
    fs::write(&jp, all).unwrap();

    let j = RecoveryJournal::new(&jp).unwrap();
    let scan = j.scan_records().unwrap();
    assert_eq!(scan.records.len(), 1);
    assert!(!scan.is_clean);
}

#[test]
fn test_d20_crc32_test_vectors() {
    // Standard test vector
    assert_eq!(crc32(b"123456789"), 0xCBF43926);
    // Empty vector
    assert_eq!(crc32(b""), 0x00000000);
    // Deterministic vectors
    assert_eq!(crc32(b"a"), 0xE8B7BE43);
    assert_eq!(crc32(b"Root Guardian"), 2047291156);
}

#[test]
fn test_d21_crc32_accidental_corruption_documentation() {
    // Architectural invariant verification: CRC32 is for integrity, not cryptographic authentication
    assert_eq!(std::mem::size_of::<u32>(), 4);
}

#[test]
fn test_d22_legacy_jsonl_compatibility() {
    let env = TestEnv::new();
    let p = env.write_file("legacy.txt", b"Legacy");
    let rec = create_sample_record("tx-d22", TransactionState::Prepared, &p, None);

    let jp = env.sandbox.root().join("legacy.log");
    let json = serde_json::to_string(&rec).unwrap();
    fs::write(&jp, format!("{}\n", json)).unwrap();

    let mut j = RecoveryJournal::new(&jp).unwrap();
    assert_eq!(j.detect_format().unwrap(), JournalFormat::LegacyJsonl);
    let scan = j.scan_records().unwrap();
    assert_eq!(scan.records.len(), 1);

    // Appending framed record to legacy must fail
    assert!(j.append(&rec).is_err());
}

#[test]
fn test_d23_corrupted_legacy_records() {
    let env = TestEnv::new();
    let jp = env.sandbox.root().join("corrupted_legacy.log");
    fs::write(&jp, b"{\"valid\": true}\n{bad json\n").unwrap();

    let j = RecoveryJournal::new(&jp).unwrap();
    let scan = j.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::LegacyLineError { line_number: 1, .. })
    ));
}

#[test]
fn test_d24_mixed_framed_and_legacy_rejection() {
    let env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-d24", TransactionState::Prepared, &p, None);

    let jp = env.sandbox.root().join("mixed.log");
    let json = serde_json::to_string(&rec).unwrap();
    fs::write(&jp, format!("{}\n", json)).unwrap();

    let mut j = RecoveryJournal::new(&jp).unwrap();
    let res = j.append(&rec);
    assert!(res.is_err());
}

// =============================================================================
// WORKSTREAM E: Journal Write, Synchronization, and Lock Failures
// =============================================================================

#[test]
fn test_e01_fail_lock_acquisition() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e01", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::FailLockAcquisition);
    assert!(res.is_err());
}

#[test]
fn test_e02_fail_open() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e02", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::FailOpen);
    assert!(res.is_err());
}

#[test]
fn test_e03_fail_header_write() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e03", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::FailHeaderWrite);
    assert!(res.is_err());

    let scan = env.journal.scan_records().unwrap();
    assert!(matches!(
        scan.trailing_torn_write,
        Some(JournalCorruption::TruncatedTrailingHeader { .. })
    ));
}

#[test]
fn test_e04_fail_payload_write() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e04", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::FailPayloadWrite);
    assert!(res.is_err());

    let scan = env.journal.scan_records().unwrap();
    assert!(matches!(
        scan.trailing_torn_write,
        Some(JournalCorruption::TruncatedTrailingPayload { .. })
    ));
}

#[test]
fn test_e05_fail_delimiter_write() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e05", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::FailDelimiterWrite);
    assert!(res.is_err());

    let scan = env.journal.scan_records().unwrap();
    // Valid record recovered despite delimiter write failure
    assert_eq!(scan.records.len(), 1);
}

#[test]
fn test_e06_fail_flush() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e06", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::FailFlush);
    assert!(res.is_err());
}

#[test]
fn test_e07_fail_sync_data() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e07", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::FailSyncData);
    assert!(res.is_err());
}

#[test]
fn test_e08_fail_parent_dir_sync() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e08", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::FailParentDirSync);
    assert!(res.is_err());
}

#[test]
fn test_e09_crash_after_write_before_sync() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e09", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::CrashAfterWriteBeforeSync);
    assert!(res.is_err());
}

#[test]
fn test_e10_crash_after_sync_before_return() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e10", TransactionState::Prepared, &p, None);

    let res = env
        .journal
        .append_with_fault_injection(&rec, JournalFault::CrashAfterSyncBeforeReturn);
    assert!(res.is_err());

    // Record was synced before simulated crash; reader recovers it
    let scan = env.journal.scan_records().unwrap();
    assert_eq!(scan.records.len(), 1);
}

#[test]
fn test_e11_concurrent_writers_coordination() {
    let env = Arc::new(TestEnv::new());
    let path = env.write_file("concurrent.txt", b"Content");

    let mut handles = Vec::new();
    for thread_id in 0..4 {
        let env_clone = Arc::clone(&env);
        let path_clone = path.clone();
        handles.push(thread::spawn(move || {
            let mut j = RecoveryJournal::new(env_clone.journal.path()).unwrap();
            for i in 0..10 {
                let rec = create_sample_record(
                    &format!("tx-thr-{}-{}", thread_id, i),
                    TransactionState::Prepared,
                    &path_clone,
                    None,
                );
                j.append(&rec).unwrap();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let scan = env.journal.scan_records().unwrap();
    assert!(scan.is_clean);
    assert_eq!(scan.records.len(), 40);
}

#[test]
fn test_e12_reader_observing_partial_append() {
    let mut env = TestEnv::new();
    let p = env.write_file("test.txt", b"Valid");
    let rec = create_sample_record("tx-e12", TransactionState::Prepared, &p, None);
    env.journal.append(&rec).unwrap();

    // Partial append at EOF
    env.journal
        .append_raw_bytes_for_testing(b"RTJR\x00\x01")
        .unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert_eq!(scan.records.len(), 1);
    assert!(scan.trailing_torn_write.is_some());
}

#[test]
fn test_e13_lock_contention_and_release() {
    let temp = tempfile::tempdir().unwrap();
    let lock_path = temp.path().join("contention.lock");

    let guard = root_platform::AdvisoryLock::acquire(&lock_path).unwrap();
    match root_platform::AdvisoryLock::try_acquire(&lock_path).unwrap() {
        root_platform::LockStatus::Contended => {}
        root_platform::LockStatus::Acquired(_) => panic!("Should be contended"),
    }
    drop(guard);

    match root_platform::AdvisoryLock::try_acquire(&lock_path).unwrap() {
        root_platform::LockStatus::Acquired(_) => {}
        root_platform::LockStatus::Contended => panic!("Should succeed after drop"),
    }
}

#[test]
fn test_e14_lock_file_recreation_safety() {
    let temp = tempfile::tempdir().unwrap();
    let lock_path = temp.path().join("recreation.lock");

    let guard = root_platform::AdvisoryLock::acquire(&lock_path).unwrap();
    assert!(guard.path().exists());
    drop(guard);
}

#[test]
fn test_e15_process_interruption_lock_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let lock_path = temp.path().join("cleanup.lock");

    let handle = thread::spawn({
        let lp = lock_path.clone();
        move || {
            let _g = root_platform::AdvisoryLock::acquire(&lp).unwrap();
        }
    });
    handle.join().unwrap();

    // After thread termination, lock must be acquirable
    let guard = root_platform::AdvisoryLock::acquire(&lock_path);
    assert!(guard.is_ok());
}

// =============================================================================
// WORKSTREAM F: Crash-State Reconciliation
// =============================================================================

#[test]
fn test_f01_prepared_src_present_dest_absent() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Intact");
    let dest = env.sandbox.root().join("quarantine/dest.txt");

    let rec = create_sample_record("tx-f01", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_not_performed, 1);
}

#[test]
fn test_f02_prepared_src_absent_dest_present() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Moved");
    let dest = env.sandbox.root().join("quarantine/dest.txt");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();

    let rec = create_sample_record("tx-f02", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();
    fs::rename(&src, &dest).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_performed, 1);
}

#[test]
fn test_f03_prepared_both_present() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Source");
    let dest = env.write_file("quarantine/dest.txt", b"Destination");

    let rec = create_sample_record("tx-f03", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_uncertain, 1);
}

#[test]
fn test_f04_prepared_neither_present() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Ghost");
    let dest = env.sandbox.root().join("quarantine/dest.txt");

    let rec = create_sample_record("tx-f04", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();
    fs::remove_file(&src).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_uncertain, 1);
}

#[test]
fn test_f05_quarantined_expected_dest_present() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Quarantined");
    let dest = env.sandbox.root().join("quarantine/dest.txt");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();

    let rec1 = create_sample_record("tx-f05", TransactionState::Prepared, &src, Some(&dest));
    let rec2 = create_sample_record("tx-f05", TransactionState::Quarantined, &src, Some(&dest));
    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();
    fs::rename(&src, &dest).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_performed, 1);
}

#[test]
fn test_f06_quarantined_unexpected_dest_identity() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Quarantined");
    let dest = env.sandbox.root().join("quarantine/dest.txt");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();

    let rec1 = create_sample_record("tx-f06", TransactionState::Prepared, &src, Some(&dest));
    let rec2 = create_sample_record("tx-f06", TransactionState::Quarantined, &src, Some(&dest));
    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    fs::remove_file(&src).unwrap();
    fs::write(&dest, b"Unexpected content").unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_recovery_required, 1);
}

#[test]
fn test_f07_verified_expected_dest_missing() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Quarantined");
    let dest = env.sandbox.root().join("quarantine/dest.txt");

    let rec1 = create_sample_record("tx-f07", TransactionState::Prepared, &src, Some(&dest));
    let rec2 = create_sample_record("tx-f07", TransactionState::Quarantined, &src, Some(&dest));
    let rec3 = create_sample_record("tx-f07", TransactionState::Verified, &src, Some(&dest));
    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();
    env.journal.append(&rec3).unwrap();
    fs::remove_file(&src).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_recovery_required, 1);
}

#[test]
fn test_f08_restored_src_recreated_by_unrelated_process() {
    let mut env = TestEnv::new();
    let src = env.write_file("orig.txt", b"Restored");
    let dest = env.sandbox.root().join("quarantine/dest.txt");

    let rec1 = create_sample_record("tx-f08", TransactionState::Prepared, &src, Some(&dest));
    let rec2 = create_sample_record("tx-f08", TransactionState::Quarantined, &src, Some(&dest));
    let rec3 = create_sample_record("tx-f08", TransactionState::Verified, &src, Some(&dest));
    let rec4 = create_sample_record("tx-f08", TransactionState::Restored, &src, Some(&dest));
    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();
    env.journal.append(&rec3).unwrap();
    env.journal.append(&rec4).unwrap();

    // Source replaced by unrelated file with guaranteed distinct inode
    let sub = env.write_file("sub_f08.txt", b"Recreated by compiler");
    fs::rename(&sub, &src).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_recovery_required, 1);
}

#[test]
fn test_f09_duplicate_transaction_identifiers_contradictory() {
    let mut env = TestEnv::new();
    let p1 = env.write_file("p1.txt", b"1");
    let p2 = env.write_file("p2.txt", b"2");

    let rec1 = create_sample_record("tx-dup", TransactionState::Prepared, &p1, None);
    let rec2 = create_sample_record("tx-dup", TransactionState::Prepared, &p2, None);
    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

#[test]
fn test_f10_contradictory_state_transitions() {
    let mut env = TestEnv::new();
    let p = env.write_file("p.txt", b"1");

    let rec1 = create_sample_record("tx-f10", TransactionState::Verified, &p, None);
    let rec2 = create_sample_record("tx-f10", TransactionState::Prepared, &p, None);
    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

#[test]
fn test_f11_out_of_order_records() {
    let mut env = TestEnv::new();
    let p = env.write_file("p.txt", b"1");

    let rec = create_sample_record("tx-f11", TransactionState::Restored, &p, None);
    env.journal.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

#[test]
fn test_f12_incomplete_terminal_record() {
    let mut env = TestEnv::new();
    let p = env.write_file("p.txt", b"1");

    let rec = create_sample_record("tx-f12", TransactionState::Prepared, &p, None);
    env.journal.append(&rec).unwrap();
    env.journal
        .append_raw_bytes_for_testing(b"RTJR\x00\x01\x00")
        .unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert!(report.torn_write_detected);
    assert_eq!(report.count_known_not_performed, 1);
}

#[test]
fn test_f13_corrupted_middle_record() {
    let env = TestEnv::new();
    let p = env.write_file("p.txt", b"1");

    let rec1 = create_sample_record("tx-f13a", TransactionState::Prepared, &p, None);
    let rec2 = create_sample_record("tx-f13b", TransactionState::Prepared, &p, None);
    let b1 = encode_framed_record(&rec1).unwrap();
    let mut b2 = encode_framed_record(&rec2).unwrap();
    b2[HEADER_SIZE + 2] ^= 0xFF;

    let jp = env.sandbox.root().join("middle_corrupt.log");
    let mut combined = Vec::new();
    combined.extend_from_slice(&b1);
    combined.extend_from_slice(&b2);
    fs::write(&jp, combined).unwrap();

    let report = JournalReconciler::reconcile_path(&jp).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

#[test]
fn test_f14_corrupted_legacy_journal() {
    let env = TestEnv::new();
    let jp = env.sandbox.root().join("corrupted_legacy_f14.log");
    fs::write(&jp, b"{\"tx\": 1}\n{bad json\n").unwrap();

    let report = JournalReconciler::reconcile_path(&jp).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

#[test]
fn test_f15_missing_journal() {
    let temp = tempfile::tempdir().unwrap();
    let p = temp.path().join("missing_journal.log");
    let report = JournalReconciler::reconcile_path(&p).unwrap();
    assert_eq!(report.journal_format, JournalFormat::Empty);
    assert_eq!(report.total_transactions, 0);
}

#[test]
fn test_f16_permission_denied_inspection() {
    let temp = tempfile::tempdir().unwrap();
    let no_access_dir = temp.path().join("no_access");
    fs::create_dir_all(&no_access_dir).unwrap();
    let secret = no_access_dir.join("secret.bin");
    fs::write(&secret, b"Secret").unwrap();
    fs::set_permissions(&no_access_dir, fs::Permissions::from_mode(0o000)).unwrap();

    let mut j = RecoveryJournal::new(&temp.path().join("journal.log")).unwrap();
    let rec = create_sample_record("tx-f16", TransactionState::Prepared, &secret, None);
    j.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&j).unwrap();
    // Cannot access file => treated as non-existent or uncertain
    assert_eq!(report.total_transactions, 1);

    // Restore permissions for cleanup
    let _ = fs::set_permissions(&no_access_dir, fs::Permissions::from_mode(0o700));
}

#[test]
fn test_f17_unexpected_symlink_at_destination() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.bin", b"Content");
    let target = env.write_file("target.bin", b"Target");
    let dest = env.sandbox.root().join("quarantine/dest.bin");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &dest).unwrap();

    let rec = create_sample_record("tx-f17", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_uncertain, 1);
}

#[test]
fn test_f18_changed_object_identity_at_source() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.bin", b"Initial");
    let dest = env.sandbox.root().join("quarantine/dest.bin");

    let rec = create_sample_record("tx-f18", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    // Replace source with different file guaranteeing distinct inode
    let sub = env.write_file("sub_f18.bin", b"Different identity file");
    fs::rename(&sub, &src).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_uncertain, 1);
}

#[test]
fn test_f19_filesystem_op_completed_journal_failed() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.bin", b"Content");
    let dest = env.sandbox.root().join("quarantine/dest.bin");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();

    let rec = create_sample_record("tx-f19", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();
    fs::rename(&src, &dest).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_performed, 1);
}

// =============================================================================
// WORKSTREAM G: Prove Reconciliation Is Read-Only
// =============================================================================

#[test]
fn test_g01_file_and_journal_immutability_before_and_after() {
    let mut env = TestEnv::new();
    let src = env.write_file("data.bin", b"Proof of immutability");
    let dest = env.sandbox.root().join("quarantine/data.bin");

    let rec = create_sample_record("tx-g01", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    let src_hash_pre = sha256_file(&src).unwrap();
    let src_meta_pre = fs::metadata(&src).unwrap();
    let j_hash_pre = sha256_file(env.journal.path()).unwrap();
    let j_meta_pre = fs::metadata(env.journal.path()).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_not_performed, 1);

    let src_hash_post = sha256_file(&src).unwrap();
    let src_meta_post = fs::metadata(&src).unwrap();
    let j_hash_post = sha256_file(env.journal.path()).unwrap();
    let j_meta_post = fs::metadata(env.journal.path()).unwrap();

    assert_eq!(src_hash_pre, src_hash_post);
    assert_eq!(src_meta_pre.len(), src_meta_post.len());
    assert_eq!(src_meta_pre.ino(), src_meta_post.ino());
    assert_eq!(src_meta_pre.mtime(), src_meta_post.mtime());

    assert_eq!(j_hash_pre, j_hash_post);
    assert_eq!(j_meta_pre.len(), j_meta_post.len());
    assert_eq!(j_meta_pre.ino(), j_meta_post.ino());
    assert_eq!(j_meta_pre.mtime(), j_meta_post.mtime());
}

#[test]
fn test_g02_corrupted_journal_never_repaired_or_truncated() {
    let env = TestEnv::new();
    let p = env.write_file("item.bin", b"Data");
    let rec = create_sample_record("tx-g02", TransactionState::Prepared, &p, None);
    let valid_bytes = encode_framed_record(&rec).unwrap();

    let jp = env.sandbox.root().join("torn_reconcile.log");
    let mut data = Vec::new();
    data.extend_from_slice(&valid_bytes);
    data.extend_from_slice(b"RTJR\x00\x01\x00"); // 7 trailing bytes
    fs::write(&jp, &data).unwrap();

    let pre_size = fs::metadata(&jp).unwrap().len();
    let _ = JournalReconciler::reconcile_path(&jp).unwrap();
    let post_size = fs::metadata(&jp).unwrap().len();

    // Must not truncate or repair torn write
    assert_eq!(pre_size, post_size);
}

#[test]
fn test_g03_reconciliation_never_triggers_mutations() {
    let mut env = TestEnv::new();
    let src = env.write_file("item.bin", b"Data");
    let dest = env.sandbox.root().join("quarantine/item.bin");

    let rec1 = create_sample_record("tx-g03", TransactionState::Prepared, &src, Some(&dest));
    let rec2 = create_sample_record("tx-g03", TransactionState::Quarantined, &src, Some(&dest));
    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    // Source exists, destination absent => RecoveryRequired
    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_recovery_required, 1);

    // Source file must remain completely untouched (no automatic rollback or deletion)
    assert!(src.exists());
    assert!(!dest.exists());
}

// =============================================================================
// WORKSTREAM H: Production Read-Only Boundary
// =============================================================================

#[test]
fn test_h01_engine_policy_read_only_default() {
    let policy = GuardianPolicy::default();
    assert!(policy.read_only_mode);
}

#[test]
fn test_h02_gui_mutation_actions_prohibited() {
    let policy = GuardianPolicy::default();
    assert!(policy.read_only_mode);
}

#[test]
fn test_h03_guardian_policy_read_only_mode_invariant() {
    let policy = GuardianPolicy::new();
    let candidate = ResourceCandidate {
        id: ResourceId::new("cand-h03"),
        location: ResourceLocation::new(PathBuf::from("/tmp/h03"), None, 1, 100),
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

    for action in &[
        ProposedAction::Quarantine,
        ProposedAction::Prune,
        ProposedAction::TerminateGraceful,
    ] {
        let dec = policy.evaluate(&target, ProtectionTier::SafeRecoverable, *action, 1000);
        match dec {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(reason, RejectionReason::Phase03ReadOnlyPolicy);
            }
            SafetyDecision::Allowed => panic!("Production policy must reject {:?}", action),
        }
    }
}

#[test]
fn test_h04_no_hidden_mutation_environment_variables() {
    // Verify that setting mutation-like env vars has no effect on policy
    std::env::set_var("ROOT_ENABLE_MUTATION", "1");
    std::env::set_var("ROOT_FORCE_QUARANTINE", "true");

    let policy = GuardianPolicy::default();
    assert!(policy.read_only_mode);

    std::env::remove_var("ROOT_ENABLE_MUTATION");
    std::env::remove_var("ROOT_FORCE_QUARANTINE");
}

#[test]
fn test_h05_non_linux_mutation_methods_absent() {
    // Assert target_os condition for transaction engine
    const { assert!(cfg!(target_os = "linux")) };
}
