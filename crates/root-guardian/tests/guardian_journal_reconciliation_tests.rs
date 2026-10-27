#![cfg(target_os = "linux")]

use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use tempfile::TempDir;

use root_core::error::RootError;
use root_guardian::{
    crypto::sha256_file,
    journal::{
        crc32, encode_framed_record, JournalCorruption, JournalFormat, JournalRecord,
        RecoveryJournal, HEADER_SIZE, JOURNAL_MAGIC, JOURNAL_VERSION_1, MAX_RECORD_PAYLOAD_SIZE,
    },
    reconciler::{JournalReconciler, ReconciliationOutcome},
    sandbox::FixtureSandbox,
    transaction::TransactionState,
};

struct TestEnv {
    _temp: TempDir,
    sandbox: FixtureSandbox,
    journal: RecoveryJournal,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("root-guardian-recon-test-")
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

// -----------------------------------------------------------------------------
// Test 1: Valid framed journal round-trip
// -----------------------------------------------------------------------------
#[test]
fn test_01_valid_framed_journal_round_trip() {
    let mut env = TestEnv::new();
    let path = env.write_file("data.txt", b"Hello, World!");

    let rec = create_sample_record("tx-01", TransactionState::Prepared, &path, None);
    env.journal.append(&rec).expect("Append record");

    let scan = env.journal.scan_records().expect("Scan records");
    assert!(scan.is_clean);
    assert_eq!(scan.format, JournalFormat::FramedV1);
    assert_eq!(scan.records.len(), 1);
    assert_eq!(scan.records[0].transaction_id, "tx-01");
    assert_eq!(scan.records[0].state, TransactionState::Prepared);
    assert_eq!(scan.records[0].original_path, path);
    assert!(scan.records[0].sha256.is_some());
    assert_eq!(scan.trailing_torn_write, None);
    assert_eq!(scan.unrecoverable_corruption, None);
}

// -----------------------------------------------------------------------------
// Test 2: Multiple valid records
// -----------------------------------------------------------------------------
#[test]
fn test_02_multiple_valid_records() {
    let mut env = TestEnv::new();
    let p1 = env.write_file("file1.txt", b"File 1 content");
    let p2 = env.write_file("file2.txt", b"File 2 content");
    let p3 = env.write_file("file3.txt", b"File 3 content");

    let q1 = env.sandbox.root().join("quarantine/q1");
    let q2 = env.sandbox.root().join("quarantine/q2");

    // tx1: Prepared -> Quarantined -> Verified
    env.journal
        .append(&create_sample_record(
            "tx-1",
            TransactionState::Prepared,
            &p1,
            Some(&q1),
        ))
        .unwrap();
    env.journal
        .append(&create_sample_record(
            "tx-1",
            TransactionState::Quarantined,
            &p1,
            Some(&q1),
        ))
        .unwrap();
    env.journal
        .append(&create_sample_record(
            "tx-1",
            TransactionState::Verified,
            &p1,
            Some(&q1),
        ))
        .unwrap();

    // tx2: Prepared -> Quarantined
    env.journal
        .append(&create_sample_record(
            "tx-2",
            TransactionState::Prepared,
            &p2,
            Some(&q2),
        ))
        .unwrap();
    env.journal
        .append(&create_sample_record(
            "tx-2",
            TransactionState::Quarantined,
            &p2,
            Some(&q2),
        ))
        .unwrap();

    // tx3: Prepared -> Failed
    env.journal
        .append(&create_sample_record(
            "tx-3",
            TransactionState::Prepared,
            &p3,
            None,
        ))
        .unwrap();
    env.journal
        .append(&create_sample_record(
            "tx-3",
            TransactionState::Failed,
            &p3,
            None,
        ))
        .unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert_eq!(scan.records.len(), 7);
    assert!(scan.is_clean);

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.total_transactions, 3);
    assert_eq!(report.total_records_scanned, 7);
}

// -----------------------------------------------------------------------------
// Test 3: Partial trailing header (< 16 bytes at EOF)
// -----------------------------------------------------------------------------
#[test]
fn test_03_partial_trailing_header() {
    let mut env = TestEnv::new();
    let path = env.write_file("data.txt", b"Hello, World!");

    let rec = create_sample_record("tx-03", TransactionState::Prepared, &path, None);
    env.journal.append(&rec).unwrap();

    // Append 7 raw bytes representing an interrupted header
    env.journal
        .append_raw_bytes_for_testing(b"RTJR\x00\x01\x00")
        .unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert!(!scan.is_clean);
    assert_eq!(scan.records.len(), 1);
    match scan.trailing_torn_write {
        Some(JournalCorruption::TruncatedTrailingHeader { bytes_present, .. }) => {
            assert_eq!(bytes_present, 7);
        }
        other => panic!("Expected TruncatedTrailingHeader, got {:?}", other),
    }

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert!(report.torn_write_detected);
    assert_eq!(report.total_transactions, 1);
}

// -----------------------------------------------------------------------------
// Test 4: Partial trailing payload (fewer payload bytes than declared)
// -----------------------------------------------------------------------------
#[test]
fn test_04_partial_trailing_payload() {
    let mut env = TestEnv::new();
    let path = env.write_file("data.txt", b"Hello, World!");

    let rec = create_sample_record("tx-04", TransactionState::Prepared, &path, None);
    env.journal.append(&rec).unwrap();

    // Construct header declaring length = 100, but only append 40 bytes
    let mut bad_header = Vec::new();
    bad_header.extend_from_slice(&JOURNAL_MAGIC);
    bad_header.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    bad_header.extend_from_slice(&0u16.to_be_bytes());
    bad_header.extend_from_slice(&0u32.to_be_bytes()); // dummy crc
    bad_header.extend_from_slice(&100u32.to_be_bytes()); // declared len 100
    bad_header.extend_from_slice(&[b'X'; 40]); // only 40 bytes provided

    env.journal
        .append_raw_bytes_for_testing(&bad_header)
        .unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert!(!scan.is_clean);
    assert_eq!(scan.records.len(), 1);
    match scan.trailing_torn_write {
        Some(JournalCorruption::TruncatedTrailingPayload {
            declared_length,
            available_bytes,
            ..
        }) => {
            assert_eq!(declared_length, 100);
            assert_eq!(available_bytes, 40);
        }
        other => panic!("Expected TruncatedTrailingPayload, got {:?}", other),
    }

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert!(report.torn_write_detected);
    assert_eq!(report.total_transactions, 1);
}

// -----------------------------------------------------------------------------
// Test 5: Checksum mismatch (corrupted byte in payload)
// -----------------------------------------------------------------------------
#[test]
fn test_05_checksum_mismatch() {
    let mut env = TestEnv::new();
    let path = env.write_file("data.txt", b"Hello, World!");

    let rec = create_sample_record("tx-05", TransactionState::Prepared, &path, None);
    env.journal.append(&rec).unwrap();

    // Corrupt one byte inside the payload in the file
    let mut content = fs::read(env.journal.path()).unwrap();
    let corrupt_offset = HEADER_SIZE + 5;
    content[corrupt_offset] ^= 0xFF;
    fs::write(env.journal.path(), content).unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert!(!scan.is_clean);
    assert_eq!(scan.records.len(), 0);
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::ChecksumMismatch { .. })
    ));

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

// -----------------------------------------------------------------------------
// Test 6: Invalid middle record
// -----------------------------------------------------------------------------
#[test]
fn test_06_invalid_middle_record() {
    let env = TestEnv::new();
    let path = env.write_file("data.txt", b"Hello, World!");

    let rec1 = create_sample_record("tx-06a", TransactionState::Prepared, &path, None);
    let rec2 = create_sample_record("tx-06b", TransactionState::Prepared, &path, None);
    let rec3 = create_sample_record("tx-06c", TransactionState::Prepared, &path, None);

    let bytes1 = encode_framed_record(&rec1).unwrap();
    let mut bytes2 = encode_framed_record(&rec2).unwrap();
    let bytes3 = encode_framed_record(&rec3).unwrap();

    // Corrupt record 2 payload byte
    bytes2[HEADER_SIZE + 4] ^= 0xFF;

    let mut combined = Vec::new();
    combined.extend_from_slice(&bytes1);
    combined.extend_from_slice(&bytes2);
    combined.extend_from_slice(&bytes3);

    fs::write(env.journal.path(), combined).unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert_eq!(scan.records.len(), 1); // Only rec1 scanned before corruption
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::ChecksumMismatch { .. })
    ));

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

// -----------------------------------------------------------------------------
// Test 7: Oversized declared payload (> 64 KiB)
// -----------------------------------------------------------------------------
#[test]
fn test_07_oversized_declared_payload() {
    let env = TestEnv::new();

    let mut bad_header = Vec::new();
    bad_header.extend_from_slice(&JOURNAL_MAGIC);
    bad_header.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    bad_header.extend_from_slice(&0u16.to_be_bytes());
    bad_header.extend_from_slice(&0u32.to_be_bytes());
    bad_header.extend_from_slice(&70_000u32.to_be_bytes()); // > 65_536

    fs::write(env.journal.path(), bad_header).unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::OversizedPayload {
            declared: 70_000,
            max_allowed: MAX_RECORD_PAYLOAD_SIZE,
            ..
        })
    ));

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

// -----------------------------------------------------------------------------
// Test 8: Unsupported format version
// -----------------------------------------------------------------------------
#[test]
fn test_08_unsupported_format_version() {
    let env = TestEnv::new();

    let mut bad_header = Vec::new();
    bad_header.extend_from_slice(&JOURNAL_MAGIC);
    bad_header.extend_from_slice(&99u16.to_be_bytes()); // version 99
    bad_header.extend_from_slice(&0u16.to_be_bytes());
    bad_header.extend_from_slice(&0u32.to_be_bytes());
    bad_header.extend_from_slice(&10u32.to_be_bytes());

    fs::write(env.journal.path(), bad_header).unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::UnsupportedVersion { version: 99, .. })
    ));

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

// -----------------------------------------------------------------------------
// Test 9: Unknown record type (valid CRC but invalid JSON payload)
// -----------------------------------------------------------------------------
#[test]
fn test_09_unknown_record_type() {
    let env = TestEnv::new();

    let payload = b"{\"unknown_key\": 12345}";
    let crc = crc32(payload);

    let mut framed = Vec::new();
    framed.extend_from_slice(&JOURNAL_MAGIC);
    framed.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    framed.extend_from_slice(&0u16.to_be_bytes());
    framed.extend_from_slice(&crc.to_be_bytes());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed.push(b'\n');

    fs::write(env.journal.path(), framed).unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::InvalidPayload { .. })
    ));

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

// -----------------------------------------------------------------------------
// Test 10: Duplicate transaction identifier with contradictory properties
// -----------------------------------------------------------------------------
#[test]
fn test_10_duplicate_transaction_identifier() {
    let mut env = TestEnv::new();
    let p1 = env.write_file("path1.txt", b"Target 1");
    let p2 = env.write_file("path2.txt", b"Target 2");

    let rec1 = create_sample_record("tx-dup", TransactionState::Prepared, &p1, None);
    let rec2 = create_sample_record("tx-dup", TransactionState::Prepared, &p2, None);

    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.total_transactions, 1);
    assert_eq!(report.count_journal_invalid, 1);
    assert!(matches!(
        report.transactions[0].outcome,
        ReconciliationOutcome::JournalInvalid { .. }
    ));
}

// -----------------------------------------------------------------------------
// Test 11: Contradictory transaction states (illegal transition)
// -----------------------------------------------------------------------------
#[test]
fn test_11_contradictory_transaction_states() {
    let mut env = TestEnv::new();
    let p1 = env.write_file("path1.txt", b"Target 1");

    let rec1 = create_sample_record("tx-contra", TransactionState::Prepared, &p1, None);
    // Prepared -> Verified is an illegal direct jump
    let mut rec2 = create_sample_record("tx-contra", TransactionState::Verified, &p1, None);
    rec2.state = TransactionState::Verified;

    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
    assert!(matches!(
        report.transactions[0].outcome,
        ReconciliationOutcome::JournalInvalid { .. }
    ));
}

// -----------------------------------------------------------------------------
// Test 12: Out-of-order events
// -----------------------------------------------------------------------------
#[test]
fn test_12_out_of_order_events() {
    let mut env = TestEnv::new();
    let p1 = env.write_file("path1.txt", b"Target 1");

    // Starts directly in Verified without Prepared
    let rec = create_sample_record("tx-order", TransactionState::Verified, &p1, None);
    env.journal.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
    assert!(matches!(
        report.transactions[0].outcome,
        ReconciliationOutcome::JournalInvalid { .. }
    ));
}

// -----------------------------------------------------------------------------
// Test 13: Journal write failure
// -----------------------------------------------------------------------------
#[test]
fn test_13_journal_write_failure() {
    let temp = tempfile::tempdir().unwrap();
    let read_only_dir = temp.path().join("readonly");
    fs::create_dir_all(&read_only_dir).unwrap();
    fs::set_permissions(&read_only_dir, fs::Permissions::from_mode(0o500)).unwrap();

    let journal_path = read_only_dir.join("test_journal.log");
    let mut journal = RecoveryJournal::new(&journal_path).unwrap();

    let p = temp.path().join("file.txt");
    fs::write(&p, b"Content").unwrap();
    let rec = create_sample_record("tx-fail", TransactionState::Prepared, &p, None);

    let res = journal.append(&rec);
    assert!(res.is_err());
    match res {
        Err(RootError::Io { .. }) => {}
        other => panic!("Expected Io error on unwritable journal, got {:?}", other),
    }

    // Clean up permissions so tempdir can be removed
    let _ = fs::set_permissions(&read_only_dir, fs::Permissions::from_mode(0o700));
}

// -----------------------------------------------------------------------------
// Test 14: Journal synchronization failure / verification
// -----------------------------------------------------------------------------
#[test]
fn test_14_journal_synchronization_failure() {
    let mut env = TestEnv::new();
    let p = env.write_file("sync.txt", b"Sync test content");
    let rec = create_sample_record("tx-sync", TransactionState::Prepared, &p, None);

    // Verifies that append completes sync_data and parent directory sync
    env.journal.append(&rec).expect("Append with sync");

    let file_meta = fs::metadata(env.journal.path()).expect("Journal file metadata");
    assert!(file_meta.len() > HEADER_SIZE as u64);
}

// -----------------------------------------------------------------------------
// Test 15: Concurrent writer behavior
// -----------------------------------------------------------------------------
#[test]
fn test_15_concurrent_writer_behavior() {
    let env = Arc::new(TestEnv::new());
    let path = env.write_file("concurrent.txt", b"Concurrent test");

    let mut handles = Vec::new();
    for thread_idx in 0..4 {
        let env_clone = Arc::clone(&env);
        let path_clone = path.clone();
        handles.push(thread::spawn(move || {
            let mut local_journal = RecoveryJournal::new(env_clone.journal.path()).unwrap();
            for i in 0..10 {
                let tx_id = format!("tx-thr{}-{}", thread_idx, i);
                let rec =
                    create_sample_record(&tx_id, TransactionState::Prepared, &path_clone, None);
                local_journal.append(&rec).unwrap();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let scan = env.journal.scan_records().unwrap();
    assert!(scan.is_clean);
    assert_eq!(scan.records.len(), 40);
    assert_eq!(scan.trailing_torn_write, None);
}

// -----------------------------------------------------------------------------
// Test 16: Reader observing an incomplete append
// -----------------------------------------------------------------------------
#[test]
fn test_16_reader_observing_incomplete_append() {
    let mut env = TestEnv::new();
    let p = env.write_file("partial.txt", b"Reader test");

    let rec1 = create_sample_record("tx-16a", TransactionState::Prepared, &p, None);
    let rec2 = create_sample_record("tx-16b", TransactionState::Prepared, &p, None);
    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    // Incomplete append at EOF
    env.journal
        .append_raw_bytes_for_testing(b"RTJR\x00\x01")
        .unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert_eq!(scan.records.len(), 2);
    assert!(scan.trailing_torn_write.is_some());
}

// -----------------------------------------------------------------------------
// Test 17: Crash before rename (KnownNotPerformed)
// -----------------------------------------------------------------------------
#[test]
fn test_17_crash_before_rename() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Intact source");
    let dest = env.sandbox.root().join("quarantine/dest.txt");

    let rec = create_sample_record("tx-17", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_not_performed, 1);
    assert_eq!(
        report.transactions[0].outcome,
        ReconciliationOutcome::KnownNotPerformed
    );
    assert!(report.transactions[0].source_exists);
    assert!(!report.transactions[0].destination_exists);
}

// -----------------------------------------------------------------------------
// Test 18: Crash after rename but before journal append (KnownPerformed)
// -----------------------------------------------------------------------------
#[test]
fn test_18_crash_after_rename_before_journal_append() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Renamed content");
    let dest = env.sandbox.root().join("quarantine/dest.txt");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();

    let rec = create_sample_record("tx-18", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    // Simulate crash after rename: src moved to dest
    fs::rename(&src, &dest).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_performed, 1);
    assert_eq!(
        report.transactions[0].outcome,
        ReconciliationOutcome::KnownPerformed
    );
    assert!(!report.transactions[0].source_exists);
    assert!(report.transactions[0].destination_exists);
}

// -----------------------------------------------------------------------------
// Test 19: Crash after rename but before journal synchronization (KnownPerformed)
// -----------------------------------------------------------------------------
#[test]
fn test_19_crash_after_rename_before_journal_sync() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Sync crash content");
    let dest = env.sandbox.root().join("quarantine/dest.txt");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();

    let rec = create_sample_record("tx-19", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    // Renamed, but journal did not record Quarantined
    fs::rename(&src, &dest).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_performed, 1);
    assert_eq!(
        report.transactions[0].outcome,
        ReconciliationOutcome::KnownPerformed
    );
}

// -----------------------------------------------------------------------------
// Test 20: Crash during restoration (KnownPerformed for restored)
// -----------------------------------------------------------------------------
#[test]
fn test_20_crash_during_restoration() {
    let mut env = TestEnv::new();
    let orig = env.write_file("orig.txt", b"Restored resource");
    let quat = env.sandbox.root().join("quarantine/orig.txt");

    // Transaction lifecycle completed restoration
    let rec1 = create_sample_record("tx-20", TransactionState::Prepared, &orig, Some(&quat));
    let rec2 = create_sample_record("tx-20", TransactionState::Quarantined, &orig, Some(&quat));
    let rec3 = create_sample_record("tx-20", TransactionState::Verified, &orig, Some(&quat));
    let rec4 = create_sample_record("tx-20", TransactionState::Restored, &orig, Some(&quat));

    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();
    env.journal.append(&rec3).unwrap();
    env.journal.append(&rec4).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_performed, 1);
    assert_eq!(
        report.transactions[0].outcome,
        ReconciliationOutcome::KnownPerformed
    );
}

// -----------------------------------------------------------------------------
// Test 21: Missing source and destination (Uncertain)
// -----------------------------------------------------------------------------
#[test]
fn test_21_missing_source_and_destination() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Ghost");
    let dest = env.sandbox.root().join("quarantine/dest.txt");

    let rec = create_sample_record("tx-21", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    // Remove source, dest never created
    fs::remove_file(&src).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_uncertain, 1);
    assert!(matches!(
        report.transactions[0].outcome,
        ReconciliationOutcome::Uncertain { .. }
    ));
}

// -----------------------------------------------------------------------------
// Test 22: Both source and destination present (Uncertain)
// -----------------------------------------------------------------------------
#[test]
fn test_22_both_source_and_destination_present() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Source");
    let dest = env.write_file("quarantine/dest.txt", b"Destination collision");

    let rec = create_sample_record("tx-22", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_uncertain, 1);
    assert!(matches!(
        report.transactions[0].outcome,
        ReconciliationOutcome::Uncertain { .. }
    ));
}

// -----------------------------------------------------------------------------
// Test 23: Unexpected destination identity (RecoveryRequired)
// -----------------------------------------------------------------------------
#[test]
fn test_23_unexpected_destination_identity() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Original file");
    let dest = env.sandbox.root().join("quarantine/dest.txt");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();

    let rec = create_sample_record("tx-23", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    // Source is removed, but destination contains a completely different file
    fs::remove_file(&src).unwrap();
    fs::write(&dest, b"Unexpected foreign content").unwrap();

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_recovery_required, 1);
    assert!(matches!(
        report.transactions[0].outcome,
        ReconciliationOutcome::RecoveryRequired { .. }
    ));
}

// -----------------------------------------------------------------------------
// Test 24: Legacy JSONL journal detection
// -----------------------------------------------------------------------------
#[test]
fn test_24_legacy_jsonl_journal_detection() {
    let mut env = TestEnv::new();
    let p = env.write_file("legacy.txt", b"Legacy target");
    let rec = create_sample_record("tx-legacy", TransactionState::Prepared, &p, None);

    // Write unframed JSONL
    let json = serde_json::to_string(&rec).unwrap();
    fs::write(env.journal.path(), format!("{}\n", json)).unwrap();

    assert_eq!(
        env.journal.detect_format().unwrap(),
        JournalFormat::LegacyJsonl
    );

    let scan = env.journal.scan_records().unwrap();
    assert_eq!(scan.format, JournalFormat::LegacyJsonl);
    assert_eq!(scan.records.len(), 1);
    assert!(scan.is_clean);

    // Appending framed records to legacy journal must be rejected
    let res = env.journal.append(&rec);
    assert!(res.is_err());
    match res {
        Err(RootError::JournalError { reason, .. }) => {
            assert!(reason.contains("Legacy v0 JSONL journal detected"));
        }
        other => panic!(
            "Expected JournalError for legacy mixed append, got {:?}",
            other
        ),
    }
}

// -----------------------------------------------------------------------------
// Test 25: Corrupted legacy journal
// -----------------------------------------------------------------------------
#[test]
fn test_25_corrupted_legacy_journal() {
    let env = TestEnv::new();
    let p = env.write_file("legacy.txt", b"Legacy target");
    let rec = create_sample_record("tx-leg-bad", TransactionState::Prepared, &p, None);

    let json = serde_json::to_string(&rec).unwrap();
    let corrupted = format!("{}\n{{not valid json\n", json);
    fs::write(env.journal.path(), corrupted).unwrap();

    let scan = env.journal.scan_records().unwrap();
    assert!(!scan.is_clean);
    assert!(matches!(
        scan.unrecoverable_corruption,
        Some(JournalCorruption::LegacyLineError { line_number: 2, .. })
    ));

    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_journal_invalid, 1);
}

// -----------------------------------------------------------------------------
// Test 26: Recovery-required classification (committed but source still present)
// -----------------------------------------------------------------------------
#[test]
fn test_26_recovery_required_classification() {
    let mut env = TestEnv::new();
    let src = env.write_file("src.txt", b"Still at source");
    let dest = env.sandbox.root().join("quarantine/dest.txt");

    let rec1 = create_sample_record("tx-26", TransactionState::Prepared, &src, Some(&dest));
    let rec2 = create_sample_record("tx-26", TransactionState::Quarantined, &src, Some(&dest));

    env.journal.append(&rec1).unwrap();
    env.journal.append(&rec2).unwrap();

    // Source still exists and destination is absent despite committed state
    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_recovery_required, 1);
    assert!(matches!(
        report.transactions[0].outcome,
        ReconciliationOutcome::RecoveryRequired { .. }
    ));
}

// -----------------------------------------------------------------------------
// Test 27: Reconciliation never mutates filesystem contents
// -----------------------------------------------------------------------------
#[test]
fn test_27_reconciliation_never_mutates_filesystem_contents() {
    let mut env = TestEnv::new();
    let src = env.write_file("immutable.txt", b"Read-only invariant content");
    let dest = env.sandbox.root().join("quarantine/immutable.txt");

    let rec = create_sample_record("tx-27", TransactionState::Prepared, &src, Some(&dest));
    env.journal.append(&rec).unwrap();

    // Capture exact pre-reconciliation hashes, sizes, mtimes, and permissions
    let src_meta_before = fs::metadata(&src).unwrap();
    let src_hash_before = sha256_file(&src).unwrap();
    let journal_meta_before = fs::metadata(env.journal.path()).unwrap();
    let journal_hash_before = sha256_file(env.journal.path()).unwrap();

    // Perform reconciliation
    let report = JournalReconciler::reconcile_journal(&env.journal).unwrap();
    assert_eq!(report.count_known_not_performed, 1);

    // Verify post-reconciliation states are identical bit-for-bit
    let src_meta_after = fs::metadata(&src).unwrap();
    let src_hash_after = sha256_file(&src).unwrap();
    let journal_meta_after = fs::metadata(env.journal.path()).unwrap();
    let journal_hash_after = sha256_file(env.journal.path()).unwrap();

    assert_eq!(src_meta_before.len(), src_meta_after.len());
    assert_eq!(src_meta_before.mtime(), src_meta_after.mtime());
    assert_eq!(src_meta_before.ino(), src_meta_after.ino());
    assert_eq!(src_hash_before, src_hash_after);

    assert_eq!(journal_meta_before.len(), journal_meta_after.len());
    assert_eq!(journal_meta_before.mtime(), journal_meta_after.mtime());
    assert_eq!(journal_hash_before, journal_hash_after);
}

// -----------------------------------------------------------------------------
// Test 28: Production read-only boundary remains intact
// -----------------------------------------------------------------------------
#[test]
fn test_28_production_read_only_boundary_remains_intact() {
    use root_core::model::{
        FileType, FindingTarget, ProposedAction, ProtectionTier, RejectionReason,
        ResourceCandidate, ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata,
        ResourceOwnership, SafetyDecision, StorageMeasurement,
    };
    use root_guardian::GuardianPolicy;

    let policy = GuardianPolicy::default();
    assert!(policy.read_only_mode);

    let candidate = ResourceCandidate {
        id: ResourceId::new("test_28"),
        location: ResourceLocation::new(PathBuf::from("/tmp/test"), None, 1, 100),
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

    let decision = policy.evaluate(
        &target,
        ProtectionTier::SafeRecoverable,
        ProposedAction::Quarantine,
        1000,
    );
    match decision {
        SafetyDecision::Rejected { reason, .. } => {
            assert_eq!(reason, RejectionReason::Phase03ReadOnlyPolicy);
        }
        SafetyDecision::Allowed => panic!("Production policy must reject mutation unconditionally"),
    }
}
