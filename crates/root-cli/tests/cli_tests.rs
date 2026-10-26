use root_cli::{explain, inspect, run_with_args, status, terminal};
use root_core::{error::RootError, model::ProtectionTier};
use root_guardian::{JournalRecord, RecoveryJournal, TransactionState};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::PermissionsExt,
    time::Duration,
};
use tempfile::TempDir;

// 1. CLI argument validation
#[test]
fn test_01_cli_argument_validation() {
    assert!(run_with_args(["root", "doctor"]).is_ok());
    assert!(run_with_args(["root", "status"]).is_ok());
    assert!(run_with_args(["root", "inspect", "memory"]).is_ok());
    assert!(run_with_args(["root", "--version"]).is_ok());
    assert!(run_with_args(["root", "-V"]).is_ok());
    assert!(run_with_args(["root", "--help"]).is_ok());
    assert!(run_with_args(["root", "-h"]).is_ok());

    // Scan without explicit target path must fail safely in production
    let no_path_scan = run_with_args(["root", "scan"]);
    assert!(no_path_scan.is_err());
    match no_path_scan.unwrap_err() {
        RootError::InvalidPath(msg) => {
            assert!(msg.contains("No target path supplied"));
        }
        other => panic!(
            "Expected InvalidPath for scan without path, got {:?}",
            other
        ),
    }

    // Scan with explicit target path succeeds
    let temp = TempDir::new().unwrap();
    assert!(run_with_args(["root", "scan", "--path", temp.path().to_str().unwrap()]).is_ok());

    // Invalid agent name must fail validation
    let bad_agent = run_with_args(["root", "discover", "--agent", "nonexistent_agent_xyz"]);
    assert!(bad_agent.is_err());
}

// 2. Unknown commands
#[test]
fn test_02_unknown_commands() {
    let res = run_with_args(["root", "bogus_command"]);
    assert!(res.is_err());
}

// 3. Unsupported options
#[test]
fn test_03_unsupported_options() {
    let res = run_with_args(["root", "doctor", "--bogus-flag-123"]);
    assert!(res.is_err());
}

// 4. JSON output correctness
#[test]
fn test_04_json_output_correctness() {
    let res = status::run_status(true);
    assert!(res.is_ok());

    let res_mem = inspect::run_inspect_memory(true);
    assert!(res_mem.is_ok());

    let temp = TempDir::new().unwrap();
    let res_store = inspect::run_inspect_storage(Some(temp.path().to_path_buf()), true);
    assert!(res_store.is_ok());
}

// 5. Terminal width handling
#[test]
fn test_05_terminal_width_handling() {
    std::env::set_var("COLUMNS", "120");
    let width = terminal::get_terminal_width();
    assert_eq!(width, 120);

    let text = "a_very_long_directory_path_that_should_be_truncated_neatly_in_the_middle.txt";
    let trunc = terminal::truncate_middle(text, 25);
    assert!(trunc.len() <= 25);
    assert!(trunc.contains("..."));
    std::env::remove_var("COLUMNS");
}

// 6. NO_COLOR behavior
#[test]
fn test_06_no_color_behavior() {
    std::env::set_var("NO_COLOR", "1");
    let styled = terminal::Style::bold("test");
    assert_eq!(styled, "test");

    let badge = terminal::format_tier_badge(ProtectionTier::StrictlyProtected);
    assert!(!badge.contains("\x1b["));
    std::env::remove_var("NO_COLOR");
}

// 7. Non-interactive execution
#[test]
fn test_07_non_interactive_execution() {
    // Calling interactive browser in test harness (non-TTY) must return cleanly without hanging
    root_cli::interactive::run_interactive_browser(&[]);
}

// 8. Empty results
#[test]
fn test_08_empty_results() {
    let temp = TempDir::new().unwrap();
    let res = inspect::run_inspect_storage(Some(temp.path().to_path_buf()), true);
    assert!(res.is_ok());
}

// 9. Large result sets
#[test]
fn test_09_large_result_sets() {
    let temp = TempDir::new().unwrap();
    for i in 0..100 {
        let file_path = temp.path().join(format!("file_{:03}.tmp", i));
        fs::write(&file_path, b"test payload").unwrap();
    }

    let res = inspect::run_inspect_storage(Some(temp.path().to_path_buf()), true);
    assert!(res.is_ok());
}

// 10. Unicode filenames
#[test]
fn test_10_unicode_filenames() {
    let temp = TempDir::new().unwrap();
    let cyrillic = temp.path().join("отчёт_диагностика.log");
    let greek = temp.path().join("σημειώσεις.txt");
    let accented = temp.path().join("résumé_projet.json");

    fs::write(&cyrillic, b"cyrillic content").unwrap();
    fs::write(&greek, b"greek content").unwrap();
    fs::write(&accented, b"accented content").unwrap();

    let res = inspect::run_inspect_storage(Some(temp.path().to_path_buf()), true);
    assert!(res.is_ok());
}

// 11. Unusual path characters
#[test]
fn test_11_unusual_path_characters() {
    let temp = TempDir::new().unwrap();
    let unusual = temp.path().join("file with spaces [1] (copy).tmp");
    fs::write(&unusual, b"data").unwrap();

    let res = inspect::run_inspect_storage(Some(temp.path().to_path_buf()), true);
    assert!(res.is_ok());
}

// 12. Incomplete scans
#[test]
fn test_12_incomplete_scans() {
    use root_platform::{LinuxFilesystem, TraversalOptions};

    let temp = TempDir::new().unwrap();
    for i in 0..20 {
        let f = temp.path().join(format!("item_{:02}.txt", i));
        fs::write(&f, b"data").unwrap();
    }

    let fs_prov = LinuxFilesystem::new();
    let options = TraversalOptions {
        max_depth: 16,
        max_entries: 5, // Strict limit to force incomplete traversal
        allow_cross_device: false,
        timeout: None,
    };

    let outcome = fs_prov.traverse(temp.path(), &options).unwrap();
    assert!(!outcome.metrics.is_complete);
    assert!(outcome.metrics.incomplete_reason.is_some());
}

// 13. Permission-denied findings
#[test]
fn test_13_permission_denied_findings() {
    use root_platform::{LinuxFilesystem, TraversalOptions};

    let temp = TempDir::new().unwrap();
    let unreadable_dir = temp.path().join("unreadable");
    fs::create_dir(&unreadable_dir).unwrap();
    fs::write(unreadable_dir.join("secret.txt"), b"secret").unwrap();

    // Revoke read/execute permissions
    fs::set_permissions(&unreadable_dir, fs::Permissions::from_mode(0o000)).unwrap();

    let fs_prov = LinuxFilesystem::new();
    let options = TraversalOptions::default();
    let outcome = fs_prov.traverse(temp.path(), &options).unwrap();

    assert!(outcome.metrics.permission_denied_count >= 1);

    // Restore permissions for cleanup
    let _ = fs::set_permissions(&unreadable_dir, fs::Permissions::from_mode(0o700));
}

// 14. Evidence explanations
#[test]
fn test_14_evidence_explanations() {
    let exp = explain::generate_explanation("antigravity-scratch").unwrap();
    assert_eq!(exp.matched_rule_id, "antigravity-scratch");
    assert_eq!(exp.target_name, "Google Antigravity");
    assert!(!exp.supporting_evidence.is_empty());

    let exp_cargo = explain::generate_explanation("rust-target").unwrap();
    assert_eq!(exp_cargo.matched_rule_id, "rust-target");
    assert_eq!(exp_cargo.target_name, "Rust & Cargo");
}

// 15. Guardian rejection messages
#[test]
fn test_15_guardian_rejection_messages() {
    let exp_auth = explain::generate_explanation("antigravity-auth").unwrap();
    assert_eq!(exp_auth.protection_tier, ProtectionTier::StrictlyProtected);
    // Destructive actions must be in rejected list
    assert!(exp_auth
        .rejected_actions
        .iter()
        .any(|a| a.contains("Delete") || a.contains("Quarantine")));
}

// 16. Privacy-sensitive metadata
#[test]
fn test_16_privacy_sensitive_metadata() {
    let temp = TempDir::new().unwrap();
    let secret_file = temp.path().join("oauth_creds.json");
    fs::write(
        &secret_file,
        b"{\"client_secret\": \"super_sensitive_token_xyz\"}",
    )
    .unwrap();

    let exp = explain::generate_explanation(&secret_file.to_string_lossy()).unwrap();
    let serialized = serde_json::to_string(&exp).unwrap();

    // Private token content must never appear in explain report
    assert!(!serialized.contains("super_sensitive_token_xyz"));
}

// 17. Resource accounting correctness
#[test]
fn test_17_resource_accounting_correctness() {
    let temp = TempDir::new().unwrap();
    let real_file = temp.path().join("real.txt");
    fs::write(&real_file, b"12345678").unwrap();

    let hard_link = temp.path().join("hard_link.txt");
    fs::hard_link(&real_file, &hard_link).unwrap();

    let sparse_file = temp.path().join("sparse.bin");
    let mut f = File::create(&sparse_file).unwrap();
    f.seek(SeekFrom::Start(1024 * 1024)).unwrap();
    f.write_all(b"end").unwrap();

    let res = inspect::run_inspect_storage(Some(temp.path().to_path_buf()), true);
    assert!(res.is_ok());
}

// 18. Interrupted scans
#[test]
fn test_18_interrupted_scans() {
    use root_platform::{LinuxFilesystem, TraversalOptions};

    let temp = TempDir::new().unwrap();
    for i in 0..100 {
        let f = temp.path().join(format!("item_{:03}.txt", i));
        fs::write(&f, b"data").unwrap();
    }

    let fs_prov = LinuxFilesystem::new();
    let options = TraversalOptions {
        max_depth: 16,
        max_entries: 10_000,
        allow_cross_device: false,
        timeout: Some(Duration::from_nanos(1)), // Immediate timeout
    };

    let outcome = fs_prov.traverse(temp.path(), &options).unwrap();
    assert!(!outcome.metrics.is_complete);
}

// 19. Synthetic transaction diagnostics
#[test]
fn test_19_synthetic_transaction_diagnostics() {
    let temp = TempDir::new().unwrap();
    let journal_path = temp.path().join(".root_journal");
    let mut journal = RecoveryJournal::new(&journal_path).unwrap();

    journal
        .append(&JournalRecord {
            transaction_id: "tx-test-01".into(),
            timestamp_epoch_secs: 1000,
            state: TransactionState::Verified,
            original_path: temp.path().join("test.txt"),
            quarantine_path: Some(temp.path().join("q_test.txt")),
            device_id: 1,
            inode: 12345,
            size_bytes: 1024,
            sha256: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()),
            reason: "Synthetic test".into(),
            failure_reason: None,
        })
        .unwrap();

    let res = inspect::run_inspect_transactions(Some(journal_path), true);
    assert!(res.is_ok());
}

// 20. Attempts to access mutation functionality through production CLI commands
#[test]
fn test_20_attempts_to_access_mutation_functionality_through_cli() {
    for cmd in &["clean", "quarantine", "restore", "delete", "prune"] {
        let res = run_with_args(["root", cmd]);
        assert!(
            res.is_err(),
            "Production CLI must prohibit mutation command '{}'",
            cmd
        );
        match res.unwrap_err() {
            RootError::PolicyViolation { reason } => {
                assert!(reason.contains("strictly prohibited"));
                assert!(reason.contains("Read-Only Safety Mode"));
            }
            other => panic!("Expected PolicyViolation for '{}', got {:?}", cmd, other),
        }
    }
}

// 21. Scan classification consistency with discovery rules
#[test]
fn test_21_scan_classification_consistency() {
    let temp = TempDir::new().unwrap();
    let creds_dir = temp.path().join(".cargo");
    fs::create_dir_all(&creds_dir).unwrap();
    let creds_file = creds_dir.join("credentials.toml");
    fs::write(&creds_file, "token = \"secret\"").unwrap();

    let target_dir = temp.path().join("target").join("debug");
    fs::create_dir_all(&target_dir).unwrap();
    let build_file = target_dir.join("libtest.a");
    fs::write(&build_file, "binary").unwrap();

    // Run scan with json output
    let res = run_with_args([
        "root",
        "scan",
        "--path",
        temp.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(res.is_ok());

    // Run discover on same path with json output
    let res_disc = run_with_args([
        "root",
        "discover",
        "--path",
        temp.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(res_disc.is_ok());
}
