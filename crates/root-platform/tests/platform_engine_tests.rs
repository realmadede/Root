#![cfg(target_os = "linux")]

use root_core::model::{CapabilityStatus, ProcessState, StorageMeasurement};
use root_platform::{
    traits::{ProcessProvider, ResourceAccountant},
    LinuxAccountant, LinuxFilesystem, LinuxProcess, SkipReason, TraversalEvent, TraversalOptions,
};
use std::{fs, os::unix::fs::symlink, path::Path};
use tempfile::tempdir;

#[test]
fn test_defensive_traversal_symlink_safety() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let root = tmp.path();

    // Create a real directory and a file
    let real_dir = root.join("real_dir");
    fs::create_dir_all(&real_dir).unwrap();
    let real_file = real_dir.join("data.txt");
    fs::write(&real_file, b"sample content").unwrap();

    // 1. Valid relative symlink
    let valid_link = root.join("link_valid");
    symlink(&real_file, &valid_link).unwrap();

    // 2. Dangling symlink (targets nonexistent path)
    let dangling_link = root.join("link_dangling");
    symlink(root.join("nonexistent_target.txt"), &dangling_link).unwrap();

    // 3. Symlink jail escape (targets parent directory)
    let escape_link = root.join("link_escape");
    symlink(root.parent().unwrap_or(Path::new("/")), &escape_link).unwrap();

    // 4. Circular symlink loop (dir_a -> dir_b -> dir_a)
    let loop_a = root.join("loop_a");
    let loop_b = root.join("loop_b");
    fs::create_dir_all(&loop_a).unwrap();
    fs::create_dir_all(&loop_b).unwrap();
    symlink(&loop_b, loop_a.join("link_to_b")).unwrap();
    symlink(&loop_a, loop_b.join("link_to_a")).unwrap();

    let fs_engine = LinuxFilesystem::new();
    let options = TraversalOptions::default();
    let outcome = fs_engine
        .traverse(root, &options)
        .expect("Traversal failed");

    // Invariant: Traversal MUST NOT crash, hang, or recurse infinitely into symlink loops
    assert!(outcome.metrics.is_complete);

    // Verify all symlinks were flagged as SymlinkNotFollowed and never traversed
    let symlink_events: Vec<_> = outcome
        .events
        .iter()
        .filter_map(|e| match e {
            TraversalEvent::Skipped { path, reason } => {
                if *reason == SkipReason::SymlinkNotFollowed {
                    Some(path.clone())
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect();

    assert!(symlink_events.contains(&valid_link));
    assert!(symlink_events.contains(&dangling_link));
    assert!(symlink_events.contains(&escape_link));
    assert!(symlink_events.contains(&loop_a.join("link_to_b")));
    assert!(symlink_events.contains(&loop_b.join("link_to_a")));
}

#[test]
fn test_defensive_traversal_deep_nesting_and_depth_limit() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let root = tmp.path();

    // Construct deeply nested directory tree (30 levels deep)
    let mut current = root.to_path_buf();
    for i in 0..30 {
        current = current.join(format!("level_{:02}", i));
        fs::create_dir_all(&current).unwrap();
    }
    let deep_file = current.join("payload.txt");
    fs::write(&deep_file, b"deep data").unwrap();

    let fs_engine = LinuxFilesystem::new();

    // Limit depth to 10
    let options = TraversalOptions {
        max_depth: 10,
        max_entries: 10_000,
        allow_cross_device: false,
        timeout: None,
    };

    let outcome = fs_engine
        .traverse(root, &options)
        .expect("Traversal failed");

    // Verify that entries beyond depth 10 were skipped due to MaxDepthExceeded
    let max_depth_skipped = outcome.events.iter().any(|e| match e {
        TraversalEvent::Skipped { reason, .. } => {
            matches!(reason, SkipReason::MaxDepthExceeded { limit: 10, .. })
        }
        _ => false,
    });

    assert!(max_depth_skipped);
    assert!(outcome.metrics.skipped_count > 0);
}

#[test]
fn test_defensive_traversal_entry_limit_enforcement() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let root = tmp.path();

    // Generate 50 files
    for i in 0..50 {
        fs::write(root.join(format!("file_{:03}.txt", i)), b"content").unwrap();
    }

    let fs_engine = LinuxFilesystem::new();

    // Cap at 15 entries
    let options = TraversalOptions {
        max_depth: 64,
        max_entries: 15,
        allow_cross_device: false,
        timeout: None,
    };

    let outcome = fs_engine
        .traverse(root, &options)
        .expect("Traversal failed");

    // Traversal must be marked incomplete when entry limit is hit
    assert!(!outcome.metrics.is_complete);
    assert_eq!(outcome.metrics.total_inspected, 15);
    assert!(outcome
        .metrics
        .incomplete_reason
        .as_ref()
        .unwrap()
        .contains("entry limit"));
}

#[test]
fn test_defensive_traversal_pseudo_filesystem_rejection() {
    let fs_engine = LinuxFilesystem::new();
    let options = TraversalOptions::default();

    // Scanning '/' directly must be rejected
    let root_res = fs_engine.traverse(Path::new("/"), &options);
    assert!(root_res.is_err());

    // Scanning pseudo-filesystems must be rejected
    let proc_res = fs_engine.traverse(Path::new("/proc"), &options);
    assert!(proc_res.is_err());

    let sys_res = fs_engine.traverse(Path::new("/sys"), &options);
    assert!(sys_res.is_err());
}

#[test]
fn test_non_latin_unicode_and_special_filenames() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let root = tmp.path();

    let cyrillic_name = "файл-тест-отчет.dat";
    let spaces_name = "report for march 2026.log";
    let newline_name = "line1\nline2.tmp";

    fs::write(root.join(cyrillic_name), b"cyrillic content").unwrap();
    fs::write(root.join(spaces_name), b"spaces content").unwrap();
    fs::write(root.join(newline_name), b"newline content").unwrap();

    let fs_engine = LinuxFilesystem::new();
    let options = TraversalOptions::default();
    let outcome = fs_engine
        .traverse(root, &options)
        .expect("Traversal failed");

    let discovered_names: Vec<String> = outcome
        .entries
        .iter()
        .map(|e| e.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(discovered_names.contains(&cyrillic_name.to_string()));
    assert!(discovered_names.contains(&spaces_name.to_string()));
    assert!(discovered_names.contains(&newline_name.to_string()));
}

#[test]
fn test_sparse_file_accounting() {
    let storage_sparse = StorageMeasurement::from_raw(10_000_000, 8, 1);
    assert!(storage_sparse.is_sparse);
    assert_eq!(storage_sparse.bytes, 10_000_000);
    assert_eq!(storage_sparse.allocated_bytes, 8 * 512);

    let storage_dense = StorageMeasurement::from_raw(4096, 8, 1);
    assert!(!storage_dense.is_sparse);
}

#[test]
fn test_process_stat_line_parsing_resilience() {
    // Standard stat line
    let sample_stat = "1234 (node) S 100 1234 1234 0 0 4194304 100 0 0 0 10 20 0 0 20 0 1 0 50000 100000 200 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
    let (pid, comm, state, ppid, tty_nr, start_time) =
        LinuxProcess::parse_stat_line(sample_stat).expect("Failed to parse stat line");

    assert_eq!(pid, 1234);
    assert_eq!(comm, "node");
    assert_eq!(state, ProcessState::Sleeping);
    assert_eq!(ppid, 100);
    assert_eq!(tty_nr, 0);
    assert_eq!(start_time, 50000);

    // Resilient test: comm containing spaces and parentheses: "(Web Content)"
    let complex_stat = "5678 (Web Content (1)) R 1 5678 5678 34816 0 4194304 100 0 0 0 10 20 0 0 20 0 1 0 75000 100000 200";
    let (pid2, comm2, state2, ppid2, tty_nr2, start_time2) =
        LinuxProcess::parse_stat_line(complex_stat).expect("Failed to parse complex stat line");

    assert_eq!(pid2, 5678);
    assert_eq!(comm2, "Web Content (1)");
    assert_eq!(state2, ProcessState::Running);
    assert_eq!(ppid2, 1);
    assert_eq!(tty_nr2, 34816);
    assert_eq!(start_time2, 75000);

    // Malformed stat line: missing closing parenthesis
    let malformed_stat = "9999 (invalid_stat S 1 2 3";
    assert!(LinuxProcess::parse_stat_line(malformed_stat).is_none());

    // Truncated stat line
    let truncated_stat = "1111 (truncated) S 1";
    assert!(LinuxProcess::parse_stat_line(truncated_stat).is_none());
}

#[test]
fn test_process_status_uid_parsing() {
    let sample_status = "\
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Tgid:\t1000
Ngid:\t0
Pid:\t1000
PPid:\t999
TracerPid:\t0
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
";
    let uid = LinuxProcess::parse_status_uid(sample_status).expect("Failed to parse UID");
    assert_eq!(uid, 1000);
}

#[test]
fn test_process_cmdline_sanitization_privacy() {
    let raw_args = vec![
        "/usr/bin/node".to_string(),
        "--token=secret_api_token_12345".to_string(),
        "--api-key".to_string(),
        "super_sensitive_key".to_string(),
        "--port".to_string(),
        "3000".to_string(),
        "extra_arg_1".to_string(),
        "extra_arg_2".to_string(),
    ];

    let sanitized = LinuxProcess::sanitize_cmdline(&raw_args);

    // Invariant: Secret values must be redacted
    assert_eq!(sanitized[0], "/usr/bin/node");
    assert_eq!(sanitized[1], "[REDACTED]");
    assert_eq!(sanitized[2], "--api-key");
    assert_eq!(sanitized[3], "[REDACTED]");
    assert_eq!(sanitized[4], "--port");
    assert_eq!(sanitized[5], "[TRUNCATED]");

    let combined = sanitized.join(" ");
    assert!(!combined.contains("secret_api_token_12345"));
    assert!(!combined.contains("super_sensitive_key"));
}

#[test]
fn test_dead_process_inspection_returns_clean_none() {
    let proc_provider = LinuxProcess::new();

    // Inspect an impossible PID (Linux PID max is 4,194,304)
    let dead_pid = 4_194_300;
    let result = proc_provider
        .inspect_process(dead_pid)
        .expect("Process inspection should not fail with I/O error on dead PID");

    assert!(result.is_none());
}

#[test]
fn test_platform_capabilities_empirical_status() {
    let accountant = LinuxAccountant::new();
    let caps = accountant
        .get_capabilities()
        .expect("Failed to inspect platform capabilities");

    assert!(caps.is_linux);
    assert_ne!(caps.os_name, "Unknown");
    assert_ne!(caps.kernel_version, "Unknown");

    // On Linux host, /proc and /proc/meminfo must be SupportedAndAccessible
    assert_eq!(caps.proc_fs, CapabilityStatus::SupportedAndAccessible);
    assert_eq!(caps.proc_meminfo, CapabilityStatus::SupportedAndAccessible);

    // Verify status display badges
    assert_eq!(
        CapabilityStatus::SupportedAndAccessible.display_badge(),
        "SUPPORTED & ACCESSIBLE"
    );
    assert_eq!(
        CapabilityStatus::PermissionRestricted.display_badge(),
        "PERMISSION RESTRICTED"
    );
    assert_eq!(CapabilityStatus::Unavailable.display_badge(), "UNAVAILABLE");
}

#[test]
fn test_system_memory_accounting_invariants() {
    let accountant = LinuxAccountant::new();
    let mem = accountant
        .get_system_memory()
        .expect("Failed to read system memory");

    // Physical RAM invariants:
    // Total must be positive
    assert!(mem.total_bytes > 0);
    // Available must be <= Total
    assert!(mem.available_bytes <= mem.total_bytes);
    // Free must be <= Total
    assert!(mem.free_bytes <= mem.total_bytes);
    // Cached must be <= Total
    assert!(mem.cached_bytes <= mem.total_bytes);
    // Swap Free must be <= Swap Total
    assert!(mem.swap_free_bytes <= mem.swap_total_bytes);
}
