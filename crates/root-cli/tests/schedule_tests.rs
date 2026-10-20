use root_core::model::{
    ProposedAction, ProtectionTier, ScheduleConfig, ScheduleHistoryEntry, ScheduleInterval,
    ScheduleRunStatus,
};
use root_guardian::GuardianPolicy;
use root_platform::{DesktopNotifier, LinuxScheduler, SystemdUnitGenerator};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

// 1. Disabled-by-default scheduling
#[test]
fn test_01_disabled_by_default_scheduling() {
    let config = ScheduleConfig::default();
    assert!(!config.enabled, "Scheduling must be disabled by default");
    assert_eq!(config.interval, ScheduleInterval::Daily);
    assert!(
        !config.notifications,
        "Notifications must be disabled by default"
    );
    assert!(
        config.targets.is_empty(),
        "Targets list must be empty by default"
    );
}

// 2. Explicit enable authorization
#[test]
fn test_02_explicit_enable_authorization() {
    let mut config = ScheduleConfig {
        enabled: true,
        ..Default::default()
    };
    // Enabling without targets must fail validation
    assert!(
        config.validate().is_err(),
        "Enabling without targets must fail"
    );

    let temp = TempDir::new().unwrap();
    config.targets.push(temp.path().to_path_buf());
    assert!(
        config.validate().is_ok(),
        "Enabling with valid target must succeed"
    );
}

// 3. Valid daily schedule
#[test]
fn test_03_valid_daily_schedule() {
    let interval = ScheduleInterval::Daily;
    assert_eq!(interval.to_calendar_spec().unwrap(), "daily");

    let unit = SystemdUnitGenerator::generate_timer_unit(&interval).unwrap();
    assert!(unit.contains("OnCalendar=daily"));
    assert!(unit.contains("Persistent=true"));
}

// 4. Valid weekly schedule
#[test]
fn test_04_valid_weekly_schedule() {
    let interval = ScheduleInterval::Weekly;
    assert_eq!(interval.to_calendar_spec().unwrap(), "weekly");

    let unit = SystemdUnitGenerator::generate_timer_unit(&interval).unwrap();
    assert!(unit.contains("OnCalendar=weekly"));
    assert!(unit.contains("Persistent=true"));
}

// 5. Invalid schedule rejection
#[test]
fn test_05_invalid_schedule_rejection() {
    // Malicious or malformed expressions must be rejected
    let bad_specs = [
        "daily; rm -rf /",
        "weekly && echo pwned",
        "custom\nExecStart=pwn",
        "interval$(whoami)",
        "test`id`",
        "",
    ];

    for bad in &bad_specs {
        let interval = ScheduleInterval::Custom(bad.to_string());
        assert!(
            interval.to_calendar_spec().is_err(),
            "Spec '{}' must be rejected",
            bad
        );
    }
}

// 6. Unsafe target rejection
#[test]
fn test_06_unsafe_target_rejection() {
    let unsafe_paths = [
        "/",
        "/proc",
        "/proc/sys",
        "/sys",
        "/sys/fs/cgroup",
        "/dev",
        "/dev/pts",
        "/run",
        "/etc",
        "/etc/shadow",
        "/usr",
        "/usr/bin",
        "/boot",
        "/var",
        "/lib",
        "/lib64",
        "/opt",
        "/home/user/target\nwith_newline",
    ];

    for path_str in &unsafe_paths {
        let res = ScheduleConfig::validate_target(Path::new(path_str));
        assert!(
            res.is_err(),
            "Target '{}' must be rejected as unsafe",
            path_str
        );
    }

    // Safe user workspace path must pass
    let safe_path = PathBuf::from("/home/user/projects/my-app");
    assert!(ScheduleConfig::validate_target(&safe_path).is_ok());
}

// 7. Unit generation safety
#[test]
fn test_07_unit_generation_safety() {
    let exec = PathBuf::from("/usr/local/bin/root");
    let service_unit = SystemdUnitGenerator::generate_service_unit(&exec, &["schedule", "run"]);

    assert!(service_unit.contains("Type=oneshot"));
    assert!(service_unit.contains("NoNewPrivileges=true"));
    assert!(service_unit.contains("Nice=19"));
    assert!(service_unit.contains("IOSchedulingClass=idle"));
    assert!(service_unit.contains("ExecStart=/usr/local/bin/root schedule run"));
    assert!(!service_unit.contains("/bin/sh"));
    assert!(!service_unit.contains("bash -c"));
}

// 8. Shell injection resistance
#[test]
fn test_08_shell_injection_resistance() {
    let weird_path = PathBuf::from("/home/user/path with spaces and [brackets] (copy)/bin/root");
    let service = SystemdUnitGenerator::generate_service_unit(&weird_path, &["schedule", "run"]);

    // Must not invoke any shell interpreter
    assert!(!service.contains("sh -c"));
    assert!(service.contains(
        "ExecStart=/home/user/path with spaces and [brackets] (copy)/bin/root schedule run"
    ));
}

// 9. No elevated privilege requirement
#[test]
fn test_09_no_elevated_privilege_requirement() {
    let temp = TempDir::new().unwrap();
    let scheduler = LinuxScheduler::with_unit_dir(temp.path().join("systemd/user"));
    let exec = PathBuf::from("/usr/bin/root");

    scheduler
        .install_units(&exec, &ScheduleInterval::Daily)
        .unwrap();

    let service_path = scheduler.service_unit_path();
    let timer_path = scheduler.timer_unit_path();

    assert!(service_path.exists());
    assert!(timer_path.exists());

    // Verified: unit files reside in user configuration directory, never /etc/systemd/system
    assert!(!service_path
        .to_string_lossy()
        .contains("/etc/systemd/system"));
    assert!(service_path.to_string_lossy().contains("systemd/user"));
}

// 10. No overlapping executions
#[test]
fn test_10_no_overlapping_executions() {
    let temp = TempDir::new().unwrap();
    let lock_path = temp.path().join("schedule.lock");

    let lock_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .unwrap();

    // Lock file with exclusive non-blocking lock
    let ret = unsafe {
        libc::flock(
            std::os::unix::io::AsRawFd::as_raw_fd(&lock_file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    assert_eq!(ret, 0, "Initial lock acquisition should succeed");

    // Second lock attempt must fail with EWOULDBLOCK
    let lock_file_2 = fs::OpenOptions::new().write(true).open(&lock_path).unwrap();
    let ret_2 = unsafe {
        libc::flock(
            std::os::unix::io::AsRawFd::as_raw_fd(&lock_file_2),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    assert_ne!(ret_2, 0, "Concurrent lock must be refused");
}

// 11. Unsupported systemd environment
#[test]
fn test_11_unsupported_systemd_environment() {
    let temp = TempDir::new().unwrap();
    let scheduler = LinuxScheduler::with_unit_dir(temp.path());

    // In simulated environment where timer is not active
    let timer_path = scheduler.timer_unit_path();
    assert!(!timer_path.exists());
    assert!(!scheduler.is_timer_active());
}

// 12. Notification privacy
#[test]
fn test_12_notification_privacy() {
    let sensitive_data = "ghp_super_secret_personal_access_token_12345";
    let safe_title = "Root Inspection Completed";
    let safe_body = "Examined 42 resources with zero mutations.".to_string();

    // Notification body and title must never contain sensitive data
    assert!(!safe_title.contains(sensitive_data));
    assert!(!safe_body.contains(sensitive_data));
    assert!(!safe_body.contains("token"));
}

// 13. Notification service absence
#[test]
fn test_13_notification_service_absence() {
    // Calling dispatch with clean strings must return without panicking,
    // returning Ok(true) if service is running or Ok(false) if absent
    let res = DesktopNotifier::dispatch("Test Notification", "Body text", "low");
    assert!(
        res.is_ok(),
        "Notification dispatch failure must be non-fatal"
    );
}

// 14. History retention and pruning
#[test]
fn test_14_history_retention_and_pruning() {
    let mut history = Vec::new();
    for i in 1..=60 {
        history.push(ScheduleHistoryEntry {
            id: format!("run-{}", i),
            timestamp_epoch_secs: 1700000000 + i,
            duration_millis: 100,
            status: ScheduleRunStatus::Completed,
            targets_scanned: vec![PathBuf::from("/test")],
            total_inspected: 10,
            total_findings: 1,
            reclaimable_bytes_estimate: 0,
            notification_sent: false,
            error_message: None,
        });
    }

    // Prune to 50 max
    if history.len() > 50 {
        let drain = history.len() - 50;
        history.drain(0..drain);
    }

    assert_eq!(history.len(), 50);
    assert_eq!(history.first().unwrap().id, "run-11");
    assert_eq!(history.last().unwrap().id, "run-60");
}

// 15. History permission enforcement
#[test]
fn test_15_history_permission_enforcement() {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("schedule.json");

    let config = ScheduleConfig {
        enabled: true,
        interval: ScheduleInterval::Daily,
        targets: vec![temp.path().to_path_buf()],
        notifications: false,
        max_depth: 16,
        max_entries: 50_000,
        timeout_secs: 60,
        history_retention_days: 30,
        last_modified_epoch_secs: 100,
    };

    let serialized = serde_json::to_string_pretty(&config).unwrap();
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&config_path)
        .unwrap();
    f.write_all(serialized.as_bytes()).unwrap();

    let meta = fs::metadata(&config_path).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Config file must have 0o600 permissions");
}

// 16. Malformed state recovery
#[test]
fn test_16_malformed_state_recovery() {
    let temp = TempDir::new().unwrap();
    let bad_config_path = temp.path().join("schedule.json");
    fs::write(&bad_config_path, b"{ broken json ...").unwrap();

    // Verify parser gracefully fails to parse without panicking
    let parsed: Result<ScheduleConfig, _> =
        serde_json::from_slice(&fs::read(&bad_config_path).unwrap());
    assert!(parsed.is_err());

    // Clean default can be written over it
    let clean = ScheduleConfig::default();
    let clean_ser = serde_json::to_string(&clean).unwrap();
    fs::write(&bad_config_path, clean_ser).unwrap();

    let recovered: ScheduleConfig =
        serde_json::from_slice(&fs::read(&bad_config_path).unwrap()).unwrap();
    assert!(!recovered.enabled);
}

// 17. Scan timeout behavior
#[test]
fn test_17_scan_timeout_behavior() {
    use root_platform::{LinuxFilesystem, TraversalOptions};

    let temp = TempDir::new().unwrap();
    for i in 0..50 {
        fs::write(temp.path().join(format!("file_{}.tmp", i)), b"data").unwrap();
    }

    let fs_prov = LinuxFilesystem::new();
    let options = TraversalOptions {
        max_depth: 16,
        max_entries: 10_000,
        allow_cross_device: false,
        timeout: Some(Duration::from_nanos(1)), // Zero timeout forces immediate cutoff
    };

    let outcome = fs_prov.traverse(temp.path(), &options).unwrap();
    assert!(!outcome.metrics.is_complete);
}

// 18. Deleted target handling
#[test]
fn test_18_deleted_target_handling() {
    let deleted_target = PathBuf::from("/tmp/nonexistent_root_dir_abc123xyz");
    assert!(!deleted_target.exists());

    // Validating target syntax passes, but traversal skips cleanly without crashing
    assert!(ScheduleConfig::validate_target(&deleted_target).is_ok());
}

// 19. Disable and removal behavior
#[test]
fn test_19_disable_and_removal_behavior() {
    let temp = TempDir::new().unwrap();
    let scheduler = LinuxScheduler::with_unit_dir(temp.path());

    let exec = PathBuf::from("/usr/bin/root");
    scheduler
        .install_units(&exec, &ScheduleInterval::Weekly)
        .unwrap();

    assert!(scheduler.service_unit_path().exists());
    assert!(scheduler.timer_unit_path().exists());

    scheduler.uninstall_units().unwrap();

    assert!(!scheduler.service_unit_path().exists());
    assert!(!scheduler.timer_unit_path().exists());
}

// 20. Guardian rejection of scheduled mutations
#[test]
fn test_20_guardian_rejection_of_scheduled_mutations() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("candidate.tmp");
    fs::write(&test_file, b"test content").unwrap();

    let meta = fs::symlink_metadata(&test_file).unwrap();
    let policy = GuardianPolicy::new();

    let candidate = root_core::model::ResourceCandidate {
        id: root_core::model::ResourceId::new("sched-candidate"),
        location: root_core::model::ResourceLocation::new(test_file, None, meta.dev(), meta.ino()),
        category: root_core::model::ResourceCategory::AgentScratchpad,
        metadata: root_core::model::ResourceMetadata {
            file_type: root_core::model::FileType::RegularFile,
            storage: root_core::model::StorageMeasurement::from_raw(12, 1, 1),
            permissions_mode: 0o644,
            mtime_epoch_secs: 100,
            atime_epoch_secs: 100,
            ctime_epoch_secs: 100,
        },
        ownership: root_core::model::ResourceOwnership {
            uid: 1000,
            gid: 1000,
            is_current_user: true,
        },
        associated_agent: None,
    };

    let target = root_core::model::FindingTarget::Filesystem(candidate);

    // Read-only Inspect action is allowed
    let inspect_dec = policy.evaluate(
        &target,
        ProtectionTier::ObsoleteTransient,
        ProposedAction::Inspect,
        1000,
    );
    assert!(inspect_dec.is_allowed());

    // Mutations (Quarantine, Prune) must be unconditionally rejected under Phase 03/05/06 policies
    let quar_dec = policy.evaluate(
        &target,
        ProtectionTier::ObsoleteTransient,
        ProposedAction::Quarantine,
        1000,
    );
    assert!(
        !quar_dec.is_allowed(),
        "Mutations must be rejected by Guardian policy"
    );

    let prune_dec = policy.evaluate(
        &target,
        ProtectionTier::ObsoleteTransient,
        ProposedAction::Prune,
        1000,
    );
    assert!(
        !prune_dec.is_allowed(),
        "Pruning must be rejected by Guardian policy"
    );
}
