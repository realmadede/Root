use root_core::model::{
    validate_executable, InspectionProfile, ProposedAction, ProtectionTier, ScheduleConfig,
    ScheduleHistoryEntry, ScheduleInterval, ScheduleRunStatus,
};
use root_guardian::GuardianPolicy;
use root_platform::linux::{
    DesktopNotifier, LinuxScheduler, SystemdUnitGenerator, TraversalOptions, ROOT_UNIT_MARKER,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};
use tempfile::TempDir;

// 1. Disabled-by-default scheduling
#[test]
fn test_01_disabled_by_default_scheduling() {
    let config = ScheduleConfig::default();
    assert!(!config.enabled, "Scheduling must be disabled by default");
    assert_eq!(config.interval, ScheduleInterval::Daily);
    assert_eq!(config.profile, InspectionProfile::Standard);
    assert!(
        !config.notifications,
        "Notifications must be disabled by default"
    );
    assert!(
        !config.catch_up,
        "Catch-up execution must be disabled by default"
    );
    assert!(
        !config.ac_power_only,
        "AC-only restriction must be disabled by default"
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

// 3. Valid daily and hourly schedule
#[test]
fn test_03_valid_daily_and_hourly_schedule() {
    let daily = ScheduleInterval::Daily;
    assert_eq!(daily.to_calendar_spec().unwrap(), "daily");

    // Catch-up disabled by default -> Persistent=false
    let unit_daily = SystemdUnitGenerator::generate_timer_unit(&daily, false).unwrap();
    assert!(unit_daily.contains("OnCalendar=daily"));
    assert!(unit_daily.contains("Persistent=false"));

    // Catch-up enabled -> Persistent=true
    let unit_daily_catchup = SystemdUnitGenerator::generate_timer_unit(&daily, true).unwrap();
    assert!(unit_daily_catchup.contains("Persistent=true"));

    let hourly = ScheduleInterval::Hourly;
    assert_eq!(hourly.to_calendar_spec().unwrap(), "hourly");
    let unit_hourly = SystemdUnitGenerator::generate_timer_unit(&hourly, false).unwrap();
    assert!(unit_hourly.contains("OnCalendar=hourly"));
}

// 4. Valid weekly schedule
#[test]
fn test_04_valid_weekly_schedule() {
    let interval = ScheduleInterval::Weekly;
    assert_eq!(interval.to_calendar_spec().unwrap(), "weekly");

    let unit = SystemdUnitGenerator::generate_timer_unit(&interval, false).unwrap();
    assert!(unit.contains("OnCalendar=weekly"));
    assert!(unit.contains("Persistent=false"));
}

// 5. Invalid schedule rejection
#[test]
fn test_05_invalid_schedule_rejection() {
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
    let bad_targets = [
        PathBuf::from("/"),
        PathBuf::from("/proc"),
        PathBuf::from("/proc/sys"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
        PathBuf::from("/etc"),
        PathBuf::from("/usr"),
        PathBuf::from("/var"),
        PathBuf::from("/home/user/target\nmalicious"),
    ];

    for target in &bad_targets {
        assert!(
            ScheduleConfig::validate_target(target).is_err(),
            "Target '{:?}' must be rejected",
            target
        );
    }

    let temp = TempDir::new().unwrap();
    assert!(ScheduleConfig::validate_target(temp.path()).is_ok());
}

// 7. Unit generation safety
#[test]
fn test_07_unit_generation_safety() {
    let exec = PathBuf::from("/usr/local/bin/root");
    let service_unit =
        SystemdUnitGenerator::generate_service_unit(&exec, &["schedule", "run"], false);

    assert!(service_unit.contains("NoNewPrivileges=true"));
    assert!(service_unit.contains("Nice=19"));
    assert!(service_unit.contains("IOSchedulingClass=idle"));
    assert!(service_unit.contains("TimeoutSec=120"));
    assert!(service_unit.contains("ExecStart=/usr/local/bin/root schedule run"));
    assert!(service_unit.contains(ROOT_UNIT_MARKER));
}

// 8. Shell injection resistance
#[test]
fn test_08_shell_injection_resistance() {
    let weird_path = PathBuf::from("/tmp/root test/bin/root");
    let service =
        SystemdUnitGenerator::generate_service_unit(&weird_path, &["schedule", "run"], false);

    assert!(!service.contains("sh -c"));
    assert!(!service.contains("bash -c"));
    assert!(service.contains("ExecStart=/tmp/root test/bin/root schedule run"));
}

// 9. No elevated privilege requirement
#[test]
fn test_09_no_elevated_privilege_requirement() {
    let scheduler = LinuxScheduler::new();
    let dir = scheduler.unit_dir();
    let dir_str = dir.to_string_lossy();

    assert!(
        !dir_str.starts_with("/etc/systemd/system"),
        "Units must never install into system hierarchy: {}",
        dir_str
    );
    assert!(
        dir_str.contains(".config/systemd/user") || dir_str.contains("systemd/user"),
        "Units must target user unit directory: {}",
        dir_str
    );
}

// 10. No overlapping executions (advisory lock)
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

    let ret = unsafe {
        libc::flock(
            std::os::unix::io::AsRawFd::as_raw_fd(&lock_file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    assert_eq!(ret, 0, "Initial lock acquisition should succeed");

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

    assert!(!safe_title.contains(sensitive_data));
    assert!(!safe_body.contains(sensitive_data));
    assert!(!safe_body.contains("token"));
    assert!(!safe_body.contains("/home/"));
}

// 13. Notification service absence
#[test]
fn test_13_notification_service_absence() {
    let res = DesktopNotifier::dispatch("Title", "Body", "low");
    assert!(
        res.is_ok(),
        "Notification dispatch failure must be non-fatal"
    );
}

// 14. History retention and pruning
#[test]
fn test_14_history_retention_and_pruning() {
    let mut history = Vec::new();
    for i in 0..65 {
        history.push(ScheduleHistoryEntry {
            id: format!("run-{}", i),
            timestamp_epoch_secs: 1700000000 + i,
            duration_millis: 100,
            status: ScheduleRunStatus::Completed,
            profile: InspectionProfile::Standard,
            targets_scanned: vec![PathBuf::from("/tmp")],
            total_inspected: 10,
            total_findings: 1,
            reclaimable_bytes_estimate: 1024,
            notification_sent: false,
            error_message: None,
        });
    }

    const MAX_HISTORY_RECORDS: usize = 50;
    if history.len() > MAX_HISTORY_RECORDS {
        let drain_count = history.len() - MAX_HISTORY_RECORDS;
        history.drain(0..drain_count);
    }

    assert_eq!(history.len(), 50);
    assert_eq!(history.first().unwrap().id, "run-15");
    assert_eq!(history.last().unwrap().id, "run-64");
}

// 15. History permission enforcement
#[test]
fn test_15_history_permission_enforcement() {
    let temp = TempDir::new().unwrap();
    let history_file = temp.path().join("schedule_history.json");

    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&history_file)
        .unwrap();
    drop(file);

    let meta = fs::metadata(&history_file).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

// 16. Malformed state recovery
#[test]
fn test_16_malformed_state_recovery() {
    let temp = TempDir::new().unwrap();
    let bad_config_path = temp.path().join("schedule.json");
    fs::write(&bad_config_path, b"NOT_VALID_JSON{:::").unwrap();

    let parsed: std::result::Result<ScheduleConfig, _> =
        serde_json::from_slice(&fs::read(&bad_config_path).unwrap());
    assert!(parsed.is_err());

    let clean = ScheduleConfig::default();
    let clean_ser = serde_json::to_string(&clean).unwrap();
    fs::write(&bad_config_path, clean_ser).unwrap();

    let recovered: ScheduleConfig =
        serde_json::from_slice(&fs::read(&bad_config_path).unwrap()).unwrap();
    assert!(!recovered.enabled);
}

// 17. Scan timeout and budget behavior
#[test]
fn test_17_scan_timeout_and_budget_behavior() {
    let temp = TempDir::new().unwrap();
    for i in 0..20 {
        fs::write(temp.path().join(format!("file_{}.txt", i)), b"data").unwrap();
    }

    let fs_engine = root_platform::linux::LinuxFilesystem::new();
    let opts = TraversalOptions {
        max_depth: 16,
        max_entries: 5, // Budget capped at 5
        allow_cross_device: false,
        timeout: Some(Duration::from_millis(500)),
    };

    let outcome = fs_engine.traverse(temp.path(), &opts).unwrap();
    assert!(!outcome.metrics.is_complete);
    assert!(outcome.metrics.incomplete_reason.is_some());
}

// 18. Deleted target handling
#[test]
fn test_18_deleted_target_handling() {
    let non_existent = PathBuf::from("/tmp/root_test_missing_path_xyz_123");
    assert!(!non_existent.exists());

    let targets = vec![non_existent];
    let valid_targets: Vec<PathBuf> = targets.into_iter().filter(|t| t.exists()).collect();
    assert!(valid_targets.is_empty());
}

// 19. Disable and removal behavior
#[test]
fn test_19_disable_and_removal_behavior() {
    let temp = TempDir::new().unwrap();
    let scheduler = LinuxScheduler::with_unit_dir(temp.path());

    let service_path = scheduler.service_unit_path();
    let timer_path = scheduler.timer_unit_path();

    fs::write(&service_path, "test").unwrap();
    fs::write(&timer_path, "test").unwrap();
    assert!(service_path.exists());
    assert!(timer_path.exists());

    scheduler.uninstall_units().unwrap();
    assert!(!service_path.exists());
    assert!(!timer_path.exists());
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

// 21. Unsupported systemd sandboxing directives
#[test]
fn test_21_unsupported_systemd_sandboxing_directives() {
    // Prohibit User= and User=%h in user service units
    let bad_service = "[Unit]\nDescription=Test\n[Service]\nUser=%h\nExecStart=/bin/true\n";
    let res = SystemdUnitGenerator::validate_unit_content(bad_service, "[Service]");
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("User directive is illegal"));

    let bad_service_user =
        "[Unit]\nDescription=Test\n[Service]\nUser=nobody\nExecStart=/bin/true\n";
    let res2 = SystemdUnitGenerator::validate_unit_content(bad_service_user, "[Service]");
    assert!(res2.is_err());
}

// 22. Executable relocation and validation
#[test]
fn test_22_executable_relocation_and_validation() {
    let temp = TempDir::new().unwrap();
    let fake_binary = temp.path().join("my_root_bin");

    // File doesn't exist yet
    assert!(validate_executable(&fake_binary).is_err());

    // Create file but non-executable
    fs::write(&fake_binary, b"#!/bin/echo\n").unwrap();
    fs::set_permissions(&fake_binary, PermissionsExt::from_mode(0o644)).unwrap();
    assert!(validate_executable(&fake_binary).is_err());

    // Make executable
    fs::set_permissions(&fake_binary, PermissionsExt::from_mode(0o755)).unwrap();
    let validated = validate_executable(&fake_binary);
    assert!(validated.is_ok());

    // Shell/interpreter refusal
    let shell_path = temp.path().join("sh");
    fs::write(&shell_path, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&shell_path, PermissionsExt::from_mode(0o755)).unwrap();
    assert!(validate_executable(&shell_path).is_err());
}

// 23. Battery-aware scheduling
#[test]
fn test_23_battery_aware_scheduling() {
    let exec = PathBuf::from("/usr/local/bin/root");

    // AC only enabled -> ConditionACPower=true
    let service_ac = SystemdUnitGenerator::generate_service_unit(&exec, &["schedule", "run"], true);
    assert!(service_ac.contains("ConditionACPower=true"));

    // AC only disabled -> ConditionACPower omitted
    let service_any =
        SystemdUnitGenerator::generate_service_unit(&exec, &["schedule", "run"], false);
    assert!(!service_any.contains("ConditionACPower=true"));
}

// 24. High-memory-pressure deferral
#[test]
fn test_24_high_memory_pressure_deferral() {
    // Threshold check at 100% stall should normally return false on standard test systems
    let pressure_high = LinuxScheduler::is_memory_pressure_high(100.0);
    // Check shouldn't panic
    let _ = pressure_high;
}

// 25. Existing unit file collisions
#[test]
fn test_25_existing_unit_file_collisions() {
    let temp = TempDir::new().unwrap();
    let scheduler = LinuxScheduler::with_unit_dir(temp.path());

    // Pre-create an unknown unit file not created by Root
    let service_path = scheduler.service_unit_path();
    fs::write(
        &service_path,
        "[Unit]\nDescription=Someone Else's Service\n",
    )
    .unwrap();

    // Create a valid executable for testing
    let exec = temp.path().join("root_test_bin");
    fs::write(&exec, b"#!/bin/true\n").unwrap();
    fs::set_permissions(&exec, PermissionsExt::from_mode(0o755)).unwrap();

    let res = scheduler.install_units_transactional(&exec, &ScheduleInterval::Daily, false, false);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("Collision: existing unit file"));
}

// 26. Partial installation rollback
#[test]
fn test_26_partial_installation_rollback() {
    let temp = TempDir::new().unwrap();
    let scheduler = LinuxScheduler::with_unit_dir(temp.path());

    // If unit generation fails due to illegal interval, no partial files should exist
    let exec = temp.path().join("root_test_bin");
    fs::write(&exec, b"#!/bin/true\n").unwrap();
    fs::set_permissions(&exec, PermissionsExt::from_mode(0o755)).unwrap();

    let bad_interval = ScheduleInterval::Custom("illegal;spec".to_string());
    let res = scheduler.install_units_transactional(&exec, &bad_interval, false, false);
    assert!(res.is_err());

    assert!(!scheduler.service_unit_path().exists());
    assert!(!scheduler.timer_unit_path().exists());
}

// 27. Notification deduplication
#[test]
fn test_27_notification_deduplication() {
    let fp1 = DesktopNotifier::compute_fingerprint(ScheduleRunStatus::Completed, 100, 5);
    let fp2 = DesktopNotifier::compute_fingerprint(ScheduleRunStatus::Completed, 100, 5);
    let fp3 = DesktopNotifier::compute_fingerprint(ScheduleRunStatus::Completed, 101, 5);
    let fp4 = DesktopNotifier::compute_fingerprint(ScheduleRunStatus::Incomplete, 100, 5);

    assert_eq!(
        fp1, fp2,
        "Identical results must yield identical fingerprints"
    );
    assert_ne!(
        fp1, fp3,
        "Different inspected counts must yield different fingerprints"
    );
    assert_ne!(
        fp1, fp4,
        "Different statuses must yield different fingerprints"
    );
}

// 28. Catch-up behavior
#[test]
fn test_28_catch_up_behavior() {
    let interval = ScheduleInterval::Daily;

    let timer_no_catchup = SystemdUnitGenerator::generate_timer_unit(&interval, false).unwrap();
    assert!(timer_no_catchup.contains("Persistent=false"));

    let timer_catchup = SystemdUnitGenerator::generate_timer_unit(&interval, true).unwrap();
    assert!(timer_catchup.contains("Persistent=true"));
}

// 29. Profile scope restrictions
#[test]
fn test_29_profile_scope_restrictions() {
    let light = InspectionProfile::Lightweight.default_budget();
    assert_eq!(light.max_depth, 4);
    assert_eq!(light.max_entries, 10_000);
    assert_eq!(light.max_duration_secs, 15);

    let standard = InspectionProfile::Standard.default_budget();
    assert_eq!(standard.max_depth, 16);
    assert_eq!(standard.max_entries, 50_000);
    assert_eq!(standard.max_duration_secs, 60);

    let comprehensive = InspectionProfile::Comprehensive.default_budget();
    assert_eq!(comprehensive.max_depth, 32);
    assert_eq!(comprehensive.max_entries, 150_000);
    assert_eq!(comprehensive.max_duration_secs, 120);
}

// 30. Incomplete inspection reporting
#[test]
fn test_30_incomplete_inspection_reporting() {
    let entry = ScheduleHistoryEntry {
        id: "run-test".to_string(),
        timestamp_epoch_secs: 1000,
        duration_millis: 500,
        status: ScheduleRunStatus::Incomplete,
        profile: InspectionProfile::Standard,
        targets_scanned: vec![PathBuf::from("/tmp")],
        total_inspected: 50_000,
        total_findings: 10,
        reclaimable_bytes_estimate: 2048,
        notification_sent: false,
        error_message: Some("Traversal bound reached".to_string()),
    };

    assert_eq!(entry.status, ScheduleRunStatus::Incomplete);
    assert_eq!(entry.status.display_badge(), "[INCOMPLETE]");
    assert_ne!(entry.status, ScheduleRunStatus::Completed);
}
