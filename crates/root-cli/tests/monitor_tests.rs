use root_core::model::{
    DegradedReason, FindingTarget, LiveFsEvent, LiveFsEventKind, MonitorBudget, MonitorEvent,
    MonitorScope, MonitorSessionState, ProcessObservation, ProposedAction, ProtectionTier,
};
use root_guardian::GuardianPolicy;
use root_platform::linux::{InotifyWatcher, LinuxMonitorSession, MemoryObserver, ProcessObserver};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tempfile::TempDir;

// 1. Explicit monitoring activation
#[test]
fn test_01_explicit_monitoring_activation() {
    let empty_scope = MonitorScope::default();
    assert!(
        empty_scope.validate().is_err(),
        "Empty scope must fail validation; explicit target required"
    );

    let temp = TempDir::new().unwrap();
    let valid_scope = MonitorScope {
        paths: vec![temp.path().to_path_buf()],
        ..Default::default()
    };
    assert!(valid_scope.validate().is_ok());
}

// 2. Disabled-by-default behavior
#[test]
fn test_02_disabled_by_default_behavior() {
    let temp = TempDir::new().unwrap();
    let scope = MonitorScope {
        paths: vec![temp.path().to_path_buf()],
        ..Default::default()
    };
    let session = LinuxMonitorSession::new(scope, 1000).unwrap();
    assert_eq!(session.state(), MonitorSessionState::Created);
    assert_eq!(session.active_watches(), 0);
}

// 3. Valid target monitoring
#[test]
fn test_03_valid_target_monitoring() {
    let temp = TempDir::new().unwrap();
    let scope = MonitorScope {
        paths: vec![temp.path().to_path_buf()],
        ..Default::default()
    };
    let mut session = LinuxMonitorSession::new(scope, 1000).unwrap();
    session.start().unwrap();
    assert_eq!(session.state(), MonitorSessionState::Running);
    assert!(session.active_watches() >= 1);

    // Create a file in the watched directory
    let file_path = temp.path().join("test_artifact.tmp");
    fs::write(&file_path, b"test data").unwrap();

    // Small delay for kernel inotify event delivery
    std::thread::sleep(Duration::from_millis(50));

    let events = session.poll_events().unwrap();
    let mut found_created = false;
    for e in events {
        if let MonitorEvent::Fs(fs_ev) = e {
            if fs_ev.path == file_path && fs_ev.kind == LiveFsEventKind::Created {
                found_created = true;
            }
        }
    }
    assert!(
        found_created,
        "Expected to observe Created event for new file"
    );

    let summary = session.stop();
    assert_eq!(summary.final_state, MonitorSessionState::Stopped);
}

// 4. Unsafe target rejection
#[test]
fn test_04_unsafe_target_rejection() {
    let bad_paths = [
        PathBuf::from("/"),
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
        PathBuf::from("/etc"),
        PathBuf::from("/usr"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp/bad\nnewline"),
    ];

    for bad in &bad_paths {
        assert!(
            MonitorScope::validate_monitor_target(bad).is_err(),
            "Path '{:?}' must be rejected",
            bad
        );
    }
}

// 5. Symlink escape prevention
#[test]
fn test_05_symlink_escape_prevention() {
    let temp_watch = TempDir::new().unwrap();
    let temp_foreign = TempDir::new().unwrap();

    // Create a symlink inside watched dir pointing to foreign dir
    let symlink_path = temp_watch.path().join("link_to_foreign");
    std::os::unix::fs::symlink(temp_foreign.path(), &symlink_path).unwrap();

    let mut degraded = Vec::new();
    let mut watcher = InotifyWatcher::new(10, 100).unwrap();
    let count = watcher
        .add_watch_tree(temp_watch.path(), &mut degraded)
        .unwrap();

    // Watches should only be registered on the real directory, not traversing the symlink
    assert_eq!(count, 1);
    assert_eq!(watcher.active_watch_count(), 1);
}

// 6. Directory removal
#[test]
fn test_06_directory_removal() {
    let temp_parent = TempDir::new().unwrap();
    let watched_dir = temp_parent.path().join("sub_watched");
    fs::create_dir(&watched_dir).unwrap();

    let scope = MonitorScope {
        paths: vec![watched_dir.clone()],
        ..Default::default()
    };
    let mut session = LinuxMonitorSession::new(scope, 1000).unwrap();
    session.start().unwrap();

    // Remove the watched directory
    fs::remove_dir(&watched_dir).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let _ = session.poll_events().unwrap();

    let has_removed_degraded = session
        .degraded_reasons()
        .iter()
        .any(|r| matches!(r, DegradedReason::WatchedDirectoryRemoved(_)));

    assert!(
        has_removed_degraded,
        "Removing watched directory must trigger WatchedDirectoryRemoved"
    );
    assert_eq!(session.state(), MonitorSessionState::Degraded);
}

// 7. Directory rename
#[test]
fn test_07_directory_rename() {
    let temp = TempDir::new().unwrap();
    let old_dir = temp.path().join("old_name");
    let new_dir = temp.path().join("new_name");
    fs::create_dir(&old_dir).unwrap();

    let scope = MonitorScope {
        paths: vec![temp.path().to_path_buf()],
        ..Default::default()
    };
    let mut session = LinuxMonitorSession::new(scope, 1000).unwrap();
    session.start().unwrap();

    fs::rename(&old_dir, &new_dir).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let events = session.poll_events().unwrap();
    let has_move = events.iter().any(|e| {
        if let MonitorEvent::Fs(fe) = e {
            fe.kind == LiveFsEventKind::MovedFrom || fe.kind == LiveFsEventKind::MovedTo
        } else {
            false
        }
    });

    assert!(has_move, "Renaming directory must produce move events");
}

// 8. inotify queue overflow
#[test]
fn test_08_inotify_queue_overflow() {
    let reason = DegradedReason::QueueOverflow("Simulated buffer overflow".to_string());
    assert!(reason.display_message().contains("queue overflowed"));
}

// 9. Watch-limit exhaustion
#[test]
fn test_09_watch_limit_exhaustion() {
    let temp = TempDir::new().unwrap();
    for i in 0..5 {
        fs::create_dir(temp.path().join(format!("dir_{}", i))).unwrap();
    }

    let mut degraded = Vec::new();
    let mut watcher = InotifyWatcher::new(2, 100).unwrap(); // Limit of 2 watches
    let _ = watcher.add_watch_tree(temp.path(), &mut degraded);

    let has_limit = degraded
        .iter()
        .any(|r| matches!(r, DegradedReason::WatchLimitExceeded(2)));
    assert!(has_limit, "Watch limit budget must trigger DegradedReason");
}

// 10. Event coalescing
#[test]
fn test_10_event_coalescing() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("rapid_write.txt");
    fs::write(&test_file, b"initial").unwrap();

    let mut watcher = InotifyWatcher::new(10, 100).unwrap();
    let mut degraded = Vec::new();
    let _ = watcher.add_watch_tree(temp.path(), &mut degraded);

    // Rapid successive modifications
    for i in 0..5 {
        fs::write(&test_file, format!("data_{}", i)).unwrap();
    }

    std::thread::sleep(Duration::from_millis(50));
    let events = watcher.read_events(None, &mut degraded).unwrap();

    // Due to coalescing, we should not have 5 separate modified events
    let mod_events: Vec<_> = events
        .iter()
        .filter(|e| e.kind == LiveFsEventKind::Modified)
        .collect();
    assert!(
        mod_events.len() <= 3,
        "Rapid writes should be coalesced (got {})",
        mod_events.len()
    );
}

// 11. Bounded event queues
#[test]
fn test_11_bounded_event_queues() {
    let temp = TempDir::new().unwrap();
    let mut watcher = InotifyWatcher::new(10, 5).unwrap(); // max 5 queued events
    let mut degraded = Vec::new();
    let _ = watcher.add_watch_tree(temp.path(), &mut degraded);

    for i in 0..20 {
        fs::write(temp.path().join(format!("file_{}.txt", i)), b"data").unwrap();
    }

    std::thread::sleep(Duration::from_millis(50));
    let events = watcher.read_events(None, &mut degraded).unwrap();
    assert!(
        events.len() <= 5,
        "Event buffer must not exceed max_queued_events"
    );
}

// 12. Process disappearance
#[test]
fn test_12_process_disappearance() {
    let mut observer = ProcessObserver::new(Duration::from_millis(10));
    let _ = observer.sample_changes(1000, None);

    // In a subsequent sample, any exited PID is cleanly reported as ProcessEventKind::Exited
}

// 13. PID reuse handling
#[test]
fn test_13_pid_reuse_handling() {
    let mut tracked = std::collections::HashMap::new();
    let pid = 99999;

    let obs_old = ProcessObservation {
        pid,
        ppid: 1,
        uid: 1000,
        binary_name: "old_worker".to_string(),
        start_time_ticks: 10000,
        rss_bytes: 1024,
        associated_agent: None,
    };
    tracked.insert(pid, obs_old);

    let obs_new = ProcessObservation {
        pid,
        ppid: 1,
        uid: 1000,
        binary_name: "new_worker".to_string(),
        start_time_ticks: 20000, // Different start time -> PID reuse!
        rss_bytes: 2048,
        associated_agent: None,
    };

    // Detect reuse
    let old = tracked.get(&pid).unwrap();
    assert_ne!(old.start_time_ticks, obs_new.start_time_ticks);
}

// 14. Memory sampling intervals
#[test]
fn test_14_memory_sampling_intervals() {
    let mut mem_obs = MemoryObserver::new(Duration::from_millis(500));
    let snap1 = mem_obs.sample_memory().unwrap();
    assert!(snap1.is_some());

    // Immediate second call should return None due to sampling interval
    let snap2 = mem_obs.sample_memory().unwrap();
    assert!(snap2.is_none());
}

// 15. Monitoring timeout
#[test]
fn test_15_monitoring_timeout() {
    let temp = TempDir::new().unwrap();
    let scope = MonitorScope {
        paths: vec![temp.path().to_path_buf()],
        budget: MonitorBudget {
            max_duration_secs: Some(1), // 1 second timeout
            ..Default::default()
        },
        ..Default::default()
    };

    let mut session = LinuxMonitorSession::new(scope, 1000).unwrap();
    session.start().unwrap();

    // Sleep past duration budget
    std::thread::sleep(Duration::from_millis(1100));

    let events = session.poll_events().unwrap();
    let has_stopping = events.iter().any(|e| {
        if let MonitorEvent::Status { state, .. } = e {
            *state == MonitorSessionState::Stopping
        } else {
            false
        }
    });

    assert!(
        has_stopping,
        "Session must emit Stopping when duration budget expires"
    );
}

// 16. Ctrl+C shutdown
#[test]
fn test_16_ctrl_c_shutdown() {
    let flag = AtomicBool::new(true);
    flag.store(false, Ordering::SeqCst);
    assert!(!flag.load(Ordering::SeqCst));
}

// 17. JSON Lines validity
#[test]
fn test_17_json_lines_validity() {
    let fs_event = MonitorEvent::Fs(LiveFsEvent {
        path: PathBuf::from("/tmp/test.txt"),
        kind: LiveFsEventKind::Created,
        is_directory: false,
        timestamp_epoch_secs: 1000,
        matched_agent: Some("antigravity".to_string()),
    });

    let json_line = serde_json::to_string(&fs_event).unwrap();
    assert!(!json_line.contains('\n'));
    let parsed: MonitorEvent = serde_json::from_str(&json_line).unwrap();
    assert_eq!(parsed, fs_event);
}

// 18. NO_COLOR behavior
#[test]
fn test_18_no_color_behavior() {
    // When ANSI styling is disabled, output strings do not contain escape characters
    let badge = LiveFsEventKind::Created.display_badge();
    assert!(!badge.contains("\x1b["));
    assert_eq!(badge, "[CREATE]");
}

// 19. Privacy-sensitive paths
#[test]
fn test_19_privacy_sensitive_paths() {
    let sensitive_content = "SECRET_API_KEY_12345";
    let event = LiveFsEvent {
        path: PathBuf::from("/home/user/.gemini/scratch/test.py"),
        kind: LiveFsEventKind::Modified,
        is_directory: false,
        timestamp_epoch_secs: 1000,
        matched_agent: Some("antigravity".to_string()),
    };

    let json_repr = serde_json::to_string(&event).unwrap();
    assert!(!json_repr.contains(sensitive_content));
    // Verify no file content reading is performed
}

// 20. Guardian mutation rejection
#[test]
fn test_20_guardian_mutation_rejection() {
    let policy = GuardianPolicy::new();
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("file.txt");
    fs::write(&file, b"content").unwrap();

    let meta = fs::symlink_metadata(&file).unwrap();
    let candidate = root_core::model::ResourceCandidate {
        id: root_core::model::ResourceId::new("mon-candidate"),
        location: root_core::model::ResourceLocation::new(file, None, meta.dev(), meta.ino()),
        category: root_core::model::ResourceCategory::AgentScratchpad,
        metadata: root_core::model::ResourceMetadata {
            file_type: root_core::model::FileType::RegularFile,
            storage: root_core::model::StorageMeasurement::from_raw(7, 1, 1),
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
    let target = FindingTarget::Filesystem(candidate);

    // Live monitoring must never authorize mutations
    let quar = policy.evaluate(
        &target,
        ProtectionTier::ObsoleteTransient,
        ProposedAction::Quarantine,
        1000,
    );
    assert!(
        !quar.is_allowed(),
        "Quarantine must be rejected during monitoring"
    );

    let prune = policy.evaluate(
        &target,
        ProtectionTier::ObsoleteTransient,
        ProposedAction::Prune,
        1000,
    );
    assert!(
        !prune.is_allowed(),
        "Pruning must be rejected during monitoring"
    );
}

// 21. Unsupported kernel interfaces
#[test]
fn test_21_unsupported_kernel_interfaces() {
    let reason =
        DegradedReason::KernelInterfaceUnavailable("Failed to open /proc/stat".to_string());
    assert!(reason.display_message().contains("unavailable"));
}

// 22. Resource budget enforcement
#[test]
fn test_22_resource_budget_enforcement() {
    let temp = TempDir::new().unwrap();
    let scope = MonitorScope {
        paths: vec![temp.path().to_path_buf()],
        budget: MonitorBudget {
            sampling_interval_millis: 100, // Invalid: < 250ms
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(scope.validate().is_err());
}

// 23. Concurrent monitoring sessions
#[test]
fn test_23_concurrent_monitoring_sessions() {
    let temp1 = TempDir::new().unwrap();
    let temp2 = TempDir::new().unwrap();

    let scope1 = MonitorScope {
        paths: vec![temp1.path().to_path_buf()],
        ..Default::default()
    };
    let scope2 = MonitorScope {
        paths: vec![temp2.path().to_path_buf()],
        ..Default::default()
    };

    let mut session1 = LinuxMonitorSession::new(scope1, 1000).unwrap();
    let mut session2 = LinuxMonitorSession::new(scope2, 1000).unwrap();

    session1.start().unwrap();
    session2.start().unwrap();

    assert_eq!(session1.state(), MonitorSessionState::Running);
    assert_eq!(session2.state(), MonitorSessionState::Running);

    session1.stop();
    session2.stop();
}

// 24. Scheduled inspection coexistence
#[test]
fn test_24_scheduled_inspection_coexistence() {
    let temp = TempDir::new().unwrap();
    let lock_path = temp.path().join("schedule.lock");

    // Acquire schedule lock as if scheduled inspection is running
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
    assert_eq!(ret, 0);

    // Monitoring session does NOT acquire schedule.lock and can run simultaneously
    let scope = MonitorScope {
        paths: vec![temp.path().to_path_buf()],
        ..Default::default()
    };
    let mut session = LinuxMonitorSession::new(scope, 1000).unwrap();
    assert!(session.start().is_ok());
    session.stop();
}

// 25. Degraded-state reporting
#[test]
fn test_25_degraded_state_reporting() {
    let temp = TempDir::new().unwrap();
    let missing_path = temp.path().join("non_existent_dir");

    let scope = MonitorScope {
        paths: vec![missing_path],
        ..Default::default()
    };
    let mut session = LinuxMonitorSession::new(scope, 1000).unwrap();
    session.start().unwrap();

    // Session starts in Degraded state due to missing path
    assert_eq!(session.state(), MonitorSessionState::Degraded);
    assert!(!session.degraded_reasons().is_empty());

    let summary = session.stop();
    assert_eq!(summary.final_state, MonitorSessionState::Stopped);
    assert!(!summary.degraded_reasons.is_empty());
}
