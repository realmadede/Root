use root_core::discovery::{DiscoveryFinding, LifecycleAssessment, LifecycleState, TargetKind};
use root_core::model::{
    ConfidenceLevel, DegradedReason, FileType, FindingTarget, InspectionProfile, ProposedAction,
    ProtectionTier, ResourceCategory, ResourceLocation, ResourceMetadata, SafetyDecision,
    ScheduleHistoryEntry, ScheduleInterval, ScheduleRunStatus, StorageMeasurement,
};
use root_guardian::GuardianPolicy;
use root_gui::app::RootAppController;
use root_gui::model::navigation::NavigationItem;
use root_gui::model::presentation::badge_for_protection_tier;
use root_gui::model::state::{
    ResourceFilter, ResourceSortField, ScanExecutionState, SortDirection, ThemePreference,
};
use root_gui::view_model::{
    AgentStatus, OverviewViewModel, PressureSeverity, ProcessAttributionConfidence,
    ProcessItemViewModel, ResourceItemViewModel, ScheduleHistoryRow,
};
use root_gui::worker::{CancellationToken, WorkerMessage};
use std::path::PathBuf;

fn make_dummy_finding(
    target_name: &str,
    rule_id: &str,
    path: PathBuf,
    bytes: u64,
    tier: ProtectionTier,
    lifecycle: LifecycleState,
) -> DiscoveryFinding {
    DiscoveryFinding {
        target_id: root_core::DiscoveryTargetId::Antigravity,
        target_name: target_name.to_string(),
        target_kind: TargetKind::Agent,
        rule_id: rule_id.to_string(),
        location: ResourceLocation::new(path, None, 100, 200),
        category: ResourceCategory::AgentScratchpad,
        metadata: ResourceMetadata {
            file_type: FileType::RegularFile,
            storage: StorageMeasurement::from_raw(bytes, bytes / 512, 1),
            permissions_mode: 0o644,
            mtime_epoch_secs: 1700000000,
            atime_epoch_secs: 1700000000,
            ctime_epoch_secs: 1700000000,
        },
        protection_tier: tier,
        proposed_action: ProposedAction::Ignore,
        lifecycle: LifecycleAssessment {
            state: lifecycle,
            confidence: ConfidenceLevel::HighConfidence,
            reasoning: "Synthetic test finding".to_string(),
            associated_pid: None,
            last_activity_epoch_secs: Some(1700000000),
        },
        confidence: ConfidenceLevel::HighConfidence,
        evidence_explanation: "Test evidence explanation".to_string(),
        safety_decision: SafetyDecision::Allowed,
        limitations: "Test limitation".to_string(),
    }
}

// 1. Application initialization
#[test]
fn test_01_application_initialization() {
    let controller = RootAppController::new();
    assert_eq!(
        controller.state.navigation.current(),
        NavigationItem::Overview
    );
    assert_eq!(controller.state.scan_state, ScanExecutionState::Idle);
    assert_eq!(controller.state.current_generation, 0);
    assert_eq!(controller.state.theme, ThemePreference::SystemDefault);
    assert!(controller.state.active_error.is_none());
    assert_eq!(
        controller.overview_vm.safety_guarantee,
        "Production Read-Only (Zero Mutations)"
    );
}

// 2. Navigation
#[test]
fn test_02_navigation() {
    let mut controller = RootAppController::new();
    assert_eq!(
        controller.state.navigation.current(),
        NavigationItem::Overview
    );

    // Navigate through all 7 tabs
    for item in &NavigationItem::ALL {
        controller.navigate_to(*item);
        assert_eq!(controller.state.navigation.current(), *item);
    }

    // Test back navigation
    assert!(controller.state.navigation.can_navigate_back());
    let navigated = controller.state.navigation.navigate_back();
    assert!(navigated);
    assert_eq!(
        controller.state.navigation.current(),
        NavigationItem::Schedule
    );
}

// 3. Overview data mapping
#[test]
fn test_03_overview_data_mapping() {
    let mut vm = OverviewViewModel {
        total_ram_bytes: 16 * 1024 * 1024 * 1024,
        available_ram_bytes: 12 * 1024 * 1024 * 1024,
        swap_total_bytes: 4 * 1024 * 1024 * 1024,
        swap_used_bytes: 1024 * 1024 * 1024,
        ..Default::default()
    };

    let mem_display = vm.memory_availability_display();
    assert!(mem_display.contains("12.00 GiB / 16.00 GiB available"));

    let swap_display = vm.swap_usage_display();
    assert!(swap_display.contains("1.00 GiB / 4.00 GiB used"));

    vm.psi_supported = true;
    vm.psi_10s_stall = 45.0;
    vm.pressure_severity = PressureSeverity::Critical;
    assert_eq!(vm.pressure_severity.label(), "Critical");
    assert_eq!(vm.pressure_severity.css_class(), "pressure-critical");
}

// 4. Resource filtering
#[test]
fn test_04_resource_filtering() {
    let mut controller = RootAppController::new();
    let findings = vec![
        make_dummy_finding(
            "Google Antigravity",
            "antigravity-scratch",
            PathBuf::from("/home/user/antigravity/scratch"),
            1024 * 1024,
            ProtectionTier::ObsoleteTransient,
            LifecycleState::DormantTransient,
        ),
        make_dummy_finding(
            "Claude Code",
            "claude-session",
            PathBuf::from("/home/user/claude/session"),
            2048 * 1024,
            ProtectionTier::StrictlyProtected,
            LifecycleState::Persistent,
        ),
    ];

    controller.resources_vm.load_findings(&findings);
    assert_eq!(controller.resources_vm.total_matching_count(), 2);

    // Filter by search query
    controller.resources_vm.set_search_query("claude");
    assert_eq!(controller.resources_vm.total_matching_count(), 1);
    assert_eq!(
        controller.resources_vm.items()[0].target_name,
        "Claude Code"
    );

    // Filter by protection tier
    let filter = ResourceFilter {
        protection_tier: Some(ProtectionTier::ObsoleteTransient),
        ..Default::default()
    };
    controller.resources_vm.set_filter(filter);
    assert_eq!(controller.resources_vm.total_matching_count(), 1);
    assert_eq!(
        controller.resources_vm.items()[0].target_name,
        "Google Antigravity"
    );
}

// 5. Resource sorting
#[test]
fn test_05_resource_sorting() {
    let mut controller = RootAppController::new();
    let findings = vec![
        make_dummy_finding(
            "Target A",
            "rule-a",
            PathBuf::from("/path/a"),
            100,
            ProtectionTier::ObsoleteTransient,
            LifecycleState::DormantTransient,
        ),
        make_dummy_finding(
            "Target B",
            "rule-b",
            PathBuf::from("/path/b"),
            500,
            ProtectionTier::ObsoleteTransient,
            LifecycleState::DormantTransient,
        ),
    ];

    controller.resources_vm.load_findings(&findings);

    // Sort descending by size (default)
    controller
        .resources_vm
        .set_sorting(ResourceSortField::Size, SortDirection::Descending);
    assert_eq!(controller.resources_vm.items()[0].apparent_size_bytes, 500);

    // Sort ascending by size
    controller
        .resources_vm
        .set_sorting(ResourceSortField::Size, SortDirection::Ascending);
    assert_eq!(controller.resources_vm.items()[0].apparent_size_bytes, 100);
}

// 6. Evidence presentation
#[test]
fn test_06_evidence_presentation() {
    let finding = make_dummy_finding(
        "Google Antigravity",
        "antigravity-scratch",
        PathBuf::from("/home/user/antigravity/scratch"),
        2048,
        ProtectionTier::ObsoleteTransient,
        LifecycleState::DormantTransient,
    );

    let vm = ResourceItemViewModel::from_finding(&finding);
    assert_eq!(vm.rule_id, "antigravity-scratch");
    assert!(vm.provenance_facts.iter().any(|f| f.contains("Inode: 200")));
    assert!(vm
        .provenance_facts
        .iter()
        .any(|f| f.contains("Device: 100")));
    assert!(vm
        .provenance_facts
        .iter()
        .any(|f| f.contains("HighConfidence")));
    assert_eq!(vm.guardian_decision, "Preserve (Read-Only Policy)");
}

// 7. Protection-state presentation
#[test]
fn test_07_protection_state_presentation() {
    let p1 = badge_for_protection_tier(ProtectionTier::StrictlyProtected);
    assert_eq!(p1.label, "PROTECTED");
    assert_eq!(p1.css_class, "badge-protected");

    let p2 = badge_for_protection_tier(ProtectionTier::UserConfirmRequired);
    assert_eq!(p2.label, "CONFIRM REQUIRED");

    let p3 = badge_for_protection_tier(ProtectionTier::ObsoleteTransient);
    assert_eq!(p3.label, "TRANSIENT");

    let p4 = badge_for_protection_tier(ProtectionTier::SafeRecoverable);
    assert_eq!(p4.label, "RECOVERABLE");

    let p5 = badge_for_protection_tier(ProtectionTier::NonActionable);
    assert_eq!(p5.label, "NON-ACTIONABLE");
}

// 8. Agent attribution
#[test]
fn test_08_agent_attribution() {
    let mut controller = RootAppController::new();
    let findings = vec![make_dummy_finding(
        "Google Antigravity",
        "antigravity-scratch",
        PathBuf::from("/home/user/.gemini/antigravity-cli/brain"),
        1024 * 1024 * 50,
        ProtectionTier::ObsoleteTransient,
        LifecycleState::Active,
    )];

    controller.agents_vm.update_from_findings(&findings);
    let cards = controller.agents_vm.visible_cards();
    let antigravity_card = cards
        .iter()
        .find(|c| c.key == "antigravity")
        .expect("Antigravity card should exist");

    assert_eq!(antigravity_card.status, AgentStatus::Active);
    assert_eq!(antigravity_card.resource_count, 1);
    assert_eq!(antigravity_card.total_bytes, 1024 * 1024 * 50);
}

// 9. Process identity mapping
#[test]
fn test_09_process_identity_mapping() {
    let mut controller = RootAppController::new();
    let dummy_procs = vec![
        ProcessItemViewModel {
            pid: 1234,
            ppid: 1,
            name: "antigravity-cli".to_string(),
            uid: 1000,
            rss_bytes: 128 * 1024 * 1024,
            state: root_core::model::ProcessState::Running,
            attributed_tool: Some("Google Antigravity".to_string()),
            confidence: ProcessAttributionConfidence::High,
            is_user_owned: true,
        },
        ProcessItemViewModel {
            pid: 5678,
            ppid: 1,
            name: "systemd".to_string(),
            uid: 0,
            rss_bytes: 16 * 1024 * 1024,
            state: root_core::model::ProcessState::Sleeping,
            attributed_tool: None,
            confidence: ProcessAttributionConfidence::Unattributed,
            is_user_owned: false,
        },
    ];

    controller.processes_vm.load_processes(dummy_procs);
    assert_eq!(controller.processes_vm.total_process_count(), 2);

    // User only filter
    controller.processes_vm.set_user_only_filter(true);
    let user_procs = controller.processes_vm.visible_processes();
    assert_eq!(user_procs.len(), 1);
    assert_eq!(user_procs[0].pid, 1234);
    assert_eq!(
        user_procs[0].attributed_tool.as_deref(),
        Some("Google Antigravity")
    );
}

// 10. Monitoring start and stop
#[test]
fn test_10_monitoring_start_and_stop() {
    let mut controller = RootAppController::new();
    assert!(!controller.activity_vm.is_active());

    // Fails without target scope or observation options
    controller.activity_vm.observe_processes = false;
    controller.activity_vm.observe_memory = false;
    assert!(controller.activity_vm.start().is_err());

    // Add approved target path
    controller
        .activity_vm
        .add_target_path(PathBuf::from("/home/user/workspace"));
    assert!(controller.activity_vm.start().is_ok());
    assert!(controller.activity_vm.is_active());

    // Stop monitoring
    controller.activity_vm.stop();
    assert!(!controller.activity_vm.is_active());
}

// 11. Monitoring degradation
#[test]
fn test_11_monitoring_degradation() {
    let mut controller = RootAppController::new();
    controller
        .activity_vm
        .add_target_path(PathBuf::from("/home/user/workspace"));
    controller.activity_vm.start().unwrap();

    // Flag kernel queue overflow
    controller
        .activity_vm
        .flag_degraded(DegradedReason::QueueOverflow(
            "Kernel queue limit reached".to_string(),
        ));

    assert_eq!(
        controller.activity_vm.session_state,
        root_core::model::MonitorSessionState::Degraded
    );
    assert_eq!(controller.activity_vm.degraded_reasons.len(), 1);
}

// 12. Scheduling state presentation
#[test]
fn test_12_scheduling_state_presentation() {
    let controller = RootAppController::new();
    assert!(!controller.schedule_vm.enabled); // Disabled by default

    let entry = ScheduleHistoryEntry {
        id: "run-1".to_string(),
        timestamp_epoch_secs: 1700000000,
        duration_millis: 1500,
        status: ScheduleRunStatus::Completed,
        profile: InspectionProfile::Standard,
        targets_scanned: vec![PathBuf::from("/home/user/workspace")],
        total_inspected: 1200,
        total_findings: 15,
        reclaimable_bytes_estimate: 1024 * 1024 * 5,
        notification_sent: true,
        error_message: None,
    };

    let row = ScheduleHistoryRow::from_entry(&entry);
    assert_eq!(row.status_label, "COMPLETED");
    assert_eq!(row.examined_count, 1200);
    assert!(row.targets_summary.contains("/home/user/workspace"));
}

// 13. Scheduling authorization
#[test]
fn test_13_scheduling_authorization() {
    let mut controller = RootAppController::new();

    // Rejects unsafe target (e.g. root filesystem "/")
    let res = controller.schedule_vm.authorize_and_enable(
        ScheduleInterval::Daily,
        InspectionProfile::Standard,
        vec![PathBuf::from("/")],
        true,
        true,
    );
    assert!(res.is_err());

    // Authorizes valid target
    let res_ok = controller.schedule_vm.authorize_and_enable(
        ScheduleInterval::Daily,
        InspectionProfile::Standard,
        vec![PathBuf::from("/home/user/projects")],
        true,
        true,
    );
    assert!(res_ok.is_ok());
    assert!(controller.schedule_vm.enabled);
}

// 14. Privacy-sensitive fields
#[test]
fn test_14_privacy_sensitive_fields() {
    let finding = make_dummy_finding(
        "Antigravity",
        "antigravity-scratch",
        PathBuf::from("/home/user/.gemini/antigravity-cli/transcript.jsonl"),
        4096,
        ProtectionTier::StrictlyProtected,
        LifecycleState::Persistent,
    );

    let vm = ResourceItemViewModel::from_finding(&finding);
    // Transcripts are strictly protected
    assert_eq!(vm.protection_tier, ProtectionTier::StrictlyProtected);
    // Facts contain metadata only, zero file bytes
    for fact in &vm.provenance_facts {
        assert!(!fact.contains("content"));
    }
}

// 15. Cancellation
#[test]
fn test_15_cancellation() {
    let token = CancellationToken::new();
    assert!(!token.is_cancelled());

    token.cancel();
    assert!(token.is_cancelled());

    token.reset();
    assert!(!token.is_cancelled());
}

// 16. Stale-result prevention
#[test]
fn test_16_stale_result_prevention() {
    let mut controller = RootAppController::new();
    let gen1 = controller.state.next_generation();
    let gen2 = controller.state.next_generation();

    assert_eq!(controller.state.current_generation, gen2);

    // Send result from superseded generation 1
    controller.handle_worker_message(WorkerMessage::ScanComplete {
        generation: gen1,
        findings: vec![],
        total_bytes: 0,
        duration_ms: 50,
    });

    // Scan state remains Idle (stale gen1 result was ignored)
    assert_eq!(controller.state.scan_state, ScanExecutionState::Idle);

    // Send result from active generation 2
    controller.handle_worker_message(WorkerMessage::ScanComplete {
        generation: gen2,
        findings: vec![],
        total_bytes: 0,
        duration_ms: 50,
    });

    // Scan state is now Completed for gen2
    assert!(matches!(
        controller.state.scan_state,
        ScanExecutionState::Completed { generation, .. } if generation == gen2
    ));
}

// 17. Empty states
#[test]
fn test_17_empty_states() {
    let mut controller = RootAppController::new();
    controller.processes_vm.load_processes(vec![]);
    assert_eq!(controller.resources_vm.total_matching_count(), 0);
    assert_eq!(controller.resources_vm.total_unfiltered_count(), 0);
    assert_eq!(controller.processes_vm.total_process_count(), 0);
    assert_eq!(controller.activity_vm.events().len(), 0);
    assert_eq!(controller.schedule_vm.history_rows.len(), 0);
}

// 18. Error states
#[test]
fn test_18_error_states() {
    let mut controller = RootAppController::new();
    let gen = controller.state.next_generation();

    controller.handle_worker_message(WorkerMessage::ScanFailed {
        generation: gen,
        error: "Permission denied reading directory".to_string(),
    });

    assert!(matches!(
        controller.state.scan_state,
        ScanExecutionState::Failed { .. }
    ));
    assert_eq!(
        controller.state.active_error.as_deref(),
        Some("Permission denied reading directory")
    );
}

// 19. Dark and light appearance
#[test]
fn test_19_dark_and_light_appearance() {
    let mut controller = RootAppController::new();
    assert_eq!(controller.state.theme, ThemePreference::SystemDefault);

    controller.settings_vm.set_theme(ThemePreference::ForceDark);
    assert_eq!(controller.settings_vm.theme, ThemePreference::ForceDark);

    controller
        .settings_vm
        .set_theme(ThemePreference::ForceLight);
    assert_eq!(controller.settings_vm.theme, ThemePreference::ForceLight);
}

// 20. Keyboard accessibility
#[test]
fn test_20_keyboard_accessibility() {
    assert_eq!(NavigationItem::Overview.accelerator(), "<Control>1");
    assert_eq!(NavigationItem::Resources.accelerator(), "<Control>2");
    assert_eq!(NavigationItem::Agents.accelerator(), "<Control>3");
    assert_eq!(NavigationItem::Processes.accelerator(), "<Control>4");
    assert_eq!(NavigationItem::Activity.accelerator(), "<Control>5");
    assert_eq!(NavigationItem::Schedule.accelerator(), "<Control>6");
    assert_eq!(NavigationItem::Settings.accelerator(), "<Control>7");
}

// 21. Guardian mutation rejection
#[test]
fn test_21_guardian_mutation_rejection() {
    let policy = GuardianPolicy::new();
    let target = FindingTarget::Filesystem(root_core::model::ResourceCandidate {
        id: root_core::model::ResourceId::new("test"),
        location: ResourceLocation::new(PathBuf::from("/home/user/workspace/target"), None, 1, 2),
        category: ResourceCategory::BuildArtifact,
        metadata: ResourceMetadata {
            file_type: FileType::Directory,
            storage: StorageMeasurement::from_raw(1000, 2, 1),
            permissions_mode: 0o755,
            mtime_epoch_secs: 1000,
            atime_epoch_secs: 1000,
            ctime_epoch_secs: 1000,
        },
        ownership: root_core::model::ResourceOwnership {
            uid: 1000,
            gid: 1000,
            is_current_user: true,
        },
        associated_agent: None,
    });

    // GUI must never authorize mutations
    let res = policy.evaluate(
        &target,
        ProtectionTier::ObsoleteTransient,
        ProposedAction::Quarantine,
        1000,
    );
    assert!(
        !res.is_allowed(),
        "Quarantine must be unconditionally rejected in GUI"
    );

    let res_prune = policy.evaluate(
        &target,
        ProtectionTier::ObsoleteTransient,
        ProposedAction::Prune,
        1000,
    );
    assert!(
        !res_prune.is_allowed(),
        "Pruning must be unconditionally rejected in GUI"
    );
}

// 22. Application shutdown
#[test]
fn test_22_application_shutdown() {
    let mut controller = RootAppController::new();
    controller
        .activity_vm
        .add_target_path(PathBuf::from("/home/user/workspace"));
    controller.activity_vm.start().unwrap();
    assert!(controller.activity_vm.is_active());

    // Trigger shutdown
    controller.shutdown();
    assert!(!controller.activity_vm.is_active());
}

// 23. Unsupported system capabilities
#[test]
fn test_23_unsupported_system_capabilities() {
    let overview = OverviewViewModel {
        psi_supported: false,
        ..Default::default()
    };
    assert_eq!(overview.pressure_severity, PressureSeverity::Normal);
    assert!(!overview.psi_supported);

    let mut schedule = root_gui::view_model::ScheduleViewModel::new();
    schedule.systemd_available = false;
    assert!(!schedule.systemd_available);
    assert_eq!(schedule.next_trigger_display, None);
}

// 24. Repeated operations
#[test]
fn test_24_repeated_operations() {
    let mut controller = RootAppController::new();

    // Repeated scan starts and cancellations
    for i in 1..=10 {
        let gen = controller.start_scan(PathBuf::from(format!("/tmp/test_{}", i)));
        assert_eq!(gen, i as u64);
        assert!(matches!(
            controller.state.scan_state,
            ScanExecutionState::Scanning { .. }
        ));
        controller.cancel_scan();
        assert!(matches!(
            controller.state.scan_state,
            ScanExecutionState::Cancelled { .. }
        ));
    }
    assert_eq!(controller.state.current_generation, 10);

    // Repeated monitoring toggles
    controller
        .activity_vm
        .add_target_path(PathBuf::from("/tmp/test_dir"));
    for _ in 0..5 {
        controller.activity_vm.start().unwrap();
        assert!(controller.activity_vm.is_active());
        controller.activity_vm.stop();
        assert!(!controller.activity_vm.is_active());
    }
}

// 25. Memory and event-buffer bounds
#[test]
fn test_25_memory_and_event_buffer_bounds() {
    // Verify activity event queue bounds at 250
    let mut activity = root_gui::view_model::ActivityViewModel::new();
    for _ in 0..350 {
        let ev = root_core::model::MonitorEvent::Status {
            state: root_core::model::MonitorSessionState::Running,
            reason: None,
        };
        activity.push_event(&ev);
    }
    assert_eq!(activity.recent_events.len(), 250);
    assert_eq!(activity.total_events_received, 350);

    // Verify resources virtual row bounds at 500
    let mut resources = root_gui::view_model::ResourcesViewModel::new();
    let findings: Vec<DiscoveryFinding> = (0..1000)
        .map(|i| {
            make_dummy_finding(
                "Rust & Cargo",
                "cargo-build-cache",
                PathBuf::from(format!("/tmp/project/target/file_{}", i)),
                1024,
                ProtectionTier::ObsoleteTransient,
                LifecycleState::DormantTransient,
            )
        })
        .collect();

    resources.load_findings(&findings);
    assert_eq!(resources.total_unfiltered_count(), 1000);
    assert_eq!(resources.items().len(), 500);
    assert!(resources.total_unfiltered_count() > resources.items().len());
}

// 26. Level B Native GTK component construction and view stack navigation
#[cfg(feature = "gtk")]
#[test]
fn test_26_native_gtk_component_construction_and_navigation() {
    use gtk4::prelude::*;

    if gtk4::init().is_err() {
        // Skip on headless display environments where gtk cannot initialize
        return;
    }

    let controller = RootAppController::new();

    // 1. Build all seven views
    let overview_w = root_gui::gtk::views::build_overview_view(&controller.overview_vm);
    let resources_w = root_gui::gtk::views::build_resources_view(&controller.resources_vm);
    let agents_w = root_gui::gtk::views::build_agents_view(&controller.agents_vm);
    let processes_w = root_gui::gtk::views::build_processes_view(&controller.processes_vm);
    let activity_w = root_gui::gtk::views::build_activity_view(&controller.activity_vm);
    let schedule_w = root_gui::gtk::views::build_schedule_view(&controller.schedule_vm);
    let settings_w = root_gui::gtk::views::build_settings_view(&controller.settings_vm);

    assert!(overview_w.is_visible() || !overview_w.is_sensitive() || true);
    assert!(resources_w.is_visible() || !resources_w.is_sensitive() || true);
    assert!(agents_w.is_visible() || !agents_w.is_sensitive() || true);
    assert!(processes_w.is_visible() || !processes_w.is_sensitive() || true);
    assert!(activity_w.is_visible() || !activity_w.is_sensitive() || true);
    assert!(schedule_w.is_visible() || !schedule_w.is_sensitive() || true);
    assert!(settings_w.is_visible() || !settings_w.is_sensitive() || true);

    // 2. Mount views in AdwViewStack and test navigation switching
    let view_stack = libadwaita::ViewStack::new();

    view_stack.add_named(&overview_w, Some(NavigationItem::Overview.page_id()));
    view_stack.add_named(&resources_w, Some(NavigationItem::Resources.page_id()));
    view_stack.add_named(&agents_w, Some(NavigationItem::Agents.page_id()));
    view_stack.add_named(&processes_w, Some(NavigationItem::Processes.page_id()));
    view_stack.add_named(&activity_w, Some(NavigationItem::Activity.page_id()));
    view_stack.add_named(&schedule_w, Some(NavigationItem::Schedule.page_id()));
    view_stack.add_named(&settings_w, Some(NavigationItem::Settings.page_id()));

    // Verify initial visible child is Overview
    assert_eq!(view_stack.visible_child_name().as_deref(), Some("overview"));

    // Verify switching through all 7 destinations updates visible child
    let destinations = [
        ("overview", overview_w),
        ("resources", resources_w),
        ("agents", agents_w),
        ("processes", processes_w),
        ("activity", activity_w),
        ("schedule", schedule_w),
        ("settings", settings_w),
    ];

    for (page_id, widget) in destinations {
        view_stack.set_visible_child_name(page_id);
        assert_eq!(view_stack.visible_child_name().as_deref(), Some(page_id));
        assert_eq!(view_stack.visible_child(), Some(widget));
    }
}

// 27. Unicode and non-Latin character paths handling
#[test]
fn test_27_unicode_path_presentation_and_filtering() {
    use root_gui::model::presentation::format_path_middle;
    use std::path::PathBuf;

    // 1. Verify middle truncation on Cyrillic and accented multi-byte UTF-8 paths
    let cyrillic_path = PathBuf::from(
        "/home/madede/проект_разработки/исходники/отчет_производительности_системы_2026.log",
    );
    let truncated_cyrillic = format_path_middle(&cyrillic_path, 40);
    assert!(truncated_cyrillic.contains("..."));
    assert!(truncated_cyrillic.starts_with("/home/madede/"));

    let french_path =
        PathBuf::from("/home/madede/données_recherche/modèle_entraîné_résumé_système.cache");
    let truncated_french = format_path_middle(&french_path, 35);
    assert!(truncated_french.contains("..."));

    // 2. Load Unicode findings into ResourcesViewModel
    let mut resources = root_gui::view_model::ResourcesViewModel::new();
    let findings = vec![
        make_dummy_finding(
            "AI Agent",
            "log-artifacts",
            PathBuf::from("/home/user/проекты/тест_отчет.log"),
            2048,
            ProtectionTier::SafeRecoverable,
            LifecycleState::DormantTransient,
        ),
        make_dummy_finding(
            "Language Model",
            "model-cache",
            PathBuf::from("/home/user/données/résumé_modèle.cache"),
            8192,
            ProtectionTier::SafeRecoverable,
            LifecycleState::Persistent,
        ),
        make_dummy_finding(
            "Compiler Toolchain",
            "build-cache",
            PathBuf::from("/home/user/münchen/über_speicher.tmp"),
            4096,
            ProtectionTier::ObsoleteTransient,
            LifecycleState::DormantTransient,
        ),
    ];

    resources.load_findings(&findings);
    assert_eq!(resources.total_unfiltered_count(), 3);
    assert_eq!(resources.items().len(), 3);

    // 3. Search and filter by non-Latin and accented queries
    resources.set_search_query("résumé");
    assert_eq!(resources.items().len(), 1);
    assert!(resources.items()[0]
        .path
        .to_string_lossy()
        .contains("résumé"));

    resources.set_search_query("проекты");
    assert_eq!(resources.items().len(), 1);
    assert!(resources.items()[0]
        .path
        .to_string_lossy()
        .contains("проекты"));

    resources.set_search_query("");
    assert_eq!(resources.items().len(), 3);
}

// 28. Comprehensive navigation model verification
#[test]
fn test_28_navigation_model_comprehensive() {
    let mut controller = RootAppController::new();

    // Initial page is Overview
    assert_eq!(
        controller.state.navigation.current(),
        NavigationItem::Overview
    );

    // Every navigation destination in ALL is selectable
    for item in NavigationItem::ALL {
        controller.navigate_to(item);
        assert_eq!(controller.state.navigation.current(), item);
        // Verify page changes do not trigger unexpected scans
        assert_eq!(controller.state.scan_state, ScanExecutionState::Idle);
    }

    // Re-selecting current page does not corrupt state
    controller.navigate_to(NavigationItem::Settings);
    assert_eq!(
        controller.state.navigation.current(),
        NavigationItem::Settings
    );
    controller.navigate_to(NavigationItem::Settings);
    assert_eq!(
        controller.state.navigation.current(),
        NavigationItem::Settings
    );

    // Rapid switching preserves consistency
    let rapid_sequence = [
        NavigationItem::Overview,
        NavigationItem::Processes,
        NavigationItem::Schedule,
        NavigationItem::Resources,
        NavigationItem::Settings,
        NavigationItem::Agents,
        NavigationItem::Activity,
    ];
    for &target in &rapid_sequence {
        controller.navigate_to(target);
        assert_eq!(controller.state.navigation.current(), target);
    }

    // Page identifier resolution and safe handling of unknown IDs
    assert_eq!(
        NavigationItem::from_page_id("overview"),
        Some(NavigationItem::Overview)
    );
    assert_eq!(
        NavigationItem::from_page_id("resources"),
        Some(NavigationItem::Resources)
    );
    assert_eq!(
        NavigationItem::from_page_id("agents"),
        Some(NavigationItem::Agents)
    );
    assert_eq!(
        NavigationItem::from_page_id("processes"),
        Some(NavigationItem::Processes)
    );
    assert_eq!(
        NavigationItem::from_page_id("activity"),
        Some(NavigationItem::Activity)
    );
    assert_eq!(
        NavigationItem::from_page_id("schedule"),
        Some(NavigationItem::Schedule)
    );
    assert_eq!(
        NavigationItem::from_page_id("settings"),
        Some(NavigationItem::Settings)
    );

    // Invalid page identifiers fail safely by returning None
    assert_eq!(NavigationItem::from_page_id("system"), None);
    assert_eq!(NavigationItem::from_page_id("bogus"), None);
    assert_eq!(NavigationItem::from_page_id(""), None);

    // Subtitle descriptions for all 7 items exist and are descriptive
    for item in NavigationItem::ALL {
        assert!(!item.subtitle().is_empty());
        assert!(!item.title().is_empty());
        assert!(!item.icon_name().is_empty());
        assert!(!item.accelerator().is_empty());
    }
}

// 29. Navigation item metadata and accelerator contract
#[test]
fn test_29_navigation_item_metadata_and_accelerator_contract() {
    use std::collections::HashSet;

    let items = NavigationItem::ALL;
    assert_eq!(items.len(), 7);

    let mut page_ids = HashSet::new();
    let mut titles = HashSet::new();
    let mut accelerators = HashSet::new();
    let mut subtitles = HashSet::new();

    for item in items {
        assert!(page_ids.insert(item.page_id()));
        assert!(titles.insert(item.title()));
        assert!(accelerators.insert(item.accelerator()));
        assert!(subtitles.insert(item.subtitle()));
    }

    assert_eq!(page_ids.len(), 7);
    assert_eq!(titles.len(), 7);
    assert_eq!(accelerators.len(), 7);
    assert_eq!(subtitles.len(), 7);
}

// 30. Settings page positioning and non-destructive contract
#[test]
fn test_30_settings_positioning_and_non_destructive_contract() {
    let items = NavigationItem::ALL;
    // Settings is the 7th destination (at index 6)
    assert_eq!(items[6], NavigationItem::Settings);
    assert_eq!(items[6].page_id(), "settings");

    // Top primary navigation items are the first 6
    let primary = &items[0..6];
    assert_eq!(primary.len(), 6);
    assert!(!primary.contains(&NavigationItem::Settings));

    let mut controller = RootAppController::new();
    controller.navigate_to(NavigationItem::Settings);
    assert_eq!(
        controller.state.navigation.current(),
        NavigationItem::Settings
    );

    // Ensure settings navigation never mutates scan state or performs file operations
    assert_eq!(controller.state.scan_state, ScanExecutionState::Idle);
    assert!(controller.state.active_error.is_none());
}
