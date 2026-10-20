use crate::model::navigation::NavigationItem;
use crate::model::state::{AppState, ScanExecutionState};
use crate::view_model::{
    ActivityViewModel, AgentsViewModel, OverviewViewModel, ProcessesViewModel, ResourcesViewModel,
    ScheduleViewModel, SettingsViewModel,
};
use crate::worker::{CancellationToken, InspectionWorker, WorkerMessage};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::JoinHandle;

/// Central application controller coordinating view-models, background workers, and UI state.
pub struct RootAppController {
    pub state: AppState,
    pub overview_vm: OverviewViewModel,
    pub resources_vm: ResourcesViewModel,
    pub agents_vm: AgentsViewModel,
    pub processes_vm: ProcessesViewModel,
    pub activity_vm: ActivityViewModel,
    pub schedule_vm: ScheduleViewModel,
    pub settings_vm: SettingsViewModel,

    worker_sender: Sender<WorkerMessage>,
    worker_receiver: Receiver<WorkerMessage>,
    current_token: Option<CancellationToken>,
    active_worker_handle: Option<JoinHandle<()>>,
}

impl Default for RootAppController {
    fn default() -> Self {
        Self::new()
    }
}

impl RootAppController {
    pub fn new() -> Self {
        let (tx, rx) = channel();

        let mut controller = Self {
            state: AppState::default(),
            overview_vm: OverviewViewModel::default(),
            resources_vm: ResourcesViewModel::new(),
            agents_vm: AgentsViewModel::new(),
            processes_vm: ProcessesViewModel::new(),
            activity_vm: ActivityViewModel::new(),
            schedule_vm: ScheduleViewModel::new(),
            settings_vm: SettingsViewModel::new(),

            worker_sender: tx,
            worker_receiver: rx,
            current_token: None,
            active_worker_handle: None,
        };

        // Initialize view models from platform
        controller.refresh_all();
        controller
    }

    /// Navigates to a specific section.
    pub fn navigate_to(&mut self, item: NavigationItem) {
        self.state.navigation.navigate_to(item);
    }

    /// Refreshes all system-level telemetry and status across tabs.
    pub fn refresh_all(&mut self) {
        self.overview_vm.refresh_system_metrics(Path::new("/"));
        self.processes_vm.refresh();
        self.schedule_vm.refresh_from_system();
    }

    /// Triggers an asynchronous inspection of target path.
    pub fn start_scan(&mut self, target_path: PathBuf) -> u64 {
        // Cancel any active scan
        self.cancel_scan();

        let gen = self.state.next_generation();
        let token = CancellationToken::new();
        self.current_token = Some(token.clone());

        self.state.scan_state = ScanExecutionState::Scanning {
            generation: gen,
            current_path: target_path.to_string_lossy().to_string(),
            entries_examined: 0,
        };

        let handle =
            InspectionWorker::spawn_scan(target_path, gen, token, self.worker_sender.clone());
        self.active_worker_handle = Some(handle);

        gen
    }

    /// Cancels currently running scan, if any.
    pub fn cancel_scan(&mut self) {
        if let Some(token) = self.current_token.take() {
            token.cancel();
        }
        if matches!(self.state.scan_state, ScanExecutionState::Scanning { .. }) {
            self.state.scan_state = ScanExecutionState::Cancelled {
                generation: self.state.current_generation,
            };
        }
    }

    /// Polls pending worker messages from background threads and updates view models.
    /// Employs generation fencing to guarantee stale results never overwrite newer state.
    pub fn poll_worker_messages(&mut self) {
        while let Ok(msg) = self.worker_receiver.try_recv() {
            self.handle_worker_message(msg);
        }
    }

    /// Processes a single message from a background worker with generation fencing.
    pub fn handle_worker_message(&mut self, msg: WorkerMessage) {
        match msg {
            WorkerMessage::ScanProgress {
                generation,
                entries_examined,
                current_path,
            } => {
                // Fencing: ignore if superseded
                if self.state.is_generation_current(generation) {
                    self.state.scan_state = ScanExecutionState::Scanning {
                        generation,
                        current_path,
                        entries_examined,
                    };
                }
            }
            WorkerMessage::ScanComplete {
                generation,
                findings,
                total_bytes,
                duration_ms,
            } => {
                if self.state.is_generation_current(generation) {
                    // Update resources view model
                    self.resources_vm.load_findings(&findings);

                    // Update agents view model
                    self.agents_vm.update_from_findings(&findings);

                    // Update overview summary
                    let detected = self.agents_vm.detected_count();
                    let active = self
                        .agents_vm
                        .visible_cards()
                        .iter()
                        .filter(|a| a.status == crate::view_model::AgentStatus::Active)
                        .count();
                    self.overview_vm.update_discovery_summary(
                        detected,
                        active,
                        findings.len(),
                        total_bytes,
                    );

                    self.state.scan_state = ScanExecutionState::Completed {
                        generation,
                        total_items: findings.len(),
                        total_bytes,
                        duration_ms,
                    };
                }
            }
            WorkerMessage::ScanCancelled { generation } => {
                if self.state.is_generation_current(generation) {
                    self.state.scan_state = ScanExecutionState::Cancelled { generation };
                }
            }
            WorkerMessage::ScanFailed { generation, error } => {
                if self.state.is_generation_current(generation) {
                    self.state.scan_state = ScanExecutionState::Failed {
                        generation,
                        error: error.clone(),
                    };
                    self.state.active_error = Some(error);
                }
            }
        }
    }

    /// Graceful application shutdown handler.
    pub fn shutdown(&mut self) {
        self.cancel_scan();
        self.activity_vm.stop();
        if let Some(handle) = self.active_worker_handle.take() {
            let _ = handle.join();
        }
    }
}
