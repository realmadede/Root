use root_core::discovery::{DiscoveryContext, DiscoveryEngine, DiscoveryFilter, DiscoveryFinding};
use root_core::model::{FindingTarget, ProposedAction, ProtectionTier};
use root_guardian::GuardianPolicy;
use root_platform::traits::{EnvironmentProvider, ProcessProvider, ResourceAccountant};
use root_platform::{
    LinuxAccountant, LinuxEnvironment, LinuxFilesystem, LinuxProcess, TraversalOptions,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// Cancellation token shared between UI thread and background workers.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }
}

/// Messages streamed from background workers to the UI thread.
#[derive(Debug, Clone)]
pub enum WorkerMessage {
    /// Incremental scan progress update.
    ScanProgress {
        generation: u64,
        entries_examined: usize,
        current_path: String,
    },
    /// Scan completed with findings.
    ScanComplete {
        generation: u64,
        findings: Vec<DiscoveryFinding>,
        total_bytes: u64,
        duration_ms: u64,
    },
    /// Scan was cancelled before completion.
    ScanCancelled { generation: u64 },
    /// Scan encountered an error.
    ScanFailed { generation: u64, error: String },
}

/// Background inspection worker orchestrating safe, non-blocking traversal.
pub struct InspectionWorker;

impl InspectionWorker {
    /// Spawns an asynchronous background scan thread with cancellation and stale-result fencing.
    pub fn spawn_scan(
        target_path: PathBuf,
        generation: u64,
        token: CancellationToken,
        sender: Sender<WorkerMessage>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let start = std::time::Instant::now();

            if token.is_cancelled() {
                let _ = sender.send(WorkerMessage::ScanCancelled { generation });
                return;
            }

            if !target_path.exists() {
                let _ = sender.send(WorkerMessage::ScanFailed {
                    generation,
                    error: format!("Target path does not exist: {}", target_path.display()),
                });
                return;
            }

            let env = LinuxEnvironment::new();
            let fs = LinuxFilesystem::new();
            let proc_provider = LinuxProcess::new();
            let accountant = LinuxAccountant::new();
            let policy = GuardianPolicy::new();

            let current_uid = env.current_uid();
            let capabilities = match accountant.get_capabilities() {
                Ok(caps) => caps,
                Err(e) => {
                    let _ = sender.send(WorkerMessage::ScanFailed {
                        generation,
                        error: e.to_string(),
                    });
                    return;
                }
            };

            // Collect active processes
            let mut active_processes = Vec::new();
            if let Ok(pids) = proc_provider.list_pids() {
                for pid in pids {
                    if let Ok(Some(candidate)) = proc_provider.inspect_process(pid) {
                        active_processes.push(candidate);
                    }
                }
            }

            let traversal_options = TraversalOptions {
                max_depth: 16,
                max_entries: 50_000,
                allow_cross_device: false,
                timeout: Some(std::time::Duration::from_secs(60)),
            };

            let outcome = match fs.traverse(&target_path, &traversal_options) {
                Ok(out) => out,
                Err(e) => {
                    let _ = sender.send(WorkerMessage::ScanFailed {
                        generation,
                        error: e.to_string(),
                    });
                    return;
                }
            };

            if token.is_cancelled() {
                let _ = sender.send(WorkerMessage::ScanCancelled { generation });
                return;
            }

            let mut all_entries = Vec::with_capacity(outcome.entries.len());
            for (idx, entry) in outcome.entries.into_iter().enumerate() {
                if idx % 500 == 0 {
                    if token.is_cancelled() {
                        let _ = sender.send(WorkerMessage::ScanCancelled { generation });
                        return;
                    }
                    let _ = sender.send(WorkerMessage::ScanProgress {
                        generation,
                        entries_examined: idx,
                        current_path: entry.path.to_string_lossy().to_string(),
                    });
                }
                all_entries.push((entry.path, entry.metadata, entry.dev, entry.ino));
            }

            let filter = DiscoveryFilter::default();
            let ctx = DiscoveryContext {
                root_paths: vec![target_path],
                filter: &filter,
                current_uid,
                active_processes: &active_processes,
                capabilities,
                skipped_count: outcome.metrics.skipped_count,
                is_complete: outcome.metrics.is_complete,
                incomplete_reason: outcome.metrics.incomplete_reason,
            };

            match DiscoveryEngine::evaluate_findings(
                &all_entries,
                &ctx,
                &|target: &FindingTarget,
                  tier: ProtectionTier,
                  action: ProposedAction,
                  uid: u32| { policy.evaluate(target, tier, action, uid) },
            ) {
                Ok(report) => {
                    let total_bytes: u64 = report
                        .findings
                        .iter()
                        .map(|f| f.metadata.storage.bytes)
                        .sum();
                    let duration_ms = start.elapsed().as_millis() as u64;

                    let _ = sender.send(WorkerMessage::ScanComplete {
                        generation,
                        findings: report.findings,
                        total_bytes,
                        duration_ms,
                    });
                }
                Err(e) => {
                    let _ = sender.send(WorkerMessage::ScanFailed {
                        generation,
                        error: e.to_string(),
                    });
                }
            }
        })
    }
}
