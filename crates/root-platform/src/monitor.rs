//! Portable live-monitoring building blocks used on platforms without a native event backend
//! wired in (macOS and Windows in Phase 10).
//!
//! - [`PollingWatcher`] detects changes by comparing bounded metadata snapshots. It never reads
//!   file contents and never follows symlinks or reparse points.
//! - [`ProviderProcessObserver`] and [`ProviderMemoryObserver`] sample through the
//!   `ProcessProvider` and `ResourceAccountant` traits.
//! - [`PortableMonitorSession`] coordinates them with the same lifecycle and budget semantics as
//!   the Linux session.
//!
//! Semantics differ from kernel event streams: changes that are reverted between two polls are
//! invisible, intermediate states are coalesced, and a rename appears as a delete plus a create.

use root_core::{
    error::Result,
    model::{
        DegradedReason, LiveFsEvent, LiveFsEventKind, MemoryObservation, MonitorEvent,
        MonitorScope, MonitorSessionState, MonitorSessionSummary, ProcessEventKind,
        ProcessObservation,
    },
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use crate::traits::{FsEventSource, ProcessProvider, ResourceAccountant};

/// Whether a directory entry is a link-like object that must not be descended into: a symlink on
/// every platform, and on Windows any reparse point (junctions, mount points, placeholders).
pub fn is_link_like(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Agent attribution by path substring, identical to the Linux watcher's rule.
pub fn detect_agent_association(path: &Path) -> Option<String> {
    let s = path.to_string_lossy().to_lowercase();
    if s.contains(".gemini") || s.contains("antigravity") {
        Some("antigravity".to_string())
    } else if s.contains(".claude") || s.contains("claude") {
        Some("claude".to_string())
    } else if s.contains("openai") || s.contains("codex") {
        Some("codex".to_string())
    } else if s.contains("aider") {
        Some("aider".to_string())
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryState {
    is_dir: bool,
    len: u64,
    modified: Option<SystemTime>,
}

/// Metadata-snapshot watcher with explicit bounds.
pub struct PollingWatcher {
    roots: Vec<PathBuf>,
    snapshot: HashMap<PathBuf, EntryState>,
    max_entries: usize,
    max_queued_events: usize,
    min_interval: Duration,
    last_poll: Option<Instant>,
    truncated: bool,
}

impl PollingWatcher {
    /// `max_watches` bounds the number of tracked entries (files and directories);
    /// `max_queued_events` bounds the events returned per poll.
    pub fn new(max_watches: usize, max_queued_events: usize, min_interval: Duration) -> Self {
        Self {
            roots: Vec::new(),
            snapshot: HashMap::new(),
            max_entries: max_watches,
            max_queued_events,
            min_interval,
            last_poll: None,
            truncated: false,
        }
    }

    /// Walks one root, bounded by the remaining entry budget. Returns the observed state.
    fn walk(
        &self,
        root: &Path,
        budget: usize,
        degraded: &mut Vec<DegradedReason>,
    ) -> (HashMap<PathBuf, EntryState>, bool) {
        let mut out = HashMap::new();
        let mut stack = vec![root.to_path_buf()];
        let mut truncated = false;

        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => {
                    let reason = DegradedReason::PermissionDenied(dir.clone());
                    if !degraded.contains(&reason) {
                        degraded.push(reason);
                    }
                    continue;
                }
            };
            for entry in entries.flatten() {
                if out.len() >= budget {
                    truncated = true;
                    return (out, truncated);
                }
                let path = entry.path();
                let meta = match fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let link = is_link_like(&meta);
                let is_dir = meta.is_dir() && !link;
                out.insert(
                    path.clone(),
                    EntryState {
                        is_dir,
                        len: if is_dir { 0 } else { meta.len() },
                        modified: meta.modified().ok(),
                    },
                );
                if is_dir {
                    stack.push(path);
                }
            }
        }
        (out, truncated)
    }
}

impl FsEventSource for PollingWatcher {
    fn backend_name(&self) -> &'static str {
        "metadata polling"
    }

    fn add_tree(&mut self, root: &Path, degraded: &mut Vec<DegradedReason>) -> Result<usize> {
        let budget = self.max_entries.saturating_sub(self.snapshot.len());
        let (state, truncated) = self.walk(root, budget, degraded);
        let added = state.len();
        self.snapshot.extend(state);
        if truncated {
            self.truncated = true;
            let reason = DegradedReason::WatchLimitExceeded(self.max_entries);
            if !degraded.contains(&reason) {
                degraded.push(reason);
            }
        }
        self.roots.push(root.to_path_buf());
        Ok(added)
    }

    fn poll(
        &mut self,
        agent_filter: Option<&str>,
        degraded: &mut Vec<DegradedReason>,
    ) -> Result<Vec<LiveFsEvent>> {
        if let Some(last) = self.last_poll {
            if last.elapsed() < self.min_interval {
                return Ok(Vec::new());
            }
        }
        self.last_poll = Some(Instant::now());

        let mut current: HashMap<PathBuf, EntryState> = HashMap::new();
        let mut removed_roots = Vec::new();
        for root in self.roots.clone() {
            if !root.exists() {
                removed_roots.push(root);
                continue;
            }
            let budget = self.max_entries.saturating_sub(current.len());
            let (state, truncated) = self.walk(&root, budget, degraded);
            current.extend(state);
            if truncated && !self.truncated {
                self.truncated = true;
                let reason = DegradedReason::WatchLimitExceeded(self.max_entries);
                if !degraded.contains(&reason) {
                    degraded.push(reason);
                }
            }
        }
        for root in removed_roots {
            let reason = DegradedReason::WatchedDirectoryRemoved(root);
            if !degraded.contains(&reason) {
                degraded.push(reason);
            }
        }

        let now_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut raw: Vec<(PathBuf, LiveFsEventKind, bool)> = Vec::new();
        let mut paths: Vec<&PathBuf> = current.keys().collect();
        paths.sort();
        for path in paths {
            let now = &current[path];
            match self.snapshot.get(path) {
                None => raw.push((
                    path.clone(),
                    if now.is_dir {
                        LiveFsEventKind::DirCreated
                    } else {
                        LiveFsEventKind::Created
                    },
                    now.is_dir,
                )),
                Some(before) if !now.is_dir && before != now => {
                    raw.push((path.clone(), LiveFsEventKind::Modified, false))
                }
                _ => {}
            }
        }
        let current_keys: HashSet<&PathBuf> = current.keys().collect();
        let mut gone: Vec<(&PathBuf, &EntryState)> = self
            .snapshot
            .iter()
            .filter(|(p, _)| !current_keys.contains(p))
            .collect();
        gone.sort_by(|a, b| a.0.cmp(b.0));
        for (path, before) in gone {
            raw.push((
                path.clone(),
                if before.is_dir {
                    LiveFsEventKind::DirDeleted
                } else {
                    LiveFsEventKind::Deleted
                },
                before.is_dir,
            ));
        }
        self.snapshot = current;

        let mut events = Vec::new();
        for (path, kind, is_directory) in raw {
            let matched_agent = detect_agent_association(&path);
            if let Some(filter) = agent_filter {
                if matched_agent.as_deref() != Some(filter) {
                    continue;
                }
            }
            if events.len() >= self.max_queued_events {
                let reason = DegradedReason::QueueOverflow(
                    "Polling event queue bound exceeded; remaining changes in this interval were dropped"
                        .to_string(),
                );
                if !degraded.contains(&reason) {
                    degraded.push(reason);
                }
                break;
            }
            events.push(LiveFsEvent {
                path,
                kind,
                is_directory,
                timestamp_epoch_secs: now_epoch,
                matched_agent,
            });
        }
        Ok(events)
    }

    fn active_watches(&self) -> usize {
        self.snapshot.values().filter(|e| e.is_dir).count() + self.roots.len()
    }
}

/// Maps a process name to an agent signature (shared with the Linux observer).
fn agent_from_name(name: &str) -> Option<String> {
    let n = name.to_lowercase();
    if n.contains("antigravity") || n.contains("gemini") {
        Some("antigravity".to_string())
    } else if n.contains("claude") {
        Some("claude".to_string())
    } else if n.contains("codex") {
        Some("codex".to_string())
    } else if n.contains("aider") {
        Some("aider".to_string())
    } else {
        None
    }
}

/// Periodic process table observer built on `ProcessProvider`.
pub struct ProviderProcessObserver<P: ProcessProvider> {
    provider: P,
    tracked: HashMap<u32, ProcessObservation>,
    last_sample: Instant,
    interval: Duration,
}

impl<P: ProcessProvider> ProviderProcessObserver<P> {
    pub fn new(provider: P, interval: Duration) -> Self {
        Self {
            provider,
            tracked: HashMap::new(),
            last_sample: Instant::now() - interval,
            interval,
        }
    }

    pub fn sample_changes(
        &mut self,
        current_uid: u32,
        agent_filter: Option<&str>,
    ) -> Result<Vec<(ProcessEventKind, ProcessObservation)>> {
        if self.last_sample.elapsed() < self.interval {
            return Ok(Vec::new());
        }
        self.last_sample = Instant::now();

        let mut changes = Vec::new();
        let mut current = HashSet::new();

        for pid in self.provider.list_pids()? {
            // A process that vanished or denied access between listing and inspection is skipped.
            let Some(candidate) = self.provider.inspect_process(pid)? else {
                continue;
            };
            let id = &candidate.identity;
            if id.real_uid != current_uid {
                continue;
            }
            let agent = agent_from_name(&id.name);
            if let Some(filter) = agent_filter {
                if agent.as_deref() != Some(filter) {
                    continue;
                }
            }
            current.insert(id.pid);

            let obs = ProcessObservation {
                pid: id.pid,
                ppid: id.ppid,
                uid: id.real_uid,
                binary_name: id.name.clone(),
                start_time_ticks: id.start_time_ticks,
                rss_bytes: candidate.memory.rss_bytes,
                associated_agent: agent,
            };

            match self.tracked.get(&id.pid) {
                Some(existing) if existing.start_time_ticks != id.start_time_ticks => {
                    // Same PID, different start time: the PID was reused.
                    changes.push((ProcessEventKind::Exited, existing.clone()));
                    changes.push((ProcessEventKind::Spawned, obs.clone()));
                    self.tracked.insert(id.pid, obs);
                }
                Some(_) => {}
                None => {
                    changes.push((ProcessEventKind::Spawned, obs.clone()));
                    self.tracked.insert(id.pid, obs);
                }
            }
        }

        let exited: Vec<u32> = self
            .tracked
            .keys()
            .copied()
            .filter(|p| !current.contains(p))
            .collect();
        for pid in exited {
            if let Some(obs) = self.tracked.remove(&pid) {
                changes.push((ProcessEventKind::Exited, obs));
            }
        }
        Ok(changes)
    }
}

/// Periodic system memory observer built on `ResourceAccountant`.
pub struct ProviderMemoryObserver<A: ResourceAccountant> {
    accountant: A,
    last_sample: Instant,
    interval: Duration,
}

impl<A: ResourceAccountant> ProviderMemoryObserver<A> {
    pub fn new(accountant: A, interval: Duration) -> Self {
        Self {
            accountant,
            last_sample: Instant::now() - interval,
            interval,
        }
    }

    pub fn sample_memory(&mut self) -> Result<Option<MemoryObservation>> {
        if self.last_sample.elapsed() < self.interval {
            return Ok(None);
        }
        self.last_sample = Instant::now();
        let mem = self.accountant.get_system_memory()?;
        let pressure = self.accountant.get_pressure_metrics()?;
        Ok(Some(MemoryObservation {
            total_ram_bytes: mem.total_bytes,
            available_ram_bytes: mem.available_bytes,
            swap_used_bytes: mem.swap_total_bytes.saturating_sub(mem.swap_free_bytes),
            swap_total_bytes: mem.swap_total_bytes,
            psi_memory_10s_pct: pressure.map(|p| p.some_10s_pct as f64),
        }))
    }
}

/// Coordinator for a live, read-only monitoring session over portable sources.
pub struct PortableMonitorSession<W, P, A>
where
    W: FsEventSource,
    P: ProcessProvider,
    A: ResourceAccountant,
{
    scope: MonitorScope,
    state: MonitorSessionState,
    degraded_reasons: Vec<DegradedReason>,
    watcher: Option<W>,
    process_observer: Option<ProviderProcessObserver<P>>,
    memory_observer: Option<ProviderMemoryObserver<A>>,
    make_watcher: fn(&MonitorScope) -> W,
    make_process: fn() -> P,
    make_accountant: fn() -> A,
    started_at: Instant,
    started_epoch_secs: i64,
    total_fs_events: u64,
    total_proc_events: u64,
    total_memory_samples: u64,
    current_uid: u32,
}

impl<W, P, A> PortableMonitorSession<W, P, A>
where
    W: FsEventSource,
    P: ProcessProvider,
    A: ResourceAccountant,
{
    /// Creates a session without starting it. The factories construct the platform sources lazily
    /// so that nothing is opened until `start`.
    pub fn with_sources(
        scope: MonitorScope,
        current_uid: u32,
        make_watcher: fn(&MonitorScope) -> W,
        make_process: fn() -> P,
        make_accountant: fn() -> A,
    ) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope,
            state: MonitorSessionState::Created,
            degraded_reasons: Vec::new(),
            watcher: None,
            process_observer: None,
            memory_observer: None,
            make_watcher,
            make_process,
            make_accountant,
            started_at: Instant::now(),
            started_epoch_secs: 0,
            total_fs_events: 0,
            total_proc_events: 0,
            total_memory_samples: 0,
            current_uid,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        self.state = MonitorSessionState::Starting;
        self.started_at = Instant::now();
        self.started_epoch_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let interval = Duration::from_millis(self.scope.budget.sampling_interval_millis);

        if !self.scope.paths.is_empty() {
            let mut watcher = (self.make_watcher)(&self.scope);
            for path in &self.scope.paths {
                if path.exists() {
                    let _ = watcher.add_tree(path, &mut self.degraded_reasons);
                } else {
                    self.degraded_reasons
                        .push(DegradedReason::WatchedDirectoryRemoved(path.clone()));
                }
            }
            self.watcher = Some(watcher);
        }
        if self.scope.observe_processes {
            self.process_observer = Some(ProviderProcessObserver::new(
                (self.make_process)(),
                interval,
            ));
        }
        if self.scope.observe_memory {
            self.memory_observer = Some(ProviderMemoryObserver::new(
                (self.make_accountant)(),
                interval,
            ));
        }

        self.state = if self.degraded_reasons.is_empty() {
            MonitorSessionState::Running
        } else {
            MonitorSessionState::Degraded
        };
        Ok(())
    }

    pub fn poll_events(&mut self) -> Result<Vec<MonitorEvent>> {
        if self.state == MonitorSessionState::Stopped || self.state == MonitorSessionState::Failed {
            return Ok(Vec::new());
        }

        if let Some(max_secs) = self.scope.budget.max_duration_secs {
            if self.started_at.elapsed() >= Duration::from_secs(max_secs) {
                self.state = MonitorSessionState::Stopping;
                return Ok(vec![MonitorEvent::Status {
                    state: MonitorSessionState::Stopping,
                    reason: Some(DegradedReason::ResourceBudgetExceeded(format!(
                        "Wall-clock duration budget of {}s reached",
                        max_secs
                    ))),
                }]);
            }
        }

        let mut events = Vec::new();

        if let Some(watcher) = self.watcher.as_mut() {
            match watcher.poll(
                self.scope.agent_filter.as_deref(),
                &mut self.degraded_reasons,
            ) {
                Ok(fs_events) => {
                    for fe in fs_events {
                        self.total_fs_events += 1;
                        events.push(MonitorEvent::Fs(fe));
                    }
                }
                Err(e) => {
                    self.degraded_reasons
                        .push(DegradedReason::KernelInterfaceUnavailable(format!(
                            "filesystem poll error: {}",
                            e
                        )));
                    self.state = MonitorSessionState::Degraded;
                }
            }
        }

        if let Some(observer) = self.process_observer.as_mut() {
            match observer.sample_changes(self.current_uid, self.scope.agent_filter.as_deref()) {
                Ok(changes) => {
                    for (kind, process) in changes {
                        self.total_proc_events += 1;
                        events.push(MonitorEvent::Process { kind, process });
                    }
                }
                Err(e) => {
                    self.degraded_reasons
                        .push(DegradedReason::KernelInterfaceUnavailable(format!(
                            "process sampling error: {}",
                            e
                        )));
                    self.state = MonitorSessionState::Degraded;
                }
            }
        }

        if let Some(observer) = self.memory_observer.as_mut() {
            if let Ok(Some(m)) = observer.sample_memory() {
                self.total_memory_samples += 1;
                events.push(MonitorEvent::Memory(m));
            }
        }

        if !self.degraded_reasons.is_empty() && self.state == MonitorSessionState::Running {
            self.state = MonitorSessionState::Degraded;
        }
        Ok(events)
    }

    /// Stops the session and releases every source. Cancellation is cooperative: callers stop
    /// polling and call this.
    pub fn stop(&mut self) -> MonitorSessionSummary {
        self.state = MonitorSessionState::Stopped;
        self.watcher = None;
        self.process_observer = None;
        self.memory_observer = None;
        MonitorSessionSummary {
            session_id: format!("mon-{}", self.started_epoch_secs),
            started_epoch_secs: self.started_epoch_secs,
            duration_millis: self.started_at.elapsed().as_millis() as u64,
            final_state: self.state,
            degraded_reasons: self.degraded_reasons.clone(),
            total_fs_events: self.total_fs_events,
            total_process_events: self.total_proc_events,
            total_memory_samples: self.total_memory_samples,
            monitored_paths: self.scope.paths.clone(),
        }
    }

    pub fn state(&self) -> MonitorSessionState {
        self.state
    }

    pub fn degraded_reasons(&self) -> &[DegradedReason] {
        &self.degraded_reasons
    }

    pub fn active_watches(&self) -> usize {
        self.watcher
            .as_ref()
            .map(|w| w.active_watches())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn watcher() -> PollingWatcher {
        PollingWatcher::new(1000, 100, Duration::from_millis(0))
    }

    #[test]
    fn detects_create_modify_delete() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = watcher();
        let mut degraded = Vec::new();
        w.add_tree(dir.path(), &mut degraded).unwrap();

        let file = dir.path().join("a.txt");
        fs::write(&file, b"1").unwrap();
        let ev = w.poll(None, &mut degraded).unwrap();
        assert!(ev
            .iter()
            .any(|e| e.path == file && e.kind == LiveFsEventKind::Created));

        sleep(Duration::from_millis(20));
        fs::write(&file, b"changed").unwrap();
        let ev = w.poll(None, &mut degraded).unwrap();
        assert!(ev
            .iter()
            .any(|e| e.path == file && e.kind == LiveFsEventKind::Modified));

        fs::remove_file(&file).unwrap();
        let ev = w.poll(None, &mut degraded).unwrap();
        assert!(ev
            .iter()
            .any(|e| e.path == file && e.kind == LiveFsEventKind::Deleted));
    }

    #[test]
    fn queue_bound_reports_overflow_instead_of_growing() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = PollingWatcher::new(1000, 3, Duration::from_millis(0));
        let mut degraded = Vec::new();
        w.add_tree(dir.path(), &mut degraded).unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("f{i}")), b"x").unwrap();
        }
        let ev = w.poll(None, &mut degraded).unwrap();
        assert_eq!(ev.len(), 3);
        assert!(degraded
            .iter()
            .any(|d| matches!(d, DegradedReason::QueueOverflow(_))));
    }

    #[test]
    fn entry_budget_reports_watch_limit() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("f{i}")), b"x").unwrap();
        }
        let mut w = PollingWatcher::new(4, 100, Duration::from_millis(0));
        let mut degraded = Vec::new();
        let added = w.add_tree(dir.path(), &mut degraded).unwrap();
        assert_eq!(added, 4);
        assert!(degraded
            .iter()
            .any(|d| matches!(d, DegradedReason::WatchLimitExceeded(4))));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directories_are_not_descended() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"x").unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let mut w = watcher();
        let mut degraded = Vec::new();
        w.add_tree(dir.path(), &mut degraded).unwrap();
        fs::write(outside.path().join("new.txt"), b"y").unwrap();
        let ev = w.poll(None, &mut degraded).unwrap();
        assert!(ev.iter().all(|e| !e.path.starts_with(outside.path())));
    }

    #[test]
    fn removed_root_degrades_session() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("watched");
        fs::create_dir(&root).unwrap();
        let mut w = watcher();
        let mut degraded = Vec::new();
        w.add_tree(&root, &mut degraded).unwrap();
        fs::remove_dir(&root).unwrap();
        w.poll(None, &mut degraded).unwrap();
        assert!(degraded
            .iter()
            .any(|d| matches!(d, DegradedReason::WatchedDirectoryRemoved(_))));
    }

    #[test]
    fn poll_is_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = PollingWatcher::new(100, 100, Duration::from_secs(60));
        let mut degraded = Vec::new();
        w.add_tree(dir.path(), &mut degraded).unwrap();
        w.poll(None, &mut degraded).unwrap();
        fs::write(dir.path().join("late"), b"x").unwrap();
        assert!(w.poll(None, &mut degraded).unwrap().is_empty());
    }
}
