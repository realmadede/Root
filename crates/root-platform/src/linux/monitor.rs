use root_core::{
    error::{Result, RootError},
    model::{
        DegradedReason, LiveFsEvent, LiveFsEventKind, MemoryObservation, MonitorEvent,
        MonitorScope, MonitorSessionState, MonitorSessionSummary, ProcessEventKind,
        ProcessObservation,
    },
};
use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use crate::{
    linux::{LinuxAccountant, LinuxProcess},
    traits::{ProcessProvider, ResourceAccountant},
};

/// High-performance Linux inotify filesystem event watcher.
pub struct InotifyWatcher {
    inotify_fd: i32,
    watch_descriptors: HashMap<i32, PathBuf>,
    path_to_wd: HashMap<PathBuf, i32>,
    max_watches: usize,
    max_queued_events: usize,
    recent_events_coalesce: HashMap<PathBuf, (LiveFsEventKind, Instant)>,
}

impl InotifyWatcher {
    /// Initializes an inotify instance with non-blocking I/O and close-on-exec flags.
    pub fn new(max_watches: usize, max_queued_events: usize) -> Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(RootError::Platform(format!(
                "Failed to initialize Linux inotify subsystem: {}",
                err
            )));
        }

        Ok(Self {
            inotify_fd: fd,
            watch_descriptors: HashMap::new(),
            path_to_wd: HashMap::new(),
            max_watches,
            max_queued_events,
            recent_events_coalesce: HashMap::new(),
        })
    }

    /// Recursively registers inotify watches on a directory tree up to the configured watch budget.
    pub fn add_watch_tree(
        &mut self,
        root_path: &Path,
        degraded: &mut Vec<DegradedReason>,
    ) -> Result<usize> {
        let mut added_count = 0;
        let mut queue = vec![root_path.to_path_buf()];

        while let Some(current_dir) = queue.pop() {
            if self.watch_descriptors.len() >= self.max_watches {
                let reason = DegradedReason::WatchLimitExceeded(self.max_watches);
                if !degraded.contains(&reason) {
                    degraded.push(reason);
                }
                break;
            }

            // Do not follow symlinks for watch registration (symlink escape guard)
            let symlink_meta = match fs::symlink_metadata(&current_dir) {
                Ok(m) => m,
                Err(_e) => {
                    degraded.push(DegradedReason::PermissionDenied(current_dir));
                    continue;
                }
            };

            if symlink_meta.file_type().is_symlink() || !symlink_meta.is_dir() {
                continue;
            }

            // Register watch on directory
            if !self.path_to_wd.contains_key(&current_dir) {
                match self.add_single_watch(&current_dir) {
                    Ok(_) => added_count += 1,
                    Err(_e) => {
                        degraded.push(DegradedReason::PermissionDenied(current_dir.clone()));
                        continue;
                    }
                }
            }

            // Scan subdirectories
            if let Ok(entries) = fs::read_dir(&current_dir) {
                for entry in entries.flatten() {
                    let child_path = entry.path();
                    if let Ok(child_meta) = fs::symlink_metadata(&child_path) {
                        if child_meta.is_dir() && !child_meta.file_type().is_symlink() {
                            queue.push(child_path);
                        }
                    }
                }
            }
        }

        Ok(added_count)
    }

    fn add_single_watch(&mut self, path: &Path) -> Result<i32> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| {
            RootError::InvalidPath(format!("Invalid path for inotify watch: {}", e))
        })?;

        let mask = libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MODIFY
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_ONLYDIR;

        let wd = unsafe { libc::inotify_add_watch(self.inotify_fd, c_path.as_ptr(), mask) };
        if wd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(RootError::Io {
                path: path.to_path_buf(),
                source: err,
            });
        }

        self.watch_descriptors.insert(wd, path.to_path_buf());
        self.path_to_wd.insert(path.to_path_buf(), wd);
        Ok(wd)
    }

    pub fn active_watch_count(&self) -> usize {
        self.watch_descriptors.len()
    }

    /// Reads queued events from the inotify descriptor non-blockingly.
    pub fn read_events(
        &mut self,
        agent_filter: Option<&str>,
        degraded: &mut Vec<DegradedReason>,
    ) -> Result<Vec<LiveFsEvent>> {
        let mut buffer = [0u8; 8192];
        let bytes_read = unsafe {
            libc::read(
                self.inotify_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };

        if bytes_read < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(Vec::new());
            }
            return Err(RootError::Platform(format!("inotify read error: {}", err)));
        }

        let mut events = Vec::new();
        let mut offset = 0;
        let now_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let now_instant = Instant::now();

        while offset < bytes_read as usize {
            let event_ptr = unsafe { buffer.as_ptr().add(offset).cast::<libc::inotify_event>() };
            let event = unsafe { &*event_ptr };

            // 1. Check for inotify queue overflow
            if event.mask & libc::IN_Q_OVERFLOW != 0 {
                let reason = DegradedReason::QueueOverflow(
                    "Kernel inotify queue capacity exceeded; events lost".to_string(),
                );
                if !degraded.contains(&reason) {
                    degraded.push(reason);
                }
            }

            // 2. Check for watch deletion
            if event.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF | libc::IN_IGNORED) != 0 {
                if let Some(removed_path) = self.watch_descriptors.remove(&event.wd) {
                    self.path_to_wd.remove(&removed_path);
                    let reason = DegradedReason::WatchedDirectoryRemoved(removed_path);
                    if !degraded.contains(&reason) {
                        degraded.push(reason);
                    }
                }
            }

            // 3. Process named file events
            if event.len > 0 {
                let name_bytes = unsafe {
                    let ptr = buffer
                        .as_ptr()
                        .add(offset + std::mem::size_of::<libc::inotify_event>());
                    std::slice::from_raw_parts(ptr, event.len as usize)
                };

                let name_end = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

                if let Some(parent_path) = self.watch_descriptors.get(&event.wd) {
                    let full_path = parent_path.join(&name);
                    let is_dir = (event.mask & libc::IN_ISDIR) != 0;

                    let kind = if event.mask & libc::IN_CREATE != 0 {
                        if is_dir {
                            // If within budget, register watch on new directory
                            if self.watch_descriptors.len() < self.max_watches {
                                let _ = self.add_single_watch(&full_path);
                            } else {
                                let reason = DegradedReason::WatchLimitExceeded(self.max_watches);
                                if !degraded.contains(&reason) {
                                    degraded.push(reason);
                                }
                            }
                            LiveFsEventKind::DirCreated
                        } else {
                            LiveFsEventKind::Created
                        }
                    } else if event.mask & libc::IN_DELETE != 0 {
                        if is_dir {
                            LiveFsEventKind::DirDeleted
                        } else {
                            LiveFsEventKind::Deleted
                        }
                    } else if event.mask & libc::IN_MODIFY != 0 {
                        LiveFsEventKind::Modified
                    } else if event.mask & libc::IN_MOVED_FROM != 0 {
                        LiveFsEventKind::MovedFrom
                    } else if event.mask & libc::IN_MOVED_TO != 0 {
                        LiveFsEventKind::MovedTo
                    } else {
                        offset += std::mem::size_of::<libc::inotify_event>() + event.len as usize;
                        continue;
                    };

                    // Correlate with matched agent
                    let matched_agent = Self::detect_agent_association(&full_path);

                    if let Some(filter) = agent_filter {
                        if matched_agent.as_deref() != Some(filter) {
                            offset +=
                                std::mem::size_of::<libc::inotify_event>() + event.len as usize;
                            continue;
                        }
                    }

                    // Event coalescing for rapid sequential modifications to the same file
                    let should_emit = match (kind, self.recent_events_coalesce.get(&full_path)) {
                        (
                            LiveFsEventKind::Modified,
                            Some((LiveFsEventKind::Modified, prev_time)),
                        ) => now_instant.duration_since(*prev_time) >= Duration::from_millis(150),
                        _ => true,
                    };

                    if should_emit {
                        self.recent_events_coalesce
                            .insert(full_path.clone(), (kind, now_instant));

                        // Enforce bounded event queue limit
                        if events.len() < self.max_queued_events {
                            events.push(LiveFsEvent {
                                path: full_path,
                                kind,
                                is_directory: is_dir,
                                timestamp_epoch_secs: now_epoch,
                                matched_agent,
                            });
                        } else {
                            let reason = DegradedReason::ResourceBudgetExceeded(
                                "Event queue capacity reached".to_string(),
                            );
                            if !degraded.contains(&reason) {
                                degraded.push(reason);
                            }
                            break;
                        }
                    }
                }
            }

            offset += std::mem::size_of::<libc::inotify_event>() + event.len as usize;
        }

        // Clean up stale coalescing entries (> 5 seconds old)
        self.recent_events_coalesce
            .retain(|_, (_, time)| now_instant.duration_since(*time) < Duration::from_secs(5));

        Ok(events)
    }

    fn detect_agent_association(path: &Path) -> Option<String> {
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
}

impl Drop for InotifyWatcher {
    fn drop(&mut self) {
        for wd in self.watch_descriptors.keys() {
            unsafe {
                libc::inotify_rm_watch(self.inotify_fd, *wd);
            }
        }
        unsafe {
            libc::close(self.inotify_fd);
        }
    }
}

impl crate::traits::FsEventSource for InotifyWatcher {
    fn backend_name(&self) -> &'static str {
        "inotify"
    }

    fn add_tree(&mut self, root: &Path, degraded: &mut Vec<DegradedReason>) -> Result<usize> {
        self.add_watch_tree(root, degraded)
    }

    fn poll(
        &mut self,
        agent_filter: Option<&str>,
        degraded: &mut Vec<DegradedReason>,
    ) -> Result<Vec<LiveFsEvent>> {
        self.read_events(agent_filter, degraded)
    }

    fn active_watches(&self) -> usize {
        self.active_watch_count()
    }
}

/// Lightweight periodic process table observer.
pub struct ProcessObserver {
    process_provider: LinuxProcess,
    tracked_processes: HashMap<u32, ProcessObservation>,
    last_sample_time: Instant,
    sample_interval: Duration,
}

impl ProcessObserver {
    pub fn new(interval: Duration) -> Self {
        Self {
            process_provider: LinuxProcess::new(),
            tracked_processes: HashMap::new(),
            last_sample_time: Instant::now() - interval,
            sample_interval: interval,
        }
    }

    pub fn sample_changes(
        &mut self,
        current_uid: u32,
        agent_filter: Option<&str>,
    ) -> Result<Vec<(ProcessEventKind, ProcessObservation)>> {
        if self.last_sample_time.elapsed() < self.sample_interval {
            return Ok(Vec::new());
        }
        self.last_sample_time = Instant::now();

        let mut changes = Vec::new();
        let pids = self.process_provider.list_pids()?;
        let mut current_pids = HashSet::new();

        for pid in pids {
            let stat_path = format!("/proc/{}/stat", pid);
            let stat_content = match fs::read_to_string(&stat_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let (parsed_pid, comm, _state, ppid, _tty, start_time_ticks) =
                match LinuxProcess::parse_stat_line(&stat_content) {
                    Some(vals) => vals,
                    None => continue,
                };

            let status_path = format!("/proc/{}/status", pid);
            let uid = match fs::read_to_string(&status_path) {
                Ok(c) => LinuxProcess::parse_status_uid(&c).unwrap_or(current_uid),
                Err(_) => current_uid,
            };

            // Only track processes for the current invoking user
            if uid != current_uid {
                continue;
            }

            let associated_agent = if comm.contains("antigravity") || comm.contains("gemini") {
                Some("antigravity".to_string())
            } else if comm.contains("claude") {
                Some("claude".to_string())
            } else if comm.contains("codex") {
                Some("codex".to_string())
            } else if comm.contains("aider") {
                Some("aider".to_string())
            } else {
                None
            };

            if let Some(filter) = agent_filter {
                if associated_agent.as_deref() != Some(filter) {
                    continue;
                }
            }

            current_pids.insert(parsed_pid);

            let mem = self
                .process_provider
                .get_process_memory(parsed_pid)?
                .map(|m| m.rss_bytes)
                .unwrap_or(0);

            let obs = ProcessObservation {
                pid: parsed_pid,
                ppid,
                uid,
                binary_name: comm,
                start_time_ticks,
                rss_bytes: mem,
                associated_agent,
            };

            // Check if PID exists and verify start_time_ticks to detect PID reuse
            if let Some(existing) = self.tracked_processes.get(&parsed_pid) {
                if existing.start_time_ticks != start_time_ticks {
                    // Process with this PID exited and was replaced by a new process
                    changes.push((ProcessEventKind::Exited, existing.clone()));
                    changes.push((ProcessEventKind::Spawned, obs.clone()));
                    self.tracked_processes.insert(parsed_pid, obs);
                }
            } else {
                // New process spawned
                changes.push((ProcessEventKind::Spawned, obs.clone()));
                self.tracked_processes.insert(parsed_pid, obs);
            }
        }

        // Identify processes that exited
        let exited_pids: Vec<u32> = self
            .tracked_processes
            .keys()
            .copied()
            .filter(|p| !current_pids.contains(p))
            .collect();

        for pid in exited_pids {
            if let Some(exited_obs) = self.tracked_processes.remove(&pid) {
                changes.push((ProcessEventKind::Exited, exited_obs));
            }
        }

        Ok(changes)
    }
}

/// Periodic host system memory observer.
pub struct MemoryObserver {
    accountant: LinuxAccountant,
    last_sample_time: Instant,
    sample_interval: Duration,
}

impl MemoryObserver {
    pub fn new(interval: Duration) -> Self {
        Self {
            accountant: LinuxAccountant::new(),
            last_sample_time: Instant::now() - interval,
            sample_interval: interval,
        }
    }

    pub fn sample_memory(&mut self) -> Result<Option<MemoryObservation>> {
        if self.last_sample_time.elapsed() < self.sample_interval {
            return Ok(None);
        }
        self.last_sample_time = Instant::now();

        let mem = self.accountant.get_system_memory()?;
        let pressure = self.accountant.get_pressure_metrics()?;
        let swap_used = mem.swap_total_bytes.saturating_sub(mem.swap_free_bytes);

        Ok(Some(MemoryObservation {
            total_ram_bytes: mem.total_bytes,
            available_ram_bytes: mem.available_bytes,
            swap_used_bytes: swap_used,
            swap_total_bytes: mem.swap_total_bytes,
            psi_memory_10s_pct: pressure.map(|p| p.some_10s_pct as f64),
        }))
    }
}

/// Linux coordinator managing a live, read-only resource monitoring session.
pub struct LinuxMonitorSession {
    scope: MonitorScope,
    state: MonitorSessionState,
    degraded_reasons: Vec<DegradedReason>,
    watcher: Option<InotifyWatcher>,
    process_observer: Option<ProcessObserver>,
    memory_observer: Option<MemoryObserver>,
    started_at: Instant,
    started_epoch_secs: i64,
    total_fs_events: u64,
    total_proc_events: u64,
    total_memory_samples: u64,
    current_uid: u32,
}

impl LinuxMonitorSession {
    /// Creates a new monitoring session for the given scope without starting it.
    pub fn new(scope: MonitorScope, current_uid: u32) -> Result<Self> {
        scope.validate()?;

        Ok(Self {
            scope,
            state: MonitorSessionState::Created,
            degraded_reasons: Vec::new(),
            watcher: None,
            process_observer: None,
            memory_observer: None,
            started_at: Instant::now(),
            started_epoch_secs: 0,
            total_fs_events: 0,
            total_proc_events: 0,
            total_memory_samples: 0,
            current_uid,
        })
    }

    /// Explicitly activates the monitoring session, configuring watches and initial snapshots.
    pub fn start(&mut self) -> Result<()> {
        self.state = MonitorSessionState::Starting;
        self.started_at = Instant::now();
        self.started_epoch_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let sample_interval = Duration::from_millis(self.scope.budget.sampling_interval_millis);

        // 1. Initialize Inotify watcher if paths or agent filter are provided
        if !self.scope.paths.is_empty() {
            let mut watcher = InotifyWatcher::new(
                self.scope.budget.max_watches,
                self.scope.budget.max_queued_events,
            )?;

            for path in &self.scope.paths {
                if path.exists() {
                    let _ = watcher.add_watch_tree(path, &mut self.degraded_reasons);
                } else {
                    self.degraded_reasons
                        .push(DegradedReason::WatchedDirectoryRemoved(path.clone()));
                }
            }

            self.watcher = Some(watcher);
        }

        // 2. Initialize Process observer if requested
        if self.scope.observe_processes {
            self.process_observer = Some(ProcessObserver::new(sample_interval));
        }

        // 3. Initialize Memory observer if requested
        if self.scope.observe_memory {
            self.memory_observer = Some(MemoryObserver::new(sample_interval));
        }

        self.state = if self.degraded_reasons.is_empty() {
            MonitorSessionState::Running
        } else {
            MonitorSessionState::Degraded
        };

        Ok(())
    }

    /// Polls all configured event sources, returning a batch of newly observed events.
    pub fn poll_events(&mut self) -> Result<Vec<MonitorEvent>> {
        if self.state == MonitorSessionState::Stopped || self.state == MonitorSessionState::Failed {
            return Ok(Vec::new());
        }

        // Check max duration budget
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

        // 1. Poll inotify filesystem events
        if let Some(ref mut watcher) = self.watcher {
            match watcher.read_events(
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
                            "inotify poll error: {}",
                            e
                        )));
                    self.state = MonitorSessionState::Degraded;
                }
            }
        }

        // 2. Sample process table events
        if let Some(ref mut proc_obs) = self.process_observer {
            match proc_obs.sample_changes(self.current_uid, self.scope.agent_filter.as_deref()) {
                Ok(proc_events) => {
                    for (kind, p) in proc_events {
                        self.total_proc_events += 1;
                        events.push(MonitorEvent::Process { kind, process: p });
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

        // 3. Sample memory metrics
        if let Some(ref mut mem_obs) = self.memory_observer {
            if let Ok(Some(m)) = mem_obs.sample_memory() {
                self.total_memory_samples += 1;
                events.push(MonitorEvent::Memory(m));
            }
        }

        // Update degraded status
        if !self.degraded_reasons.is_empty() && self.state == MonitorSessionState::Running {
            self.state = MonitorSessionState::Degraded;
        }

        Ok(events)
    }

    /// Stops the live monitoring session, cleans up resources, and returns a summary report.
    pub fn stop(&mut self) -> MonitorSessionSummary {
        self.state = MonitorSessionState::Stopped;
        self.watcher = None; // Drops inotify fd cleanly
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
            .map(|w| w.active_watch_count())
            .unwrap_or(0)
    }
}
