use crate::model::presentation::format_path_middle;
use root_core::model::{
    DegradedReason, LiveFsEventKind, MonitorBudget, MonitorEvent, MonitorScope,
    MonitorSessionState, ProcessEventKind,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;

/// Formatted live event item for display in the activity stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormattedActivityEvent {
    pub timestamp_rfc3339: String,
    pub event_kind: String,
    pub css_class: &'static str,
    pub summary: String,
}

impl FormattedActivityEvent {
    pub fn from_monitor_event(event: &MonitorEvent) -> Self {
        match event {
            MonitorEvent::Fs(fs) => {
                let (kind_str, css) = match fs.kind {
                    LiveFsEventKind::Created => ("CREATE", "event-create"),
                    LiveFsEventKind::Modified => ("MODIFY", "event-modify"),
                    LiveFsEventKind::Deleted => ("DELETE", "event-delete"),
                    LiveFsEventKind::MovedFrom => ("MOVE FROM", "event-move"),
                    LiveFsEventKind::MovedTo => ("MOVE TO", "event-move"),
                    LiveFsEventKind::DirCreated => ("DIR CREATE", "event-create"),
                    LiveFsEventKind::DirDeleted => ("DIR DELETE", "event-delete"),
                };

                let path_display = format_path_middle(&fs.path, 50);
                let agent_tag = fs
                    .matched_agent
                    .as_deref()
                    .map(|a| format!(" [{}]", a))
                    .unwrap_or_default();

                Self {
                    timestamp_rfc3339: format!("{}s", fs.timestamp_epoch_secs),
                    event_kind: kind_str.to_string(),
                    css_class: css,
                    summary: format!("{}{}", path_display, agent_tag),
                }
            }
            MonitorEvent::Process { kind, process } => {
                let (kind_str, css) = match kind {
                    ProcessEventKind::Spawned => ("SPAWN", "event-spawn"),
                    ProcessEventKind::Exited => ("EXIT", "event-exit"),
                };

                let tool_tag = process
                    .associated_agent
                    .as_deref()
                    .map(|a| format!(" ({})", a))
                    .unwrap_or_default();

                Self {
                    timestamp_rfc3339: "live".to_string(),
                    event_kind: kind_str.to_string(),
                    css_class: css,
                    summary: format!("PID {} {}{}", process.pid, process.binary_name, tool_tag),
                }
            }
            MonitorEvent::Memory(mem) => {
                let psi_str = mem
                    .psi_memory_10s_pct
                    .map(|pct| format!("PSI 10s: {:.1}%", pct))
                    .unwrap_or_else(|| "PSI unavailable".to_string());

                Self {
                    timestamp_rfc3339: "live".to_string(),
                    event_kind: "MEM SAMPLE".to_string(),
                    css_class: "event-sample",
                    summary: format!("RAM Available: {} B, {}", mem.available_ram_bytes, psi_str),
                }
            }
            MonitorEvent::Status { state, reason } => {
                let reason_str = reason
                    .as_ref()
                    .map(|r| format!(" — {}", r.display_message()))
                    .unwrap_or_default();
                Self {
                    timestamp_rfc3339: "live".to_string(),
                    event_kind: "STATUS".to_string(),
                    css_class: "event-state",
                    summary: format!("{:?}{}", state, reason_str),
                }
            }
        }
    }
}

/// View-model for Mode C live monitoring.
#[derive(Debug, Clone)]
pub struct ActivityViewModel {
    pub session_state: MonitorSessionState,
    pub approved_paths: Vec<PathBuf>,
    pub agent_filter: Option<String>,
    pub observe_processes: bool,
    pub observe_memory: bool,
    pub recent_events: VecDeque<FormattedActivityEvent>,
    pub degraded_reasons: Vec<DegradedReason>,
    pub max_buffer_events: usize,
    pub total_events_received: usize,
}

impl Default for ActivityViewModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivityViewModel {
    pub fn new() -> Self {
        Self {
            session_state: MonitorSessionState::Stopped,
            approved_paths: Vec::new(),
            agent_filter: None,
            observe_processes: true,
            observe_memory: true,
            recent_events: VecDeque::with_capacity(250),
            degraded_reasons: Vec::new(),
            max_buffer_events: 250,
            total_events_received: 0,
        }
    }

    /// Adds an approved path to the monitoring scope.
    pub fn add_target_path(&mut self, path: PathBuf) {
        if !self.approved_paths.contains(&path) {
            self.approved_paths.push(path);
        }
    }

    /// Clears target paths.
    pub fn clear_target_paths(&mut self) {
        self.approved_paths.clear();
    }

    /// Validates whether monitoring can be started with the configured scope.
    pub fn validate_scope(&self) -> Result<MonitorScope, String> {
        let scope = MonitorScope {
            paths: self.approved_paths.clone(),
            agent_filter: self.agent_filter.clone(),
            observe_processes: self.observe_processes,
            observe_memory: self.observe_memory,
            budget: MonitorBudget::default(),
        };

        scope.validate().map_err(|e| e.to_string())?;
        Ok(scope)
    }

    /// Simulates/starts monitoring session.
    pub fn start(&mut self) -> Result<(), String> {
        self.validate_scope()?;
        self.session_state = MonitorSessionState::Running;
        self.degraded_reasons.clear();
        Ok(())
    }

    /// Stops monitoring session.
    pub fn stop(&mut self) {
        self.session_state = MonitorSessionState::Stopped;
    }

    /// Pushes a newly received event into the bounded buffer.
    pub fn push_event(&mut self, event: &MonitorEvent) {
        self.total_events_received += 1;
        let formatted = FormattedActivityEvent::from_monitor_event(event);

        if self.recent_events.len() >= self.max_buffer_events {
            self.recent_events.pop_back();
        }
        self.recent_events.push_front(formatted);
    }

    /// Appends a degraded condition.
    pub fn flag_degraded(&mut self, reason: DegradedReason) {
        self.session_state = MonitorSessionState::Degraded;
        if !self.degraded_reasons.contains(&reason) {
            self.degraded_reasons.push(reason);
        }
    }

    /// Returns true if currently running or degraded.
    pub fn is_active(&self) -> bool {
        matches!(
            self.session_state,
            MonitorSessionState::Running | MonitorSessionState::Degraded
        )
    }

    /// Returns list of visible formatted events.
    pub fn events(&self) -> &VecDeque<FormattedActivityEvent> {
        &self.recent_events
    }

    /// Clears the event buffer.
    pub fn clear_events(&mut self) {
        self.recent_events.clear();
        self.total_events_received = 0;
    }
}
