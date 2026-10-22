use crate::model::presentation::{format_bytes_tabular, format_pid};
use root_core::model::ProcessState;
use root_platform::traits::{EnvironmentProvider, ProcessProvider};
use root_platform::{NativeEnvironment, NativeProcess};
use serde::{Deserialize, Serialize};

/// Attribution confidence level for linking a process to an AI agent or development tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessAttributionConfidence {
    High,
    Medium,
    Low,
    Unattributed,
}

impl ProcessAttributionConfidence {
    pub fn label(&self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Unattributed => "None",
        }
    }
}

/// Process item in the process inspection table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessItemViewModel {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub uid: u32,
    pub rss_bytes: u64,
    pub state: ProcessState,
    pub attributed_tool: Option<String>,
    pub confidence: ProcessAttributionConfidence,
    pub is_user_owned: bool,
}

impl ProcessItemViewModel {
    pub fn pid_display(&self) -> String {
        format_pid(self.pid)
    }

    pub fn rss_display(&self) -> String {
        format_bytes_tabular(self.rss_bytes)
    }

    pub fn state_display(&self) -> &'static str {
        match self.state {
            ProcessState::Running => "Running",
            ProcessState::Sleeping => "Sleeping",
            ProcessState::DiskSleep => "Disk Sleep",
            ProcessState::Zombie => "Zombie",
            ProcessState::Stopped => "Stopped",
            ProcessState::TracingStop => "Tracing Stop",
            ProcessState::Dead => "Dead",
            ProcessState::Unknown => "Unknown",
        }
    }
}

/// Process list sorting options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProcessSortField {
    #[default]
    RssMemory,
    Pid,
    Name,
    State,
}

/// View-model managing unprivileged process table inspection.
#[derive(Debug, Clone, Default)]
pub struct ProcessesViewModel {
    all_processes: Vec<ProcessItemViewModel>,
    filtered_processes: Vec<ProcessItemViewModel>,
    user_only_filter: bool,
    attributed_only_filter: bool,
    search_query: String,
    sort_field: ProcessSortField,
    sort_descending: bool,
}

impl ProcessesViewModel {
    pub fn new() -> Self {
        Self {
            all_processes: Vec::new(),
            filtered_processes: Vec::new(),
            user_only_filter: true, // Default to user-owned processes
            attributed_only_filter: false,
            search_query: String::new(),
            sort_field: ProcessSortField::RssMemory,
            sort_descending: true,
        }
    }

    /// Refreshes process table by querying `/proc` via `root-platform`.
    pub fn refresh(&mut self) {
        let provider = NativeProcess::new();
        let my_uid = NativeEnvironment::new().current_uid();

        if let Ok(pids) = provider.list_pids() {
            let mut list = Vec::new();
            for pid in pids {
                if let Ok(Some(candidate)) = provider.inspect_process(pid) {
                    let (attributed_tool, confidence) =
                        Self::attribute_process(&candidate.identity.name);
                    list.push(ProcessItemViewModel {
                        pid: candidate.identity.pid,
                        ppid: candidate.identity.ppid,
                        name: candidate.identity.name,
                        uid: candidate.identity.real_uid,
                        rss_bytes: candidate.memory.rss_bytes,
                        state: candidate.state,
                        attributed_tool,
                        confidence,
                        is_user_owned: candidate.identity.real_uid == my_uid,
                    });
                }
            }
            self.all_processes = list;
            self.apply_filter_and_sort();
        }
    }

    /// Injects processes directly (used for testing and headless simulation).
    pub fn load_processes(&mut self, processes: Vec<ProcessItemViewModel>) {
        self.all_processes = processes;
        self.apply_filter_and_sort();
    }

    pub fn set_user_only_filter(&mut self, user_only: bool) {
        self.user_only_filter = user_only;
        self.apply_filter_and_sort();
    }

    pub fn set_attributed_only_filter(&mut self, attributed_only: bool) {
        self.attributed_only_filter = attributed_only;
        self.apply_filter_and_sort();
    }

    pub fn set_search_query(&mut self, query: &str) {
        self.search_query = query.to_string();
        self.apply_filter_and_sort();
    }

    pub fn set_sorting(&mut self, field: ProcessSortField, descending: bool) {
        self.sort_field = field;
        self.sort_descending = descending;
        self.apply_filter_and_sort();
    }

    pub fn visible_processes(&self) -> &[ProcessItemViewModel] {
        &self.filtered_processes
    }

    pub fn total_process_count(&self) -> usize {
        self.all_processes.len()
    }

    pub fn total_filtered_rss_bytes(&self) -> u64 {
        self.filtered_processes.iter().map(|p| p.rss_bytes).sum()
    }

    fn attribute_process(name: &str) -> (Option<String>, ProcessAttributionConfidence) {
        let n = name.to_lowercase();
        if n.contains("antigravity") || n.contains("agy") {
            (
                Some("Google Antigravity".to_string()),
                ProcessAttributionConfidence::High,
            )
        } else if n.contains("claude") {
            (
                Some("Claude Code".to_string()),
                ProcessAttributionConfidence::High,
            )
        } else if n.contains("codex") {
            (
                Some("OpenAI Codex".to_string()),
                ProcessAttributionConfidence::High,
            )
        } else if n.contains("gemini") {
            (
                Some("Gemini CLI".to_string()),
                ProcessAttributionConfidence::High,
            )
        } else if n.contains("aider") {
            (
                Some("Aider".to_string()),
                ProcessAttributionConfidence::High,
            )
        } else if n.contains("cargo") || n.contains("rustc") {
            (
                Some("Rust / Cargo".to_string()),
                ProcessAttributionConfidence::Medium,
            )
        } else if n.contains("node") || n.contains("npm") || n.contains("pnpm") {
            (
                Some("Node.js / npm".to_string()),
                ProcessAttributionConfidence::Medium,
            )
        } else if n.contains("rust-analyzer") || n.contains("pyright") || n.contains("gopls") {
            (
                Some("Language Server".to_string()),
                ProcessAttributionConfidence::High,
            )
        } else if n.contains("python") || n.contains("python3") {
            (
                Some("Python Runtime".to_string()),
                ProcessAttributionConfidence::Low,
            )
        } else {
            (None, ProcessAttributionConfidence::Unattributed)
        }
    }

    fn apply_filter_and_sort(&mut self) {
        let q = self.search_query.to_lowercase();

        let mut filtered: Vec<ProcessItemViewModel> = self
            .all_processes
            .iter()
            .filter(|p| {
                if self.user_only_filter && !p.is_user_owned {
                    return false;
                }
                if self.attributed_only_filter && p.attributed_tool.is_none() {
                    return false;
                }
                if !q.is_empty() {
                    let name_match = p.name.to_lowercase().contains(&q);
                    let pid_match = p.pid.to_string().contains(&q);
                    let tool_match = p
                        .attributed_tool
                        .as_ref()
                        .map(|t| t.to_lowercase().contains(&q))
                        .unwrap_or(false);
                    if !name_match && !pid_match && !tool_match {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        filtered.sort_by(|a, b| {
            let cmp = match self.sort_field {
                ProcessSortField::RssMemory => a.rss_bytes.cmp(&b.rss_bytes),
                ProcessSortField::Pid => a.pid.cmp(&b.pid),
                ProcessSortField::Name => a.name.cmp(&b.name),
                ProcessSortField::State => (a.state as u8).cmp(&(b.state as u8)),
            };

            if self.sort_descending {
                cmp.reverse()
            } else {
                cmp
            }
        });

        self.filtered_processes = filtered;
    }
}
