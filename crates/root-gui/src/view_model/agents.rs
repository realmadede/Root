use crate::model::presentation::format_bytes_tabular;
use root_core::discovery::{DiscoveryFinding, LifecycleState};
use root_core::model::ProtectionTier;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// High-level detection status for an agent or toolchain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Active,
    Persistent,
    Dormant,
    NotDetected,
}

impl AgentStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Persistent => "PERSISTENT",
            Self::Dormant => "DORMANT",
            Self::NotDetected => "NOT DETECTED",
        }
    }

    pub fn css_class(&self) -> &'static str {
        match self {
            Self::Active => "badge-active",
            Self::Persistent => "badge-persistent",
            Self::Dormant => "badge-dormant",
            Self::NotDetected => "badge-not-detected",
        }
    }
}

/// Agent card view-model summarizing an AI coding agent or toolchain footprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCardViewModel {
    pub key: &'static str,
    pub display_name: &'static str,
    pub is_ai_agent: bool,
    pub description: &'static str,
    pub status: AgentStatus,
    pub resource_count: usize,
    pub total_bytes: u64,
    pub paths: Vec<PathBuf>,
    pub strictly_protected_count: usize,
    pub transient_count: usize,
    pub known_limitations: Vec<String>,
    pub ownership_notice: &'static str,
}

impl AgentCardViewModel {
    pub fn size_display(&self) -> String {
        format_bytes_tabular(self.total_bytes)
    }
}

/// View-model for the Agents and Development Tools tab.
#[derive(Debug, Clone)]
pub struct AgentsViewModel {
    agents: Vec<AgentCardViewModel>,
    filter_ai_only: bool,
    search_query: String,
}

impl Default for AgentsViewModel {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentsViewModel {
    pub fn new() -> Self {
        let initial_catalog = vec![
            AgentCardViewModel {
                key: "antigravity",
                display_name: "Google Antigravity",
                is_ai_agent: true,
                description: "Agent workspaces, transcripts, checkpoints, and task artifacts.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Active tasks may be holding open file handles in scratch directories.".to_string(),
                    "Transcripts must never be parsed or exposed.".to_string(),
                ],
                ownership_notice: "Worktrees may contain uncommitted user edits; non-exclusive ownership.",
            },
            AgentCardViewModel {
                key: "claude",
                display_name: "Claude Code",
                is_ai_agent: true,
                description: "Session transcripts, conversation caches, and ephemeral working state.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Config directories contain authentication tokens; strictly protected.".to_string(),
                ],
                ownership_notice: "Sessions may run concurrently in background terminal tabs.",
            },
            AgentCardViewModel {
                key: "codex",
                display_name: "OpenAI Codex",
                is_ai_agent: true,
                description: "Temporary execution sandboxes, generation logs, and prompt caches.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Sandbox containers may map host temporary files.".to_string(),
                ],
                ownership_notice: "Cached generation artifacts require age corroboration.",
            },
            AgentCardViewModel {
                key: "gemini",
                display_name: "Gemini CLI",
                is_ai_agent: true,
                description: "Gemini coding assistants, auth caches, and transient workspaces.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "OAuth credentials in ~/.config must never be inspected.".to_string(),
                ],
                ownership_notice: "Scratch files may be actively referenced by background CLI instances.",
            },
            AgentCardViewModel {
                key: "aider",
                display_name: "Aider",
                is_ai_agent: true,
                description: "Git repo auto-commits, voice caches, and tag database files.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Chat history in .aider.chat.history.md contains user prompts.".to_string(),
                ],
                ownership_notice: "Aider tags database (.aider.tags.cache.v3) is safe to re-generate.",
            },
            AgentCardViewModel {
                key: "rust",
                display_name: "Rust & Cargo",
                is_ai_agent: false,
                description: "Cargo target directories, incremental build artifacts, and registry caches.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Cargo locks must be checked to prevent deleting active compilation artifacts.".to_string(),
                ],
                ownership_notice: "Target artifacts belong to human projects as well as agent sessions.",
            },
            AgentCardViewModel {
                key: "node",
                display_name: "Node.js & npm",
                is_ai_agent: false,
                description: "node_modules trees, npm cache tarballs, and build outputs.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Uncommitted local packages may reside within node_modules.".to_string(),
                ],
                ownership_notice: "Multi-project dependencies share storage across toolchains.",
            },
            AgentCardViewModel {
                key: "pnpm",
                display_name: "pnpm Package Store",
                is_ai_agent: false,
                description: "Hard-linked content-addressable package store.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Hard-linked inodes must never be pruned directly to prevent corrupting projects.".to_string(),
                ],
                ownership_notice: "Store is strictly protected; only pnpm itself may prune safely.",
            },
            AgentCardViewModel {
                key: "python",
                display_name: "Python Virtualenvs & Pycache",
                is_ai_agent: false,
                description: ".venv directories, __pycache__, and pytest artifact directories.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Editable pip installs (-e) reference local project sources.".to_string(),
                ],
                ownership_notice: "Virtual environments can be shared between agents and developers.",
            },
            AgentCardViewModel {
                key: "git",
                display_name: "Git Worktrees & Packfiles",
                is_ai_agent: false,
                description: "Secondary worktrees, dangling packfiles, and index caches.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Uncommitted worktree changes must be preserved at all costs.".to_string(),
                ],
                ownership_notice: "Git object databases are immutable and strictly protected.",
            },
            AgentCardViewModel {
                key: "lsp",
                display_name: "Language Servers",
                is_ai_agent: false,
                description: "rust-analyzer, typescript-language-server, pyright, and clangd caches.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Active language server processes hold memory-mapped database files.".to_string(),
                ],
                ownership_notice: "LSP caches are automatically recreated upon workspace reopen.",
            },
            AgentCardViewModel {
                key: "dev",
                display_name: "Development Servers",
                is_ai_agent: false,
                description: "Next.js, Vite, Webpack, and Parcel hot-module-reload scratch caches.",
                status: AgentStatus::NotDetected,
                resource_count: 0,
                total_bytes: 0,
                paths: Vec::new(),
                strictly_protected_count: 0,
                transient_count: 0,
                known_limitations: vec![
                    "Running dev servers will immediately crash if .next/cache is removed in-flight.".to_string(),
                ],
                ownership_notice: "HMR caches are transient and non-authoritative.",
            },
        ];

        Self {
            agents: initial_catalog,
            filter_ai_only: false,
            search_query: String::new(),
        }
    }

    /// Updates agent cards from discovery findings.
    pub fn update_from_findings(&mut self, findings: &[DiscoveryFinding]) {
        // Group findings by target name (case-insensitive substring match against key)
        let mut by_target: HashMap<&'static str, Vec<&DiscoveryFinding>> = HashMap::new();

        for agent in &self.agents {
            by_target.insert(agent.key, Vec::new());
        }

        for finding in findings {
            let target_lower = finding.target_name.to_lowercase();
            let rule_lower = finding.rule_id.to_lowercase();

            for (key, list) in by_target.iter_mut() {
                if target_lower.contains(key) || rule_lower.contains(key) {
                    list.push(finding);
                }
            }
        }

        for agent in &mut self.agents {
            if let Some(list) = by_target.get(agent.key) {
                if list.is_empty() {
                    agent.status = AgentStatus::NotDetected;
                    agent.resource_count = 0;
                    agent.total_bytes = 0;
                    agent.paths.clear();
                    agent.strictly_protected_count = 0;
                    agent.transient_count = 0;
                } else {
                    agent.resource_count = list.len();
                    agent.total_bytes = list.iter().map(|f| f.metadata.storage.bytes).sum();

                    let mut unique_paths = HashSet::new();
                    let mut has_active = false;
                    let mut has_persistent = false;
                    let mut protected = 0;
                    let mut transient = 0;

                    for f in list {
                        unique_paths.insert(f.location.path.clone());
                        match f.lifecycle.state {
                            LifecycleState::Active => has_active = true,
                            LifecycleState::Persistent => has_persistent = true,
                            _ => {}
                        }
                        if f.protection_tier == ProtectionTier::StrictlyProtected {
                            protected += 1;
                        } else {
                            transient += 1;
                        }
                    }

                    agent.paths = unique_paths.into_iter().collect();
                    agent.strictly_protected_count = protected;
                    agent.transient_count = transient;

                    agent.status = if has_active {
                        AgentStatus::Active
                    } else if has_persistent {
                        AgentStatus::Persistent
                    } else {
                        AgentStatus::Dormant
                    };
                }
            }
        }
    }

    /// Sets whether to show only AI coding agents or all development tools.
    pub fn set_filter_ai_only(&mut self, ai_only: bool) {
        self.filter_ai_only = ai_only;
    }

    /// Sets search query.
    pub fn set_search_query(&mut self, query: &str) {
        self.search_query = query.to_string();
    }

    /// Returns visible cards according to active filters.
    pub fn visible_cards(&self) -> Vec<&AgentCardViewModel> {
        let q = self.search_query.to_lowercase();
        self.agents
            .iter()
            .filter(|a| {
                if self.filter_ai_only && !a.is_ai_agent {
                    return false;
                }
                if !q.is_empty() {
                    let name_match = a.display_name.to_lowercase().contains(&q);
                    let key_match = a.key.to_lowercase().contains(&q);
                    let desc_match = a.description.to_lowercase().contains(&q);
                    if !name_match && !key_match && !desc_match {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Count of currently detected agents/tools.
    pub fn detected_count(&self) -> usize {
        self.agents
            .iter()
            .filter(|a| a.status != AgentStatus::NotDetected)
            .count()
    }
}
