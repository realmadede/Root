use serde::{Deserialize, Serialize};

/// Broad classification of a discovery target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// Autonomous or conversational AI coding assistant.
    Agent,
    /// Language toolchain, compiler cache, package manager, or build system.
    Tool,
}

/// Supported discovery target identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryTargetId {
    // AI Coding Agents
    Antigravity,
    ClaudeCode,
    OpenAiCodex,
    GeminiCli,
    Aider,

    // Development Tooling
    NodeNpm,
    Pnpm,
    RustCargo,
    Python,
    Git,
    LanguageServers,
    DevServers,
}

impl DiscoveryTargetId {
    pub fn all() -> &'static [DiscoveryTargetId] {
        &[
            DiscoveryTargetId::Antigravity,
            DiscoveryTargetId::ClaudeCode,
            DiscoveryTargetId::OpenAiCodex,
            DiscoveryTargetId::GeminiCli,
            DiscoveryTargetId::Aider,
            DiscoveryTargetId::NodeNpm,
            DiscoveryTargetId::Pnpm,
            DiscoveryTargetId::RustCargo,
            DiscoveryTargetId::Python,
            DiscoveryTargetId::Git,
            DiscoveryTargetId::LanguageServers,
            DiscoveryTargetId::DevServers,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            DiscoveryTargetId::Antigravity => "Google Antigravity",
            DiscoveryTargetId::ClaudeCode => "Claude Code",
            DiscoveryTargetId::OpenAiCodex => "OpenAI Codex",
            DiscoveryTargetId::GeminiCli => "Gemini CLI",
            DiscoveryTargetId::Aider => "Aider Pair Programmer",
            DiscoveryTargetId::NodeNpm => "Node.js & npm",
            DiscoveryTargetId::Pnpm => "pnpm Package Manager",
            DiscoveryTargetId::RustCargo => "Rust & Cargo",
            DiscoveryTargetId::Python => "Python Ecosystem",
            DiscoveryTargetId::Git => "Git Version Control",
            DiscoveryTargetId::LanguageServers => "Language Servers",
            DiscoveryTargetId::DevServers => "Development Servers",
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            DiscoveryTargetId::Antigravity => "antigravity",
            DiscoveryTargetId::ClaudeCode => "claude",
            DiscoveryTargetId::OpenAiCodex => "codex",
            DiscoveryTargetId::GeminiCli => "gemini",
            DiscoveryTargetId::Aider => "aider",
            DiscoveryTargetId::NodeNpm => "node-npm",
            DiscoveryTargetId::Pnpm => "pnpm",
            DiscoveryTargetId::RustCargo => "rust-cargo",
            DiscoveryTargetId::Python => "python",
            DiscoveryTargetId::Git => "git",
            DiscoveryTargetId::LanguageServers => "lsp",
            DiscoveryTargetId::DevServers => "dev-servers",
        }
    }

    pub fn kind(&self) -> TargetKind {
        match self {
            DiscoveryTargetId::Antigravity
            | DiscoveryTargetId::ClaudeCode
            | DiscoveryTargetId::OpenAiCodex
            | DiscoveryTargetId::GeminiCli
            | DiscoveryTargetId::Aider => TargetKind::Agent,

            DiscoveryTargetId::NodeNpm
            | DiscoveryTargetId::Pnpm
            | DiscoveryTargetId::RustCargo
            | DiscoveryTargetId::Python
            | DiscoveryTargetId::Git
            | DiscoveryTargetId::LanguageServers
            | DiscoveryTargetId::DevServers => TargetKind::Tool,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            DiscoveryTargetId::Antigravity => {
                "Google Antigravity agent CLI/IDE workspaces, scratchpads, and step logs"
            }
            DiscoveryTargetId::ClaudeCode => {
                "Claude Code sessions, leaked session environments, and shell snapshots"
            }
            DiscoveryTargetId::OpenAiCodex => {
                "OpenAI Codex CLI response caches and configuration directories"
            }
            DiscoveryTargetId::GeminiCli => {
                "Gemini CLI upload chunks, temporary files, and historical logs"
            }
            DiscoveryTargetId::Aider => {
                "Aider Git-integrated chat histories and repository tags cache"
            }
            DiscoveryTargetId::NodeNpm => {
                "Node.js dependency modules (node_modules) and npm global cache"
            }
            DiscoveryTargetId::Pnpm => "pnpm content-addressable hard-link store and project links",
            DiscoveryTargetId::RustCargo => {
                "Cargo build directories (target/) and crates.io registry cache"
            }
            DiscoveryTargetId::Python => {
                "Python bytecode (__pycache__), pytest cache, and virtual environments"
            }
            DiscoveryTargetId::Git => {
                "Git repository metadata, object database, and reflog integrity"
            }
            DiscoveryTargetId::LanguageServers => {
                "Language server background processes (rust-analyzer, tsserver, pyright)"
            }
            DiscoveryTargetId::DevServers => {
                "Background development and live-reload servers (vite, next, uvicorn)"
            }
        }
    }

    pub fn from_filter(s: &str) -> Option<Self> {
        let clean = s.trim().to_lowercase();
        match clean.as_str() {
            "antigravity" | "agy" | "google-antigravity" => Some(DiscoveryTargetId::Antigravity),
            "claude" | "claude-code" => Some(DiscoveryTargetId::ClaudeCode),
            "codex" | "openai" | "openai-codex" => Some(DiscoveryTargetId::OpenAiCodex),
            "gemini" | "gemini-cli" => Some(DiscoveryTargetId::GeminiCli),
            "aider" => Some(DiscoveryTargetId::Aider),
            "node" | "npm" | "node-npm" => Some(DiscoveryTargetId::NodeNpm),
            "pnpm" => Some(DiscoveryTargetId::Pnpm),
            "rust" | "cargo" | "rust-cargo" => Some(DiscoveryTargetId::RustCargo),
            "python" | "py" => Some(DiscoveryTargetId::Python),
            "git" => Some(DiscoveryTargetId::Git),
            "lsp" | "language-servers" => Some(DiscoveryTargetId::LanguageServers),
            "dev" | "dev-servers" => Some(DiscoveryTargetId::DevServers),
            _ => None,
        }
    }
}
