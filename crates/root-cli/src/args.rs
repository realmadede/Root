use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "root",
    author = "Raphael Madede <bagomwaraphael@gmail.com>",
    version = env!("CARGO_PKG_VERSION"),
    about = "Deterministic, security-first Linux resource management utility",
    long_about = "Root is a deterministic, security-first Linux system utility engineered to help developers understand, audit, and safely inspect system resources accumulated through agentic coding workflows."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Inspect system capabilities, kernel interfaces, memory distribution, and XDG paths
    Doctor,

    /// Concise system overview, memory pressure, supported targets, and scan activity
    Status {
        /// Output status summary as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Scan and audit development resources and agent artifacts (Dry-Run mode)
    Scan {
        /// Optional path to scan (defaults to isolated synthetic fixture tree if omitted)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Dry-run simulation (mandated in Phase 05)
        #[arg(long, default_value_t = true)]
        dry_run: bool,

        /// Output results as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,

        /// Launch interactive read-only resource browser
        #[arg(short, long, default_value_t = false)]
        interactive: bool,
    },

    /// Discover and classify resources created by AI coding agents and development tools
    Discover {
        /// Optional root path to scan (defaults to detected agent paths or synthetic fixture)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Filter discovery to AI coding agents only
        #[arg(long, default_value_t = false)]
        agents: bool,

        /// Filter discovery to development tooling only
        #[arg(long, default_value_t = false)]
        tools: bool,

        /// Filter discovery to a specific AI coding agent (e.g. antigravity, claude, codex, gemini, aider)
        #[arg(long)]
        agent: Option<String>,

        /// Filter discovery to a specific development tool (e.g. rust, cargo, node, npm, pnpm, python, git, lsp, dev)
        #[arg(long)]
        tool: Option<String>,

        /// Output results as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,

        /// Launch interactive read-only resource browser
        #[arg(short, long, default_value_t = false)]
        interactive: bool,
    },

    /// Inspect Linux platform resources, memory distribution, running processes, storage, or transaction journals
    Inspect {
        #[command(subcommand)]
        target: InspectCommands,
    },

    /// Explain the origin, matched rule, evidence provenance, and Guardian safety decision for a resource
    Explain {
        /// Resource identifier, discovery rule ID (e.g. antigravity-scratch, claude-session-data), or filesystem path
        #[arg(value_name = "RESOURCE_ID")]
        identifier: String,

        /// Output explanation as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Generate a comprehensive diagnostic and resource audit report
    Report {
        /// Optional target path for resource accounting (defaults to detected agent roots)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Output report as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum InspectCommands {
    /// Inspect host RAM, swap accounting, and PSI memory pressure stalls
    Memory {
        /// Output results as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Enumerate and inspect running processes via /proc with privacy protections
    Processes {
        /// Restrict inspection to processes owned by the current invoking user
        #[arg(long, default_value_t = false)]
        user_only: bool,

        /// Output results as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Inspect filesystem capacity, free space, and directory allocation (apparent vs allocated, sparse, multi-link)
    Storage {
        /// Optional path to inspect (defaults to current working directory)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Output results as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Read-only diagnostic inspection of synthetic transaction recovery journals
    Transactions {
        /// Path to synthetic transaction journal (defaults to .root_journal if present)
        #[arg(short, long)]
        journal_path: Option<PathBuf>,

        /// Output results as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}
