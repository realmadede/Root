use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod doctor;
mod scan;

#[derive(Parser)]
#[command(
    name = "root",
    author = "Raphael Madede <bagomwaraphael@gmail.com>",
    version = "0.1.0",
    about = "Deterministic, security-first Linux resource management utility",
    long_about = "Root is a deterministic, security-first Linux system utility engineered to help developers understand, audit, and safely recover system resources accumulated through agentic coding workflows."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect system capabilities, kernel interfaces, memory distribution, and XDG paths
    Doctor,

    /// Scan and audit development resources and agent artifacts (Dry-Run mode)
    Scan {
        /// Optional path to scan (defaults to isolated synthetic fixture tree if omitted)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Dry-run simulation (mandated in Phase 01)
        #[arg(long, default_value_t = true)]
        dry_run: bool,

        /// Output results as structured JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor => {
            doctor::run_doctor()?;
        }
        Commands::Scan { path, json, .. } => {
            scan::run_scan(path, json)?;
        }
    }

    Ok(())
}
