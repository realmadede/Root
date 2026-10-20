use clap::Parser;
use root_core::error::{Result, RootError};

pub mod args;
pub mod discover;
pub mod doctor;
pub mod explain;
pub mod history;
pub mod inspect;
pub mod interactive;
pub mod report;
pub mod scan;
pub mod status;
pub mod terminal;

pub use args::{Cli, Commands, InspectCommands};

/// Executes Root CLI commands using the process command-line arguments.
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    run_with_args(args)
}

/// Executes Root CLI commands using an explicit argument sequence.
pub fn run_with_args<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args_vec: Vec<std::ffi::OsString> = args.into_iter().map(|a| a.into()).collect();

    // Check for attempts to access mutation operations through the production CLI
    if let Some(sub_os) = args_vec.get(1) {
        let sub = sub_os.to_string_lossy();
        if sub == "clean"
            || sub == "quarantine"
            || sub == "restore"
            || sub == "delete"
            || sub == "prune"
        {
            return Err(RootError::PolicyViolation {
                reason: format!(
                    "Mutation command '{}' is strictly prohibited in the production CLI. Root is operating in Read-Only Safety Mode. Quarantine and restoration mechanics are restricted to isolated synthetic test fixtures.",
                    sub
                ),
            });
        }
    }

    let cli = match Cli::try_parse_from(&args_vec) {
        Ok(c) => c,
        Err(e) => {
            // Re-render clap error to stderr and return an InvalidPath/Parse error
            eprintln!("{}", e);
            return Err(RootError::InvalidPath(e.to_string()));
        }
    };

    dispatch_command(cli.command)
}

/// Dispatches a validated CLI command to its respective handler.
pub fn dispatch_command(command: Commands) -> Result<()> {
    match command {
        Commands::Doctor => {
            doctor::run_doctor()?;
        }
        Commands::Status { json } => {
            status::run_status(json)?;
        }
        Commands::Scan {
            path,
            dry_run,
            json,
            interactive,
        } => {
            scan::run_scan(path, dry_run, json, interactive)?;
        }
        Commands::Discover {
            path,
            agents,
            tools,
            agent,
            tool,
            json,
            interactive,
        } => {
            discover::run_discover(path, agents, tools, agent, tool, json, interactive)?;
        }
        Commands::Inspect { target } => match target {
            InspectCommands::Memory { json } => {
                inspect::run_inspect_memory(json)?;
            }
            InspectCommands::Processes { user_only, json } => {
                inspect::run_inspect_processes(user_only, json)?;
            }
            InspectCommands::Storage { path, json } => {
                inspect::run_inspect_storage(path, json)?;
            }
            InspectCommands::Transactions { journal_path, json } => {
                inspect::run_inspect_transactions(journal_path, json)?;
            }
        },
        Commands::Explain { identifier, json } => {
            explain::run_explain(&identifier, json)?;
        }
        Commands::Report { path, json } => {
            report::run_report(path, json)?;
        }
    }

    Ok(())
}
