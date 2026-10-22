use root_core::{
    error::{Result, RootError},
    model::{
        LiveFsEventKind, MonitorBudget, MonitorEvent, MonitorScope, MonitorSessionState,
        ProcessEventKind,
    },
};
use root_platform::{traits::EnvironmentProvider, NativeEnvironment, NativeMonitorSession};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use crate::terminal::{format_bytes, format_percent, truncate_middle, Style};

static RUNNING: AtomicBool = AtomicBool::new(true);

#[cfg(unix)]
extern "C" fn sigint_handler(_: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

/// CLI options for live monitoring command.
#[derive(Debug, Clone)]
pub struct MonitorCliOptions {
    pub paths: Vec<PathBuf>,
    pub agent: Option<String>,
    pub processes: bool,
    pub memory: bool,
    pub interval: f64,
    pub duration: Option<u64>,
    pub max_events: usize,
    pub max_watches: usize,
    pub json: bool,
}

/// Executes the live resource monitoring session (Mode C).
pub fn run_monitor(opts: MonitorCliOptions) -> Result<()> {
    // 1. Validate that an explicit observation target was provided
    if opts.paths.is_empty() && opts.agent.is_none() && !opts.processes && !opts.memory {
        return Err(RootError::PolicyViolation {
            reason: "Monitoring requires an explicit observation scope. Supply at least one target path (--path <dir>), agent filter (--agent <name>), or subsystem flag (--processes, --memory). Blind monitoring of entire user home or system root is prohibited."
                .to_string(),
        });
    }

    // 2. Resolve target directories
    let env = NativeEnvironment::new();
    let home = env.home_dir();
    let mut resolved_paths = Vec::new();

    for p in &opts.paths {
        MonitorScope::validate_monitor_target(p)?;
        if p.exists() {
            resolved_paths.push(p.clone());
        } else {
            eprintln!(
                "Notice: Specified target directory '{}' does not currently exist.",
                p.display()
            );
            resolved_paths.push(p.clone());
        }
    }

    // If agent filter is provided without explicit paths, resolve standard agent directory
    if let Some(ref agent_name) = opts.agent {
        if resolved_paths.is_empty() {
            let candidate_dirs = match agent_name.to_lowercase().as_str() {
                "antigravity" | "gemini" => vec![home.join(".gemini")],
                "claude" => vec![home.join(".claude")],
                "codex" | "openai" => vec![home.join(".cache/openai"), home.join(".openai")],
                "aider" => vec![home.join(".aider")],
                _ => Vec::new(),
            };

            for candidate in candidate_dirs {
                if candidate.exists() {
                    resolved_paths.push(candidate);
                }
            }

            if resolved_paths.is_empty() {
                eprintln!(
                    "Notice: No default directory found for agent '{}'. Monitoring process table and system memory.",
                    agent_name
                );
            }
        }
    }

    // 3. Configure budget & scope
    let budget = MonitorBudget {
        max_monitored_paths: 32,
        max_watches: opts.max_watches,
        max_queued_events: opts.max_events,
        max_duration_secs: opts.duration,
        max_memory_rss_bytes: Some(256 * 1024 * 1024),
        sampling_interval_millis: (opts.interval.max(0.25) * 1000.0) as u64,
    };

    let scope = MonitorScope {
        paths: resolved_paths,
        agent_filter: opts.agent.clone(),
        observe_processes: opts.processes,
        observe_memory: opts.memory,
        budget,
    };

    scope.validate()?;

    // 4. Register signal handler for graceful Ctrl+C shutdown
    RUNNING.store(true, Ordering::SeqCst);
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as usize);
        libc::signal(libc::SIGTERM, sigint_handler as *const () as usize);
    }

    let current_uid = env.current_uid();
    let mut session = NativeMonitorSession::new(scope.clone(), current_uid)?;
    session.start()?;

    if opts.json {
        run_monitor_json_loop(&mut session)?;
    } else {
        run_monitor_terminal_loop(&mut session, &opts)?;
    }

    Ok(())
}

fn run_monitor_json_loop(session: &mut NativeMonitorSession) -> Result<()> {
    // Initial status event
    let start_event = MonitorEvent::Status {
        state: session.state(),
        reason: None,
    };
    println!(
        "{}",
        serde_json::to_string(&start_event).map_err(|e| RootError::Serialization(e.to_string()))?
    );

    while RUNNING.load(Ordering::SeqCst) {
        let events = session.poll_events()?;
        for event in events {
            println!(
                "{}",
                serde_json::to_string(&event)
                    .map_err(|e| RootError::Serialization(e.to_string()))?
            );
        }

        if session.state() == MonitorSessionState::Stopping
            || session.state() == MonitorSessionState::Stopped
        {
            break;
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    let summary = session.stop();
    let summary_json =
        serde_json::to_string(&summary).map_err(|e| RootError::Serialization(e.to_string()))?;
    println!("{}", summary_json);

    Ok(())
}

fn run_monitor_terminal_loop(
    session: &mut NativeMonitorSession,
    opts: &MonitorCliOptions,
) -> Result<()> {
    println!("================================================================================");
    println!(" {}", Style::bold("ROOT LIVE RESOURCE MONITOR (MODE C)"));
    println!("================================================================================");
    println!("Session Parameters:");
    println!(
        "  Session State         : {}",
        Style::green(session.state().display_badge())
    );
    println!("  Monitored Targets     : {} directories", opts.paths.len());
    println!(
        "  Active inotify Watches: {} watches",
        session.active_watches()
    );
    println!("  Sampling Interval     : {:.2}s", opts.interval);
    println!(
        "  Subsystem Scopes      : Filesystem: [Active] | Processes: [{}] | Memory: [{}]",
        if opts.processes { "Active" } else { "Off" },
        if opts.memory { "Active" } else { "Off" }
    );
    if let Some(dur) = opts.duration {
        println!("  Session Duration Limit: {}s", dur);
    }
    if let Some(ref agent) = opts.agent {
        println!("  Agent Target Filter   : {}", agent);
    }
    println!("  Exit Instruction      : Press Ctrl+C to conclude monitoring session");
    println!("================================================================================");
    println!(
        " {:<8} | {:<13} | {:<52}",
        "Time", "Event", "Resource Observation"
    );
    println!("---------+---------------+------------------------------------------------------");

    let start_time = Instant::now();
    let mut reported_degraded = false;

    while RUNNING.load(Ordering::SeqCst) {
        let events = session.poll_events()?;

        for event in events {
            let elapsed_secs = start_time.elapsed().as_secs();
            let time_str = format!("+{:>4}s", elapsed_secs);

            match event {
                MonitorEvent::Fs(fs_event) => {
                    let badge = match fs_event.kind {
                        LiveFsEventKind::Created => Style::green(fs_event.kind.display_badge()),
                        LiveFsEventKind::DirCreated => Style::green(fs_event.kind.display_badge()),
                        LiveFsEventKind::Modified => Style::yellow(fs_event.kind.display_badge()),
                        LiveFsEventKind::Deleted => Style::red(fs_event.kind.display_badge()),
                        LiveFsEventKind::DirDeleted => Style::red(fs_event.kind.display_badge()),
                        LiveFsEventKind::MovedFrom => Style::yellow(fs_event.kind.display_badge()),
                        LiveFsEventKind::MovedTo => Style::green(fs_event.kind.display_badge()),
                    };

                    let path_display = truncate_middle(&fs_event.path.to_string_lossy(), 46);
                    let agent_tag = if let Some(ref a) = fs_event.matched_agent {
                        format!(" [{}]", a)
                    } else {
                        String::new()
                    };

                    println!(
                        " {:<8} | {:<13} | {}{}",
                        time_str, badge, path_display, agent_tag
                    );
                }
                MonitorEvent::Process { kind, process } => {
                    let badge = match kind {
                        ProcessEventKind::Spawned => Style::green(kind.display_badge()),
                        ProcessEventKind::Exited => Style::dim(kind.display_badge()),
                    };

                    let agent_tag = if let Some(ref a) = process.associated_agent {
                        format!(" [{}]", a)
                    } else {
                        String::new()
                    };

                    println!(
                        " {:<8} | {:<13} | PID {:>6}: {} ({}){}",
                        time_str,
                        badge,
                        process.pid,
                        process.binary_name,
                        format_bytes(process.rss_bytes),
                        agent_tag
                    );
                }
                MonitorEvent::Memory(mem) => {
                    let badge = Style::bold("[MEM_SNAP]");
                    let press_str = if let Some(p) = mem.psi_memory_10s_pct {
                        format!("PSI: {}", format_percent(p as f32))
                    } else {
                        "PSI: N/A".to_string()
                    };

                    println!(
                        " {:<8} | {:<13} | Avail: {:>8} | Swap: {:>8} | {}",
                        time_str,
                        badge,
                        format_bytes(mem.available_ram_bytes),
                        format_bytes(mem.swap_used_bytes),
                        press_str
                    );
                }
                MonitorEvent::Status { state, reason } => {
                    let badge = match state {
                        MonitorSessionState::Degraded => Style::yellow(state.display_badge()),
                        MonitorSessionState::Stopping => Style::bold(state.display_badge()),
                        _ => Style::dim(state.display_badge()),
                    };

                    let msg = reason
                        .map(|r| r.display_message())
                        .unwrap_or_else(|| "Session state updated".to_string());
                    println!(" {:<8} | {:<13} | {}", time_str, badge, msg);
                }
            }
        }

        // Check for degraded status changes
        if !session.degraded_reasons().is_empty() && !reported_degraded {
            reported_degraded = true;
            for reason in session.degraded_reasons() {
                eprintln!("Notice: Monitoring degraded — {}", reason.display_message());
            }
        }

        if session.state() == MonitorSessionState::Stopping
            || session.state() == MonitorSessionState::Stopped
        {
            break;
        }

        std::thread::sleep(Duration::from_millis(80));
    }

    println!("--------------------------------------------------------------------------------");
    let summary = session.stop();

    println!("================================================================================");
    println!(" {}", Style::bold("MONITORING SESSION CONCLUDED"));
    println!("================================================================================");
    println!(
        "  Duration Elapsed      : {:.2}s",
        summary.duration_millis as f64 / 1000.0
    );
    println!("  Filesystem Events     : {}", summary.total_fs_events);
    println!("  Process Transitions   : {}", summary.total_process_events);
    println!("  Memory Samples Taken  : {}", summary.total_memory_samples);
    println!(
        "  Final Session Status  : {}",
        match summary.final_state {
            MonitorSessionState::Stopped => Style::green("[STOPPED]"),
            MonitorSessionState::Degraded => Style::yellow("[DEGRADED]"),
            _ => Style::dim(summary.final_state.display_badge()),
        }
    );

    if !summary.degraded_reasons.is_empty() {
        println!("\nDegraded Conditions Encountered during Session:");
        for reason in &summary.degraded_reasons {
            println!("  - {}", Style::yellow(&reason.display_message()));
        }
    }

    println!("================================================================================");
    Ok(())
}
