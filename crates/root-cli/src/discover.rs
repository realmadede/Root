use root_core::{
    error::{Result, RootError},
    model::{FindingTarget, ProposedAction, ProtectionTier, SafetyDecision},
    DiscoveryContext, DiscoveryEngine, DiscoveryFilter, DiscoveryReport, DiscoveryTargetId,
    TargetKind,
};
use root_guardian::GuardianPolicy;
use root_platform::{
    traits::{EnvironmentProvider, ProcessProvider, ResourceAccountant},
    NativeAccountant, NativeEnvironment, NativeFilesystem, NativeProcess, TraversalOptions,
};
use std::path::PathBuf;

pub fn run_discover(
    target_path: Option<PathBuf>,
    agents_only: bool,
    tools_only: bool,
    agent_filter: Option<String>,
    tool_filter: Option<String>,
    json_output: bool,
    interactive: bool,
) -> Result<()> {
    let env = NativeEnvironment::new();
    let fs = NativeFilesystem::new();
    let proc_provider = NativeProcess::new();
    let accountant = NativeAccountant::new();
    let policy = GuardianPolicy::new();

    let current_uid = env.current_uid();
    let capabilities = accountant.get_capabilities()?;

    // 1. Resolve filter
    let mut filter = DiscoveryFilter::default();

    if let Some(agent_name) = agent_filter {
        match DiscoveryTargetId::from_filter(&agent_name) {
            Some(target) => {
                if target.kind() != TargetKind::Agent {
                    return Err(RootError::InvalidPath(format!(
                        "Target '{}' is a development tool, not an AI coding agent. Use '--tool {}' instead.",
                        agent_name, agent_name
                    )));
                }
                filter.target_id = Some(target);
            }
            None => {
                return Err(RootError::InvalidPath(format!(
                    "Unsupported agent target '{}'. Supported agents: antigravity, claude, codex, gemini, aider",
                    agent_name
                )));
            }
        }
    } else if let Some(tool_name) = tool_filter {
        match DiscoveryTargetId::from_filter(&tool_name) {
            Some(target) => {
                if target.kind() != TargetKind::Tool {
                    return Err(RootError::InvalidPath(format!(
                        "Target '{}' is an AI coding agent, not a development tool. Use '--agent {}' instead.",
                        tool_name, tool_name
                    )));
                }
                filter.target_id = Some(target);
            }
            None => {
                return Err(RootError::InvalidPath(format!(
                    "Unsupported development tool target '{}'. Supported tools: node, npm, pnpm, rust, cargo, python, git, lsp, dev",
                    tool_name
                )));
            }
        }
    } else if agents_only {
        filter.kind = Some(TargetKind::Agent);
    } else if tools_only {
        filter.kind = Some(TargetKind::Tool);
    }

    // 2. Resolve scan roots (Explicit target or known agent locations)
    let scan_roots = if let Some(p) = target_path {
        vec![p]
    } else {
        let mut roots = Vec::new();
        let home = env.home_dir();

        // Check allowlisted agent locations in user home
        let gemini_dir = home.join(".gemini");
        if gemini_dir.exists() {
            roots.push(gemini_dir);
        }

        let claude_dir = home.join(".claude");
        if claude_dir.exists() {
            roots.push(claude_dir);
        }

        let codex_cache = home.join(".cache/openai");
        if codex_cache.exists() {
            roots.push(codex_cache);
        }

        if roots.is_empty() {
            if !json_output {
                println!(
                    "No installed agent directories detected in user home (~/.gemini, ~/.claude, ~/.cache/openai)."
                );
                println!("Specify a target workspace directory using '--path <DIRECTORY>'.");
            }
            return Ok(());
        }

        roots
    };

    // 3. Collect active processes for lifecycle correlation
    let mut active_processes = Vec::new();
    if let Ok(pids) = proc_provider.list_pids() {
        for pid in pids {
            if let Ok(Some(candidate)) = proc_provider.inspect_process(pid) {
                active_processes.push(candidate);
            }
        }
    }

    // 4. Perform defensive traversal across scan roots
    let traversal_options = TraversalOptions {
        max_depth: 16, // Bounded depth for targeted discovery
        max_entries: 50_000,
        allow_cross_device: false,
        timeout: Some(std::time::Duration::from_secs(20)),
    };

    let mut all_entries = Vec::new();
    let mut total_skipped = 0u64;
    let mut is_complete = true;
    let mut incomplete_reason = None;

    for root in &scan_roots {
        match fs.traverse(root, &traversal_options) {
            Ok(outcome) => {
                total_skipped += outcome.metrics.skipped_count;
                if !outcome.metrics.is_complete {
                    is_complete = false;
                    incomplete_reason = outcome.metrics.incomplete_reason;
                }
                for entry in outcome.entries {
                    all_entries.push((entry.path, entry.metadata, entry.dev, entry.ino));
                }
            }
            Err(e) => {
                // If a specific directory is unreadable, record and continue
                total_skipped += 1;
                eprintln!(
                    "Notice: Skipping inaccessible path {}: {}",
                    root.display(),
                    e
                );
            }
        }
    }

    // 5. Evaluate findings via DiscoveryEngine
    let ctx = DiscoveryContext {
        root_paths: scan_roots.clone(),
        filter: &filter,
        current_uid,
        active_processes: &active_processes,
        capabilities,
        skipped_count: total_skipped,
        is_complete,
        incomplete_reason,
    };

    let report =
        DiscoveryEngine::evaluate_findings(&all_entries, &ctx, &|target: &FindingTarget,
                                                                 tier: ProtectionTier,
                                                                 action: ProposedAction,
                                                                 uid: u32|
         -> SafetyDecision {
            policy.evaluate(target, tier, action, uid)
        })?;

    // Record last scan activity in persistent state
    if let Some(first_root) = scan_roots.first() {
        let _ = crate::history::save_last_scan(
            first_root,
            report.summary.total_inspected,
            report.findings.len(),
            report.summary.is_complete,
            "discover",
        );
    }

    if json_output {
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(|e| RootError::Serialization(e.to_string()))?;
        println!("{}", json_str);
    } else {
        render_discovery_terminal_report(&scan_roots, &report);
        if interactive {
            crate::interactive::run_interactive_browser(&report.findings);
        }
    }

    Ok(())
}

fn render_discovery_terminal_report(scan_roots: &[PathBuf], report: &DiscoveryReport) {
    println!("\n==========================================================================================================");
    println!(" ROOT AGENT & TOOL DISCOVERY AUDIT");
    if let Some(ref filter_name) = report.target_filter {
        println!(" Target Filter : {}", filter_name);
    }
    println!(
        " Scanned Roots : {}",
        scan_roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("==========================================================================================================");
    println!(
        " {:<18} | {:<16} | {:<18} | {:>9} | {:<24} | {:<18}",
        "Target", "Category", "Lifecycle State", "Size", "Resource Location", "Protection Status"
    );
    println!("-------------------+------------------+--------------------+-----------+--------------------------+-------------------");

    for finding in &report.findings {
        let size_str = format_bytes(finding.metadata.storage.bytes);
        let raw_name = finding.location.path.to_string_lossy().replace('\n', "\\n");
        let truncated_name = truncate_middle(&raw_name, 24);

        println!(
            " {:<18} | {:<16} | {:<18} | {:>9} | {:<24} | {}",
            finding.target_name,
            format!("{:?}", finding.category),
            finding.lifecycle.state.display_badge(),
            size_str,
            truncated_name,
            finding.protection_tier.display_badge()
        );
    }

    println!("==========================================================================================================");
    println!(" DISCOVERY SUMMARY METRICS");
    println!("==========================================================================================================");
    println!(
        "  Total Identified Findings     : {:>10}",
        report.summary.total_findings
    );
    println!(
        "  Active Lifecycle Entities     : {:>10} (Held by running processes or live locks)",
        report.summary.active_lifecycle_count
    );
    println!(
        "  Persistent User Records       : {:>10} (Sessions, keys, config, version history)",
        report.summary.persistent_lifecycle_count
    );
    println!(
        "  Dormant Transient Artifacts   : {:>10} (Scratchpads, caches, old logs)",
        report.summary.dormant_transient_count
    );
    println!(
        "  Inconclusive Lifecycle State  : {:>10} (Uncertainty defaults to protection)",
        report.summary.unknown_lifecycle_count
    );
    println!(
        "  Tier 1: Strictly Protected    : {:>10}",
        report.summary.protected_count
    );
    println!(
        "  Tier 2: Confirm Required      : {:>10}",
        report.summary.confirm_required_count
    );
    println!(
        "  Tier 3: Obsolete Transient    : {:>10}",
        report.summary.transient_count
    );
    println!(
        "  Tier 4: Safe Recoverable      : {:>10}",
        report.summary.recoverable_count
    );
    println!(
        "  Estimated Candidate Storage   : {:>10} (Estimated upper bound; not guaranteed recoverable)",
        format_bytes(report.summary.reclaimable_bytes_estimate)
    );
    println!(
        "  Scan Completeness Status      : {}",
        if report.summary.is_complete {
            "COMPLETE".to_string()
        } else {
            format!(
                "INCOMPLETE ({})",
                report
                    .summary
                    .incomplete_reason
                    .as_deref()
                    .unwrap_or("Halted early")
            )
        }
    );
    println!(
        "\n  Guardian Policy Invariant     : ALL MUTATIONS REJECTED (Phase 03 Read-Only Discovery)"
    );
    println!("  Safety Guarantee              : Zero files modified. Zero processes signaled. Audit only.");
    println!("==========================================================================================================");
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GiB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}

fn truncate_middle(text: &str, max_chars: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        return text.to_string();
    }
    if max_chars <= 3 {
        return chars[..max_chars].iter().collect();
    }
    let keep = (max_chars - 3) / 2;
    let end_start = chars.len() - (max_chars - 3 - keep);
    let start_part: String = chars[..keep].iter().collect();
    let end_part: String = chars[end_start..].iter().collect();
    format!("{}...{}", start_part, end_part)
}
