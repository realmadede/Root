use root_core::{discovery::DiscoveryFinding, model::ProtectionTier};
use std::io::{stdin, stdout, IsTerminal, Write};

use crate::terminal::{format_bytes, format_tier_badge, truncate_middle, Style};

/// Starts an interactive, read-only terminal browser for discovery findings.
pub fn run_interactive_browser(findings: &[DiscoveryFinding]) {
    if !stdin().is_terminal() || !stdout().is_terminal() {
        eprintln!("Notice: Standard input or output is not an interactive terminal. Skipping interactive browser.");
        return;
    }

    if findings.is_empty() {
        println!("No findings to display in interactive browser.");
        return;
    }

    let mut current_items = findings.to_vec();
    let mut filter_text: Option<String> = None;
    let mut tier_filter: Option<ProtectionTier> = None;

    loop {
        // Apply active filters
        let display_list: Vec<&DiscoveryFinding> = current_items
            .iter()
            .filter(|f| {
                if let Some(ref text) = filter_text {
                    let needle = text.to_lowercase();
                    let matches_name = f.target_name.to_lowercase().contains(&needle);
                    let matches_rule = f.rule_id.to_lowercase().contains(&needle);
                    let matches_path = f
                        .location
                        .path
                        .to_string_lossy()
                        .to_lowercase()
                        .contains(&needle);
                    if !matches_name && !matches_rule && !matches_path {
                        return false;
                    }
                }
                if let Some(tier) = tier_filter {
                    if f.protection_tier != tier {
                        return false;
                    }
                }
                true
            })
            .collect();

        println!(
            "\n================================================================================"
        );
        println!(
            " {}",
            Style::bold("ROOT INTERACTIVE RESOURCE INSPECTION (READ-ONLY)")
        );
        if let Some(ref f) = filter_text {
            println!(" Active Filter: Target/Path contains '{}'", f);
        }
        if let Some(t) = tier_filter {
            println!(" Active Tier Filter: {:?}", t);
        }
        println!(
            " Total Findings Displayed: {} / {}",
            display_list.len(),
            findings.len()
        );
        println!(
            "================================================================================"
        );
        println!(
            " {:>4} | {:<16} | {:>9} | {:<20} | {:<22}",
            "#", "Target", "Size", "Protection Status", "Location"
        );
        println!(
            "------+------------------+-----------+----------------------+-----------------------"
        );

        for (idx, item) in display_list.iter().enumerate().take(20) {
            let size_str = format_bytes(item.metadata.storage.bytes);
            let raw_path = item.location.path.to_string_lossy().replace('\n', "\\n");
            let path_trunc = truncate_middle(&raw_path, 22);

            println!(
                " {:>4} | {:<16} | {:>9} | {:<20} | {}",
                idx + 1,
                truncate_middle(&item.target_name, 16),
                size_str,
                format_tier_badge(item.protection_tier),
                path_trunc
            );
        }

        if display_list.len() > 20 {
            println!(
                "  ... and {} more findings. Use 'f <text>' or 't <1-4>' to narrow list.",
                display_list.len() - 20
            );
        }

        println!(
            "--------------------------------------------------------------------------------"
        );
        print!("Command [<num> to inspect, f <str>, t <1-4>, s <size|tier|name>, r (reset), q (quit)]: ");
        let _ = stdout().flush();

        let mut input = String::new();
        if stdin().read_line(&mut input).is_err() {
            break;
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "q" || trimmed == "quit" || trimmed == "exit" {
            println!("Exiting interactive inspection.");
            break;
        } else if trimmed == "r" || trimmed == "reset" {
            filter_text = None;
            tier_filter = None;
            current_items = findings.to_vec();
            println!("Filters reset.");
        } else if let Some(stripped) = trimmed.strip_prefix("f ") {
            let filter = stripped.trim();
            if filter.is_empty() {
                filter_text = None;
            } else {
                filter_text = Some(filter.to_string());
            }
        } else if let Some(stripped) = trimmed.strip_prefix("t ") {
            match stripped.trim() {
                "1" => tier_filter = Some(ProtectionTier::StrictlyProtected),
                "2" => tier_filter = Some(ProtectionTier::UserConfirmRequired),
                "3" => tier_filter = Some(ProtectionTier::ObsoleteTransient),
                "4" => tier_filter = Some(ProtectionTier::SafeRecoverable),
                _ => println!("Invalid tier. Choose 1 (Protected), 2 (Confirm), 3 (Transient), or 4 (Recoverable)."),
            }
        } else if let Some(stripped) = trimmed.strip_prefix("s ") {
            match stripped.trim() {
                "size" => {
                    current_items.sort_by_key(|a| std::cmp::Reverse(a.metadata.storage.bytes))
                }
                "tier" => current_items.sort_by_key(|a| a.protection_tier),
                "name" => current_items.sort_by(|a, b| a.target_name.cmp(&b.target_name)),
                _ => println!("Unknown sort field. Choose 'size', 'tier', or 'name'."),
            }
        } else if let Ok(idx) = trimmed.parse::<usize>() {
            if idx >= 1 && idx <= display_list.len() {
                show_single_finding_detail(display_list[idx - 1]);
            } else {
                println!("Index {} is out of range [1-{}].", idx, display_list.len());
            }
        } else {
            println!("Unknown command '{}'. Enter a number to inspect, 'f <query>', 't <1-4>', 's <sort>', 'r', or 'q'.", trimmed);
        }
    }
}

fn show_single_finding_detail(item: &DiscoveryFinding) {
    println!("\n================================================================================");
    println!(" {}", Style::bold("DETAILED FINDING INSPECTION"));
    println!("================================================================================");
    println!("Target Name           : {}", item.target_name);
    println!("Target Kind           : {:?}", item.target_kind);
    println!("Rule ID               : {}", item.rule_id);
    println!("Resource Category     : {:?}", item.category);
    println!("Location Path         : {}", item.location.path.display());
    println!(
        "Device / Inode        : dev {} / ino {}",
        item.location.device_id, item.location.inode
    );

    println!("\nStorage Allocation:");
    println!(
        "  Apparent Size       : {} ({} bytes)",
        format_bytes(item.metadata.storage.bytes),
        item.metadata.storage.bytes
    );
    println!(
        "  Allocated Blocks    : {} ({} bytes)",
        format_bytes(item.metadata.storage.allocated_bytes),
        item.metadata.storage.allocated_bytes
    );
    println!(
        "  Sparse File         : {}",
        item.metadata.storage.is_sparse
    );
    println!(
        "  Multi-Link Sharing  : {}",
        item.metadata.storage.is_multi_link
    );
    println!(
        "  Hard Link Count     : {}",
        item.metadata.storage.link_count
    );

    println!("\nLifecycle Assessment:");
    println!("  Lifecycle State     : {:?}", item.lifecycle.state);
    println!(
        "  Process Attribution : {}",
        item.lifecycle.attribution.display_badge()
    );
    println!("  Reasoning           : {}", item.lifecycle.reasoning);
    if let Some(pid) = item.lifecycle.associated_pid {
        println!("  Associated PID      : {}", pid);
    }
    if let Some(act) = item.lifecycle.last_activity_epoch_secs {
        println!("  Last Activity Epoch : {}s", act);
    }
    println!("  Confidence          : {:?}", item.confidence);

    println!("\nProtection Status & Guardian Decision:");
    println!(
        "  Protection Tier     : {}",
        format_tier_badge(item.protection_tier)
    );
    println!("  Guardian Invariant  : {:?}", item.safety_decision);
    println!("  Evidence Summary    : {}", item.evidence_explanation);
    println!("  Known Limitations   : {}", item.limitations);

    println!("================================================================================");
    print!("Press [Enter] to return to findings list: ");
    let _ = stdout().flush();
    let mut discard = String::new();
    let _ = stdin().read_line(&mut discard);
}
