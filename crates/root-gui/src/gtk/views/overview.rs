#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

use crate::model::presentation::{escape_markup, format_bytes_tabular};
use crate::view_model::OverviewViewModel;

#[cfg(feature = "gtk")]
pub fn build_overview_view(vm: &OverviewViewModel) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    // 1. System Memory Group
    let mem_group = adw::PreferencesGroup::new();
    mem_group.set_title("System Memory");
    mem_group.set_description(Some("Host physical RAM and swap space distribution"));

    let ram_row = adw::ActionRow::new();
    ram_row.set_title("Physical RAM");
    let ram_sub = format!(
        "Available: {} | Free: {} | Cached: {}",
        format_bytes_tabular(vm.available_ram_bytes),
        format_bytes_tabular(vm.free_ram_bytes),
        format_bytes_tabular(vm.cached_ram_bytes)
    );
    ram_row.set_subtitle(&ram_sub);
    let ram_label = gtk4::Label::new(Some(&format_bytes_tabular(vm.total_ram_bytes)));
    ram_label.add_css_class("numeric");
    ram_row.add_suffix(&ram_label);
    mem_group.add(&ram_row);

    let swap_row = adw::ActionRow::new();
    swap_row.set_title("Swap Storage");
    let swap_sub = format!(
        "Used: {} | Free: {}",
        format_bytes_tabular(vm.swap_used_bytes),
        format_bytes_tabular(vm.swap_free_bytes)
    );
    swap_row.set_subtitle(&swap_sub);
    let swap_label = gtk4::Label::new(Some(&format_bytes_tabular(vm.swap_total_bytes)));
    swap_label.add_css_class("numeric");
    swap_row.add_suffix(&swap_label);
    mem_group.add(&swap_row);

    page.add(&mem_group);

    // 2. Kernel Pressure Stall Information
    let psi_group = adw::PreferencesGroup::new();
    psi_group.set_title("Kernel PSI Memory Pressure");
    psi_group.set_description(Some(
        "Memory contention stall percentages across rolling windows",
    ));

    let psi_row = adw::ActionRow::new();
    psi_row.set_title("Memory Pressure Stalls");
    let psi_sub = if vm.psi_supported {
        format!(
            "10s: {:.1}% | 60s: {:.1}% | 300s: {:.1}%",
            vm.psi_10s_stall, vm.psi_60s_stall, vm.psi_300s_stall
        )
    } else {
        "PSI interface unsupported or unavailable".to_string()
    };
    psi_row.set_subtitle(&psi_sub);
    let psi_badge = gtk4::Label::new(Some(vm.pressure_severity.label()));
    psi_badge.add_css_class("tag");
    psi_badge.add_css_class(vm.pressure_severity.css_class());
    psi_row.add_suffix(&psi_badge);
    psi_group.add(&psi_row);

    page.add(&psi_group);

    // 3. Filesystem Capacity
    let fs_group = adw::PreferencesGroup::new();
    fs_group.set_title("Filesystem Capacity");
    fs_group.set_description(Some(
        "Root partition storage capacity and inode availability",
    ));

    let cap_row = adw::ActionRow::new();
    cap_row.set_title("Storage Space");
    let cap_sub = format!(
        "Available: {} | Free Inodes: {}",
        format_bytes_tabular(vm.filesystem_available_bytes),
        vm.filesystem_free_inodes
    );
    cap_row.set_subtitle(&cap_sub);
    let cap_label = gtk4::Label::new(Some(&format_bytes_tabular(vm.filesystem_capacity_bytes)));
    cap_label.add_css_class("numeric");
    cap_row.add_suffix(&cap_label);
    fs_group.add(&cap_row);

    page.add(&fs_group);

    // 4. Agent Discovery Footprint
    let agent_group = adw::PreferencesGroup::new();
    agent_group.set_title(&escape_markup("Coding Agent & Development Footprint"));
    agent_group.set_description(Some(
        "Resource audit across AI coding agents and development toolchains",
    ));

    let summary_row = adw::ActionRow::new();
    summary_row.set_title("Discovered Entities");
    let summary_sub = format!(
        "Detected Agents: {} | Active: {} | Total Findings: {}",
        vm.detected_agents_count, vm.active_agents_count, vm.total_resources_count
    );
    summary_row.set_subtitle(&summary_sub);
    let cand_label = gtk4::Label::new(Some(&format!(
        "Upper Bound: {}",
        format_bytes_tabular(vm.potential_transient_bytes)
    )));
    cand_label.add_css_class("numeric");
    summary_row.add_suffix(&cand_label);
    agent_group.add(&summary_row);

    page.add(&agent_group);

    // 5. Operational Status & Safety
    let status_group = adw::PreferencesGroup::new();
    status_group.set_title("Operational Governance");

    let mode_row = adw::ActionRow::new();
    mode_row.set_title("Operating Modes");
    let mode_sub = format!(
        "Mode A: {} | Mode B (Schedule): {} | Mode C (Monitor): {}",
        vm.mode_a_status,
        if vm.mode_b_enabled {
            "Active"
        } else {
            "Disabled"
        },
        if vm.mode_c_active {
            "Active"
        } else {
            "Inactive"
        }
    );
    mode_row.set_subtitle(&mode_sub);
    status_group.add(&mode_row);

    let safety_row = adw::ActionRow::new();
    safety_row.set_title("Safety Policy");
    safety_row.set_subtitle(vm.safety_guarantee);
    let safety_badge = gtk4::Label::new(Some("READ-ONLY"));
    safety_badge.add_css_class("success");
    safety_row.add_suffix(&safety_badge);
    status_group.add(&safety_row);

    page.add(&status_group);

    page.upcast()
}
