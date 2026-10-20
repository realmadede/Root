#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

use crate::model::presentation::escape_markup;
use crate::view_model::ScheduleViewModel;

#[cfg(feature = "gtk")]
pub fn build_schedule_view(vm: &ScheduleViewModel) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    let config_group = adw::PreferencesGroup::new();
    config_group.set_title("Mode B Scheduled Inspections");
    config_group.set_description(Some(
        "Periodic, read-only systemd user timer inspections without background daemons",
    ));

    let state_row = adw::ActionRow::new();
    state_row.set_title("Schedule Status");
    let state_text = if vm.enabled {
        "ENABLED"
    } else {
        "DISABLED (Default)"
    };
    let state_sub = format!(
        "Interval: {:?} | Profile: {:?} | systemd User: {}",
        vm.interval,
        vm.profile,
        if vm.systemd_available {
            "Accessible"
        } else {
            "Unavailable"
        }
    );
    state_row.set_subtitle(&state_sub);
    let state_badge = gtk4::Label::new(Some(state_text));
    state_badge.add_css_class("tag");
    state_badge.add_css_class(if vm.enabled { "success" } else { "dim-label" });
    state_row.add_suffix(&state_badge);
    config_group.add(&state_row);

    let next_row = adw::ActionRow::new();
    next_row.set_title("Next Scheduled Execution");
    let next_text = vm
        .next_trigger_display
        .as_deref()
        .unwrap_or("None scheduled (timer inactive)");
    next_row.set_subtitle(next_text);
    config_group.add(&next_row);

    let budget_row = adw::ActionRow::new();
    budget_row.set_title(&escape_markup("Resource Limits & Hardening"));
    budget_row.set_subtitle(
        "Timeout: 60s | Max Entries: 50,000 | Max Depth: 16 | Battery Aware: Yes | No root/sudo",
    );
    config_group.add(&budget_row);

    page.add(&config_group);

    let history_group = adw::PreferencesGroup::new();
    history_group.set_title("Inspection History");
    history_group.set_description(Some(
        "Historical execution log records from systemd user timer",
    ));

    if vm.history_rows.is_empty() {
        let empty_row = adw::ActionRow::new();
        empty_row.set_title("No Scheduled Inspections Recorded");
        empty_row.set_subtitle(
            "Scheduled inspections run periodically once explicitly enabled by the user.",
        );
        history_group.add(&empty_row);
    } else {
        for row in vm.history_rows.iter().take(20) {
            let hist_row = adw::ActionRow::new();
            hist_row.set_title(&format!("Inspection at {}", row.timestamp_rfc3339));
            let sub = format!(
                "Status: {} | Duration: {} | Inspected: {} entities",
                row.status_label, row.duration_display, row.examined_count
            );
            hist_row.set_subtitle(&sub);

            let badge = gtk4::Label::new(Some(row.status_label));
            badge.add_css_class("tag");
            badge.add_css_class(row.status_css);
            hist_row.add_suffix(&badge);

            history_group.add(&hist_row);
        }
    }

    page.add(&history_group);

    page.upcast()
}
