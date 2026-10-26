#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

use crate::view_model::ActivityViewModel;
use root_core::model::MonitorSessionState;

#[cfg(feature = "gtk")]
pub fn build_activity_view(vm: &ActivityViewModel) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    let header_group = adw::PreferencesGroup::new();
    header_group.set_title("Live Activity Monitoring (Mode C)");
    header_group.set_description(Some(
        "Lightweight, read-only observation of filesystem and process activity during active development",
    ));

    let status_row = adw::ActionRow::new();
    status_row.set_title("Monitoring Session State");
    let (status_text, status_class) = match vm.session_state {
        MonitorSessionState::Running => ("RUNNING", "success"),
        MonitorSessionState::Degraded => ("DEGRADED", "warning"),
        MonitorSessionState::Starting | MonitorSessionState::Created => ("STARTING", "info"),
        MonitorSessionState::Stopping => ("STOPPING", "warning"),
        MonitorSessionState::Stopped => ("STOPPED (Disabled by default)", "dim-label"),
        MonitorSessionState::Failed => ("FAILED", "error"),
    };
    let sub = format!(
        "State: {} | Queued Events: {}/{} | Scoped Paths: {}",
        status_text,
        vm.recent_events.len(),
        vm.max_buffer_events,
        vm.approved_paths.len()
    );
    status_row.set_subtitle(&sub);
    let status_badge = gtk4::Label::new(Some(status_text));
    status_badge.add_css_class("tag");
    status_badge.add_css_class(status_class);
    status_row.add_suffix(&status_badge);
    header_group.add(&status_row);

    if !vm.degraded_reasons.is_empty() {
        let deg_row = adw::ActionRow::new();
        deg_row.set_title("Degraded Monitoring Condition");
        let deg_sub = vm
            .degraded_reasons
            .iter()
            .map(|r| r.display_message())
            .collect::<Vec<_>>()
            .join("; ");
        deg_row.set_subtitle(&deg_sub);
        let deg_badge = gtk4::Label::new(Some("DEGRADED"));
        deg_badge.add_css_class("tag");
        deg_badge.add_css_class("warning");
        deg_row.add_suffix(&deg_badge);
        header_group.add(&deg_row);
    }

    let cli_row = adw::ActionRow::new();
    cli_row.set_title("CLI Activity Monitoring");
    cli_row.set_subtitle("Start live monitoring: 'root monitor start' | Watch stream: 'root monitor watch' | Stop: 'root monitor stop'");
    header_group.add(&cli_row);

    page.add(&header_group);

    let events_group = adw::PreferencesGroup::new();
    events_group.set_title("Recent Activity Events (Bounded circular buffer)");

    if vm.recent_events.is_empty() {
        let empty_row = adw::ActionRow::new();
        empty_row.set_title("No Live Events Recorded");
        empty_row.set_subtitle(
            "Monitoring is disabled by default. Start a monitoring session to observe live filesystem events.",
        );
        events_group.add(&empty_row);
    } else {
        for ev in vm.recent_events.iter().take(50) {
            let row = adw::ActionRow::new();
            row.set_title(&format!("[{}] {}", ev.event_kind, ev.summary));
            row.set_subtitle(&ev.timestamp_rfc3339);

            let tag = gtk4::Label::new(Some(&ev.event_kind));
            tag.add_css_class("tag");
            tag.add_css_class(ev.css_class);
            row.add_suffix(&tag);

            events_group.add(&row);
        }
    }

    page.add(&events_group);

    page.upcast()
}
