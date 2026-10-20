#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

use crate::model::presentation::{escape_markup, format_bytes_tabular};
use crate::view_model::ProcessesViewModel;

#[cfg(feature = "gtk")]
pub fn build_processes_view(vm: &ProcessesViewModel) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    let header_group = adw::PreferencesGroup::new();
    header_group.set_title("Process Inspection");
    header_group.set_description(Some(
        "Unprivileged survey of workstation processes via /proc with toolchain attribution",
    ));

    let summary_row = adw::ActionRow::new();
    summary_row.set_title("Process Memory Consumption");
    let sub = format!(
        "{} processes listed | Combined RSS: {}",
        vm.visible_processes().len(),
        format_bytes_tabular(vm.total_filtered_rss_bytes())
    );
    summary_row.set_subtitle(&sub);
    let count_label = gtk4::Label::new(Some(&format!("{}", vm.visible_processes().len())));
    count_label.add_css_class("numeric");
    summary_row.add_suffix(&count_label);
    header_group.add(&summary_row);

    let priv_row = adw::ActionRow::new();
    priv_row.set_title(&escape_markup("Privacy & Security Invariants"));
    priv_row.set_subtitle("Command-line arguments and environment variables are strictly hidden. Termination controls are prohibited.");
    let priv_badge = gtk4::Label::new(Some("RESTRICTED"));
    priv_badge.add_css_class("tag");
    priv_row.add_suffix(&priv_badge);
    header_group.add(&priv_row);

    page.add(&header_group);

    let list_group = adw::PreferencesGroup::new();
    list_group.set_title("Running Processes");

    for proc in vm.visible_processes().iter().take(200) {
        let row = adw::ActionRow::new();
        row.set_title(&format!("PID {} — {}", proc.pid, proc.name));
        let attr_display = proc
            .attributed_tool
            .as_deref()
            .unwrap_or("Unattributed System Process");
        let sub = format!(
            "State: {} | UID: {} | Attribution: {} (Confidence: {})",
            proc.state_display(),
            proc.uid,
            attr_display,
            proc.confidence.label()
        );
        row.set_subtitle(&sub);

        let rss_label = gtk4::Label::new(Some(&proc.rss_display()));
        rss_label.add_css_class("numeric");
        row.add_suffix(&rss_label);

        list_group.add(&row);
    }

    page.add(&list_group);

    page.upcast()
}
