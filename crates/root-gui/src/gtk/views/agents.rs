#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

use crate::model::presentation::{escape_markup, format_bytes_tabular};
use crate::view_model::AgentsViewModel;

#[cfg(feature = "gtk")]
pub fn build_agents_view(vm: &AgentsViewModel) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    let header_group = adw::PreferencesGroup::new();
    header_group.set_title(&escape_markup(
        "Supported Coding Agents & Development Toolchains",
    ));
    header_group.set_description(Some(
        "Observation and footprint accounting across 12 targets with non-exclusive ownership transparency",
    ));

    let cards = vm.visible_cards();
    let total_footprint: u64 = cards.iter().map(|c| c.total_bytes).sum();

    let count_row = adw::ActionRow::new();
    count_row.set_title("Detected Targets");
    let count_sub = format!(
        "{} of 12 targets active or persistent on workstation | Combined footprint: {}",
        vm.detected_count(),
        format_bytes_tabular(total_footprint)
    );
    count_row.set_subtitle(&count_sub);
    let count_badge = gtk4::Label::new(Some(&format!("{}/12", vm.detected_count())));
    count_badge.add_css_class("numeric");
    count_row.add_suffix(&count_badge);
    header_group.add(&count_row);
    page.add(&header_group);

    // AI Coding Agents Group
    let ai_group = adw::PreferencesGroup::new();
    ai_group.set_title("AI Coding Agents");

    // Development Toolchains Group
    let tool_group = adw::PreferencesGroup::new();
    tool_group.set_title(&escape_markup("Development Toolchains & Runtimes"));

    for card in cards {
        let row = adw::ActionRow::new();
        row.set_title(&escape_markup(card.display_name));
        let sub = format!(
            "Status: {} | Findings: {} | Footprint: {}\nNotice: {}",
            card.status.label(),
            card.resource_count,
            card.size_display(),
            card.ownership_notice
        );
        row.set_subtitle(&escape_markup(&sub));

        let status_badge = gtk4::Label::new(Some(card.status.label()));
        status_badge.add_css_class("tag");
        status_badge.add_css_class(card.status.css_class());
        row.add_suffix(&status_badge);

        if card.is_ai_agent {
            ai_group.add(&row);
        } else {
            tool_group.add(&row);
        }
    }

    page.add(&ai_group);
    page.add(&tool_group);

    page.upcast()
}
