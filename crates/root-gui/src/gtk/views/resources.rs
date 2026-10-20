#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

use crate::model::presentation::{
    badge_for_protection_tier, format_bytes_tabular, format_path_middle,
};
use crate::view_model::ResourcesViewModel;

#[cfg(feature = "gtk")]
pub fn build_resources_view(vm: &ResourcesViewModel) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    let count_group = adw::PreferencesGroup::new();
    count_group.set_title("Resource Inventory");

    let is_truncated = vm.total_unfiltered_count() > vm.items().len();
    let count_row = adw::ActionRow::new();
    count_row.set_title("Identified Resources");
    let count_sub = if is_truncated {
        format!(
            "Showing {} of {} resources (Virtual row limit applied to maintain 60fps GTK rendering)",
            vm.items().len(),
            vm.total_unfiltered_count()
        )
    } else {
        format!("{} total findings loaded", vm.total_unfiltered_count())
    };
    count_row.set_subtitle(&count_sub);
    let count_badge = gtk4::Label::new(Some(&format!("{}", vm.total_unfiltered_count())));
    count_badge.add_css_class("numeric");
    count_row.add_suffix(&count_badge);
    count_group.add(&count_row);
    page.add(&count_group);

    if vm.items().is_empty() {
        let status_group = adw::PreferencesGroup::new();
        let empty_row = adw::ActionRow::new();
        empty_row.set_title("No Resources Available");
        empty_row.set_subtitle(
            "Run a discovery or synthetic inspection pass to populate the resource explorer.",
        );
        status_group.add(&empty_row);
        page.add(&status_group);
    } else {
        let list_group = adw::PreferencesGroup::new();
        list_group.set_title("Audited Resources");
        list_group.set_description(Some(
            "Classified files and directories with Guardian policy evaluation",
        ));

        for row in vm.items() {
            let row_widget = adw::ActionRow::new();
            row_widget.set_title(&format_path_middle(&row.path, 55));
            let sub = format!(
                "{} | {:?} | Decision: {}",
                row.category, row.lifecycle, row.guardian_decision
            );
            row_widget.set_subtitle(&sub);

            let size_label = gtk4::Label::new(Some(&format_bytes_tabular(row.apparent_size_bytes)));
            size_label.add_css_class("numeric");
            row_widget.add_suffix(&size_label);

            let badge = badge_for_protection_tier(row.protection_tier);
            let tier_label = gtk4::Label::new(Some(badge.label));
            tier_label.add_css_class("tag");
            tier_label.add_css_class(badge.css_class);
            row_widget.add_suffix(&tier_label);

            list_group.add(&row_widget);
        }
        page.add(&list_group);
    }

    page.upcast()
}
