#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;
#[cfg(feature = "gtk")]
use root_core::model::ProtectionTier;
#[cfg(feature = "gtk")]
use std::cell::RefCell;
#[cfg(feature = "gtk")]
use std::rc::Rc;

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
        // Filter and Search Group
        let filter_group = adw::PreferencesGroup::new();
        filter_group.set_title("Filter & Search");

        let search_entry = gtk4::SearchEntry::new();
        search_entry.set_placeholder_text(Some("Search by path, category, or rule..."));
        search_entry.set_hexpand(true);

        let search_row = adw::ActionRow::new();
        search_row.set_title("Search");
        search_row.add_suffix(&search_entry);
        filter_group.add(&search_row);

        let dropdown = gtk4::DropDown::from_strings(&[
            "All Tiers",
            "Strictly Protected",
            "User Confirm Required",
            "Obsolete Transient",
            "Safe Recoverable",
            "Non Actionable",
        ]);

        let tier_row = adw::ActionRow::new();
        tier_row.set_title("Protection Tier Filter");
        tier_row.add_suffix(&dropdown);
        filter_group.add(&tier_row);

        page.add(&filter_group);

        let list_group = adw::PreferencesGroup::new();
        list_group.set_title("Audited Resources");
        list_group.set_description(Some(
            "Classified files and directories with Guardian policy evaluation",
        ));

        struct RowFilterData {
            row: adw::ActionRow,
            search_text: String,
            tier: ProtectionTier,
        }

        let mut row_records = Vec::new();

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

            let search_text = format!(
                "{} {} {:?} {}",
                row.path.to_string_lossy().to_lowercase(),
                row.category.to_string().to_lowercase(),
                row.lifecycle,
                badge.label.to_lowercase()
            );

            row_records.push(RowFilterData {
                row: row_widget.clone(),
                search_text,
                tier: row.protection_tier,
            });

            list_group.add(&row_widget);
        }
        page.add(&list_group);

        let records_rc = Rc::new(RefCell::new(row_records));
        let active_query = Rc::new(RefCell::new(String::new()));
        let active_tier_idx = Rc::new(RefCell::new(0u32));

        let update_visibility = {
            let records = records_rc.clone();
            let query_rc = active_query.clone();
            let tier_idx_rc = active_tier_idx.clone();
            move || {
                let query = query_rc.borrow().to_lowercase();
                let tier_idx = *tier_idx_rc.borrow();
                let records = records.borrow();

                for item in records.iter() {
                    let matches_query = query.is_empty() || item.search_text.contains(&query);
                    let matches_tier = match tier_idx {
                        0 => true,
                        1 => item.tier == ProtectionTier::StrictlyProtected,
                        2 => item.tier == ProtectionTier::UserConfirmRequired,
                        3 => item.tier == ProtectionTier::ObsoleteTransient,
                        4 => item.tier == ProtectionTier::SafeRecoverable,
                        5 => item.tier == ProtectionTier::NonActionable,
                        _ => true,
                    };
                    item.row.set_visible(matches_query && matches_tier);
                }
            }
        };

        {
            let query_rc = active_query.clone();
            let update = update_visibility.clone();
            search_entry.connect_search_changed(move |entry| {
                *query_rc.borrow_mut() = entry.text().to_string();
                update();
            });
        }

        {
            let tier_idx_rc = active_tier_idx.clone();
            let update = update_visibility;
            dropdown.connect_selected_notify(move |drop| {
                *tier_idx_rc.borrow_mut() = drop.selected();
                update();
            });
        }
    }

    page.upcast()
}
