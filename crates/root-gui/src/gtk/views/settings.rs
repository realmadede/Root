#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

use crate::model::presentation::escape_markup;
use crate::view_model::SettingsViewModel;

#[cfg(feature = "gtk")]
pub fn build_settings_view(vm: &SettingsViewModel) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    // 1. Appearance Group
    let app_group = adw::PreferencesGroup::new();
    app_group.set_title(&escape_markup("Appearance & Theming"));
    app_group.set_description(Some(
        "Adwaita interface styling with light, dark, and system preference support",
    ));

    let theme_row = adw::ActionRow::new();
    theme_row.set_title("Color Scheme");
    theme_row.set_subtitle("Adapts automatically to system GNOME preference or forces mode");

    let theme_btn_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);

    let default_btn = gtk4::Button::with_label("System");
    default_btn.connect_clicked(|_| {
        adw::StyleManager::default().set_color_scheme(adw::ColorScheme::Default);
    });
    theme_btn_box.append(&default_btn);

    let light_btn = gtk4::Button::with_label("Light");
    light_btn.connect_clicked(|_| {
        adw::StyleManager::default().set_color_scheme(adw::ColorScheme::ForceLight);
    });
    theme_btn_box.append(&light_btn);

    let dark_btn = gtk4::Button::with_label("Dark");
    dark_btn.connect_clicked(|_| {
        adw::StyleManager::default().set_color_scheme(adw::ColorScheme::ForceDark);
    });
    theme_btn_box.append(&dark_btn);

    theme_row.add_suffix(&theme_btn_box);
    app_group.add(&theme_row);
    page.add(&app_group);

    // 2. Resource Budgets
    let budget_group = adw::PreferencesGroup::new();
    budget_group.set_title("Inspection Budgets");
    budget_group.set_description(Some(
        "Deterministic limits bounding traversal depth and memory",
    ));

    let depth_row = adw::ActionRow::new();
    depth_row.set_title("Maximum Traversal Depth");
    depth_row.set_subtitle("Guarantees defense against deeply nested directory loops");
    let depth_label = gtk4::Label::new(Some(&format!("{}", vm.max_traversal_depth)));
    depth_label.add_css_class("numeric");
    depth_row.add_suffix(&depth_label);
    budget_group.add(&depth_row);

    let entries_row = adw::ActionRow::new();
    entries_row.set_title("Maximum Scanned Entries");
    entries_row.set_subtitle("Terminates traversal safely if entity count exceeds budget");
    let entries_label = gtk4::Label::new(Some(&format!("{}", vm.max_entries_limit)));
    entries_label.add_css_class("numeric");
    entries_row.add_suffix(&entries_label);
    budget_group.add(&entries_row);

    let timeout_row = adw::ActionRow::new();
    timeout_row.set_title("Watchdog Execution Timeout");
    timeout_row.set_subtitle("Aborts runaway scans to protect workstation responsiveness");
    let timeout_label = gtk4::Label::new(Some(&format!("{}s", vm.traversal_timeout_seconds)));
    timeout_label.add_css_class("numeric");
    timeout_row.add_suffix(&timeout_label);
    budget_group.add(&timeout_row);

    page.add(&budget_group);

    // 3. Privacy & Security Invariants
    let sec_group = adw::PreferencesGroup::new();
    sec_group.set_title(&escape_markup("Security & Privacy Invariants"));
    sec_group.set_description(Some(
        "Guaranteed permanent protections enforced by Root architecture",
    ));

    let read_only_row = adw::ActionRow::new();
    read_only_row.set_title("Production Read-Only Invariant");
    read_only_row.set_subtitle(
        "Root Guardian unconditionally denies all mutating operations on host files.",
    );
    let read_only_badge = gtk4::Label::new(Some("ENFORCED"));
    read_only_badge.add_css_class("tag");
    read_only_badge.add_css_class("success");
    read_only_row.add_suffix(&read_only_badge);
    sec_group.add(&read_only_row);

    let priv_row = adw::ActionRow::new();
    priv_row.set_title("Confidentiality Boundary");
    priv_row.set_subtitle(
        "Developer credentials, API keys, and conversation transcripts are never inspected.",
    );
    let priv_badge = gtk4::Label::new(Some("ENFORCED"));
    priv_badge.add_css_class("tag");
    priv_badge.add_css_class("success");
    priv_row.add_suffix(&priv_badge);
    sec_group.add(&priv_row);

    let ai_row = adw::ActionRow::new();
    ai_row.set_title("Deterministic Local Execution");
    ai_row.set_subtitle("Zero telemetry, zero cloud calls, zero LLM runtimes. Runs 100% locally.");
    let ai_badge = gtk4::Label::new(Some("ENFORCED"));
    ai_badge.add_css_class("tag");
    ai_badge.add_css_class("success");
    ai_row.add_suffix(&ai_badge);
    sec_group.add(&ai_row);

    let unpriv_row = adw::ActionRow::new();
    unpriv_row.set_title("Least-Privilege Unprivileged Execution");
    unpriv_row
        .set_subtitle("Operates purely in user space under invoking UID. Never invokes sudo.");
    let unpriv_badge = gtk4::Label::new(Some("ENFORCED"));
    unpriv_badge.add_css_class("tag");
    unpriv_badge.add_css_class("success");
    unpriv_row.add_suffix(&unpriv_badge);
    sec_group.add(&unpriv_row);

    page.add(&sec_group);

    // 4. About Root
    let about_group = adw::PreferencesGroup::new();
    about_group.set_title("About Root");

    let ver_row = adw::ActionRow::new();
    ver_row.set_title("Application Version");
    ver_row.set_subtitle(&format!(
        "{} v{} ({}) | License: {}",
        vm.app_name, vm.app_version, vm.target_platform, vm.license
    ));
    about_group.add(&ver_row);

    let repo_row = adw::ActionRow::new();
    repo_row.set_title("Source Repository");
    repo_row.set_subtitle(vm.repository_url);
    about_group.add(&repo_row);

    page.add(&about_group);

    page.upcast()
}
