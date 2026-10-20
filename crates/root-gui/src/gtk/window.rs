#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

#[cfg(feature = "gtk")]
pub fn build_and_present_window(app: &adw::Application) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Root")
        .default_width(1024)
        .default_height(720)
        .build();

    let header_bar = adw::HeaderBar::new();

    // Central view stack
    let view_stack = adw::ViewStack::new();

    // 1. Overview Page
    let overview_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    overview_box.set_margin_top(24);
    overview_box.set_margin_bottom(24);
    overview_box.set_margin_start(24);
    overview_box.set_margin_end(24);
    let overview_title = gtk4::Label::new(Some("System Overview"));
    overview_title.add_css_class("title-1");
    overview_box.append(&overview_title);
    let page1 = view_stack.add_titled(&overview_box, Some("overview"), "Overview");
    page1.set_icon_name(Some("view-dashboard-symbolic"));

    // 2. Resources Page
    let resources_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    let resources_title = gtk4::Label::new(Some("Resource Explorer"));
    resources_title.add_css_class("title-1");
    resources_box.append(&resources_title);
    let page2 = view_stack.add_titled(&resources_box, Some("resources"), "Resources");
    page2.set_icon_name(Some("drive-harddisk-symbolic"));

    // 3. Agents Page
    let agents_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    let agents_title = gtk4::Label::new(Some("Agent Discovery"));
    agents_title.add_css_class("title-1");
    agents_box.append(&agents_title);
    let page3 = view_stack.add_titled(&agents_box, Some("agents"), "Agents");
    page3.set_icon_name(Some("system-run-symbolic"));

    // 4. Processes Page
    let processes_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    let processes_title = gtk4::Label::new(Some("Process Inspection"));
    processes_title.add_css_class("title-1");
    processes_box.append(&processes_title);
    let page4 = view_stack.add_titled(&processes_box, Some("processes"), "Processes");
    page4.set_icon_name(Some("application-x-executable-symbolic"));

    // 5. Activity Page
    let activity_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    let activity_title = gtk4::Label::new(Some("Live Activity Monitoring"));
    activity_title.add_css_class("title-1");
    activity_box.append(&activity_title);
    let page5 = view_stack.add_titled(&activity_box, Some("activity"), "Activity");
    page5.set_icon_name(Some("utilities-system-monitor-symbolic"));

    // 6. Schedule Page
    let schedule_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    let schedule_title = gtk4::Label::new(Some("Scheduled Inspections"));
    schedule_title.add_css_class("title-1");
    schedule_box.append(&schedule_title);
    let page6 = view_stack.add_titled(&schedule_box, Some("schedule"), "Schedule");
    page6.set_icon_name(Some("alarm-symbolic"));

    // 7. Settings Page
    let settings_box = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    let settings_title = gtk4::Label::new(Some("Settings"));
    settings_title.add_css_class("title-1");
    settings_box.append(&settings_title);
    let page7 = view_stack.add_titled(&settings_box, Some("settings"), "Settings");
    page7.set_icon_name(Some("emblem-system-symbolic"));

    // View switcher in header
    let switcher = adw::ViewSwitcher::new();
    switcher.set_stack(Some(&view_stack));
    header_bar.set_title_widget(Some(&switcher));

    let main_box = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    main_box.append(&header_bar);
    main_box.append(&view_stack);

    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&main_box));

    window.set_content(Some(&toast_overlay));
    window.present();
}
