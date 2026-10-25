#[cfg(feature = "gtk")]
use std::cell::{Cell, RefCell};
#[cfg(feature = "gtk")]
use std::rc::Rc;
#[cfg(feature = "gtk")]
use std::time::Duration;

#[cfg(feature = "gtk")]
use gtk4::gio;
#[cfg(feature = "gtk")]
use gtk4::gio::prelude::*;
#[cfg(feature = "gtk")]
use gtk4::glib;
#[cfg(feature = "gtk")]
use gtk4::prelude::*;
#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

#[cfg(feature = "gtk")]
use crate::app::RootAppController;
#[cfg(feature = "gtk")]
use crate::gtk::views::*;
#[cfg(feature = "gtk")]
use crate::model::navigation::NavigationItem;

/// Helper constructing a standardized navigation sidebar row with icon, title, and shortcut.
#[cfg(feature = "gtk")]
fn build_nav_row(item: NavigationItem) -> gtk4::ListBoxRow {
    let row = gtk4::ListBoxRow::new();
    row.set_widget_name(item.page_id());

    let h_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
    h_box.set_margin_top(6);
    h_box.set_margin_bottom(6);
    h_box.set_margin_start(12);
    h_box.set_margin_end(12);

    let icon = gtk4::Image::from_icon_name(item.icon_name());
    icon.set_pixel_size(16);

    let label = gtk4::Label::new(Some(item.title()));
    label.set_xalign(0.0);
    label.set_hexpand(true);

    let shortcut_hint = gtk4::Label::new(Some(item.accelerator()));
    shortcut_hint.add_css_class("dim-label");
    shortcut_hint.add_css_class("caption");
    shortcut_hint.set_xalign(1.0);

    h_box.append(&icon);
    h_box.append(&label);
    h_box.append(&shortcut_hint);

    row.set_child(Some(&h_box));
    row
}

#[cfg(feature = "gtk")]
pub fn build_and_present_window(app: &adw::Application) {
    let controller = Rc::new(RefCell::new(RootAppController::new()));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Root")
        .default_width(1080)
        .default_height(740)
        .build();

    let toast_overlay = adw::ToastOverlay::new();

    // Main horizontal layout: Left vertical sidebar + Right content area
    let root_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 0);
    root_box.set_hexpand(true);
    root_box.set_vexpand(true);

    // ==========================================
    // 1. Vertical Navigation Sidebar (Left Pane)
    // ==========================================
    let sidebar_box = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    sidebar_box.set_size_request(240, -1);
    sidebar_box.set_hexpand(false);
    sidebar_box.set_vexpand(true);
    sidebar_box.add_css_class("sidebar");

    // Sidebar Header (Branding area)
    let sidebar_header = adw::HeaderBar::new();
    sidebar_header.set_show_end_title_buttons(false);
    sidebar_header.set_show_start_title_buttons(false);

    let branding_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    let app_icon = gtk4::Image::from_icon_name("system-search-symbolic");
    app_icon.set_pixel_size(18);
    let app_title = gtk4::Label::new(Some("Root"));
    app_title.add_css_class("title");
    app_title.add_css_class("heading");
    branding_box.append(&app_icon);
    branding_box.append(&app_title);
    sidebar_header.set_title_widget(Some(&branding_box));
    sidebar_box.append(&sidebar_header);

    // Primary destinations list (Overview, Resources, Agents, Processes, Activity, Schedule)
    let top_list = gtk4::ListBox::new();
    top_list.add_css_class("navigation-sidebar");
    top_list.set_selection_mode(gtk4::SelectionMode::Single);

    let primary_items = [
        NavigationItem::Overview,
        NavigationItem::Resources,
        NavigationItem::Agents,
        NavigationItem::Processes,
        NavigationItem::Activity,
        NavigationItem::Schedule,
    ];

    let mut top_rows = Vec::new();
    for &item in &primary_items {
        let row = build_nav_row(item);
        top_list.append(&row);
        top_rows.push(row);
    }
    sidebar_box.append(&top_list);

    // Flexible vertical spacer pushing Settings to the bottom of the sidebar
    let spacer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    spacer.set_vexpand(true);
    sidebar_box.append(&spacer);

    // Separator line above Settings
    let sep = gtk4::Separator::new(gtk4::Orientation::Horizontal);
    sep.set_margin_start(12);
    sep.set_margin_end(12);
    sidebar_box.append(&sep);

    // Bottom destinations list (Settings)
    let bottom_list = gtk4::ListBox::new();
    bottom_list.add_css_class("navigation-sidebar");
    bottom_list.set_selection_mode(gtk4::SelectionMode::Single);
    let settings_row = build_nav_row(NavigationItem::Settings);
    bottom_list.append(&settings_row);
    sidebar_box.append(&bottom_list);

    // Operational safety status badge
    let footer_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    footer_box.set_margin_top(8);
    footer_box.set_margin_bottom(12);
    footer_box.set_margin_start(12);
    footer_box.set_margin_end(12);

    let badge = gtk4::Label::new(Some("READ-ONLY"));
    badge.add_css_class("tag");
    badge.add_css_class("success");

    let status_lbl = gtk4::Label::new(Some("Production Safety"));
    status_lbl.add_css_class("dim-label");
    status_lbl.set_xalign(0.0);

    footer_box.append(&badge);
    footer_box.append(&status_lbl);
    sidebar_box.append(&footer_box);

    root_box.append(&sidebar_box);

    // Vertical Divider between sidebar and content
    let divider = gtk4::Separator::new(gtk4::Orientation::Vertical);
    root_box.append(&divider);

    // ==========================================
    // 2. Main Content Area (Right Pane)
    // ==========================================
    let content_box = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content_box.set_hexpand(true);
    content_box.set_vexpand(true);

    let content_header = adw::HeaderBar::new();
    let title_widget = adw::WindowTitle::new(
        NavigationItem::Overview.title(),
        NavigationItem::Overview.subtitle(),
    );
    content_header.set_title_widget(Some(&title_widget));

    // Refresh action button
    let refresh_btn = gtk4::Button::from_icon_name("view-refresh-symbolic");
    refresh_btn.set_tooltip_text(Some("Refresh telemetry and process table (Ctrl+R / F5)"));
    content_header.pack_start(&refresh_btn);

    // Scan trigger button
    let scan_btn = gtk4::Button::from_icon_name("system-search-symbolic");
    scan_btn.set_tooltip_text(Some("Select directory to inspect"));
    content_header.pack_end(&scan_btn);

    content_box.append(&content_header);

    // Central ViewStack hosting the seven dedicated views
    let view_stack = adw::ViewStack::new();
    view_stack.set_hexpand(true);
    view_stack.set_vexpand(true);

    // Page container boxes (allowing dynamic rebuilds on refresh/scan events)
    let overview_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    overview_container.set_vexpand(true);
    overview_container.set_hexpand(true);

    let resources_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    resources_container.set_vexpand(true);
    resources_container.set_hexpand(true);

    let agents_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    agents_container.set_vexpand(true);
    agents_container.set_hexpand(true);

    let processes_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    processes_container.set_vexpand(true);
    processes_container.set_hexpand(true);

    let activity_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    activity_container.set_vexpand(true);
    activity_container.set_hexpand(true);

    let schedule_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    schedule_container.set_vexpand(true);
    schedule_container.set_hexpand(true);

    let settings_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    settings_container.set_vexpand(true);
    settings_container.set_hexpand(true);

    // Populate initial views
    {
        let ctrl = controller.borrow();
        overview_container.append(&build_overview_view(&ctrl.overview_vm));
        resources_container.append(&build_resources_view(&ctrl.resources_vm));
        agents_container.append(&build_agents_view(&ctrl.agents_vm));
        processes_container.append(&build_processes_view(&ctrl.processes_vm));
        activity_container.append(&build_activity_view(&ctrl.activity_vm));
        schedule_container.append(&build_schedule_view(&ctrl.schedule_vm));
        settings_container.append(&build_settings_view(&ctrl.settings_vm));
    }

    view_stack.add_named(
        &overview_container,
        Some(NavigationItem::Overview.page_id()),
    );
    view_stack.add_named(
        &resources_container,
        Some(NavigationItem::Resources.page_id()),
    );
    view_stack.add_named(&agents_container, Some(NavigationItem::Agents.page_id()));
    view_stack.add_named(
        &processes_container,
        Some(NavigationItem::Processes.page_id()),
    );
    view_stack.add_named(
        &activity_container,
        Some(NavigationItem::Activity.page_id()),
    );
    view_stack.add_named(
        &schedule_container,
        Some(NavigationItem::Schedule.page_id()),
    );
    view_stack.add_named(
        &settings_container,
        Some(NavigationItem::Settings.page_id()),
    );

    content_box.append(&view_stack);
    root_box.append(&content_box);

    toast_overlay.set_child(Some(&root_box));
    window.set_content(Some(&toast_overlay));

    // ==========================================
    // 3. Navigation State Synchronization & Signal Wiring
    // ==========================================
    let switch_page = {
        let view_stack = view_stack.clone();
        let title_widget = title_widget.clone();
        let top_list = top_list.clone();
        let bottom_list = bottom_list.clone();
        let top_rows = top_rows.clone();
        let settings_row = settings_row.clone();
        let ctrl_clone = controller.clone();
        let is_switching = Rc::new(Cell::new(false));

        Rc::new(move |item: NavigationItem| {
            if is_switching.get() {
                return;
            }
            is_switching.set(true);

            // 1. Switch ViewStack active page
            view_stack.set_visible_child_name(item.page_id());

            // 2. Update Content HeaderBar title and descriptive subtitle
            title_widget.set_title(item.title());
            title_widget.set_subtitle(item.subtitle());

            // 3. Synchronize ListBox row selections
            match item {
                NavigationItem::Settings => {
                    top_list.unselect_all();
                    bottom_list.select_row(Some(&settings_row));
                }
                _ => {
                    bottom_list.unselect_all();
                    if let Some(row) = top_rows.get(item.index()) {
                        top_list.select_row(Some(row));
                    }
                }
            }

            // 4. Update Controller Navigation State
            ctrl_clone.borrow_mut().navigate_to(item);

            is_switching.set(false);
        })
    };

    // Connect top list click and keyboard selection
    {
        let switcher = switch_page.clone();
        top_list.connect_row_selected(move |_, row_opt| {
            if let Some(row) = row_opt {
                let idx = row.index() as usize;
                if let Some(&item) = primary_items.get(idx) {
                    switcher(item);
                }
            }
        });
    }

    {
        let switcher = switch_page.clone();
        top_list.connect_row_activated(move |_, row| {
            let idx = row.index() as usize;
            if let Some(&item) = primary_items.get(idx) {
                switcher(item);
            }
        });
    }

    // Connect bottom list (Settings) click and keyboard selection
    {
        let switcher = switch_page.clone();
        bottom_list.connect_row_selected(move |_, row_opt| {
            if row_opt.is_some() {
                switcher(NavigationItem::Settings);
            }
        });
    }

    {
        let switcher = switch_page.clone();
        bottom_list.connect_row_activated(move |_, _| {
            switcher(NavigationItem::Settings);
        });
    }

    // Connect Gio actions for keyboard shortcuts (Ctrl+1 .. Ctrl+7)
    {
        for item in NavigationItem::ALL {
            let action_name = item.page_id();
            if app.lookup_action(action_name).is_none() {
                let switcher = switch_page.clone();
                let action = gio::SimpleAction::new(action_name, None);
                action.connect_activate(move |_, _| {
                    switcher(item);
                });
                app.add_action(&action);
            }
        }

        if app.lookup_action("refresh").is_none() {
            let refresh_action = gio::SimpleAction::new("refresh", None);
            let r_btn = refresh_btn.clone();
            refresh_action.connect_activate(move |_, _| {
                r_btn.emit_clicked();
            });
            app.add_action(&refresh_action);
        }

        if app.lookup_action("quit").is_none() {
            let quit_action = gio::SimpleAction::new("quit", None);
            let win = window.clone();
            quit_action.connect_activate(move |_, _| {
                win.close();
            });
            app.add_action(&quit_action);
        }
    }

    // Refresh action button handling
    {
        let ctrl_clone = controller.clone();
        let overview_box = overview_container.clone();
        let proc_box = processes_container.clone();
        let sched_box = schedule_container.clone();
        let toast_overlay_clone = toast_overlay.clone();

        refresh_btn.connect_clicked(move |_| {
            let mut ctrl = ctrl_clone.borrow_mut();
            ctrl.refresh_all();

            // Refresh overview
            while let Some(child) = overview_box.first_child() {
                overview_box.remove(&child);
            }
            overview_box.append(&build_overview_view(&ctrl.overview_vm));

            // Refresh processes
            while let Some(child) = proc_box.first_child() {
                proc_box.remove(&child);
            }
            proc_box.append(&build_processes_view(&ctrl.processes_vm));

            // Refresh schedule
            while let Some(child) = sched_box.first_child() {
                sched_box.remove(&child);
            }
            sched_box.append(&build_schedule_view(&ctrl.schedule_vm));

            toast_overlay_clone.add_toast(adw::Toast::new("System telemetry refreshed"));
        });
    }

    // Scan trigger button handling (Directory Chooser Dialog)
    {
        let ctrl_clone = controller.clone();
        let toast_overlay_clone = toast_overlay.clone();
        let window_clone = window.clone();

        scan_btn.connect_clicked(move |_| {
            let chooser = gtk4::FileChooserNative::new(
                Some("Select Directory to Inspect"),
                Some(&window_clone),
                gtk4::FileChooserAction::SelectFolder,
                Some("Inspect"),
                Some("Cancel"),
            );
            let ctrl_inner = ctrl_clone.clone();
            let toast_inner = toast_overlay_clone.clone();
            chooser.connect_response(move |dialog, response| {
                if response == gtk4::ResponseType::Accept {
                    if let Some(file) = dialog.file() {
                        if let Some(path) = file.path() {
                            let mut ctrl = ctrl_inner.borrow_mut();
                            ctrl.start_scan(path.clone());
                            let msg = format!("Resource discovery started for {}", path.display());
                            toast_inner.add_toast(adw::Toast::new(&msg));
                        }
                    }
                }
            });
            chooser.show();
        });
    }

    // Periodic worker poll timer
    {
        let ctrl_clone = controller.clone();
        let res_box = resources_container;
        let agents_box = agents_container;
        let overview_box = overview_container;
        let toast_overlay_clone = toast_overlay.clone();

        glib::timeout_add_local(Duration::from_millis(200), move || {
            let mut ctrl = ctrl_clone.borrow_mut();
            let prev_state = ctrl.state.scan_state.clone();
            ctrl.poll_worker_messages();

            if let (
                crate::model::state::ScanExecutionState::Scanning { .. },
                crate::model::state::ScanExecutionState::Completed { total_items, .. },
            ) = (&prev_state, &ctrl.state.scan_state)
            {
                let items_count = *total_items;
                while let Some(child) = res_box.first_child() {
                    res_box.remove(&child);
                }
                res_box.append(&build_resources_view(&ctrl.resources_vm));

                while let Some(child) = agents_box.first_child() {
                    agents_box.remove(&child);
                }
                agents_box.append(&build_agents_view(&ctrl.agents_vm));

                while let Some(child) = overview_box.first_child() {
                    overview_box.remove(&child);
                }
                overview_box.append(&build_overview_view(&ctrl.overview_vm));

                toast_overlay_clone.add_toast(adw::Toast::new(&format!(
                    "Resource discovery completed: {} findings",
                    items_count
                )));
            }

            if let (
                crate::model::state::ScanExecutionState::Scanning { .. },
                crate::model::state::ScanExecutionState::Failed { error, .. },
            ) = (&prev_state, &ctrl.state.scan_state)
            {
                toast_overlay_clone.add_toast(adw::Toast::new(&format!(
                    "Discovery scan failed: {}",
                    error
                )));
            }

            if let (
                crate::model::state::ScanExecutionState::Scanning { .. },
                crate::model::state::ScanExecutionState::Cancelled { .. },
            ) = (&prev_state, &ctrl.state.scan_state)
            {
                toast_overlay_clone.add_toast(adw::Toast::new("Discovery scan cancelled"));
            }

            glib::ControlFlow::Continue
        });
    }

    // Clean shutdown on window close
    {
        let ctrl_clone = controller;
        window.connect_close_request(move |_| {
            ctrl_clone.borrow_mut().shutdown();
            glib::Propagation::Proceed
        });
    }

    // Initial page selection (Overview)
    switch_page(NavigationItem::Overview);

    window.present();
}
