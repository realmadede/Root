#[cfg(feature = "gtk")]
use std::cell::RefCell;
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
pub fn build_and_present_window(app: &adw::Application) {
    let controller = Rc::new(RefCell::new(RootAppController::new()));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Root")
        .default_width(1024)
        .default_height(720)
        .build();

    let header_bar = adw::HeaderBar::new();

    // Central view stack
    let view_stack = adw::ViewStack::new();

    // Setup pages with scrolled containers and clamps
    let overview_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    let resources_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    let agents_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    let processes_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    let activity_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    let schedule_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    let settings_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);

    // Initial population
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

    let wrap_in_scrolled_clamp = |widget: &gtk4::Box| -> gtk4::Widget {
        let clamp = adw::Clamp::new();
        clamp.set_maximum_size(960);
        clamp.set_tightening_threshold(700);
        clamp.set_child(Some(widget));

        let scrolled = gtk4::ScrolledWindow::new();
        scrolled.set_hscrollbar_policy(gtk4::PolicyType::Never);
        scrolled.set_vscrollbar_policy(gtk4::PolicyType::Automatic);
        scrolled.set_child(Some(&clamp));
        scrolled.upcast()
    };

    let page1 = view_stack.add_titled(
        &wrap_in_scrolled_clamp(&overview_container),
        Some("overview"),
        "Overview",
    );
    page1.set_icon_name(Some("view-dashboard-symbolic"));

    let page2 = view_stack.add_titled(
        &wrap_in_scrolled_clamp(&resources_container),
        Some("resources"),
        "Resources",
    );
    page2.set_icon_name(Some("drive-harddisk-symbolic"));

    let page3 = view_stack.add_titled(
        &wrap_in_scrolled_clamp(&agents_container),
        Some("agents"),
        "Agents",
    );
    page3.set_icon_name(Some("system-run-symbolic"));

    let page4 = view_stack.add_titled(
        &wrap_in_scrolled_clamp(&processes_container),
        Some("processes"),
        "Processes",
    );
    page4.set_icon_name(Some("application-x-executable-symbolic"));

    let page5 = view_stack.add_titled(
        &wrap_in_scrolled_clamp(&activity_container),
        Some("activity"),
        "Activity",
    );
    page5.set_icon_name(Some("utilities-system-monitor-symbolic"));

    let page6 = view_stack.add_titled(
        &wrap_in_scrolled_clamp(&schedule_container),
        Some("schedule"),
        "Schedule",
    );
    page6.set_icon_name(Some("alarm-symbolic"));

    let page7 = view_stack.add_titled(
        &wrap_in_scrolled_clamp(&settings_container),
        Some("settings"),
        "Settings",
    );
    page7.set_icon_name(Some("emblem-system-symbolic"));

    // View switcher in header bar
    let switcher = adw::ViewSwitcher::new();
    switcher.set_stack(Some(&view_stack));
    header_bar.set_title_widget(Some(&switcher));

    // Toast overlay
    let toast_overlay = adw::ToastOverlay::new();

    // Refresh action button
    let refresh_btn = gtk4::Button::from_icon_name("view-refresh-symbolic");
    refresh_btn.set_tooltip_text(Some("Refresh telemetry and process table (Ctrl+R / F5)"));
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
    header_bar.pack_start(&refresh_btn);

    // Scan trigger button
    let scan_btn = gtk4::Button::from_icon_name("system-search-symbolic");
    scan_btn.set_tooltip_text(Some("Run read-only resource discovery"));
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
    header_bar.pack_end(&scan_btn);

    // Register Gio actions for keyboard shortcuts (Ctrl+1..Ctrl+7, Ctrl+R, F5, Ctrl+Q)
    {
        let page_actions = [
            ("overview", "overview"),
            ("resources", "resources"),
            ("agents", "agents"),
            ("processes", "processes"),
            ("activity", "activity"),
            ("schedule", "schedule"),
            ("settings", "settings"),
        ];

        for (action_name, page_name) in page_actions {
            if app.lookup_action(action_name).is_none() {
                let stack = view_stack.clone();
                let action = gio::SimpleAction::new(action_name, None);
                action.connect_activate(move |_, _| {
                    stack.set_visible_child_name(page_name);
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
                // Scan just finished! Update resources and agents views
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

    let main_box = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    main_box.append(&header_bar);
    main_box.append(&view_stack);

    toast_overlay.set_child(Some(&main_box));
    window.set_content(Some(&toast_overlay));
    window.present();
}
