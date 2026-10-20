#[cfg(feature = "gtk")]
use libadwaita as adw;
#[cfg(feature = "gtk")]
use libadwaita::prelude::*;

#[cfg(feature = "gtk")]
pub struct RootGtkApplication {
    app: adw::Application,
}

#[cfg(feature = "gtk")]
impl RootGtkApplication {
    pub fn new() -> Self {
        let app = adw::Application::builder()
            .application_id("io.github.realmadede.Root")
            .build();

        app.connect_startup(|app| {
            // Setup keyboard accelerators adhering to Designing-Skills:
            // Keyboard actions must switch immediately without transition delay.
            app.set_accels_for_action("app.overview", &["<Control>1"]);
            app.set_accels_for_action("app.resources", &["<Control>2"]);
            app.set_accels_for_action("app.agents", &["<Control>3"]);
            app.set_accels_for_action("app.processes", &["<Control>4"]);
            app.set_accels_for_action("app.activity", &["<Control>5"]);
            app.set_accels_for_action("app.schedule", &["<Control>6"]);
            app.set_accels_for_action("app.settings", &["<Control>7"]);
            app.set_accels_for_action("app.refresh", &["<Control>r", "F5"]);
            app.set_accels_for_action("app.quit", &["<Control>q"]);
        });

        app.connect_activate(|app| {
            super::window::build_and_present_window(app);
        });

        Self { app }
    }

    pub fn run(&self) -> i32 {
        let empty_args: [&str; 0] = [];
        self.app.run_with_args(&empty_args).into()
    }
}

#[cfg(feature = "gtk")]
impl Default for RootGtkApplication {
    fn default() -> Self {
        Self::new()
    }
}
