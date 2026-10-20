#[cfg(feature = "gtk")]
pub mod application;
#[cfg(feature = "gtk")]
pub mod window;

#[cfg(feature = "gtk")]
pub use application::RootGtkApplication;

/// Runs the native GTK4 + libadwaita desktop application.
/// Returns exit code (0 for success).
#[cfg(feature = "gtk")]
pub fn run_desktop_app() -> i32 {
    use gtk4::prelude::*;
    let app = RootGtkApplication::new();
    app.run()
}

/// Fallback runner when compiled in headless mode without GTK bindings.
#[cfg(not(feature = "gtk"))]
pub fn run_desktop_app() -> i32 {
    eprintln!("Root Native GUI — Headless View-Model Mode");
    eprintln!();
    eprintln!(
        "The GUI engine was compiled in headless mode. To launch the native graphical interface,"
    );
    eprintln!("ensure libgtk-4-dev and libadwaita-1-dev C development libraries and pkg-config are installed:");
    eprintln!();
    eprintln!("  sudo apt install pkg-config libgtk-4-dev libadwaita-1-dev");
    eprintln!("  cargo run -p root-gui --features gtk");
    eprintln!();
    eprintln!(
        "All headless view models, data controllers, and background workers are fully functional."
    );
    0
}
