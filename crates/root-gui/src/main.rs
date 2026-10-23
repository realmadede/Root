fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--version" | "-V" => {
                println!("root-gui {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!("root-gui {}", env!("CARGO_PKG_VERSION"));
                println!("Graphical desktop interface for Root resource inspection");
                println!();
                println!("Usage: root-gui [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -h, --help     Print help");
                println!("  -V, --version  Print version");
                return;
            }
            _ => {}
        }
    }

    let exit_code = root_gui::run_desktop_app();
    std::process::exit(exit_code);
}
