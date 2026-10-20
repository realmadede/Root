fn main() {
    if let Err(err) = root_cli::run() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
