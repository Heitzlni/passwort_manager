fn main() {
    if let Err(e) = passwort_manager::native_host::run() {
        eprintln!("native host error: {}", e);
        std::process::exit(1);
    }
}
