fn main() {
    if let Err(e) = passwort_manager::ipc::run_ctl() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
