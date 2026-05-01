fn main() {
    passwort_manager::harden_process();
    passwort_manager::storage::migrate_local_vault_if_needed();
    if let Err(e) = passwort_manager::ipc::run_daemon() {
        eprintln!("daemon error: {}", e);
        std::process::exit(1);
    }
}
