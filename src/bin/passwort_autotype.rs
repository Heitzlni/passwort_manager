fn main() {
    if let Err(e) = passwort_manager::autotype::run() {
        eprintln!("passwort-autotype error: {}", e);
        std::process::exit(1);
    }
}
