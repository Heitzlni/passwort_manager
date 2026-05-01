use passwort_manager::{gui, harden_process, storage, vault};

fn main() {
    harden_process();
    storage::migrate_local_vault_if_needed();

    let use_cli = std::env::args().any(|a| a == "--cli");

    if use_cli {
        println!("==== Password Manager ====");
        vault::start();
        return;
    }

    if let Err(e) = gui::run() {
        eprintln!("GUI failed to start ({}). Falling back to CLI.", e);
        println!("==== Password Manager ====");
        vault::start();
    }
}
