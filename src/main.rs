use passwort_manager::{gui, harden_process, storage, vault};

fn main() {
    harden_process();
    storage::migrate_local_vault_if_needed();

    let args: Vec<String> = std::env::args().collect();
    let arg_after = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
    };

    // Quick-pick mode (launched by passwort-autotype's fill hotkey).
    if args.iter().any(|a| a == "--picker") {
        let target = arg_after("--target-title");
        if let Err(e) = gui::run_picker(target) {
            eprintln!("picker failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Quick-save mode (launched by passwort-autotype's save hotkey).
    if args.iter().any(|a| a == "--quick-save") {
        let target = arg_after("--target-title");
        if let Err(e) = gui::run_quick_save(target) {
            eprintln!("quick-save failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let use_cli = args.iter().any(|a| a == "--cli");

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
