use passwort_manager::{gui, harden_process, storage, vault};

fn main() {
    harden_process();
    storage::migrate_local_vault_if_needed();

    let args: Vec<String> = std::env::args().collect();
    let arg_after = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
    };

    // Quick-pick mode (launched by passwort-autotype's fill hotkey).
    // The picker no longer talks to the daemon: autotype passes the
    // entries as a JSON array on stdin (normal mode), or runs us with
    // `--unlock` (stdin carries an optional error note to show) and
    // reads the typed master password back on stdout.
    if args.iter().any(|a| a == "--picker") {
        use std::io::Read;
        let target = arg_after("--target-title");
        let unlock_mode = args.iter().any(|a| a == "--unlock");
        let mut stdin_buf = String::new();
        let _ = std::io::stdin().read_to_string(&mut stdin_buf);
        let (entries, note) = if unlock_mode {
            let t = stdin_buf.trim();
            (Vec::new(), if t.is_empty() { None } else { Some(t.to_string()) })
        } else {
            let entries: Vec<passwort_manager::ipc::EntryRef> =
                serde_json::from_str(stdin_buf.trim()).unwrap_or_default();
            (entries, None)
        };
        if let Err(e) = gui::run_picker(target, entries, unlock_mode, note) {
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
