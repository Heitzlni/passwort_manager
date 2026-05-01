mod crypto;
mod gui;
mod session;
mod storage;
mod vault;

#[cfg(unix)]
fn harden_process() {
    unsafe {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }

    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    unsafe {
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

#[cfg(not(unix))]
fn harden_process() {}

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
