// `passwort-autotype` runs in two modes:
//   * default  — supervisor: spawns itself with --child and restarts on death
//   * --child  — the actual hotkey listener
//
// Why: X11's default error handler aborts the process on a BadAccess from
// XGrabKey (e.g. when the user picks a hotkey already owned by the WM or
// another app). Without the supervisor a single bad hotkey choice would
// take auto-type out of service for the rest of the login session. With it,
// the user just edits the config (or uses the GUI Settings → Change hotkey)
// and the next respawn picks up the new combination.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const RESPAWN_DELAY: Duration = Duration::from_secs(5);
const SPAWN_FAIL_DELAY: Duration = Duration::from_secs(10);

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--child") {
        if let Err(e) = passwort_manager::autotype::run() {
            eprintln!("passwort-autotype: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let exe: PathBuf = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("passwort-autotype"));

    loop {
        let status = Command::new(&exe).arg("--child").status();
        match status {
            Ok(s) if s.success() => return,
            Ok(s) => {
                eprintln!(
                    "[supervisor] passwort-autotype exited with {} — restarting in {}s",
                    s,
                    RESPAWN_DELAY.as_secs()
                );
                std::thread::sleep(RESPAWN_DELAY);
            }
            Err(e) => {
                eprintln!(
                    "[supervisor] failed to respawn passwort-autotype ({}); waiting {}s",
                    e,
                    SPAWN_FAIL_DELAY.as_secs()
                );
                std::thread::sleep(SPAWN_FAIL_DELAY);
            }
        }
    }
}
