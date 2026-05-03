//! Auto-type for native apps.
//!
//! Architecture:
//!
//! 1. `passwort-autotype` runs as a long-lived user systemd service.
//! 2. It registers a global hotkey (default Ctrl+Alt+P) via `global-hotkey`.
//! 3. On hotkey press: snapshot the active X11 window, spawn the GUI binary
//!    as `passwort-manager --picker --target-title <title>`, wait for it to
//!    print the chosen entry name on stdout.
//! 4. Re-focus the original window via `xdotool windowactivate`.
//! 5. Fetch the credential from the daemon and type
//!    `<username><Tab><password>` via `enigo`.
//!
//! The picker is its own process because eframe's winit-based event loop
//! can only be created once per process — we'd love to keep it warm but
//! we'd lose the window after first close. Cold-start is fast enough.
//!
//! Wayland: `enigo` and `global-hotkey` both have very limited Wayland
//! support today. This module assumes X11. On Wayland the hotkey may not
//! register and the keystrokes will go nowhere; we fall back to writing
//! the password to the clipboard so the user can paste it (TODO).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use global_hotkey::{
    hotkey::{Code, HotKey, Modifiers},
    GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState,
};

use crate::config::{self, HotkeyConfig};
use crate::ipc::{rpc, Request, Response};

const KEYSTROKE_DELAY_MS: u64 = 80; // small pause after focus return

pub fn run() -> std::io::Result<()> {
    let manager = GlobalHotKeyManager::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let mut current_cfg = config::load();
    let mut current_hk = match register_hotkey(&manager, &current_cfg.hotkey) {
        Ok(hk) => hk,
        Err(e) => {
            eprintln!(
                "passwort-autotype: failed to register hotkey {}: {}",
                current_cfg.hotkey.human(),
                e
            );
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }
    };
    let mut current_mtime = config::mtime();

    eprintln!(
        "passwort-autotype listening for {} (config: {})",
        current_cfg.hotkey.human(),
        config::config_path().display()
    );

    let receiver = GlobalHotKeyEvent::receiver();

    loop {
        // Block on hotkey events, but wake up periodically to check for
        // config-file changes (e.g. user changed the hotkey via the GUI).
        // The receiver's error type is crossbeam_channel's, not std mpsc's,
        // and we don't want to add crossbeam as a direct dep just to name
        // it — so collapse Timeout / Disconnected into the same "wake up
        // and check config" branch.
        match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(event) => {
                if event.id == current_hk.id() && event.state == HotKeyState::Pressed {
                    handle_hotkey_press();
                }
            }
            Err(_) => {
                let new_mtime = config::mtime();
                if new_mtime != current_mtime {
                    current_mtime = new_mtime;
                    let new_cfg = config::load();
                    if new_cfg != current_cfg {
                        eprintln!(
                            "passwort-autotype: hotkey changed → {}",
                            new_cfg.hotkey.human()
                        );
                        let _ = manager.unregister(current_hk);
                        match register_hotkey(&manager, &new_cfg.hotkey) {
                            Ok(hk) => {
                                current_hk = hk;
                                current_cfg = new_cfg;
                            }
                            Err(e) => {
                                eprintln!(
                                    "passwort-autotype: failed to reload hotkey: {}",
                                    e
                                );
                                // Try to reinstall the previous one
                                if let Ok(hk) = register_hotkey(&manager, &current_cfg.hotkey) {
                                    current_hk = hk;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// =================== hotkey parsing ===================

fn register_hotkey(
    manager: &GlobalHotKeyManager,
    cfg: &HotkeyConfig,
) -> Result<HotKey, String> {
    let modifiers = parse_modifiers(&cfg.modifiers)?;
    let code = parse_key_code(&cfg.key)?;
    let hk = HotKey::new(Some(modifiers), code);
    manager.register(hk).map_err(|e| e.to_string())?;
    Ok(hk)
}

fn parse_modifiers(mods: &[String]) -> Result<Modifiers, String> {
    let mut out = Modifiers::empty();
    for m in mods {
        match m.to_lowercase().as_str() {
            "ctrl" | "control" => out |= Modifiers::CONTROL,
            "alt" | "option" => out |= Modifiers::ALT,
            "shift" => out |= Modifiers::SHIFT,
            "super" | "meta" | "win" => out |= Modifiers::SUPER,
            other => return Err(format!("unknown modifier: {}", other)),
        }
    }
    if out.is_empty() {
        return Err("hotkey must have at least one modifier".into());
    }
    Ok(out)
}

fn parse_key_code(key: &str) -> Result<Code, String> {
    let k = key.to_lowercase();
    Ok(match k.as_str() {
        "a" => Code::KeyA, "b" => Code::KeyB, "c" => Code::KeyC, "d" => Code::KeyD,
        "e" => Code::KeyE, "f" => Code::KeyF, "g" => Code::KeyG, "h" => Code::KeyH,
        "i" => Code::KeyI, "j" => Code::KeyJ, "k" => Code::KeyK, "l" => Code::KeyL,
        "m" => Code::KeyM, "n" => Code::KeyN, "o" => Code::KeyO, "p" => Code::KeyP,
        "q" => Code::KeyQ, "r" => Code::KeyR, "s" => Code::KeyS, "t" => Code::KeyT,
        "u" => Code::KeyU, "v" => Code::KeyV, "w" => Code::KeyW, "x" => Code::KeyX,
        "y" => Code::KeyY, "z" => Code::KeyZ,
        "0" => Code::Digit0, "1" => Code::Digit1, "2" => Code::Digit2, "3" => Code::Digit3,
        "4" => Code::Digit4, "5" => Code::Digit5, "6" => Code::Digit6, "7" => Code::Digit7,
        "8" => Code::Digit8, "9" => Code::Digit9,
        "f1" => Code::F1, "f2" => Code::F2, "f3" => Code::F3, "f4" => Code::F4,
        "f5" => Code::F5, "f6" => Code::F6, "f7" => Code::F7, "f8" => Code::F8,
        "f9" => Code::F9, "f10" => Code::F10, "f11" => Code::F11, "f12" => Code::F12,
        "space" => Code::Space,
        "enter" | "return" => Code::Enter,
        other => return Err(format!("unknown key: {}", other)),
    })
}

// =================== hotkey handler ===================

fn handle_hotkey_press() {
    eprintln!("[hotkey] pressed → opening picker");
    let target_window_id = active_window_id();
    let target_window_title = active_window_title();
    eprintln!(
        "[hotkey] target window: id={:?} title={:?}",
        target_window_id, target_window_title
    );

    let picker_bin = picker_binary_path();

    let mut cmd = Command::new(&picker_bin);
    cmd.arg("--picker");
    if let Some(t) = &target_window_title {
        cmd.arg("--target-title").arg(t);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("passwort-autotype: failed to launch picker: {}", e);
            return;
        }
    };

    let mut chosen = String::new();
    if let Some(stdout) = child.stdout.take() {
        let mut r = BufReader::new(stdout);
        let _ = r.read_line(&mut chosen);
    }
    let exit = child.wait().ok();
    let chosen = chosen.trim().to_string();
    if chosen.is_empty() || exit.map(|s| !s.success()).unwrap_or(true) {
        return; // cancelled or no selection
    }

    // Re-focus the original window so our keystrokes land in the right place.
    if let Some(id) = &target_window_id {
        let _ = Command::new("xdotool")
            .args(["windowactivate", "--sync", id])
            .status();
    }
    thread::sleep(Duration::from_millis(KEYSTROKE_DELAY_MS));

    // Fetch credential and type it.
    let resp = match rpc(&Request::Get { name: chosen }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("passwort-autotype: rpc(get) failed: {}", e);
            return;
        }
    };
    if let Response::Credential { username, password, .. } = resp {
        type_credential(&username, &password);
    }
}

fn picker_binary_path() -> PathBuf {
    // Prefer the binary the user installed; fall back to PATH lookup.
    let installed = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".local/bin/passwort-manager"));
    if let Some(p) = installed {
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from("passwort-manager")
}

fn active_window_id() -> Option<String> {
    let out = Command::new("xdotool").arg("getactivewindow").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

fn active_window_title() -> Option<String> {
    let out = Command::new("xdotool")
        .args(["getactivewindow", "getwindowname"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

fn type_credential(username: &str, password: &str) {
    // We shell out to xdotool. It already handles every X11 weirdness
    // (modifier maps, dead keys, key release timing) and we already
    // depend on it for window-id / title detection above. Pass the text
    // via stdin (`type --file -`) so it doesn't appear on the command
    // line where /proc/<pid>/cmdline could leak it.
    if !username.is_empty() {
        if !xdotool_type(username) {
            return;
        }
        let _ = Command::new("xdotool")
            .args(["key", "--delay", "20", "Tab"])
            .status();
        thread::sleep(Duration::from_millis(30));
    }
    xdotool_type(password);
    // Don't auto-press Enter — risky if focus is wrong, and many apps
    // need an explicit user click anyway (CAPTCHAs, 2FA prompts).
}

fn xdotool_type(text: &str) -> bool {
    let child = Command::new("xdotool")
        .args(["type", "--delay", "12", "--clearmodifiers", "--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "passwort-autotype: failed to spawn xdotool ({}). Install with: sudo apt install xdotool",
                e
            );
            return false;
        }
    };
    if let Some(stdin) = child.stdin.as_mut() {
        if let Err(e) = stdin.write_all(text.as_bytes()) {
            eprintln!("passwort-autotype: failed to write to xdotool stdin: {}", e);
            return false;
        }
    }
    match child.wait() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("passwort-autotype: xdotool exited with {}", s);
            false
        }
        Err(e) => {
            eprintln!("passwort-autotype: xdotool wait failed: {}", e);
            false
        }
    }
}

