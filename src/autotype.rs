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
use crate::ipc::{rpc_authed, EntryRef, Request, Response};

const KEYSTROKE_DELAY_MS: u64 = 80; // small pause after focus return

pub fn run() -> std::io::Result<()> {
    // Wayland short-circuit: there's no reliable cross-compositor way to
    // grab a global hotkey today (the GlobalShortcuts portal exists but
    // requires per-app interactive opt-in, and most compositors don't
    // implement it yet). Tell the user how to wire things up themselves
    // and exit cleanly so the systemd service doesn't keep restarting.
    if std::env::var("XDG_SESSION_TYPE").as_deref() == Ok("wayland") {
        eprintln!("passwort-autotype: Wayland session detected.");
        eprintln!("Global hotkeys aren't portably supported under Wayland.");
        eprintln!("Bind your compositor's own hotkey to one of these commands instead:");
        eprintln!("    passwortctl fill         # pick + type credential into the focused window");
        eprintln!("    passwortctl quick-save   # capture credential from a native app");
        eprintln!("Examples:");
        eprintln!("  GNOME: Settings → Keyboard → Custom Shortcuts → Add");
        eprintln!("    Command: {}/.local/bin/passwortctl fill", std::env::var("HOME").unwrap_or_default());
        eprintln!("  Sway/Hyprland: bindsym <key> exec passwortctl fill");
        eprintln!("Also install ydotool (sudo apt install ydotool) and enable ydotoold —");
        eprintln!("see SETUP.md for the input-group / ydotoold details.");
        return Ok(());
    }
    let manager = GlobalHotKeyManager::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let mut current_cfg = config::load();
    let mut current_fill_hk = match register_hotkey(&manager, &current_cfg.hotkey) {
        Ok(hk) => hk,
        Err(e) => {
            eprintln!(
                "passwort-autotype: failed to register fill hotkey {}: {}",
                current_cfg.hotkey.human(),
                e
            );
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }
    };
    // Save hotkey is best-effort: if it conflicts we still want to run
    // for fill, so we just log and continue.
    let mut current_save_hk: Option<HotKey> = match register_hotkey(&manager, &current_cfg.save_hotkey)
    {
        Ok(hk) => Some(hk),
        Err(e) => {
            eprintln!(
                "passwort-autotype: failed to register save hotkey {}: {} (skipping)",
                current_cfg.save_hotkey.human(),
                e
            );
            None
        }
    };
    let mut current_mtime = config::mtime();

    eprintln!(
        "passwort-autotype listening: fill={}  save={} (config: {})",
        current_cfg.hotkey.human(),
        current_save_hk.as_ref().map(|_| current_cfg.save_hotkey.human()).unwrap_or_else(|| "<unavailable>".into()),
        config::config_path().display()
    );

    // Eager Register so the user can approve us once via passwortctl,
    // instead of having to press the hotkey, see it silently fail with
    // client_pending, then notice the new entry in `passwortctl approvals`.
    match rpc_authed("passwort-autotype", &Request::AuthStatus) {
        Ok(Response::AuthStatusResp { state }) => {
            eprintln!("passwort-autotype: auth state = {}", state);
            if state == "pending" {
                eprintln!(
                    "passwort-autotype: not yet approved. Run:  passwortctl approvals  →  passwortctl approve <id>"
                );
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("passwort-autotype: initial register failed: {}", e),
    }

    let receiver = GlobalHotKeyEvent::receiver();

    loop {
        match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(event) => {
                if event.state != HotKeyState::Pressed {
                    continue;
                }
                if event.id == current_fill_hk.id() {
                    handle_fill_hotkey();
                } else if Some(event.id) == current_save_hk.as_ref().map(|h| h.id()) {
                    handle_save_hotkey();
                }
            }
            Err(_) => {
                let new_mtime = config::mtime();
                if new_mtime != current_mtime {
                    current_mtime = new_mtime;
                    let new_cfg = config::load();
                    if new_cfg != current_cfg {
                        eprintln!(
                            "passwort-autotype: config changed → fill={} save={}",
                            new_cfg.hotkey.human(),
                            new_cfg.save_hotkey.human()
                        );
                        let _ = manager.unregister(current_fill_hk);
                        if let Some(h) = current_save_hk.take() {
                            let _ = manager.unregister(h);
                        }
                        current_fill_hk = match register_hotkey(&manager, &new_cfg.hotkey) {
                            Ok(hk) => hk,
                            Err(e) => {
                                eprintln!(
                                    "passwort-autotype: failed to reload fill hotkey: {}",
                                    e
                                );
                                // Try to reinstall the previous one so we
                                // don't completely lose the listener
                                match register_hotkey(&manager, &current_cfg.hotkey) {
                                    Ok(hk) => hk,
                                    Err(e2) => {
                                        eprintln!(
                                            "passwort-autotype: also failed to reinstall previous: {} — exiting",
                                            e2
                                        );
                                        return Err(std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            e2,
                                        ));
                                    }
                                }
                            }
                        };
                        current_save_hk = match register_hotkey(&manager, &new_cfg.save_hotkey) {
                            Ok(hk) => Some(hk),
                            Err(e) => {
                                eprintln!(
                                    "passwort-autotype: failed to reload save hotkey: {} (skipping)",
                                    e
                                );
                                None
                            }
                        };
                        current_cfg = new_cfg;
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

fn handle_save_hotkey() {
    eprintln!("[save-hotkey] pressed");
    let target_window_title = active_window_title();
    eprintln!("[save-hotkey] target window title: {:?}", target_window_title);

    let bin = picker_binary_path();
    let mut cmd = Command::new(&bin);
    cmd.arg("--quick-save");
    if let Some(t) = &target_window_title {
        cmd.arg("--target-title").arg(t);
    }
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::inherit());
    if let Err(e) = cmd.spawn() {
        eprintln!("passwort-autotype: failed to launch quick-save dialog: {}", e);
    }
}

fn handle_fill_hotkey() {
    eprintln!("[fill-hotkey] pressed");
    run_fill_flow();
}

/// Run the "pick an entry, then type its credential" flow once. Used by
/// the X11 hotkey path AND by the standalone `passwortctl fill` command
/// (which is how Wayland users trigger it — they bind their compositor's
/// own hotkey to the CLI command since there's no portable Wayland
/// global-hotkey API).
///
/// Window-context features (auto-pick by title, focus return) require
/// xdotool and only run on X11; on Wayland we skip them and always show
/// the picker.
pub fn run_fill_flow() {
    let on_x11 = crate::typing::detect() == crate::typing::Backend::Xdotool;
    let target_window_id = if on_x11 { active_window_id() } else { None };
    let target_window_title = if on_x11 { active_window_title() } else { None };
    eprintln!(
        "[fill] target window: id={:?} title={:?} backend={:?}",
        target_window_id, target_window_title, crate::typing::detect()
    );

    // autotype is the single approved daemon client. It fetches the
    // entries itself (and, if the vault is locked, drives an unlock
    // through the picker). The picker is now a dumb UI fed via stdin.
    let mut note: Option<String> = None;
    let entries = loop {
        match fetch_entries() {
            Fetch::Entries(e) => break e,
            Fetch::Failed(m) => {
                eprintln!("[fill] list failed: {}", m);
                return;
            }
            Fetch::Locked => {
                let master = match spawn_picker_unlock(
                    target_window_title.as_deref(),
                    note.as_deref(),
                ) {
                    Some(m) => m,
                    None => return, // cancelled
                };
                match rpc_authed(
                    "passwort-autotype",
                    &Request::Unlock { password: master },
                ) {
                    Ok(Response::Ok) => {
                        note = None;
                        continue;
                    }
                    Ok(Response::Error { code, .. })
                        if code == "wrong_password" =>
                    {
                        note = Some("Wrong master password.".into());
                        continue;
                    }
                    Ok(Response::Error { message, .. }) => {
                        eprintln!("[fill] unlock failed: {}", message);
                        return;
                    }
                    Ok(_) => {
                        eprintln!("[fill] unlock: unexpected response");
                        return;
                    }
                    Err(e) => {
                        eprintln!("[fill] unlock rpc failed: {}", e);
                        return;
                    }
                }
            }
        }
    };

    let entries = sorted_by_title(entries, target_window_title.as_deref());

    // Fast path (X11 only): exactly one entry matching the window title
    // → skip the picker and type immediately (KeePassXC does the same).
    if on_x11 {
        if let Some(name) = unique_match(&entries, target_window_title.as_deref())
        {
            eprintln!("[fill] auto-pick → '{}' (unique title match)", name);
            type_for_entry(&name, target_window_id.as_deref());
            return;
        }
    }

    eprintln!("[fill] opening picker");
    if let Some(name) =
        spawn_picker_pick(&entries, target_window_title.as_deref())
    {
        type_for_entry(&name, target_window_id.as_deref());
    }
}

enum Fetch {
    Entries(Vec<EntryRef>),
    Locked,
    Failed(String),
}

fn fetch_entries() -> Fetch {
    match rpc_authed("passwort-autotype", &Request::ListEntries) {
        Ok(Response::Entries { entries }) => Fetch::Entries(entries),
        Ok(Response::Error { code, message }) => {
            if code == "locked" {
                Fetch::Locked
            } else {
                Fetch::Failed(message)
            }
        }
        Ok(_) => Fetch::Failed("unexpected response".into()),
        Err(e) => Fetch::Failed(e.to_string()),
    }
}

/// Entries whose name appears in the active window title sort first;
/// the rest keep their original order. (Was inside the picker; moved
/// here now that autotype owns the fetch.)
fn sorted_by_title(mut entries: Vec<EntryRef>, title: Option<&str>) -> Vec<EntryRef> {
    if let Some(t) = title {
        let t_low = t.to_lowercase();
        entries.sort_by_key(|e| {
            let n = e.name.to_lowercase();
            !(t_low.contains(&n) || n.split('.').any(|p| t_low.contains(p)))
        });
    }
    entries
}

/// Spawn the picker in list mode, feed it the entries on stdin (on a
/// thread so a big vault can't deadlock the pipe), and return the
/// chosen entry name (None = cancelled).
fn spawn_picker_pick(
    entries: &[EntryRef],
    target_title: Option<&str>,
) -> Option<String> {
    let mut cmd = Command::new(picker_binary_path());
    cmd.arg("--picker");
    if let Some(t) = target_title {
        cmd.arg("--target-title").arg(t);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("passwort-autotype: failed to launch picker: {}", e);
            return None;
        }
    };
    if let Some(mut sin) = child.stdin.take() {
        let json = serde_json::to_string(entries).unwrap_or_else(|_| "[]".into());
        thread::spawn(move || {
            let _ = sin.write_all(json.as_bytes());
            // drop closes stdin → picker sees EOF
        });
    }
    let mut chosen = String::new();
    if let Some(out) = child.stdout.take() {
        let _ = BufReader::new(out).read_line(&mut chosen);
    }
    let ok = child.wait().map(|s| s.success()).unwrap_or(false);
    let chosen = chosen.trim().to_string();
    if ok && !chosen.is_empty() {
        Some(chosen)
    } else {
        None
    }
}

/// Spawn the picker in unlock mode; return the typed master password
/// (None = cancelled). `note` is shown above the prompt on a retry.
fn spawn_picker_unlock(
    target_title: Option<&str>,
    note: Option<&str>,
) -> Option<String> {
    let mut cmd = Command::new(picker_binary_path());
    cmd.arg("--picker").arg("--unlock");
    if let Some(t) = target_title {
        cmd.arg("--target-title").arg(t);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("passwort-autotype: failed to launch unlock prompt: {}", e);
            return None;
        }
    };
    if let Some(mut sin) = child.stdin.take() {
        let n = note.unwrap_or("").to_string();
        thread::spawn(move || {
            let _ = sin.write_all(n.as_bytes());
        });
    }
    let mut master = String::new();
    if let Some(out) = child.stdout.take() {
        let _ = BufReader::new(out).read_line(&mut master);
    }
    let ok = child.wait().map(|s| s.success()).unwrap_or(false);
    let master = master.trim_end_matches(['\n', '\r']).to_string();
    if ok && !master.is_empty() {
        Some(master)
    } else {
        None
    }
}

/// Standalone "save the credential for the active app" flow. Wayland
/// counterpart to `handle_save_hotkey`. Same as that function, except we
/// don't depend on having been triggered by a global hotkey — the user
/// invoked us directly via `passwortctl save`.
pub fn run_save_flow() {
    let on_x11 = crate::typing::detect() == crate::typing::Backend::Xdotool;
    let target_window_title = if on_x11 { active_window_title() } else { None };
    let bin = picker_binary_path();
    let mut cmd = Command::new(&bin);
    cmd.arg("--quick-save");
    if let Some(t) = &target_window_title {
        cmd.arg("--target-title").arg(t);
    }
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::inherit());
    if let Err(e) = cmd.spawn() {
        eprintln!("passwort-autotype: failed to launch quick-save dialog: {}", e);
    }
}

/// Case-insensitive substring match: an entry's name must appear in the
/// active window title (or vice-versa). Returns Some(name) only when
/// EXACTLY one entry matches — picker is shown otherwise so the user
/// disambiguates.
fn unique_match(entries: &[EntryRef], title: Option<&str>) -> Option<String> {
    let title = title?.to_lowercase();
    if title.trim().is_empty() {
        return None;
    }
    let matches: Vec<&EntryRef> = entries
        .iter()
        .filter(|e| {
            let n = e.name.to_lowercase();
            // Either name appears in the window title (e.g. "Steam" in
            // "Steam Sign In"), or, for short titles, the title appears
            // in the name (e.g. window "Discord" matches saved
            // "discord.com").
            (!n.is_empty() && title.contains(&n))
                || (title.len() >= 3 && n.contains(&title))
        })
        .collect();
    if matches.len() == 1 {
        Some(matches[0].name.clone())
    } else {
        None
    }
}

fn type_for_entry(name: &str, target_window_id: Option<&str>) {
    // X11-only: snap focus back to the original window before typing.
    // On Wayland the compositor restores focus when our picker window
    // closes, and we have no portable way to force-focus an arbitrary
    // window anyway.
    if let Some(id) = target_window_id {
        if crate::typing::detect() == crate::typing::Backend::Xdotool {
            let _ = Command::new("xdotool")
                .args(["windowactivate", "--sync", id])
                .status();
        }
    }
    thread::sleep(Duration::from_millis(KEYSTROKE_DELAY_MS));
    let resp = match rpc_authed("passwort-autotype", &Request::Get {
        name: name.to_string(),
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("passwort-autotype: rpc(get) failed: {}", e);
            return;
        }
    };
    if let Response::Credential {
        username, password, ..
    } = resp
    {
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
    // Backend (xdotool / ydotool) is auto-detected from XDG_SESSION_TYPE;
    // see crate::typing. Both backends stream via stdin so the credential
    // never appears on the command line.
    if !username.is_empty() {
        if let Err(e) = crate::typing::type_text(username) {
            eprintln!("passwort-autotype: type username failed: {}", e);
            return;
        }
        // Some apps (notably game launchers like Steam) need a real
        // moment after the username is typed before Tab actually moves
        // focus. With less than ~120 ms here we'd send the Tab and then
        // start typing the password before the field switch took
        // effect, dumping the password back into the username box.
        crate::typing::sleep_ms(120);
        if let Err(e) = crate::typing::press_key("Tab") {
            eprintln!("passwort-autotype: Tab keypress failed: {}", e);
            return;
        }
        crate::typing::sleep_ms(180);
    }
    if let Err(e) = crate::typing::type_text(password) {
        eprintln!("passwort-autotype: type password failed: {}", e);
    }
    // Don't auto-press Enter — risky if focus is wrong, and many apps
    // need an explicit user click anyway (CAPTCHAs, 2FA prompts).
}

