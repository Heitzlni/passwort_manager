//! Synthetic-input backends. Picks `xdotool` on X11 and `ydotool` on
//! Wayland based on `XDG_SESSION_TYPE`. Both shell out — keeps the
//! dependency surface zero (no input-method libraries linked in) and lets
//! the user audit what's typed by running the same commands by hand.
//!
//! Wayland note: `ydotool` requires the `ydotoold` system service to be
//! running and the user to have access to `/dev/uinput` (typically by
//! being in the `input` group). See SETUP.md.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Which backend to use. Detected from XDG_SESSION_TYPE; "wayland" maps to
/// Ydotool, anything else (including missing) defaults to Xdotool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Xdotool,
    Ydotool,
}

pub fn detect() -> Backend {
    match std::env::var("XDG_SESSION_TYPE").as_deref() {
        Ok("wayland") => Backend::Ydotool,
        _ => Backend::Xdotool,
    }
}

/// Type a literal string into the focused window. Streams the text via
/// stdin so it doesn't appear on the spawned process's argv (which is
/// world-readable through /proc/<pid>/cmdline).
pub fn type_text(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Ok(());
    }
    match detect() {
        Backend::Xdotool => xdotool_type(text),
        Backend::Ydotool => ydotool_type(text),
    }
}

/// Press a single named key (e.g. "Tab", "Return"). Names follow the
/// xdotool convention; the Wayland backend translates the common ones.
pub fn press_key(key: &str) -> Result<(), String> {
    match detect() {
        Backend::Xdotool => {
            let status = Command::new("xdotool")
                .args(["key", "--clearmodifiers", "--delay", "30", key])
                .status()
                .map_err(|e| format!("spawn xdotool: {}", e))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("xdotool key {} exited with {}", key, status))
            }
        }
        Backend::Ydotool => {
            // ydotool's `key` takes Linux input-event-codes pairs like
            // "15:1 15:0" (Tab down, Tab up). Translate the common names
            // we actually use; everything else falls back to literal text.
            let code = match key {
                "Tab" => 15,
                "Return" | "Enter" => 28,
                "Escape" => 1,
                "BackSpace" => 14,
                _ => return Err(format!("ydotool: unknown key '{}'", key)),
            };
            let status = Command::new("ydotool")
                .args(["key", &format!("{}:1", code), &format!("{}:0", code)])
                .status()
                .map_err(|e| format!("spawn ydotool: {}", e))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("ydotool key {} exited with {}", key, status))
            }
        }
    }
}

/// Sleep helper; centralizes the timing constants so the autotype flow
/// reads cleanly.
pub fn sleep_ms(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

fn xdotool_type(text: &str) -> Result<(), String> {
    let mut child = Command::new("xdotool")
        .args(["type", "--delay", "12", "--clearmodifiers", "--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "xdotool not installed (sudo apt install xdotool)".to_string()
            } else {
                format!("spawn xdotool: {}", e)
            }
        })?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| format!("write to xdotool: {}", e))?;
    }
    let status = child.wait().map_err(|e| format!("wait xdotool: {}", e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("xdotool exited with {}", status))
    }
}

fn ydotool_type(text: &str) -> Result<(), String> {
    // `ydotool type --file -` reads from stdin so the credential never
    // hits argv. `--key-delay` is in milliseconds (12 matches xdotool's
    // pacing — fast enough to feel instant, slow enough that target apps
    // don't drop characters).
    let mut child = Command::new("ydotool")
        .args(["type", "--key-delay", "12", "--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "ydotool not installed (sudo apt install ydotool, then enable ydotoold service — see SETUP.md)".to_string()
            } else {
                format!("spawn ydotool: {}", e)
            }
        })?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| format!("write to ydotool: {}", e))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait ydotool: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Common failure: "couldn't connect to socket" → ydotoold not running.
        if stderr.contains("connect") || stderr.contains("socket") {
            Err(format!(
                "ydotool: couldn't reach ydotoold daemon. Is it running? (systemctl --user status ydotool, or see SETUP.md)"
            ))
        } else {
            Err(format!("ydotool exited with {}: {}", out.status, stderr.trim()))
        }
    }
}
