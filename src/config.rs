//! Plain-JSON config at $XDG_CONFIG_HOME/passwort-manager/config.json
//! (default: ~/.config/passwort-manager/config.json). Holds the auto-type
//! hotkey. Not encrypted — the hotkey isn't a secret.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const CONFIG_FILENAME: &str = "config.json";
const APP_DIR_NAME: &str = "passwort-manager";

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Config {
    pub hotkey: HotkeyConfig,
    /// Hotkey for "save credential for the active native app". Optional —
    /// older configs without this field default to Ctrl+Alt+S.
    #[serde(default = "default_save_hotkey")]
    pub save_hotkey: HotkeyConfig,
    /// Allow the daemon to query haveibeenpwned.com for breach checks.
    /// Default: enabled. Set to false in config.json to disable the
    /// outbound HTTPS calls entirely (no audit, no per-entry pwned check).
    /// Even when enabled, only a 5-char SHA-1 prefix is sent — never the
    /// password or its full hash. See src/hibp.rs.
    #[serde(default = "default_hibp_enabled")]
    pub hibp_enabled: bool,
    /// Which optional top-bar buttons the GUI shows. Lets a user who
    /// doesn't use, say, HIBP or 2FA hide those buttons for a cleaner
    /// window. Missing in old config files → all on (see Default).
    #[serde(default)]
    pub toolbar: ToolbarConfig,
    /// Lock the GUI window back to the password prompt after this many
    /// minutes with no keyboard/mouse activity. Independent of the
    /// daemon's own idle lock (PASSWORT_IDLE_TIMEOUT_SECS) — this one
    /// guards the always-open window. Missing in old configs → disabled.
    #[serde(default)]
    pub gui_autolock_enabled: bool,
    #[serde(default = "default_gui_autolock_minutes")]
    pub gui_autolock_minutes: u32,
}

fn default_hibp_enabled() -> bool { true }
fn default_true() -> bool { true }
fn default_gui_autolock_minutes() -> u32 { 5 }

/// Visibility flags for the optional top-bar buttons. `Settings` and
/// `Lock` are deliberately NOT here — they're always shown (hiding
/// Settings would make the toggles unreachable; Lock is security-core).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ToolbarConfig {
    #[serde(default = "default_true")]
    pub change_master: bool,
    #[serde(default = "default_true")]
    pub tokens: bool,
    #[serde(default = "default_true")]
    pub audit: bool,
    #[serde(default = "default_true")]
    pub health: bool,
    #[serde(default = "default_true")]
    pub export: bool,
    #[serde(default = "default_true")]
    pub import: bool,
}

impl Default for ToolbarConfig {
    fn default() -> Self {
        Self {
            change_master: true,
            tokens: true,
            audit: true,
            health: true,
            export: true,
            import: true,
        }
    }
}

fn default_save_hotkey() -> HotkeyConfig {
    HotkeyConfig {
        modifiers: vec!["ctrl".into(), "alt".into()],
        key: "s".into(),
    }
}

/// e.g. modifiers=["ctrl","alt"], key="p" → Ctrl+Alt+P
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct HotkeyConfig {
    pub modifiers: Vec<String>,
    pub key: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hotkey: HotkeyConfig {
                modifiers: vec!["ctrl".into(), "alt".into()],
                key: "p".into(),
            },
            save_hotkey: default_save_hotkey(),
            hibp_enabled: default_hibp_enabled(),
            toolbar: ToolbarConfig::default(),
            gui_autolock_enabled: false,
            gui_autolock_minutes: default_gui_autolock_minutes(),
        }
    }
}

impl HotkeyConfig {
    pub fn human(&self) -> String {
        let mut parts: Vec<String> = self
            .modifiers
            .iter()
            .map(|m| {
                let s = m.to_lowercase();
                match s.as_str() {
                    "ctrl" | "control" => "Ctrl".into(),
                    "alt" | "option" => "Alt".into(),
                    "shift" => "Shift".into(),
                    "super" | "meta" | "win" => "Super".into(),
                    other => {
                        let mut c = other.chars();
                        match c.next() {
                            Some(f) => f.to_uppercase().chain(c).collect(),
                            None => String::new(),
                        }
                    }
                }
            })
            .collect();
        parts.push(self.key.to_uppercase());
        parts.join("+")
    }
}

fn xdg_config_home() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if let Some(p) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(p);
        let is_snap_redirect = home
            .as_ref()
            .map(|h| p.starts_with(h.join("snap")))
            .unwrap_or(false);
        if p.is_absolute() && !is_snap_redirect {
            return p;
        }
    }
    home.unwrap_or_else(|| PathBuf::from(".")).join(".config")
}

pub fn config_dir() -> PathBuf {
    xdg_config_home().join(APP_DIR_NAME)
}

pub fn config_path() -> PathBuf {
    config_dir().join(CONFIG_FILENAME)
}

pub fn load() -> Config {
    let path = config_path();
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(cfg: &Config) -> std::io::Result<()> {
    let dir = config_dir();
    fs::create_dir_all(&dir)?;
    let path = config_path();
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(path, json)
}

pub fn mtime() -> Option<std::time::SystemTime> {
    fs::metadata(config_path()).ok().and_then(|m| m.modified().ok())
}
