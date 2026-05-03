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
    if let Some(p) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(p);
        let is_snap_redirect = p.to_string_lossy().contains("/snap/");
        if p.is_absolute() && !is_snap_redirect {
            return p;
        }
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config")
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
