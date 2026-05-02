use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const VAULT_FILENAME: &str = "vault.json";
const APP_DIR_NAME: &str = "passwort-manager";
const ENV_VAULT_OVERRIDE: &str = "PASSWORT_VAULT_PATH";
pub const CURRENT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Account {
    pub name: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    pub version: u32,
    pub kdf_algo: String,
    pub kdf_m_cost: u32,
    pub kdf_t_cost: u32,
    pub kdf_p_cost: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Deserialize)]
pub struct LegacyVerifierVault {
    pub salt: String,
    pub verifier: String,
    pub accounts: Vec<Account>,
}

fn xdg_data_home() -> PathBuf {
    if let Some(p) = std::env::var_os("XDG_DATA_HOME") {
        let p = PathBuf::from(p);
        // Snap-confined apps (e.g. VS Code installed via snap) re-set
        // XDG_DATA_HOME to their own per-snap data dir. Honoring it would
        // give the daemon/CLI/GUI different vault paths depending on which
        // terminal launched them. Ignore snap-redirected paths so we
        // always converge on $HOME/.local/share.
        let is_snap_redirect = p.to_string_lossy().contains("/snap/");
        if p.is_absolute() && !is_snap_redirect {
            return p;
        }
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local").join("share")
}

pub fn vault_path() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        if let Some(custom) = std::env::var_os(ENV_VAULT_OVERRIDE) {
            let p = PathBuf::from(custom);
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            return p;
        }
        let dir = xdg_data_home().join(APP_DIR_NAME);
        let _ = fs::create_dir_all(&dir);
        dir.join(VAULT_FILENAME)
    })
    .as_path()
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from(VAULT_FILENAME));
    name.push(".tmp");
    path.with_file_name(name)
}

/// Move a stale local-directory vault (`./accounts.json` from older versions)
/// into the standard XDG location, but only if no vault exists there yet.
pub fn migrate_local_vault_if_needed() {
    if std::env::var_os(ENV_VAULT_OVERRIDE).is_some() {
        return;
    }
    let target = vault_path();
    if target.exists() {
        return;
    }
    let local = Path::new("accounts.json");
    if !local.exists() {
        return;
    }
    if let Some(parent) = target.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::rename(local, target).is_err() {
        // Cross-filesystem rename can fail; fall back to copy + remove.
        if fs::copy(local, target).is_ok() {
            let _ = fs::remove_file(local);
        }
    }
}

pub fn vault_file_exists() -> bool {
    vault_path().exists()
}

pub fn read_vault_file() -> std::io::Result<String> {
    fs::read_to_string(vault_path())
}

pub fn parse_encrypted(data: &str) -> Option<EncryptedVault> {
    serde_json::from_str(data).ok()
}

pub fn parse_legacy_verifier(data: &str) -> Option<LegacyVerifierVault> {
    serde_json::from_str(data).ok()
}

pub fn parse_legacy_plaintext(data: &str) -> Option<Vec<Account>> {
    serde_json::from_str(data).ok()
}

pub fn save_encrypted_vault(vault: &EncryptedVault) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(vault)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let path = vault_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = tmp_path_for(path);
    let _ = fs::remove_file(&tmp_path);

    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = opts.open(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

pub fn cleanup_stale_tmp() {
    let tmp_path = tmp_path_for(vault_path());
    let _ = fs::remove_file(&tmp_path);
}
