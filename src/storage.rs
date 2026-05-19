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
    /// Site/app URL, e.g. `https://mail.google.com`. Used by the browser
    /// extension to match the right credential to the active tab's host
    /// (far more reliable than guessing from the entry name). May be
    /// empty. `#[serde(default)]` keeps pre-url vault files readable.
    #[serde(default)]
    pub url: String,
    /// Username for the site. May be empty (older entries didn't have one).
    /// `#[serde(default)]` keeps existing vault files readable.
    #[serde(default)]
    pub username: String,
    pub password: String,
    /// Optional Base32-encoded TOTP secret (RFC 6238). Empty = no 2FA.
    /// Codes are derived on the fly via `crypto::totp_code`.
    #[serde(default)]
    pub totp_secret: String,
    /// Free-text notes — recovery/backup codes, PINs, security-question
    /// answers. Encrypted with everything else. `#[serde(default)]` keeps
    /// pre-notes vault files readable.
    #[serde(default)]
    pub notes: String,
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

    // Best-effort rotating backup of the just-written (already
    // encrypted) blob. A failure here must never fail the primary save
    // — the vault is already safely on disk at this point.
    let _ = rotate_backup(&json);

    Ok(())
}

/// How many timestamped vault backups to keep.
const BACKUP_KEEP: usize = 15;

fn backups_dir() -> PathBuf {
    let parent = vault_path()
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    parent.join("backups")
}

/// Given backup filenames sorted ascending (oldest first), return the
/// ones to delete so only the newest `keep` remain. Pure for testing.
fn backups_to_prune(sorted: &[String], keep: usize) -> &[String] {
    if sorted.len() > keep {
        &sorted[..sorted.len() - keep]
    } else {
        &[]
    }
}

/// Write a timestamped copy of the encrypted vault into `backups/` and
/// prune to the newest `BACKUP_KEEP`. The backup is the exact same
/// ciphertext as the live vault (no plaintext, same crypto), so it can
/// be restored later via the normal Import flow. Best-effort.
fn rotate_backup(encrypted_json: &str) -> std::io::Result<()> {
    let dir = backups_dir();
    fs::create_dir_all(&dir)?;

    // Seconds since epoch, fixed 10+ digits → lexicographic sort == time
    // order. Same-second collisions just skip (one backup/sec is plenty).
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let file_path = dir.join(format!("vault-{:010}.json", ts));

    if !file_path.exists() {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = opts.open(&file_path)?;
        f.write_all(encrypted_json.as_bytes())?;
        f.sync_all()?;
    }

    // Prune oldest beyond BACKUP_KEEP.
    let mut names: Vec<String> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("vault-") && n.ends_with(".json"))
        .collect();
    names.sort();
    for old in backups_to_prune(&names, BACKUP_KEEP) {
        let _ = fs::remove_file(dir.join(old));
    }
    Ok(())
}

pub fn cleanup_stale_tmp() {
    let tmp_path = tmp_path_for(vault_path());
    let _ = fs::remove_file(&tmp_path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn keeps_newest_n_prunes_the_rest() {
        let names = v(&[
            "vault-0000000001.json",
            "vault-0000000002.json",
            "vault-0000000003.json",
            "vault-0000000004.json",
            "vault-0000000005.json",
        ]);
        // keep 2 → prune the 3 oldest (sorted ascending = oldest first)
        let pruned = backups_to_prune(&names, 2);
        assert_eq!(
            pruned,
            &[
                "vault-0000000001.json".to_string(),
                "vault-0000000002.json".to_string(),
                "vault-0000000003.json".to_string(),
            ]
        );
    }

    #[test]
    fn nothing_pruned_when_at_or_under_limit() {
        let names = v(&["vault-1.json", "vault-2.json"]);
        assert!(backups_to_prune(&names, 2).is_empty());
        assert!(backups_to_prune(&names, 5).is_empty());
        assert!(backups_to_prune(&[], 15).is_empty());
    }
}
