//! Per-client API-token authentication for the daemon.
//!
//! Threat model: even though the socket is 0600 + SO_PEERCRED-checked
//! to the user's UID, anything *running as the user* (rogue browser
//! extension, malware-installed binary, weird shell command in a script)
//! can talk to it. Token auth raises the bar so a brand-new client must
//! be explicitly approved by the user before it can read or write the
//! vault.
//!
//! Token = 32 random bytes, base64-encoded in the JSON. Daemon stores
//! the SHA-256 of the token (so a leaked allowlist file doesn't grant
//! access on its own) along with a human-readable label.
//!
//! Files:
//!   * approved at  $XDG_DATA_HOME/passwort-manager/approved-clients.json
//!   * pending  at  $XDG_DATA_HOME/passwort-manager/pending-clients.json
//!
//! The pending file is created when an unknown token tries to register;
//! the user reviews via `passwortctl approvals` and grants via
//! `passwortctl approve <id>`.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const APPROVED_FILE: &str = "approved-clients.json";
const PENDING_FILE: &str = "pending-clients.json";
const APP_DIR: &str = "passwort-manager";

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Allowlist {
    /// Map<short_id, ApprovedClient>. short_id is the first 12 hex chars
    /// of the token hash — enough to uniquely identify and remember.
    #[serde(default)]
    pub approved: HashMap<String, ApprovedClient>,
    /// Map<short_id, PendingClient>. Lives until the user approves or
    /// denies via `passwortctl`.
    #[serde(default)]
    pub pending: HashMap<String, PendingClient>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApprovedClient {
    pub label: String,
    /// Hex-encoded SHA-256 of the token bytes. Compared constant-time at
    /// auth time.
    pub token_sha256_hex: String,
    pub approved_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PendingClient {
    pub label: String,
    pub token_sha256_hex: String,
    pub requested_at: String,
}

fn xdg_data_home() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if let Some(p) = std::env::var_os("XDG_DATA_HOME") {
        let pp = PathBuf::from(p);
        let is_snap = home
            .as_ref()
            .map(|h| pp.starts_with(h.join("snap")))
            .unwrap_or(false);
        if pp.is_absolute() && !is_snap {
            return pp;
        }
    }
    home.unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("share")
}

pub fn data_dir() -> PathBuf {
    xdg_data_home().join(APP_DIR)
}

fn approved_path() -> PathBuf {
    data_dir().join(APPROVED_FILE)
}

fn pending_path() -> PathBuf {
    data_dir().join(PENDING_FILE)
}

pub fn load() -> Allowlist {
    let approved: HashMap<String, ApprovedClient> = fs::read_to_string(approved_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let pending: HashMap<String, PendingClient> = fs::read_to_string(pending_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Allowlist { approved, pending }
}

pub fn save(list: &Allowlist) -> std::io::Result<()> {
    fs::create_dir_all(data_dir())?;
    fs::write(
        approved_path(),
        serde_json::to_string_pretty(&list.approved)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
    )?;
    fs::write(
        pending_path(),
        serde_json::to_string_pretty(&list.pending)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
    )?;
    Ok(())
}

pub fn token_hash_hex(token_b64: &str) -> Option<String> {
    let bytes = general_purpose::STANDARD.decode(token_b64).ok()?;
    let h = Sha256::digest(&bytes);
    Some(hex_encode(&h))
}

/// First 12 chars of the hex hash — short enough to type, long enough to
/// be unambiguous across the few clients a single user has.
pub fn short_id(token_hash_hex: &str) -> String {
    token_hash_hex.chars().take(12).collect()
}

pub fn is_approved(list: &Allowlist, token_b64: &str) -> bool {
    let h = match token_hash_hex(token_b64) {
        Some(h) => h,
        None => return false,
    };
    let id = short_id(&h);
    if let Some(c) = list.approved.get(&id) {
        // Constant-time-ish comparison
        return ct_eq_str(&c.token_sha256_hex, &h);
    }
    false
}

/// Add a token to the pending list (or noop if already approved/pending).
/// Returns the short_id so the daemon can tell the client what to ask
/// the user to approve.
pub fn record_pending(list: &mut Allowlist, token_b64: &str, label: &str) -> Option<String> {
    let h = token_hash_hex(token_b64)?;
    let id = short_id(&h);
    if list.approved.contains_key(&id) || list.pending.contains_key(&id) {
        return Some(id);
    }
    list.pending.insert(
        id.clone(),
        PendingClient {
            label: label.to_string(),
            token_sha256_hex: h,
            requested_at: now_iso(),
        },
    );
    Some(id)
}

pub fn approve(list: &mut Allowlist, short_id: &str) -> bool {
    if let Some(p) = list.pending.remove(short_id) {
        list.approved.insert(
            short_id.to_string(),
            ApprovedClient {
                label: p.label,
                token_sha256_hex: p.token_sha256_hex,
                approved_at: now_iso(),
            },
        );
        true
    } else {
        false
    }
}

pub fn revoke(list: &mut Allowlist, short_id: &str) -> bool {
    list.approved.remove(short_id).is_some() || list.pending.remove(short_id).is_some()
}

pub fn random_token_b64() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    general_purpose::STANDARD.encode(buf)
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Cheap ISO-ish stamp without a date crate.
    format!("@{}", s)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_token() -> String { random_token_b64() }

    #[test]
    fn token_is_32_bytes_b64() {
        let t = random_token_b64();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&t)
            .unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn unknown_token_is_not_approved() {
        let list = Allowlist::default();
        assert!(!is_approved(&list, &fresh_token()));
    }

    #[test]
    fn record_pending_then_approve_then_is_approved() {
        let mut list = Allowlist::default();
        let token = fresh_token();
        let id = record_pending(&mut list, &token, "test client").unwrap();
        assert!(list.pending.contains_key(&id));
        assert!(!is_approved(&list, &token));
        assert!(approve(&mut list, &id));
        assert!(!list.pending.contains_key(&id));
        assert!(is_approved(&list, &token));
    }

    #[test]
    fn record_pending_twice_returns_same_id() {
        let mut list = Allowlist::default();
        let token = fresh_token();
        let id1 = record_pending(&mut list, &token, "a").unwrap();
        let id2 = record_pending(&mut list, &token, "b").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn revoke_removes_approved_or_pending() {
        let mut list = Allowlist::default();
        let token = fresh_token();
        let id = record_pending(&mut list, &token, "x").unwrap();
        approve(&mut list, &id);
        assert!(is_approved(&list, &token));
        assert!(revoke(&mut list, &id));
        assert!(!is_approved(&list, &token));
    }

    #[test]
    fn malformed_token_rejected() {
        let mut list = Allowlist::default();
        // Not valid base64
        assert!(record_pending(&mut list, "this is not base64!", "x").is_none());
        assert!(!is_approved(&list, "this is not base64!"));
    }

    #[test]
    fn ct_eq_str_works() {
        assert!(ct_eq_str("abc", "abc"));
        assert!(!ct_eq_str("abc", "abd"));
        assert!(!ct_eq_str("abc", "abcd"));
    }
}
