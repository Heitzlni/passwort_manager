//! "Save while locked" sealed inbox.
//!
//! The browser extension can capture a new credential even when the
//! vault is locked. Plaintext must never touch disk, and a locked
//! daemon (no master key in memory) must still be able to *write* a
//! capture that only the master-password holder can later read. That's
//! an asymmetric drop-box:
//!
//!   * One X25519 keypair. The PUBLIC key lives unencrypted on disk
//!     (`inbox.pub`) so a locked daemon can seal to it. The SECRET key
//!     lives encrypted under the vault master key (`inbox.key.enc`), so
//!     only an unlocked session can open captures.
//!   * Each capture is sealed with an ephemeral-static X25519 exchange,
//!     a SHA-256 KDF and AES-256-GCM (reusing `crypto`), then appended
//!     as one base64 line to `inbox.jsonl`.
//!   * On unlock the GUI decrypts the inbox, shows the captures for
//!     review, and only on the user's OK merges them and clears it.
//!
//! Inbox writes are UNAUTHENTICATED (any local process that already
//! passes the daemon's client allowlist can drop an entry). That is why
//! review-on-unlock is mandatory and the inbox is hard-capped on both
//! count and bytes so it can't be used to exhaust disk.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use base64::{engine::general_purpose, Engine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::auth::data_dir;
use crate::crypto;

/// Most pending captures kept before new ones are refused.
pub const MAX_PENDING: usize = 50;
/// Hard byte cap on the inbox file.
pub const MAX_INBOX_BYTES: u64 = 256 * 1024;

/// A captured credential, before review/merge. Same shape as an
/// `Account` plus when it was captured.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capture {
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub captured_at: String,
}

impl From<Capture> for crate::storage::Account {
    fn from(c: Capture) -> Self {
        crate::storage::Account {
            name: c.name,
            url: c.url,
            username: c.username,
            password: c.password,
            totp_secret: c.totp_secret,
            notes: c.notes,
            history: Vec::new(),
            // Materialised from a sealed capture at unlock time —
            // stamp current time so sync treats it as fresh.
            updated_at: crate::storage::now_secs(),
        }
    }
}

fn pub_path() -> PathBuf {
    data_dir().join("inbox.pub")
}
fn key_path() -> PathBuf {
    data_dir().join("inbox.key.enc")
}
fn inbox_path() -> PathBuf {
    data_dir().join("inbox.jsonl")
}

fn io_err(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, m)
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Ensure a keypair exists. (Re)generates it when missing, or when the
/// stored secret can't be decrypted with `master_key` (e.g. the master
/// password was changed since) — in that case any now-unreadable
/// pending captures are dropped, which is the safe degradation for the
/// rare change-while-pending edge. Call on every unlock.
pub fn ensure_keypair(master_key: &[u8]) -> std::io::Result<()> {
    fs::create_dir_all(data_dir())?;
    if pub_path().exists() && key_path().exists() && load_secret(master_key).is_ok() {
        return Ok(());
    }
    // Stale or missing → reset cleanly.
    let _ = fs::remove_file(inbox_path());
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let (nonce, ct) = crypto::encrypt(secret.as_bytes(), master_key);
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    write_private(
        &pub_path(),
        general_purpose::STANDARD
            .encode(public.as_bytes())
            .as_bytes(),
    )?;
    write_private(
        &key_path(),
        general_purpose::STANDARD.encode(&blob).as_bytes(),
    )?;
    Ok(())
}

fn load_public() -> std::io::Result<PublicKey> {
    let s = fs::read_to_string(pub_path())?;
    let bytes = general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| io_err("bad inbox.pub"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| io_err("bad inbox.pub length"))?;
    Ok(PublicKey::from(arr))
}

fn load_secret(master_key: &[u8]) -> std::io::Result<StaticSecret> {
    let s = fs::read_to_string(key_path())?;
    let blob = general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| io_err("bad inbox.key"))?;
    if blob.len() < 12 {
        return Err(io_err("short inbox.key"));
    }
    let (nonce, ct) = blob.split_at(12);
    let pt = crypto::decrypt(ct, nonce, master_key)
        .map_err(|_| io_err("inbox key decrypt failed"))?;
    let arr: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| io_err("bad secret length"))?;
    Ok(StaticSecret::from(arr))
}

/// Single-use KDF: domain tag + ECDH secret + both public keys → the
/// AES-256 key. Binding both public keys prevents key/identity reuse
/// surprises; the ephemeral key makes every sealing unique.
fn kdf(shared: &[u8], epk: &[u8], rpk: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"passwort-inbox-v1");
    h.update(shared);
    h.update(epk);
    h.update(rpk);
    h.finalize().into()
}

pub fn count() -> usize {
    match fs::read_to_string(inbox_path()) {
        Ok(s) => s.lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
}

pub fn has_pending() -> bool {
    count() > 0
}

/// Seal one capture to the inbox public key and append it. Works
/// without the master key (the locked-daemon write path). Enforces the
/// count + byte caps.
pub fn append_sealed(cap: &Capture) -> std::io::Result<()> {
    let recipient = load_public()?;
    if let Ok(meta) = fs::metadata(inbox_path()) {
        if meta.len() >= MAX_INBOX_BYTES {
            return Err(io_err("inbox full (size cap)"));
        }
    }
    if count() >= MAX_PENDING {
        return Err(io_err("inbox full (count cap)"));
    }

    let eph = StaticSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    let sym = kdf(shared.as_bytes(), epk.as_bytes(), recipient.as_bytes());
    let plaintext = serde_json::to_vec(cap).map_err(|_| io_err("serialize capture"))?;
    let (nonce, ct) = crypto::encrypt(&plaintext, &sym);

    let mut blob = Vec::with_capacity(32 + 12 + ct.len());
    blob.extend_from_slice(epk.as_bytes());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    let line = general_purpose::STANDARD.encode(&blob);

    fs::create_dir_all(data_dir())?;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(inbox_path())?;
    writeln!(f, "{}", line)?;
    f.sync_all()
}

/// Decrypt every pending capture with the master key. Corrupt or
/// undecryptable lines are skipped rather than failing the whole batch.
pub fn open_all(master_key: &[u8]) -> std::io::Result<Vec<Capture>> {
    let secret = load_secret(master_key)?;
    let our_pub = PublicKey::from(&secret);
    let data = match fs::read_to_string(inbox_path()) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let blob = match general_purpose::STANDARD.decode(line) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if blob.len() < 32 + 12 {
            continue;
        }
        let epk_arr: [u8; 32] = blob[..32].try_into().unwrap();
        let nonce = &blob[32..44];
        let ct = &blob[44..];
        let epk = PublicKey::from(epk_arr);
        let shared = secret.diffie_hellman(&epk);
        let sym = kdf(shared.as_bytes(), epk.as_bytes(), our_pub.as_bytes());
        let pt = match crypto::decrypt(ct, nonce, &sym) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(cap) = serde_json::from_slice::<Capture>(&pt) {
            out.push(cap);
        }
    }
    Ok(out)
}

pub fn clear() -> std::io::Result<()> {
    match fs::remove_file(inbox_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test runs in its own data dir so they don't collide.
    fn isolate(tag: &str) -> tempdirs::Guard {
        tempdirs::Guard::new(tag)
    }

    mod tempdirs {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        pub struct Guard {
            _g: std::sync::MutexGuard<'static, ()>,
            prev: Option<std::ffi::OsString>,
            dir: std::path::PathBuf,
        }
        impl Guard {
            pub fn new(tag: &str) -> Self {
                let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
                let dir = std::env::temp_dir().join(format!(
                    "pwm-inbox-test-{}-{}",
                    tag,
                    std::process::id()
                ));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let prev = std::env::var_os("XDG_DATA_HOME");
                unsafe { std::env::set_var("XDG_DATA_HOME", &dir) };
                Guard { _g: g, prev, dir }
            }
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    match &self.prev {
                        Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                        None => std::env::remove_var("XDG_DATA_HOME"),
                    }
                }
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }
    }

    fn cap(name: &str, pw: &str) -> Capture {
        Capture {
            name: name.into(),
            url: "https://x.test".into(),
            username: "u".into(),
            password: pw.into(),
            totp_secret: String::new(),
            notes: String::new(),
            captured_at: "2026-05-16".into(),
        }
    }

    #[test]
    fn seal_then_open_roundtrips_without_master_at_write_time() {
        let _g = isolate("roundtrip");
        let master = [7u8; 32];
        ensure_keypair(&master).unwrap();
        // append_sealed needs only the public key — no master.
        append_sealed(&cap("Site A", "pw-A-strong")).unwrap();
        append_sealed(&cap("Site B", "pw-B-strong")).unwrap();
        assert_eq!(count(), 2);
        let mut got = open_all(&master).unwrap();
        got.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "Site A");
        assert_eq!(got[0].password, "pw-A-strong");
        assert_eq!(got[1].password, "pw-B-strong");
        clear().unwrap();
        assert_eq!(count(), 0);
    }

    #[test]
    fn wrong_master_cannot_open() {
        let _g = isolate("wrongkey");
        ensure_keypair(&[1u8; 32]).unwrap();
        append_sealed(&cap("S", "secret")).unwrap();
        // A different master key can't load the secret key at all.
        assert!(open_all(&[2u8; 32]).is_err());
    }

    #[test]
    fn count_cap_is_enforced() {
        let _g = isolate("cap");
        ensure_keypair(&[9u8; 32]).unwrap();
        for i in 0..MAX_PENDING {
            append_sealed(&cap(&format!("s{i}"), "pw")).unwrap();
        }
        assert_eq!(count(), MAX_PENDING);
        assert!(append_sealed(&cap("overflow", "pw")).is_err());
    }

    #[test]
    fn master_change_resets_and_drops_stale_pending() {
        let _g = isolate("rotate");
        ensure_keypair(&[3u8; 32]).unwrap();
        append_sealed(&cap("old", "pw")).unwrap();
        assert_eq!(count(), 1);
        // New master: ensure_keypair must regenerate and clear inbox.
        ensure_keypair(&[4u8; 32]).unwrap();
        assert_eq!(count(), 0);
        // And the new keypair works.
        append_sealed(&cap("new", "pw2")).unwrap();
        let got = open_all(&[4u8; 32]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "new");
    }
}
