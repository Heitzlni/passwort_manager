//! Portable export/import format ("bundle").
//!
//! The bundle is a single JSON file with:
//!   * the encrypted vault (same `EncryptedVault` shape as `vault.json`)
//!   * an optional `config` (the user's hotkey + HIBP settings)
//!
//! This is what you copy to a USB stick or another machine. Import side
//! detects both this format and the legacy "just the raw vault.json" so
//! older backups still work.
//!
//! Note: the master password is NOT in the bundle. It can't be — it's
//! never stored. The encrypted vault is *what's encrypted with it*. To
//! decrypt on a new machine the user must type the master password they
//! used at the time of export.

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::storage::EncryptedVault;

pub const BUNDLE_FORMAT: &str = "passwort-bundle-v1";

#[derive(Serialize, Deserialize)]
pub struct Bundle {
    /// Magic string. Lets the importer distinguish bundles from raw
    /// `EncryptedVault` files.
    pub format: String,
    pub exported_at_unix: u64,
    pub vault: EncryptedVault,
    /// `None` = the user chose "accounts only" at export time. `Some(_)`
    /// = the importer can optionally apply these settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Config>,
}

/// What the importer found inside the file.
pub enum Parsed {
    Bundle(Bundle),
    /// Legacy / "raw" export — just the encrypted vault, no config.
    RawVault(EncryptedVault),
}

pub fn parse(text: &str) -> Option<Parsed> {
    // Try bundle first (it has the more specific schema).
    if let Ok(b) = serde_json::from_str::<Bundle>(text) {
        if b.format == BUNDLE_FORMAT {
            return Some(Parsed::Bundle(b));
        }
    }
    if let Ok(v) = serde_json::from_str::<EncryptedVault>(text) {
        return Some(Parsed::RawVault(v));
    }
    None
}

pub fn serialize_bundle(
    vault: &EncryptedVault,
    config: Option<&Config>,
) -> Result<String, serde_json::Error> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bundle = Bundle {
        format: BUNDLE_FORMAT.to_string(),
        exported_at_unix: now,
        vault: clone_vault(vault),
        config: config.cloned(),
    };
    serde_json::to_string_pretty(&bundle)
}

// EncryptedVault doesn't derive Clone (and shouldn't add it just for this);
// build a fresh one by re-serializing through serde.
fn clone_vault(v: &EncryptedVault) -> EncryptedVault {
    let s = serde_json::to_string(v).expect("serialize EncryptedVault");
    serde_json::from_str(&s).expect("re-parse EncryptedVault")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vault() -> EncryptedVault {
        EncryptedVault {
            version: 1,
            kdf_algo: "argon2id".into(),
            kdf_m_cost: 65536,
            kdf_t_cost: 3,
            kdf_p_cost: 4,
            salt: "AAAA".into(),
            nonce: "AAAA".into(),
            ciphertext: "AAAA".into(),
        }
    }

    #[test]
    fn roundtrip_bundle_with_config() {
        let cfg = Config::default();
        let json = serialize_bundle(&sample_vault(), Some(&cfg)).unwrap();
        match parse(&json).unwrap() {
            Parsed::Bundle(b) => {
                assert_eq!(b.format, BUNDLE_FORMAT);
                assert!(b.config.is_some());
            }
            _ => panic!("expected Bundle"),
        }
    }

    #[test]
    fn roundtrip_bundle_without_config() {
        let json = serialize_bundle(&sample_vault(), None).unwrap();
        match parse(&json).unwrap() {
            Parsed::Bundle(b) => {
                assert!(b.config.is_none());
            }
            _ => panic!("expected Bundle"),
        }
    }

    #[test]
    fn raw_vault_recognized_as_legacy() {
        let json = serde_json::to_string(&sample_vault()).unwrap();
        match parse(&json).unwrap() {
            Parsed::RawVault(_) => {}
            _ => panic!("expected RawVault"),
        }
    }

    #[test]
    fn garbage_returns_none() {
        assert!(parse("not json").is_none());
        assert!(parse("{}").is_none());
        assert!(parse(r#"{"format":"wrong-magic"}"#).is_none());
    }
}
