//! JNI bridge for the Android client. Reuses the same Argon2id +
//! AES-256-GCM scheme as the desktop crate so a `vault.json` written
//! on Linux opens here byte-for-byte. Phase 1 only exposes
//! `unlockVault` (read path) — encrypt / save lives on desktop.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine};
use jni::objects::{JByteArray, JClass};
use jni::sys::jstring;
use jni::JNIEnv;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// Minimum on-disk schema we need to read. Encryption-side fields
// (kdf_algo, version) we tolerate but ignore; the algorithm is
// implied by aes-gcm + argon2id.
#[derive(Deserialize)]
struct EncryptedVault {
    kdf_m_cost: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

// Same shape as the desktop `Account`. Kept here for self-contained
// (de)serialization; once we add a write path we'll share with the
// desktop crate via a workspace.
#[derive(Serialize, Deserialize)]
struct Account {
    name: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    username: String,
    password: String,
    #[serde(default)]
    totp_secret: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    history: Vec<PasswordHistoryEntry>,
    /// Vault format v2 — Unix epoch seconds at last create/edit.
    /// Defaults to 0 for entries written by a v1 desktop.
    #[serde(default)]
    updated_at: u64,
}

#[derive(Serialize, Deserialize)]
struct PasswordHistoryEntry {
    password: String,
    #[serde(default)]
    changed_at: String,
}

/// Vault format v2 inner shape — accounts plus deletion tombstones.
/// Read-side only on Android (phase 1 stays read-only).
#[derive(Deserialize)]
struct VaultPayload {
    #[serde(default)]
    accounts: Vec<Account>,
    #[serde(default)]
    #[allow(dead_code)] // surfaced once Android writes/syncs.
    tombstones: Vec<Tombstone>,
}

#[derive(Deserialize)]
struct Tombstone {
    #[allow(dead_code)]
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    username: String,
    #[allow(dead_code)]
    deleted_at: u64,
}

fn derive_key(password: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let params = Params::new(m, t, p, Some(KEY_LEN)).expect("invalid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(password, salt, &mut *key)
        .expect("argon2 hashing failed");
    key
}

fn decrypt(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>, ()> {
    if nonce.len() != NONCE_LEN {
        return Err(());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| ())
}

fn unlock(vault_bytes: &[u8], password: &[u8]) -> Result<String, String> {
    let vault: EncryptedVault =
        serde_json::from_slice(vault_bytes).map_err(|e| format!("parse vault file: {}", e))?;

    let salt = general_purpose::STANDARD
        .decode(&vault.salt)
        .map_err(|_| "salt is not valid base64".to_string())?;
    if salt.len() != SALT_LEN {
        return Err(format!("salt length {} (expected {})", salt.len(), SALT_LEN));
    }
    let nonce = general_purpose::STANDARD
        .decode(&vault.nonce)
        .map_err(|_| "nonce is not valid base64".to_string())?;
    let ciphertext = general_purpose::STANDARD
        .decode(&vault.ciphertext)
        .map_err(|_| "ciphertext is not valid base64".to_string())?;

    let key = derive_key(
        password,
        &salt,
        vault.kdf_m_cost,
        vault.kdf_t_cost,
        vault.kdf_p_cost,
    );
    let plaintext = decrypt(&ciphertext, &nonce, &*key)
        .map_err(|_| "wrong password or corrupt vault".to_string())?;

    // v2: JSON object `{accounts: [...], tombstones: [...]}`.
    // v1: bare JSON array of accounts. Sniff the first non-ws byte.
    let first = plaintext
        .iter()
        .find(|&&b| !b.is_ascii_whitespace())
        .copied();
    let accounts: Vec<Account> = match first {
        Some(b'{') => serde_json::from_slice::<VaultPayload>(&plaintext)
            .map_err(|e| format!("parse decrypted payload: {}", e))?
            .accounts,
        _ => serde_json::from_slice::<Vec<Account>>(&plaintext)
            .map_err(|e| format!("parse decrypted accounts (legacy): {}", e))?,
    };
    serde_json::to_string(&accounts).map_err(|e| format!("serialize accounts: {}", e))
}

/// JNI entry point.
/// Kotlin side:
///   external fun unlockVault(vaultJson: ByteArray, password: ByteArray): String
/// Returns a JSON envelope: `{"ok": "<accounts json>"}` on success,
/// `{"err": "<message>"}` on failure. Kotlin parses one or the other.
/// The accounts JSON inside is the same shape the desktop client uses,
/// so callers can `Json.decodeFromString<List<Account>>(...)` directly.
// JNI name mangling: a `_` in the Java package name encodes as `_1`,
// so `com.example.passwort_manager` becomes `com_example_passwort_1manager`.
#[no_mangle]
pub extern "system" fn Java_com_example_passwort_1manager_VaultBridge_unlockVault<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    vault_json: JByteArray<'a>,
    password_bytes: JByteArray<'a>,
) -> jstring {
    let vault_bytes = match env.convert_byte_array(&vault_json) {
        Ok(b) => b,
        Err(_) => return make_err(&mut env, "could not read vault bytes"),
    };
    let pw_bytes = match env.convert_byte_array(&password_bytes) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => return make_err(&mut env, "could not read password bytes"),
    };

    let envelope = match unlock(&vault_bytes, &pw_bytes) {
        Ok(json) => {
            // Embed already-serialized JSON via a raw value field so we
            // don't re-encode the (potentially large) accounts array.
            format!(r#"{{"ok":{}}}"#, json)
        }
        Err(msg) => {
            let msg_json = serde_json::to_string(&msg).unwrap_or_else(|_| "\"\"".to_string());
            format!(r#"{{"err":{}}}"#, msg_json)
        }
    };

    env.new_string(envelope)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn make_err(env: &mut JNIEnv, msg: &str) -> jstring {
    let payload = format!(
        r#"{{"err":{}}}"#,
        serde_json::to_string(msg).unwrap_or_else(|_| "\"\"".to_string())
    );
    env.new_string(payload)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
