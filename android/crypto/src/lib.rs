//! JNI bridge for the Android client. Reuses the same Argon2id +
//! AES-256-GCM scheme as the desktop crate so a `vault.json` written
//! on Linux opens here byte-for-byte.
//!
//! Exposed entry points:
//!   * `unlockVault(vault, password)` — derive key, decrypt, return
//!     accounts + the derived key (used for silent live-refresh).
//!   * `refreshVault(vault, key)` — decrypt with a cached key,
//!     skipping Argon2id.
//!   * `saveVault(currentFile, key, payloadJson)` — re-encrypt a
//!     fresh payload using the existing vault's salt + kdf params,
//!     return the new file bytes for the caller to write atomically.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// KDF parameters used when *rotating* the master password from the
// Android side. Must match the desktop crate's constants (src/crypto.rs)
// so a phone-initiated rotation produces a file the desktop opens
// without an extra round of param upgrades.
const KDF_M_COST: u32 = 131_072; // 128 MiB
const KDF_T_COST: u32 = 3;
const KDF_P_COST: u32 = 4;

// On-disk schema. Now Serialize too: phase-3 write support
// re-emits a fresh EncryptedVault with the same salt + kdf params
// (so the file is still openable by the desktop side with the
// shared master password) and a fresh nonce + ciphertext.
#[derive(Deserialize, Serialize)]
struct EncryptedVault {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default = "default_kdf_algo")]
    kdf_algo: String,
    kdf_m_cost: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn default_version() -> u32 {
    2
}
fn default_kdf_algo() -> String {
    "argon2id".to_string()
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

fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), ()> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| ())?;
    Ok((nonce_bytes, ciphertext))
}

struct UnlockResult {
    accounts_json: String,
    key_b64: String,
}

fn unlock(vault_bytes: &[u8], password: &[u8]) -> Result<UnlockResult, String> {
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
    let accounts_json = decrypted_accounts_json(&plaintext)?;
    // Encode the derived key so the Kotlin caller can stash it for
    // silent file re-reads (e.g. after a PC-initiated sync replaced
    // the vault.json on disk). The key bytes never leave this process
    // (Kotlin holds them just as long as the unlocked accounts).
    let key_b64 = general_purpose::STANDARD.encode(&*key);
    Ok(UnlockResult {
        accounts_json,
        key_b64,
    })
}

/// Silent re-decrypt path used by the live-refresh ticker. Given the
/// raw vault file and a previously-derived key (from a successful
/// `unlock` in the same session), decrypt and return the same
/// accounts JSON. Returns an Err if the key no longer matches —
/// typically because the PC changed master / salt — so the caller
/// can lock the vault and prompt the user.
fn decrypt_with_key(vault_bytes: &[u8], key: &[u8]) -> Result<String, String> {
    if key.len() != KEY_LEN {
        return Err(format!("key must be {} bytes", KEY_LEN));
    }
    let vault: EncryptedVault =
        serde_json::from_slice(vault_bytes).map_err(|e| format!("parse vault file: {}", e))?;
    let nonce = general_purpose::STANDARD
        .decode(&vault.nonce)
        .map_err(|_| "nonce is not valid base64".to_string())?;
    let ciphertext = general_purpose::STANDARD
        .decode(&vault.ciphertext)
        .map_err(|_| "ciphertext is not valid base64".to_string())?;
    let plaintext =
        decrypt(&ciphertext, &nonce, key).map_err(|_| "cached key no longer decrypts this vault".to_string())?;
    decrypted_accounts_json(&plaintext)
}

/// Rotate the master password: decrypt the current vault with
/// `old_key`, derive a fresh key from `new_master` and a fresh salt
/// using the current desktop KDF parameters, re-encrypt the same
/// payload under it, and return the new on-disk file bytes plus the
/// new derived key (so the caller can update VaultState's cached key).
fn rotate_master(
    current_bytes: &[u8],
    old_key: &[u8],
    new_master: &[u8],
) -> Result<(String, [u8; KEY_LEN]), String> {
    if old_key.len() != KEY_LEN {
        return Err(format!("old key must be {} bytes", KEY_LEN));
    }
    let existing: EncryptedVault = serde_json::from_slice(current_bytes)
        .map_err(|e| format!("parse current vault file: {}", e))?;
    let nonce = general_purpose::STANDARD
        .decode(&existing.nonce)
        .map_err(|_| "nonce is not valid base64".to_string())?;
    let ciphertext = general_purpose::STANDARD
        .decode(&existing.ciphertext)
        .map_err(|_| "ciphertext is not valid base64".to_string())?;

    // Decrypt with the existing key. If this fails the caller passed
    // the wrong derived key, treat as "current master wrong".
    let plaintext = decrypt(&ciphertext, &nonce, old_key)
        .map_err(|_| "current master incorrect".to_string())?;

    // Fresh salt + derive a new key under the current desktop KDF
    // params so a phone-initiated rotation never produces a file
    // with weaker params than the desktop would write.
    let mut new_salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut new_salt);
    let new_key = derive_key(new_master, &new_salt, KDF_M_COST, KDF_T_COST, KDF_P_COST);
    let mut key_out = [0u8; KEY_LEN];
    key_out.copy_from_slice(&*new_key);

    let (new_nonce, new_ct) =
        encrypt(&plaintext, &*new_key).map_err(|_| "encrypt failed".to_string())?;
    let new_vault = EncryptedVault {
        version: 2,
        kdf_algo: "argon2id".to_string(),
        kdf_m_cost: KDF_M_COST,
        kdf_t_cost: KDF_T_COST,
        kdf_p_cost: KDF_P_COST,
        salt: general_purpose::STANDARD.encode(new_salt),
        nonce: general_purpose::STANDARD.encode(new_nonce),
        ciphertext: general_purpose::STANDARD.encode(new_ct),
    };
    let file_json = serde_json::to_string_pretty(&new_vault)
        .map_err(|e| format!("serialise rotated vault: {}", e))?;
    Ok((file_json, key_out))
}

/// Re-encrypt a freshly-serialised vault payload using the same key
/// and same salt/kdf params as the existing file. Returns the new
/// on-disk-format JSON bytes — the Kotlin caller writes them
/// atomically. The salt stays put so the desktop side can still
/// decrypt with the shared master password.
fn save_vault(current_bytes: &[u8], key: &[u8], payload_json: &str) -> Result<String, String> {
    if key.len() != KEY_LEN {
        return Err(format!("key must be {} bytes", KEY_LEN));
    }
    let existing: EncryptedVault = serde_json::from_slice(current_bytes)
        .map_err(|e| format!("parse current vault file: {}", e))?;
    let (nonce, ciphertext) =
        encrypt(payload_json.as_bytes(), key).map_err(|_| "encrypt failed".to_string())?;
    let new_vault = EncryptedVault {
        version: 2,
        kdf_algo: existing.kdf_algo,
        kdf_m_cost: existing.kdf_m_cost,
        kdf_t_cost: existing.kdf_t_cost,
        kdf_p_cost: existing.kdf_p_cost,
        salt: existing.salt,
        nonce: general_purpose::STANDARD.encode(nonce),
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
    };
    serde_json::to_string_pretty(&new_vault)
        .map_err(|e| format!("serialise new vault: {}", e))
}

fn decrypted_accounts_json(plaintext: &[u8]) -> Result<String, String> {
    // v2: JSON object `{accounts: [...], tombstones: [...]}`.
    // v1: bare JSON array of accounts. Sniff the first non-ws byte.
    let first = plaintext
        .iter()
        .find(|&&b| !b.is_ascii_whitespace())
        .copied();
    let accounts: Vec<Account> = match first {
        Some(b'{') => serde_json::from_slice::<VaultPayload>(plaintext)
            .map_err(|e| format!("parse decrypted payload: {}", e))?
            .accounts,
        _ => serde_json::from_slice::<Vec<Account>>(plaintext)
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
        Ok(r) => {
            // Embed already-serialized JSON via a raw value field so we
            // don't re-encode the (potentially large) accounts array.
            format!(
                r#"{{"ok":{},"key":"{}"}}"#,
                r.accounts_json, r.key_b64,
            )
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

/// Silent re-decrypt entry point — pairs with the `key` returned by
/// the original unlock. Kotlin side:
///   external fun refreshVault(vaultJson: ByteArray, keyBytes: ByteArray): String
/// Same envelope shape: `{"ok": [accounts]}` or `{"err": "..."}`.
#[no_mangle]
pub extern "system" fn Java_com_example_passwort_1manager_VaultBridge_refreshVault<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    vault_json: JByteArray<'a>,
    key_bytes: JByteArray<'a>,
) -> jstring {
    let vault_bytes = match env.convert_byte_array(&vault_json) {
        Ok(b) => b,
        Err(_) => return make_err(&mut env, "could not read vault bytes"),
    };
    let key = match env.convert_byte_array(&key_bytes) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => return make_err(&mut env, "could not read cached key"),
    };

    let envelope = match decrypt_with_key(&vault_bytes, &key) {
        Ok(json) => format!(r#"{{"ok":{}}}"#, json),
        Err(msg) => {
            let msg_json = serde_json::to_string(&msg).unwrap_or_else(|_| "\"\"".to_string());
            format!(r#"{{"err":{}}}"#, msg_json)
        }
    };

    env.new_string(envelope)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Re-encrypt a fresh VaultPayload as the new on-disk vault.json
/// bytes, using the same key the Kotlin side cached from
/// [unlockVault]. The salt + kdf params from the existing file are
/// reused so the desktop side keeps decrypting with the shared master.
///
/// Kotlin signature:
///   external fun saveVault(currentFileBytes: ByteArray,
///                          keyBytes: ByteArray,
///                          payloadJson: String): String
///
/// Returns the same envelope as the other entry points:
///   {"ok": "<new vault file content as a JSON string>"} on success
///   {"err": "<message>"}                                on failure
#[no_mangle]
pub extern "system" fn Java_com_example_passwort_1manager_VaultBridge_saveVault<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    current_file: JByteArray<'a>,
    key_bytes: JByteArray<'a>,
    payload_json: JString<'a>,
) -> jstring {
    let current_bytes = match env.convert_byte_array(&current_file) {
        Ok(b) => b,
        Err(_) => return make_err(&mut env, "could not read current file bytes"),
    };
    let key = match env.convert_byte_array(&key_bytes) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => return make_err(&mut env, "could not read cached key"),
    };
    let payload_str: String = match env.get_string(&payload_json) {
        Ok(s) => s.into(),
        Err(_) => return make_err(&mut env, "could not read payload JSON"),
    };

    let envelope = match save_vault(&current_bytes, &key, &payload_str) {
        Ok(file_json) => {
            // Serialise the inner JSON as a JSON-string value so the
            // envelope is itself valid JSON.
            let escaped = serde_json::to_string(&file_json).unwrap_or_else(|_| "\"\"".to_string());
            format!(r#"{{"ok":{}}}"#, escaped)
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

/// Rotate the master password. Verifies the current master indirectly
/// by attempting to decrypt the existing file with the cached `old_key`
/// — if the caller-supplied key doesn't match, the decrypt fails and
/// we surface a "current master incorrect" error.
///
/// Kotlin signature:
///   external fun rotateMaster(currentFileBytes: ByteArray,
///                             oldKeyBytes: ByteArray,
///                             newMasterBytes: ByteArray): String
///
/// Success envelope: `{"ok": "<new vault file>", "key": "<b64 new key>"}`
/// Failure envelope: `{"err": "<message>"}`
#[no_mangle]
pub extern "system" fn Java_com_example_passwort_1manager_VaultBridge_rotateMaster<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    current_file: JByteArray<'a>,
    old_key_bytes: JByteArray<'a>,
    new_master_bytes: JByteArray<'a>,
) -> jstring {
    let current_bytes = match env.convert_byte_array(&current_file) {
        Ok(b) => b,
        Err(_) => return make_err(&mut env, "could not read current file bytes"),
    };
    let old_key = match env.convert_byte_array(&old_key_bytes) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => return make_err(&mut env, "could not read old key bytes"),
    };
    let new_master = match env.convert_byte_array(&new_master_bytes) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => return make_err(&mut env, "could not read new master bytes"),
    };

    let envelope = match rotate_master(&current_bytes, &old_key, &new_master) {
        Ok((file_json, key)) => {
            let key_b64 = general_purpose::STANDARD.encode(&key);
            let escaped =
                serde_json::to_string(&file_json).unwrap_or_else(|_| "\"\"".to_string());
            format!(r#"{{"ok":{},"key":"{}"}}"#, escaped, key_b64)
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
