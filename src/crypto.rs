use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

pub const KDF_M_COST: u32 = 65536; // 64 MiB
pub const KDF_T_COST: u32 = 3;
pub const KDF_P_COST: u32 = 4;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

pub fn derive_key(
    master_password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .expect("invalid argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(master_password, salt, &mut *key)
        .expect("argon2 hashing failed");
    key
}

pub fn derive_key_legacy(
    master_password: &[u8],
    salt: &[u8],
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(master_password, salt, &mut *key)
        .expect("argon2 hashing failed");
    key
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("invalid key length");
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failed");
    (nonce_bytes, ciphertext)
}

pub fn decrypt(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>, ()> {
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

// Decrypt a base64 blob laid out as [nonce(12) || ciphertext+tag] — the
// encoding used by the legacy per-password format.
pub fn decrypt_combined(b64: &str, key: &[u8]) -> Result<Zeroizing<String>, ()> {
    let decoded = general_purpose::STANDARD.decode(b64).map_err(|_| ())?;
    if decoded.len() < NONCE_LEN {
        return Err(());
    }
    let (nonce_bytes, ciphertext) = decoded.split_at(NONCE_LEN);
    let plaintext = decrypt(ciphertext, nonce_bytes, key)?;
    let s = String::from_utf8(plaintext.to_vec()).map_err(|_| ())?;
    Ok(Zeroizing::new(s))
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
