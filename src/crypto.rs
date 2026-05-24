use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

pub const KDF_M_COST: u32 = 131072; // 128 MiB
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

/// Generate the current 6-digit TOTP code (RFC 6238) for a Base32 secret.
/// Returns `(code, seconds_remaining_in_window)` so callers can show a
/// countdown. Returns `None` if the secret can't be parsed.
///
/// We bypass `TOTP::new`'s 128-bit minimum-length validation because some
/// short test/demo secrets that real users paste in are still useful;
/// browsers / authenticator apps don't enforce it either.
/// Normalize a Base32 TOTP secret for the strict decoder: uppercase,
/// drop spaces / dashes (services often display `abcd efgh` or
/// `ABCD-EFGH-…`), and strip `=` padding (RFC4648-no-padding decode
/// rejects it). Base32 is case-insensitive, but the decoder is not — so
/// a lowercase secret from a QR/issuer would otherwise fail with the
/// misleading "Invalid TOTP secret" error.
pub fn normalize_b32_secret(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

pub fn totp_code(b32_secret: &str) -> Option<(String, u64)> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let cleaned = normalize_b32_secret(b32_secret);
    if cleaned.is_empty() {
        return None;
    }
    let raw = totp_rs::Secret::Encoded(cleaned).to_bytes().ok()?;
    let totp = totp_rs::TOTP {
        algorithm: totp_rs::Algorithm::SHA1,
        digits: 6,
        skew: 1,
        step: 30,
        secret: raw,
        issuer: None,
        account_name: String::new(),
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let code = totp.generate(now);
    let remaining = 30 - (now % 30);
    Some((code, remaining))
}

/// Parsed fields from an `otpauth://totp/...` URI (the thing QR codes on
/// 2FA setup pages encode). We only surface what the rest of the app uses;
/// `algorithm`/`digits`/`period` are parsed so we can warn if a site uses
/// non-default values (our `totp_code` is hardcoded to the SHA1/6/30
/// Google-Authenticator defaults that ~all sites use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpauthParams {
    /// Base32 secret (whitespace already stripped).
    pub secret: String,
    /// Human label — issuer + account, best-effort from the URI path.
    pub label: String,
    /// Issuer, if present (from the `issuer=` query param or the label
    /// prefix before the colon).
    pub issuer: String,
    /// Account name (the part after `issuer:` in the label), may be empty.
    pub account: String,
    /// True if algorithm/digits/period differ from SHA1/6/30 — caller
    /// should warn the user the generated codes may not match.
    pub nonstandard: bool,
}

/// Parse an `otpauth://totp/LABEL?secret=...&issuer=...` URI. Returns None
/// for HOTP, missing secret, or anything not matching the scheme. Tolerant
/// of URL-encoding in the label and of the common `issuer:account` form.
pub fn parse_otpauth_uri(uri: &str) -> Option<OtpauthParams> {
    let uri = uri.trim();
    let rest = uri.strip_prefix("otpauth://")?;
    // We only do TOTP. HOTP needs a counter we don't store.
    let rest = rest.strip_prefix("totp/")?;

    let (label_enc, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };
    let label = url_decode(label_enc);

    let mut secret = String::new();
    let mut issuer_q = String::new();
    let mut algorithm = String::from("SHA1");
    let mut digits = String::from("6");
    let mut period = String::from("30");
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let v = url_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = v,
            "issuer" => issuer_q = v,
            "algorithm" => algorithm = v.to_ascii_uppercase(),
            "digits" => digits = v,
            "period" => period = v,
            _ => {}
        }
    }
    let secret = normalize_b32_secret(&secret);
    if secret.is_empty() {
        return None;
    }

    // Label is typically "Issuer:account" or just "account".
    let (issuer_label, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };
    let issuer = if !issuer_q.is_empty() {
        issuer_q
    } else {
        issuer_label
    };

    let nonstandard = algorithm != "SHA1" || digits != "6" || period != "30";

    Some(OtpauthParams {
        secret,
        label: label.clone(),
        issuer,
        account,
        nonstandard,
    })
}

/// Minimal percent-decoder (also turns '+' into space, like form-encoding,
/// which some issuers use in the label). Enough for otpauth labels.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_otpauth() {
        let p = parse_otpauth_uri(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        .unwrap();
        assert_eq!(p.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(p.issuer, "GitHub");
        assert_eq!(p.account, "alice");
        assert!(!p.nonstandard);
    }

    #[test]
    fn parse_otpauth_url_encoded_label() {
        let p = parse_otpauth_uri(
            "otpauth://totp/Big%20Corp%3Abob%40example.com?secret=ABCDEFGH234567",
        )
        .unwrap();
        assert_eq!(p.secret, "ABCDEFGH234567");
        // "Big Corp:bob@example.com" → issuer "Big Corp", account "bob@…"
        assert_eq!(p.issuer, "Big Corp");
        assert_eq!(p.account, "bob@example.com");
    }

    #[test]
    fn parse_otpauth_flags_nonstandard() {
        let p = parse_otpauth_uri(
            "otpauth://totp/X?secret=AAAA&digits=8&period=60",
        )
        .unwrap();
        assert!(p.nonstandard);
    }

    #[test]
    fn parse_otpauth_rejects_hotp_and_garbage() {
        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=AAAA&counter=1").is_none());
        assert!(parse_otpauth_uri("https://example.com").is_none());
        assert!(parse_otpauth_uri("otpauth://totp/x").is_none()); // no secret
    }

    #[test]
    fn parse_otpauth_strips_secret_whitespace() {
        let p = parse_otpauth_uri(
            "otpauth://totp/x?secret=JBSW%20Y3DP%20EHPK%203PXP",
        )
        .unwrap();
        assert_eq!(p.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn normalize_handles_lowercase_padding_dashes() {
        assert_eq!(normalize_b32_secret("jbswy3dpehpk3pxp"), "JBSWY3DPEHPK3PXP");
        assert_eq!(normalize_b32_secret("JBSW-Y3DP-EHPK-3PXP"), "JBSWY3DPEHPK3PXP");
        assert_eq!(normalize_b32_secret("JBSWY3DP====="), "JBSWY3DP");
        assert_eq!(normalize_b32_secret(" jb sw y3 dp "), "JBSWY3DP");
    }

    #[test]
    fn totp_code_accepts_lowercase_secret() {
        // Same secret, different case → must produce a code (not None).
        let upper = totp_code("JBSWY3DPEHPK3PXP");
        let lower = totp_code("jbswy3dpehpk3pxp");
        assert!(upper.is_some());
        assert!(lower.is_some());
        // And the same code, since it's the same key.
        assert_eq!(upper.unwrap().0, lower.unwrap().0);
    }

    #[test]
    fn parse_otpauth_normalizes_lowercase_secret() {
        let p = parse_otpauth_uri("otpauth://totp/x?secret=jbswy3dpehpk3pxp").unwrap();
        assert_eq!(p.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; KEY_LEN];
        let plaintext = b"hello, vault";
        let (nonce, ciphertext) = encrypt(plaintext, &key);
        let recovered = decrypt(&ciphertext, &nonce, &key).expect("decrypt should succeed");
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = [7u8; KEY_LEN];
        let other = [8u8; KEY_LEN];
        let (nonce, ciphertext) = encrypt(b"secret", &key);
        assert!(decrypt(&ciphertext, &nonce, &other).is_err());
    }

    #[test]
    fn decrypt_with_tampered_ciphertext_fails() {
        let key = [7u8; KEY_LEN];
        let (nonce, mut ciphertext) = encrypt(b"secret", &key);
        ciphertext[0] ^= 0x01; // flip one bit
        assert!(decrypt(&ciphertext, &nonce, &key).is_err());
    }

    #[test]
    fn decrypt_with_wrong_nonce_length_fails() {
        let key = [7u8; KEY_LEN];
        let (_n, ciphertext) = encrypt(b"x", &key);
        assert!(decrypt(&ciphertext, &[1u8; 5], &key).is_err());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [42u8; SALT_LEN];
        let pw = b"correct horse battery staple";
        // Use very low Argon2 cost so the test runs in milliseconds, not
        // hundreds. We're testing determinism, not the production params.
        let k1 = derive_key(pw, &salt, 1024, 1, 1);
        let k2 = derive_key(pw, &salt, 1024, 1, 1);
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_key_changes_with_salt() {
        let pw = b"same password";
        let k1 = derive_key(pw, &[1u8; SALT_LEN], 1024, 1, 1);
        let k2 = derive_key(pw, &[2u8; SALT_LEN], 1024, 1, 1);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn nonces_are_unique() {
        // 12 random bytes should not collide across a small batch — a
        // collision here would be a catastrophic RNG failure.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let n = generate_nonce();
            assert!(seen.insert(n));
        }
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }
}
