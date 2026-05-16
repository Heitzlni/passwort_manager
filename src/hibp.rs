//! Have I Been Pwned (HIBP) "Pwned Passwords" check via the k-anonymity
//! API at https://api.pwnedpasswords.com/range/<5-char prefix>.
//!
//! How it stays private:
//!   1. SHA-1 hash the password locally (the API uses SHA-1 for historical
//!      reasons; this is a *lookup*, not a security primitive — we don't
//!      hash the password for storage).
//!   2. Send only the FIRST 5 hex chars of the hash to the API. The API
//!      replies with every full hash that starts with those 5 chars
//!      (typically 500–1000 entries) plus a per-hash breach count.
//!   3. We locally check whether the *suffix* (chars 6..40) of our hash
//!      appears in the response. If so, the password is in a breach.
//!
//! HIBP never sees the full hash and certainly never sees the password.
//! See https://haveibeenpwned.com/API/v3#PwnedPasswords for the protocol.

use sha1::{Digest, Sha1};

const ENDPOINT: &str = "https://api.pwnedpasswords.com/range/";
const USER_AGENT: &str = "passwort-manager-hibp/0.2";
const TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Copy)]
pub struct PwnedResult {
    /// Number of times this password has been seen across known breaches.
    /// 0 means "not in the HIBP database" (safe-ish).
    pub breach_count: u64,
}

#[derive(Debug)]
pub enum HibpError {
    Network(String),
    BadResponse(String),
}

impl std::fmt::Display for HibpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HibpError::Network(s) => write!(f, "network: {}", s),
            HibpError::BadResponse(s) => write!(f, "bad response: {}", s),
        }
    }
}

/// Check whether a single password is known to HIBP. Returns the breach
/// count (0 if clean). Synchronous / blocking — call from a worker thread
/// in the GUI to avoid stalling the event loop.
pub fn check_password(password: &str) -> Result<PwnedResult, HibpError> {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let hex = hex_encode_upper(&digest);
    let (prefix, suffix) = hex.split_at(5);

    let url = format!("{}{}", ENDPOINT, prefix);
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(TIMEOUT_SECS))
        .timeout_read(std::time::Duration::from_secs(TIMEOUT_SECS))
        .user_agent(USER_AGENT)
        .build();
    let body = match agent.get(&url).call() {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| HibpError::BadResponse(e.to_string()))?,
        Err(e) => return Err(HibpError::Network(e.to_string())),
    };

    // Response is `\r\n`-separated lines of `SUFFIX:COUNT`. Compare
    // suffixes case-insensitively (HIBP returns uppercase but be liberal).
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.splitn(2, ':');
        let line_suffix = match it.next() {
            Some(s) => s,
            None => continue,
        };
        if line_suffix.eq_ignore_ascii_case(suffix) {
            let count: u64 = it
                .next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1);
            return Ok(PwnedResult { breach_count: count });
        }
    }
    Ok(PwnedResult { breach_count: 0 })
}

fn hex_encode_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_upper_known_vectors() {
        assert_eq!(hex_encode_upper(&[]), "");
        assert_eq!(hex_encode_upper(&[0x00]), "00");
        assert_eq!(hex_encode_upper(&[0xff]), "FF");
        assert_eq!(hex_encode_upper(&[0xde, 0xad, 0xbe, 0xef]), "DEADBEEF");
    }

    #[test]
    fn sha1_of_password_is_known_value() {
        // Sanity check that we're hashing correctly: SHA-1("password")
        // is the well-known value 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
        let mut hasher = Sha1::new();
        hasher.update(b"password");
        let h = hasher.finalize();
        assert_eq!(
            hex_encode_upper(&h),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }
}
