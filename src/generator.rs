//! Random password generator. Uses OS entropy (`OsRng`) and rejection
//! sampling so each character of the requested alphabet is equally likely
//! (no modulo bias).
//!
//! Default alphabet is 89 ASCII printable chars (26 lower + 26 upper +
//! 10 digits + 27 common symbols), which gives ~6.48 bits per character.
//! A 20-char generated password therefore has ~129 bits of entropy — far
//! past the point Argon2id can be brute-forced.

use rand::rngs::OsRng;
use rand::RngCore;

pub const DEFAULT_LENGTH: usize = 20;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/~";

#[derive(Clone, Copy, Debug)]
pub struct Charset {
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for Charset {
    fn default() -> Self {
        Self { lower: true, upper: true, digits: true, symbols: true }
    }
}

impl Charset {
    pub fn alphabet(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(94);
        if self.lower { a.extend_from_slice(LOWER); }
        if self.upper { a.extend_from_slice(UPPER); }
        if self.digits { a.extend_from_slice(DIGITS); }
        if self.symbols { a.extend_from_slice(SYMBOLS); }
        a
    }
}

/// Generate a password of the given length using rejection sampling against
/// a uniform byte. Guarantees no modulo bias regardless of alphabet size.
pub fn generate(length: usize, charset: Charset) -> String {
    let alpha = charset.alphabet();
    if alpha.is_empty() || length == 0 {
        return String::new();
    }
    // Largest multiple of alpha.len() that fits in u8 — bytes >= this value
    // get rejected and re-rolled to keep the distribution uniform.
    let n = alpha.len() as u32;
    let max_unbiased = (256 / n) * n;
    let mut out = String::with_capacity(length);
    let mut buf = [0u8; 64];
    while out.len() < length {
        OsRng.fill_bytes(&mut buf);
        for &b in &buf {
            if (b as u32) < max_unbiased {
                out.push(alpha[(b as usize) % alpha.len()] as char);
                if out.len() >= length {
                    break;
                }
            }
        }
    }
    out
}

/// Approximate entropy in bits for a generated password of this length and
/// alphabet. log2(alphabet_size) * length.
pub fn entropy_bits(length: usize, charset: Charset) -> f64 {
    let n = charset.alphabet().len();
    if n <= 1 || length == 0 {
        return 0.0;
    }
    (n as f64).log2() * (length as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_length_is_correct() {
        let pw = generate(DEFAULT_LENGTH, Charset::default());
        assert_eq!(pw.len(), DEFAULT_LENGTH);
    }

    #[test]
    fn custom_lengths_respected() {
        for len in [1, 5, 16, 32, 100] {
            let pw = generate(len, Charset::default());
            assert_eq!(pw.len(), len, "wrong length for requested {}", len);
        }
    }

    #[test]
    fn empty_alphabet_yields_empty() {
        let cs = Charset { lower: false, upper: false, digits: false, symbols: false };
        assert_eq!(generate(20, cs), "");
    }

    #[test]
    fn zero_length_yields_empty() {
        assert_eq!(generate(0, Charset::default()), "");
    }

    #[test]
    fn only_uses_chars_from_alphabet() {
        let cs = Charset { lower: true, upper: false, digits: true, symbols: false };
        let alpha: std::collections::HashSet<char> =
            cs.alphabet().iter().map(|&b| b as char).collect();
        let pw = generate(200, cs);
        for c in pw.chars() {
            assert!(alpha.contains(&c), "char {} not in alphabet", c);
        }
    }

    #[test]
    fn passwords_are_different_run_to_run() {
        // 20 chars from a 94-char alphabet has ~131 bits of entropy. Two
        // generations being equal would be a catastrophic RNG failure.
        let a = generate(DEFAULT_LENGTH, Charset::default());
        let b = generate(DEFAULT_LENGTH, Charset::default());
        assert_ne!(a, b);
    }

    #[test]
    fn entropy_bits_reasonable() {
        let bits = entropy_bits(20, Charset::default());
        // Default alphabet is 26+26+10+27 = 89 chars, so 20*log2(89) ≈ 129.5
        assert!(bits > 128.0 && bits < 131.0, "bits = {}", bits);
    }
}
