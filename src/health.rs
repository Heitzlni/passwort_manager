//! Offline vault health checks: weak and reused passwords. Pure,
//! network-free analysis over the already-decrypted accounts — the
//! local-only complement to the online HIBP audit (src/hibp.rs).
//!
//! Password values are never copied out or logged; reuse is detected by
//! grouping on the password string in-place and only the *count* and
//! entry labels are reported.

use std::collections::HashMap;

use crate::storage::Account;

/// Below this estimated strength a password is flagged "weak".
/// ~60 bits ≈ a 12-char lowercase+digit password, or a 10-char password
/// using all four character classes — anything weaker is worth changing.
pub const WEAK_BITS: f64 = 60.0;

/// Rough entropy estimate (bits) for an arbitrary, user-chosen password:
/// detect which character classes occur, size the pool accordingly, and
/// return `len * log2(pool)`. This deliberately *over*-estimates (it
/// ignores dictionary words, keyboard walks and repetition), so anything
/// it still calls weak is genuinely weak — few false positives.
pub fn estimate_bits(pw: &str) -> f64 {
    let len = pw.chars().count();
    if len == 0 {
        return 0.0;
    }
    let (mut lower, mut upper, mut digit, mut sym) = (false, false, false, false);
    for c in pw.chars() {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else {
            sym = true;
        }
    }
    let mut pool = 0u32;
    if lower {
        pool += 26;
    }
    if upper {
        pool += 26;
    }
    if digit {
        pool += 10;
    }
    if sym {
        pool += 32; // approximate printable-symbol space
    }
    if pool == 0 {
        return 0.0;
    }
    (pool as f64).log2() * (len as f64)
}

/// Health verdict for a single entry. No password material.
#[derive(Debug, Clone)]
pub struct EntryHealth {
    pub name: String,
    pub username: String,
    /// Estimated strength in bits (rounded). 0 means empty password.
    pub bits: u32,
    pub weak: bool,
    /// How many *other* entries share this exact password (0 = unique).
    pub reused_with: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub total: usize,
    /// One per account, in input order.
    pub entries: Vec<EntryHealth>,
    /// Groups of entry indices (into `entries`) that share one password;
    /// every group has length >= 2.
    pub reused_groups: Vec<Vec<usize>>,
}

impl Report {
    pub fn weak_count(&self) -> usize {
        self.entries.iter().filter(|e| e.weak).count()
    }
    /// Number of entries involved in any password reuse.
    pub fn reused_count(&self) -> usize {
        self.entries.iter().filter(|e| e.reused_with > 0).count()
    }
    pub fn all_clear(&self) -> bool {
        self.weak_count() == 0 && self.reused_groups.is_empty()
    }
}

/// Analyze the vault. O(n) over accounts; passwords are only borrowed.
pub fn analyze(accounts: &[Account]) -> Report {
    // Group entry indices by exact password to find reuse.
    let mut by_pw: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, a) in accounts.iter().enumerate() {
        by_pw.entry(a.password.as_str()).or_default().push(i);
    }

    let mut entries: Vec<EntryHealth> = accounts
        .iter()
        .map(|a| {
            let group = by_pw.get(a.password.as_str()).map(|v| v.len()).unwrap_or(1);
            let bits = estimate_bits(&a.password);
            EntryHealth {
                name: a.name.clone(),
                username: a.username.clone(),
                bits: bits.round() as u32,
                weak: bits < WEAK_BITS,
                reused_with: group.saturating_sub(1),
            }
        })
        .collect();

    // Reuse groups (size >= 2). Empty passwords are not "reuse" — an
    // empty password is already flagged weak; grouping every blank entry
    // together would just be noise.
    let mut reused_groups: Vec<Vec<usize>> = by_pw
        .iter()
        .filter(|(pw, idxs)| !pw.is_empty() && idxs.len() >= 2)
        .map(|(_, idxs)| {
            let mut v = idxs.clone();
            v.sort_unstable();
            v
        })
        .collect();
    reused_groups.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(&b[0])));

    // An entry whose password is empty has no "reuse" partners.
    for (i, a) in accounts.iter().enumerate() {
        if a.password.is_empty() {
            entries[i].reused_with = 0;
        }
    }

    Report {
        total: accounts.len(),
        entries,
        reused_groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(name: &str, user: &str, pw: &str) -> Account {
        Account {
            name: name.into(),
            url: String::new(),
            username: user.into(),
            password: pw.into(),
            totp_secret: String::new(),
            notes: String::new(),
        }
    }

    #[test]
    fn empty_password_is_zero_bits_and_weak() {
        assert_eq!(estimate_bits(""), 0.0);
        let r = analyze(&[acct("a", "", "")]);
        assert!(r.entries[0].weak);
        assert_eq!(r.entries[0].bits, 0);
        assert_eq!(r.entries[0].reused_with, 0);
    }

    #[test]
    fn long_random_mixed_password_is_strong() {
        let bits = estimate_bits("Gx7!qomZ2#vKt4&pLwRe");
        assert!(bits > WEAK_BITS, "bits = {}", bits);
        let r = analyze(&[acct("a", "u", "Gx7!qomZ2#vKt4&pLwRe")]);
        assert!(!r.entries[0].weak);
        assert!(r.all_clear());
    }

    #[test]
    fn short_simple_password_is_weak() {
        assert!(estimate_bits("hunter2") < WEAK_BITS);
        let r = analyze(&[acct("a", "u", "hunter2")]);
        assert_eq!(r.weak_count(), 1);
    }

    #[test]
    fn reuse_is_detected_and_grouped() {
        let v = vec![
            acct("site-a", "alice", "SharedPass!9xQ2zr"),
            acct("site-b", "bob", "SharedPass!9xQ2zr"),
            acct("site-c", "carol", "UniqueOne!7mPz3wV"),
        ];
        let r = analyze(&v);
        assert_eq!(r.reused_groups.len(), 1);
        assert_eq!(r.reused_groups[0], vec![0, 1]);
        assert_eq!(r.entries[0].reused_with, 1);
        assert_eq!(r.entries[1].reused_with, 1);
        assert_eq!(r.entries[2].reused_with, 0);
        assert_eq!(r.reused_count(), 2);
    }

    #[test]
    fn empty_passwords_do_not_count_as_reuse() {
        let v = vec![acct("a", "", ""), acct("b", "", "")];
        let r = analyze(&v);
        assert!(r.reused_groups.is_empty());
        assert_eq!(r.entries[0].reused_with, 0);
        assert_eq!(r.entries[1].reused_with, 0);
    }
}
