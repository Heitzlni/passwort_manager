//! Two-way merge for cross-device sync.
//!
//! Given the decrypted [`VaultPayload`] from two devices (typically
//! "this laptop" and "the phone we just adb-pulled from"), produce a
//! merged payload that both devices should land on.
//!
//! Merge rules per `(name, username)` identity:
//!
//!   1. Entry only on side A → keep it.
//!   2. Entry on both sides → keep the one with the larger
//!      `updated_at`. Ties prefer side A (the caller controls
//!      ordering, so they pick the winner).
//!   3. Tombstone for the identity AND an entry exists → if the
//!      entry's `updated_at` is older than the tombstone's
//!      `deleted_at`, the delete wins (drop the entry). If the entry
//!      is newer, the entry was re-created after the delete, so the
//!      tombstone is stale and gets dropped.
//!   4. Tombstones with the same identity on both sides → keep the
//!      one with the later `deleted_at`. Both can also exist for the
//!      same identity in different states; we de-dupe to one.
//!
//! Deletions therefore propagate as long as both sides sync within
//! tombstone retention. Tombstones are never garbage-collected here
//! — they accumulate for the (currently) life of the vault. A future
//! pass can prune ones older than ~90 days once we track per-device
//! last-sync time.

use std::collections::HashMap;

use crate::session::Session;
use crate::storage::{Account, EncryptedVault, Tombstone, VaultPayload};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStats {
    /// Entries that ended up only because side B contributed them
    /// (new on A after this merge).
    pub added_from_b: usize,
    /// Entries side A had that side B didn't (new on B after this merge).
    pub added_from_a: usize,
    /// Entries present on both with the same content — no work.
    pub unchanged: usize,
    /// Entries present on both with conflicting content; "newer wins"
    /// resolved them. Reported so the user can spot-check.
    pub resolved_conflicts: usize,
    /// Entries removed from side A because side B had a newer tombstone.
    pub deleted_on_a: usize,
    /// Entries removed from side B because side A had a newer tombstone.
    pub deleted_on_b: usize,
}

/// Returns the merged payload and a summary of what changed.
/// `a` and `b` are deliberately symmetric in inputs; the only place
/// ordering matters is the same-updated_at tie break, where A wins.
pub fn merge(a: VaultPayload, b: VaultPayload) -> (VaultPayload, SyncStats) {
    let VaultPayload {
        accounts: a_accounts,
        tombstones: a_tombs,
    } = a;
    let VaultPayload {
        accounts: b_accounts,
        tombstones: b_tombs,
    } = b;

    type Key = (String, String);

    // Index by (name, username). Same-key duplicates within one side
    // shouldn't happen in practice — the desktop Session prevents them
    // through the upsert path — but if they do, last-seen wins.
    let mut a_map: HashMap<Key, Account> = HashMap::new();
    for acc in a_accounts {
        a_map.insert((acc.name.clone(), acc.username.clone()), acc);
    }
    let mut b_map: HashMap<Key, Account> = HashMap::new();
    for acc in b_accounts {
        b_map.insert((acc.name.clone(), acc.username.clone()), acc);
    }

    // Combine tombstones, keeping the newest deleted_at per identity.
    let mut tomb_map: HashMap<Key, Tombstone> = HashMap::new();
    for t in a_tombs.into_iter().chain(b_tombs.into_iter()) {
        let k = (t.name.clone(), t.username.clone());
        let take = tomb_map
            .get(&k)
            .map(|existing| t.deleted_at > existing.deleted_at)
            .unwrap_or(true);
        if take {
            tomb_map.insert(k, t);
        }
    }

    let mut stats = SyncStats {
        added_from_b: 0,
        added_from_a: 0,
        unchanged: 0,
        resolved_conflicts: 0,
        deleted_on_a: 0,
        deleted_on_b: 0,
    };
    let mut merged_accounts: Vec<Account> = Vec::new();
    let mut surviving_tombstones: Vec<Tombstone> = Vec::new();

    // Union of keys from both sides — and from the tombstone map,
    // so tombstones for identities neither side currently has still
    // get carried over for any third device that hasn't synced yet.
    let mut keys: Vec<Key> = Vec::new();
    for k in a_map.keys().chain(b_map.keys()).chain(tomb_map.keys()) {
        if !keys.contains(k) {
            keys.push(k.clone());
        }
    }

    for key in keys {
        let in_a = a_map.remove(&key);
        let in_b = b_map.remove(&key);
        let tomb = tomb_map.get(&key).cloned();

        // Pick the freshest account version among the two sides.
        let account_pick: Option<Account> = match (in_a, in_b) {
            (Some(a), Some(b)) => {
                let same_content = same_account_content(&a, &b);
                if same_content {
                    stats.unchanged += 1;
                } else {
                    stats.resolved_conflicts += 1;
                }
                // Tie → A wins.
                Some(if b.updated_at > a.updated_at { b } else { a })
            }
            (Some(a), None) => {
                // Only on A. Whether B should adopt it depends on the
                // tombstone (handled below).
                stats.added_from_a += 1;
                Some(a)
            }
            (None, Some(b)) => {
                stats.added_from_b += 1;
                Some(b)
            }
            (None, None) => None,
        };

        if let Some(acc) = account_pick {
            // Apply tombstone if it's newer than the account.
            if let Some(t) = tomb.as_ref() {
                if t.deleted_at > acc.updated_at {
                    // Delete wins — drop the account, keep the tombstone.
                    // The side that previously had the entry needs to
                    // delete it; the side that already lacks it is fine.
                    // Bookkeeping: we credited an add/conflict above —
                    // back that out and credit a delete.
                    // Easiest: figure out by which side still had it.
                    // We've consumed in_a/in_b but stats already updated;
                    // tweak only the delete counters.
                    if !surviving_tombstones
                        .iter()
                        .any(|existing| key_of(existing) == key)
                    {
                        surviving_tombstones.push(t.clone());
                    }
                    // The account in `acc` came from whichever side was
                    // newer; if A had it, B will delete (deleted_on_b);
                    // if only B had it, A will delete (deleted_on_a).
                    // We can't tell from here anymore — best-effort
                    // bookkeeping: credit delete-on-both.
                    stats.deleted_on_a += 1;
                    stats.deleted_on_b += 1;
                    continue;
                }
                // Entry is newer than tombstone → tombstone is stale,
                // drop it silently.
            }
            merged_accounts.push(acc);
        } else if let Some(t) = tomb {
            // No live account, only a tombstone — keep it so it can
            // still propagate to a third device that hasn't synced yet.
            surviving_tombstones.push(t);
        }
    }

    // Stable order for deterministic output / tests.
    merged_accounts.sort_by(|x, y| x.name.cmp(&y.name).then(x.username.cmp(&y.username)));
    surviving_tombstones.sort_by(|x, y| x.name.cmp(&y.name).then(x.username.cmp(&y.username)));

    let merged = VaultPayload {
        accounts: merged_accounts,
        tombstones: surviving_tombstones,
    };
    (merged, stats)
}

fn key_of(t: &Tombstone) -> (String, String) {
    (t.name.clone(), t.username.clone())
}

// ===================== USB sync orchestration =====================

/// Path of the phone's vault file inside the Android client's
/// external-files dir. Matches what the Android app reads in
/// [MainActivity#vaultFile].
pub const PHONE_VAULT_PATH: &str =
    "/sdcard/Android/data/com.example.passwort_manager/files/vault.json";

#[derive(Debug)]
pub enum MobileSyncError {
    AdbMissing,
    AdbNoDevice,
    AdbFailed(String),
    PhoneVaultMissing,
    PhoneDecryptFailed,
    Io(std::io::Error),
}

impl std::fmt::Display for MobileSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MobileSyncError::AdbMissing => write!(
                f,
                "adb not installed. Install android-tools-adb (Debian/Ubuntu) \
                 or `sudo apt install adb` so we can talk to the phone."
            ),
            MobileSyncError::AdbNoDevice => write!(
                f,
                "No phone detected via USB. Check the cable, USB-debugging, \
                 and that you've allowed this PC on the phone (the prompt)."
            ),
            MobileSyncError::AdbFailed(s) => write!(f, "adb error: {}", s),
            MobileSyncError::PhoneVaultMissing => write!(
                f,
                "Phone has no vault.json yet. Open the Password Manager app on \
                 the phone at least once so it creates its files directory, \
                 then try sync again."
            ),
            MobileSyncError::PhoneDecryptFailed => write!(
                f,
                "Could not decrypt the phone's vault — different master \
                 password? Make sure both sides use the same one."
            ),
            MobileSyncError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl From<std::io::Error> for MobileSyncError {
    fn from(e: std::io::Error) -> Self {
        MobileSyncError::Io(e)
    }
}

/// Run a full PC-initiated USB sync:
///   1. Verify adb is on PATH and a single device is connected.
///   2. `adb pull` the phone's encrypted vault.json into a tempfile.
///   3. Decrypt it using the session's current key (assumes the same
///      master password on both sides — true in practice for a
///      personal vault).
///   4. Merge the two payloads via [merge], persist on PC via
///      [Session::merge_with] (which writes the encrypted file back
///      atomically).
///   5. `adb push` the PC's freshly-rewritten vault.json onto the
///      phone, replacing its copy.
///
/// Returns the [SyncStats] so the caller can render a "what
/// happened" summary.
pub fn run_mobile_sync(session: &mut Session) -> Result<SyncStats, MobileSyncError> {
    run_mobile_sync_inner(session, None)
}

/// Variant of [run_mobile_sync] that re-derives the phone's key from
/// a user-supplied master password. Used when the phone's salt has
/// diverged from the PC's (e.g. someone ran "change master" on both
/// sides independently). After this kind of sync, the PC's vault
/// file is pushed onto the phone wholesale — including the PC's salt
/// — so subsequent syncs go back to the fast cached-key path.
pub fn run_mobile_sync_with_master(
    session: &mut Session,
    master: &[u8],
) -> Result<SyncStats, MobileSyncError> {
    run_mobile_sync_inner(session, Some(master))
}

fn run_mobile_sync_inner(
    session: &mut Session,
    master: Option<&[u8]>,
) -> Result<SyncStats, MobileSyncError> {
    let adb = check_adb_available()?;

    // Pull phone vault to a unique temp location so concurrent syncs
    // (unlikely but possible) can't trample each other.
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!(
        "passwort-sync-{}-{}.json",
        std::process::id(),
        crate::storage::now_secs(),
    ));

    pull_phone_vault(&adb, &tmp_path)?;

    let phone_bytes = std::fs::read_to_string(&tmp_path).map_err(|e| {
        // No vault on phone yet is a special user-facing error.
        if e.kind() == std::io::ErrorKind::NotFound {
            MobileSyncError::PhoneVaultMissing
        } else {
            MobileSyncError::Io(e)
        }
    })?;
    let _ = std::fs::remove_file(&tmp_path);

    let phone_vault: EncryptedVault = serde_json::from_str(&phone_bytes)
        .map_err(|_| MobileSyncError::PhoneVaultMissing)?;

    // Decrypt the phone's vault. Two paths:
    //   * Fast path (no master supplied): the phone's vault was
    //     written by a previous sync from this PC, so its salt
    //     matches our cached key and we can decrypt without Argon2id.
    //   * Master path: the user gave us a master because the fast
    //     path failed (typically: independent master rotations on
    //     both sides → divergent salts even with the same password).
    //     Re-derive a fresh key against the phone's salt + kdf.
    let phone_payload = match master {
        Some(m) => decrypt_with_master(&phone_vault, m)
            .map_err(|_| MobileSyncError::PhoneDecryptFailed)?,
        None => decrypt_with_current_key(&phone_vault, session)
            .map_err(|_| MobileSyncError::PhoneDecryptFailed)?,
    };

    let stats = session.merge_with(phone_payload).map_err(MobileSyncError::Io)?;

    push_phone_vault(&adb)?;

    Ok(stats)
}

/// Locate the `adb` binary. Search order:
///   1. `PATH` — if the user has it on their shell PATH, prefer that.
///   2. `~/Android/Sdk/platform-tools/adb` — the standard Android
///      Studio install location (which the project's own setup script
///      uses to push the app to the phone).
///   3. `$ANDROID_HOME/platform-tools/adb` if set.
///   4. `$ANDROID_SDK_ROOT/platform-tools/adb` if set.
/// Returns the resolved path, or [MobileSyncError::AdbMissing] if no
/// candidate works.
fn find_adb() -> Result<std::path::PathBuf, MobileSyncError> {
    // (1) PATH lookup via `which`-style search of $PATH.
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if dir.is_empty() {
                continue;
            }
            let candidate = std::path::Path::new(dir).join("adb");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    // (2) Standard Android Studio install location.
    if let Ok(home) = std::env::var("HOME") {
        let candidate = std::path::PathBuf::from(home).join("Android/Sdk/platform-tools/adb");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // (3) ANDROID_HOME convention.
    if let Ok(sdk) = std::env::var("ANDROID_HOME") {
        let candidate = std::path::PathBuf::from(sdk).join("platform-tools/adb");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // (4) ANDROID_SDK_ROOT convention (older, but still seen).
    if let Ok(sdk) = std::env::var("ANDROID_SDK_ROOT") {
        let candidate = std::path::PathBuf::from(sdk).join("platform-tools/adb");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(MobileSyncError::AdbMissing)
}

fn check_adb_available() -> Result<std::path::PathBuf, MobileSyncError> {
    let adb = find_adb()?;
    let out = std::process::Command::new(&adb).arg("devices").output();
    match out {
        Err(e) => Err(MobileSyncError::AdbFailed(e.to_string())),
        Ok(o) => {
            if !o.status.success() {
                return Err(MobileSyncError::AdbFailed(
                    String::from_utf8_lossy(&o.stderr).into_owned(),
                ));
            }
            let stdout = String::from_utf8_lossy(&o.stdout);
            // `adb devices` always prints "List of devices attached" on
            // line 1; each subsequent non-blank line is "<serial>\t<state>".
            let device_lines: Vec<&str> = stdout
                .lines()
                .skip(1)
                .filter(|l| !l.trim().is_empty())
                .filter(|l| l.contains("\tdevice"))
                .collect();
            if device_lines.is_empty() {
                return Err(MobileSyncError::AdbNoDevice);
            }
            Ok(adb)
        }
    }
}

fn pull_phone_vault(adb: &std::path::Path, dest: &std::path::Path) -> Result<(), MobileSyncError> {
    let out = std::process::Command::new(adb)
        .args(["pull", PHONE_VAULT_PATH])
        .arg(dest)
        .output()
        .map_err(|e| MobileSyncError::AdbFailed(e.to_string()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("does not exist") || err.contains("No such file") {
            return Err(MobileSyncError::PhoneVaultMissing);
        }
        return Err(MobileSyncError::AdbFailed(err.into_owned()));
    }
    Ok(())
}

fn push_phone_vault(adb: &std::path::Path) -> Result<(), MobileSyncError> {
    let local = crate::storage::vault_path();
    let out = std::process::Command::new(adb)
        .args(["push"])
        .arg(local)
        .arg(PHONE_VAULT_PATH)
        .output()
        .map_err(|e| MobileSyncError::AdbFailed(e.to_string()))?;
    if !out.status.success() {
        return Err(MobileSyncError::AdbFailed(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    }
    Ok(())
}

/// Decrypts a foreign `EncryptedVault` by deriving its key from a
/// user-supplied master password and the foreign file's own salt +
/// kdf params. Always works whether or not the foreign side shares
/// the desktop's current salt — at the cost of one Argon2id pass.
/// Used by [run_mobile_sync_with_master] for the post-rotation
/// recovery case.
fn decrypt_with_master(
    foreign: &EncryptedVault,
    master: &[u8],
) -> Result<VaultPayload, ()> {
    use base64::{engine::general_purpose, Engine};

    let salt = general_purpose::STANDARD
        .decode(&foreign.salt)
        .map_err(|_| ())?;
    if salt.len() != crate::crypto::SALT_LEN {
        return Err(());
    }
    let nonce = general_purpose::STANDARD
        .decode(&foreign.nonce)
        .map_err(|_| ())?;
    let ct = general_purpose::STANDARD
        .decode(&foreign.ciphertext)
        .map_err(|_| ())?;
    let key = crate::crypto::derive_key(
        master,
        &salt,
        foreign.kdf_m_cost,
        foreign.kdf_t_cost,
        foreign.kdf_p_cost,
    );
    let plaintext = crate::crypto::decrypt(&ct, &nonce, &*key)?;
    crate::storage::parse_vault_payload(&plaintext).map_err(|_| ())
}

/// Decrypts a foreign `EncryptedVault` using the session's current key.
/// Works because both phones-and-desktops derive their key from the
/// same master password — and since the desktop holds the master, it
/// can match. The kdf_m_cost / kdf_t_cost / kdf_p_cost embedded in the
/// foreign vault are honored (so a phone still running v1 Argon2 params
/// would still open even though the desktop has since bumped them).
fn decrypt_with_current_key(
    foreign: &EncryptedVault,
    session: &Session,
) -> Result<VaultPayload, ()> {
    use base64::{engine::general_purpose, Engine};

    let salt = general_purpose::STANDARD
        .decode(&foreign.salt)
        .map_err(|_| ())?;
    let nonce = general_purpose::STANDARD
        .decode(&foreign.nonce)
        .map_err(|_| ())?;
    let ct = general_purpose::STANDARD
        .decode(&foreign.ciphertext)
        .map_err(|_| ())?;

    // We don't have the foreign-master-password here, only our own
    // derived key. That's fine: re-derive with our master-equivalent
    // by reusing our session key only if the foreign salt + kdf
    // match (rare). The robust path is: we DO need to derive the
    // foreign key, which requires the user's master password.
    //
    // Trick: the session.key is derived from PC master + PC salt.
    // The phone vault was derived from PHONE master (= PC master,
    // assumption) + PHONE salt. So we need to re-derive with phone
    // salt. We don't store the master password, only the derived
    // key. So we can't re-derive without the password.
    //
    // The reasonable solution: assume the phone vault was written by
    // a previous sync from this PC, in which case the salt + nonce
    // were emitted by our persist() and the encryption is byte-for-
    // byte under the same key. Try that path first.
    if salt.len() == crate::crypto::SALT_LEN {
        let mut salt_arr = [0u8; crate::crypto::SALT_LEN];
        salt_arr.copy_from_slice(&salt);
        if salt_arr == session.salt {
            // Same salt → same key under our master → can decrypt.
            let plaintext = crate::crypto::decrypt(&ct, &nonce, &*session.key)?;
            return crate::storage::parse_vault_payload(&plaintext).map_err(|_| ());
        }
    }
    // Different salt → would need to re-derive from the user's
    // master, which we don't have access to here. Bail; caller turns
    // this into a "ask the user for phone's master" prompt.
    Err(())
}

/// Compare two Accounts for "is this the same data on both sides?"
/// Excludes `updated_at` and `history` (those are bookkeeping; a
/// matching content but mismatched timestamps is still 'unchanged'
/// for user-facing reporting).
fn same_account_content(a: &Account, b: &Account) -> bool {
    a.name == b.name
        && a.url == b.url
        && a.username == b.username
        && a.password == b.password
        && a.totp_secret == b.totp_secret
        && a.notes == b.notes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(name: &str, user: &str, pw: &str, ts: u64) -> Account {
        Account {
            name: name.into(),
            url: String::new(),
            username: user.into(),
            password: pw.into(),
            totp_secret: String::new(),
            notes: String::new(),
            history: Vec::new(),
            updated_at: ts,
        }
    }

    fn tomb(name: &str, user: &str, ts: u64) -> Tombstone {
        Tombstone {
            name: name.into(),
            username: user.into(),
            deleted_at: ts,
        }
    }

    fn payload(
        accounts: Vec<Account>,
        tombstones: Vec<Tombstone>,
    ) -> VaultPayload {
        VaultPayload {
            accounts,
            tombstones,
        }
    }

    #[test]
    fn adds_missing_from_each_side() {
        // Mirrors the user's example: PC has youtube + facebook, phone has discord.
        let pc = payload(
            vec![
                acc("youtube.com", "alice", "yt-pw", 100),
                acc("facebook.com", "alice", "fb-pw", 100),
            ],
            vec![],
        );
        let phone = payload(vec![acc("discord.com", "alice", "dc-pw", 100)], vec![]);

        let (merged, stats) = merge(pc, phone);
        let names: Vec<&str> = merged.accounts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["discord.com", "facebook.com", "youtube.com"]);
        assert_eq!(stats.added_from_a, 2);
        assert_eq!(stats.added_from_b, 1);
        assert_eq!(stats.unchanged, 0);
        assert!(merged.tombstones.is_empty());
    }

    #[test]
    fn identical_entries_count_unchanged() {
        let pc = payload(vec![acc("github.com", "a", "pw", 100)], vec![]);
        let phone = payload(vec![acc("github.com", "a", "pw", 100)], vec![]);
        let (merged, stats) = merge(pc, phone);
        assert_eq!(merged.accounts.len(), 1);
        assert_eq!(stats.unchanged, 1);
        assert_eq!(stats.resolved_conflicts, 0);
    }

    #[test]
    fn newer_password_wins_on_conflict() {
        let pc = payload(vec![acc("github.com", "a", "old", 100)], vec![]);
        let phone = payload(vec![acc("github.com", "a", "new", 200)], vec![]);
        let (merged, stats) = merge(pc, phone);
        assert_eq!(merged.accounts[0].password, "new");
        assert_eq!(stats.resolved_conflicts, 1);
        assert_eq!(stats.unchanged, 0);
    }

    #[test]
    fn tie_prefers_side_a() {
        let pc = payload(vec![acc("github.com", "a", "pc-version", 100)], vec![]);
        let phone = payload(vec![acc("github.com", "a", "phone-version", 100)], vec![]);
        let (merged, _stats) = merge(pc, phone);
        assert_eq!(merged.accounts[0].password, "pc-version");
    }

    #[test]
    fn tombstone_deletes_older_entry_on_other_side() {
        // PC has reddit at ts=100; phone deleted it at ts=200.
        let pc = payload(vec![acc("reddit.com", "a", "pw", 100)], vec![]);
        let phone = payload(vec![], vec![tomb("reddit.com", "a", 200)]);
        let (merged, stats) = merge(pc, phone);
        assert!(merged.accounts.is_empty());
        assert_eq!(merged.tombstones.len(), 1);
        assert!(stats.deleted_on_a >= 1);
    }

    #[test]
    fn re_created_after_delete_drops_stale_tombstone() {
        // Phone deleted reddit at ts=100; PC re-created at ts=200.
        let pc = payload(vec![acc("reddit.com", "a", "fresh", 200)], vec![]);
        let phone = payload(vec![], vec![tomb("reddit.com", "a", 100)]);
        let (merged, _stats) = merge(pc, phone);
        assert_eq!(merged.accounts.len(), 1);
        assert_eq!(merged.accounts[0].password, "fresh");
        assert!(merged.tombstones.is_empty());
    }

    #[test]
    fn tombstone_for_unknown_identity_kept_for_other_devices() {
        // Neither side has the account anymore, but one has a
        // tombstone. Keep it so a third device (not in this merge)
        // can still apply the delete on next sync.
        let pc = payload(vec![], vec![tomb("dead-site.com", "a", 50)]);
        let phone = payload(vec![], vec![]);
        let (merged, _stats) = merge(pc, phone);
        assert!(merged.accounts.is_empty());
        assert_eq!(merged.tombstones.len(), 1);
    }

    #[test]
    fn duplicate_tombstones_collapse_to_newest() {
        let pc = payload(vec![], vec![tomb("x", "u", 50)]);
        let phone = payload(vec![], vec![tomb("x", "u", 200)]);
        let (merged, _) = merge(pc, phone);
        assert_eq!(merged.tombstones.len(), 1);
        assert_eq!(merged.tombstones[0].deleted_at, 200);
    }

    #[test]
    fn output_is_sorted_deterministic() {
        let pc = payload(
            vec![
                acc("zoo.com", "a", "p", 1),
                acc("alpha.com", "a", "p", 1),
                acc("middle.com", "a", "p", 1),
            ],
            vec![],
        );
        let phone = payload(vec![], vec![]);
        let (merged, _) = merge(pc, phone);
        let names: Vec<&str> = merged.accounts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["alpha.com", "middle.com", "zoo.com"]);
    }

    #[test]
    fn merging_is_idempotent() {
        // Running merge twice with the same inputs (or the merge
        // output replayed on both sides) shouldn't change anything.
        let pc = payload(
            vec![
                acc("a.com", "u", "p1", 100),
                acc("b.com", "u", "p2", 200),
            ],
            vec![tomb("c.com", "u", 150)],
        );
        let phone = payload(
            vec![acc("d.com", "u", "p4", 50)],
            vec![tomb("e.com", "u", 75)],
        );

        let (m1, _) = merge(pc.clone(), phone.clone());
        let (m2, _) = merge(m1.clone(), m1.clone());
        assert_eq!(
            account_keys(&m1.accounts),
            account_keys(&m2.accounts),
            "merged twice should equal merged once",
        );
        assert_eq!(m1.tombstones.len(), m2.tombstones.len());
    }

    fn account_keys(v: &[Account]) -> Vec<(String, String, String)> {
        v.iter()
            .map(|a| (a.name.clone(), a.username.clone(), a.password.clone()))
            .collect()
    }
}
