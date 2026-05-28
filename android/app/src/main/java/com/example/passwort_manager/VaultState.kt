package com.example.passwort_manager

import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.mutableStateOf
import java.io.File

/**
 * Process-scoped store for the unlocked vault.
 *
 * Holds the decrypted account list and a sliding-window auto-lock timer
 * (default 5 min). Touched by:
 *   - MainActivity        (manual unlock + lock; the main UI)
 *   - AutofillActivity    (autofill-triggered unlock)
 *   - PasswortAutofillService (reads the list to satisfy fill requests)
 *
 * No persistent storage — when Android kills our process, the state
 * vanishes and the next caller has to re-unlock. That's the right
 * trade-off for a personal manager: we never pay the audit-burden of
 * keeping a decryption key alive across reboots.
 */
object VaultState {
    /// Default idle window before we wipe the in-memory accounts.
    private const val DEFAULT_AUTO_LOCK_MS = 5L * 60L * 1000L

    private val mainHandler = Handler(Looper.getMainLooper())
    private var lockRunnable: Runnable? = null
    private var autoLockMs = DEFAULT_AUTO_LOCK_MS

    /** Observable so Compose recomposes when the lock state flips. */
    val accounts = mutableStateOf<List<Account>?>(null)

    /** Tombstones (soft-deletes) maintained while unlocked. Pushed to
     *  the file via [persistTo] on every write so sync can propagate
     *  the deletion. Loaded from the file on next implementation pass
     *  — for now we only emit them. */
    val tombstones = mutableStateOf<List<Tombstone>>(emptyList())

    /** Derived AES key from the most recent unlock, used for silent
     *  file re-reads when sync rewrites vault.json underneath us.
     *  Lives only as long as `accounts.value != null`; wiped on lock. */
    private var derivedKey: ByteArray? = null

    /** Last vault.json mtime we successfully read, for change detection. */
    private var lastVaultMtime: Long = 0L

    val isUnlocked: Boolean get() = accounts.value != null

    fun unlock(list: List<Account>, derivedKey: ByteArray?, vaultFile: File?) {
        accounts.value = list
        this.tombstones.value = emptyList() // freshly loaded — see TODO below
        this.derivedKey = derivedKey?.copyOf()
        this.lastVaultMtime = vaultFile?.lastModified() ?: 0L
        rearmAutoLock()
    }

    fun lock() {
        // Reassign rather than mutate — Compose observes the value
        // identity, and Account is a value type so we want the old
        // list to drop out of scope so its strings can be GC'd. The
        // OS still gets to keep copies in clipboard etc. — wiping
        // those is on the caller.
        accounts.value = null
        tombstones.value = emptyList()
        // Zero the cached key bytes before dropping the reference so a
        // memory dump after lock has nothing left to find. (The
        // accounts list itself contains the actual secrets — those
        // can't be wiped this aggressively because Compose held a
        // reference, but at least the key is cleaned.)
        derivedKey?.fill(0)
        derivedKey = null
        lastVaultMtime = 0L
        cancelAutoLock()
    }

    // ===================== Write path =====================

    /** Outcome of a write attempt. */
    sealed class WriteResult {
        object Ok : WriteResult()
        data class Failed(val message: String) : WriteResult()
    }

    /** Insert a new account. Stamps updated_at = now; clears any
     *  matching tombstone (re-creating a previously-deleted entry). */
    fun addAccount(account: Account, vaultFile: File): WriteResult {
        if (!isUnlocked) return WriteResult.Failed("vault is locked")
        val current = accounts.value.orEmpty()
        val now = System.currentTimeMillis() / 1000
        val stamped = account.copy(updatedAt = now)
        val newList = current + stamped
        val newTombs = tombstones.value.filterNot {
            it.name == stamped.name && it.username == stamped.username
        }
        return persistTo(newList, newTombs, vaultFile)
    }

    /** Update an account at [idx]. Stamps updated_at = now. */
    fun editAccount(idx: Int, replacement: Account, vaultFile: File): WriteResult {
        if (!isUnlocked) return WriteResult.Failed("vault is locked")
        val current = accounts.value.orEmpty()
        if (idx !in current.indices) return WriteResult.Failed("entry index out of range")
        val now = System.currentTimeMillis() / 1000
        val stamped = replacement.copy(updatedAt = now)
        val newList = current.toMutableList().apply { this[idx] = stamped }
        return persistTo(newList, tombstones.value, vaultFile)
    }

    /** Remove an account and push a tombstone so sync propagates. */
    fun deleteAccount(idx: Int, vaultFile: File): WriteResult {
        if (!isUnlocked) return WriteResult.Failed("vault is locked")
        val current = accounts.value.orEmpty()
        if (idx !in current.indices) return WriteResult.Failed("entry index out of range")
        val removed = current[idx]
        val now = System.currentTimeMillis() / 1000
        val newList = current.toMutableList().apply { removeAt(idx) }
        val newTombs = tombstones.value.filterNot {
            it.name == removed.name && it.username == removed.username
        } + Tombstone(removed.name, removed.username, now)
        return persistTo(newList, newTombs, vaultFile)
    }

    /**
     * Change the master password. Re-derives a fresh key from
     * [newMaster] + a fresh salt under the current desktop KDF
     * params, re-encrypts the existing payload, atomically writes
     * the new vault.json, and replaces the in-memory cached key.
     *
     * Returns Failed("wrong current master") if [currentMaster]
     * doesn't decrypt the current file (i.e. someone is impersonating
     * the authenticated user). Biometric wrapped master + Keystore
     * key are wiped since both were tied to the old key.
     */
    fun changeMaster(
        currentMaster: String,
        newMaster: String,
        vaultFile: File,
    ): WriteResult {
        if (!isUnlocked) return WriteResult.Failed("vault is locked")
        val key = derivedKey ?: return WriteResult.Failed("no cached key (unlock again)")
        if (!vaultFile.exists()) return WriteResult.Failed("vault file disappeared")
        val currentBytes = try {
            vaultFile.readBytes()
        } catch (e: Exception) {
            return WriteResult.Failed("read failed: ${e.message}")
        }

        // Verify current master by deriving its key + decrypting the
        // current file. Slow (Argon2id), but it's the right gate for
        // a high-value action.
        val verify = VaultBridge.unlock(currentBytes, currentMaster)
        if (verify !is UnlockResult.Success) {
            return WriteResult.Failed("Current master password is wrong.")
        }
        // Tidy: zero the temporary derived key we just unboxed.
        verify.derivedKey?.fill(0)

        // Rotate.
        val rotated = VaultBridge.rotate(currentBytes, key, newMaster)
            ?: return WriteResult.Failed("Encrypt failed during master rotation.")
        val (newFileBytes, newKey) = rotated

        val tmp = File(vaultFile.parentFile, "vault.json.tmp")
        try {
            tmp.outputStream().use { it.write(newFileBytes) }
            if (!tmp.renameTo(vaultFile)) {
                tmp.delete()
                newKey.fill(0)
                return WriteResult.Failed("Atomic rename failed.")
            }
        } catch (e: Exception) {
            tmp.delete()
            newKey.fill(0)
            return WriteResult.Failed("Write failed: ${e.message}")
        }

        // Swap the in-memory cached key under our feet, zero the old.
        derivedKey?.fill(0)
        derivedKey = newKey
        lastVaultMtime = vaultFile.lastModified()
        rearmAutoLock()

        // The biometric wrapped master + Keystore key were tied to
        // the OLD master — wipe both. The user will re-enroll on
        // their next master-password unlock if biometric is on.
        AppSettings.clearWrappedMaster()
        KeystoreCipher.wipeKey()

        return WriteResult.Ok
    }

    private fun persistTo(
        newAccounts: List<Account>,
        newTombstones: List<Tombstone>,
        vaultFile: File,
    ): WriteResult {
        val key = derivedKey ?: return WriteResult.Failed("no cached key (unlock again)")
        if (!vaultFile.exists()) return WriteResult.Failed("vault file disappeared")
        val current = try {
            vaultFile.readBytes()
        } catch (e: Exception) {
            return WriteResult.Failed("read failed: ${e.message}")
        }
        val newBytes = VaultBridge.save(current, key, newAccounts, newTombstones)
            ?: return WriteResult.Failed("encrypt failed")
        val tmp = File(vaultFile.parentFile, "vault.json.tmp")
        try {
            tmp.outputStream().use { it.write(newBytes) }
            if (!tmp.renameTo(vaultFile)) {
                tmp.delete()
                return WriteResult.Failed("atomic rename failed")
            }
        } catch (e: Exception) {
            tmp.delete()
            return WriteResult.Failed("write failed: ${e.message}")
        }
        accounts.value = newAccounts
        tombstones.value = newTombstones
        // Bump our seen mtime so the live-refresh ticker doesn't try
        // to re-decrypt the file we just wrote.
        lastVaultMtime = vaultFile.lastModified()
        rearmAutoLock()
        return WriteResult.Ok
    }

    /** Bump the auto-lock timer — call on every vault-touching action. */
    fun touch() {
        if (isUnlocked) rearmAutoLock()
    }

    fun setAutoLockTimeoutMs(ms: Long) {
        autoLockMs = ms.coerceAtLeast(15_000L) // never go shorter than 15s
        if (isUnlocked) rearmAutoLock()
    }

    private fun rearmAutoLock() {
        cancelAutoLock()
        val r = Runnable { lock() }
        lockRunnable = r
        mainHandler.postDelayed(r, autoLockMs)
    }

    private fun cancelAutoLock() {
        lockRunnable?.let { mainHandler.removeCallbacks(it) }
        lockRunnable = null
    }

    /**
     * Silent live-refresh: if the on-disk vault.json's mtime has
     * advanced since the last unlock/refresh, re-decrypt with the
     * cached AES key and update the visible accounts list. Used by
     * a periodic ticker on the main screen so a PC-initiated sync
     * appears without the user having to lock + unlock manually.
     *
     * Returns one of:
     *   - [RefreshResult.NoChange]  — file hasn't moved, nothing done
     *   - [RefreshResult.Refreshed] — accounts updated in place
     *   - [RefreshResult.NeedsUnlock] — cached key no longer decrypts
     *     the file (typically because the PC rotated the master),
     *     vault was force-locked so the UI can prompt for master
     */
    fun refreshIfChanged(vaultFile: File): RefreshResult {
        if (!isUnlocked) return RefreshResult.NoChange
        val key = derivedKey ?: return RefreshResult.NoChange
        if (!vaultFile.exists()) return RefreshResult.NoChange

        val mtime = vaultFile.lastModified()
        if (mtime == 0L || mtime <= lastVaultMtime) return RefreshResult.NoChange

        val bytes = try {
            vaultFile.readBytes()
        } catch (_: Exception) {
            return RefreshResult.NoChange
        }

        val refreshed = VaultBridge.refresh(bytes, key)
        return if (refreshed == null) {
            // Cached key no longer matches — typically because the
            // PC changed master / rotated the salt. The user needs
            // to re-enter master to derive a new key.
            lock()
            RefreshResult.NeedsUnlock
        } else {
            accounts.value = refreshed
            lastVaultMtime = mtime
            rearmAutoLock()
            RefreshResult.Refreshed
        }
    }

    /** Lookup helper used by the autofill service. */
    fun findByHost(host: String): List<Account> {
        if (host.isBlank()) return emptyList()
        val needle = host.lowercase()
        return accounts.value.orEmpty().filter { entryMatchesHost(it, needle) }
    }

    /**
     * Broader autofill-match used for native apps where the package
     * name is the only signal we have. Tries (in order):
     *   1. The exact `webDomain` from the form, if any.
     *   2. A `<brand>.com` reconstruction from the package
     *      (`com.spotify.music` → `spotify.com`).
     *   3. An entry-name substring match against the package's
     *      "brand" segment, normalised to letters+digits — catches
     *      cases like an entry called "Spotify Family" matching
     *      package `com.spotify.music`.
     *
     * Tighter than fuzzy matching (we don't show every entry); only
     * fires when the package brand is at least 3 chars to avoid
     * everything matching common 1–2 letter prefixes.
     */
    fun findByHostOrPackage(webDomain: String, packageName: String): List<Account> {
        val accs = accounts.value.orEmpty()
        if (accs.isEmpty()) return emptyList()

        // 1) Strict web match if we have a webDomain.
        if (webDomain.isNotBlank()) {
            val byHost = accs.filter { entryMatchesHost(it, webDomain.lowercase()) }
            if (byHost.isNotEmpty()) return byHost
        }

        // 2 + 3) Try the package brand.
        val brand = packageBrand(packageName)
        if (brand.length < 3) return emptyList()

        // 2) Strict <brand>.com host match.
        val byBrandHost = accs.filter { entryMatchesHost(it, "$brand.com") }
        if (byBrandHost.isNotEmpty()) return byBrandHost

        // 3) Entry-name fuzzy match — only if the entry's name
        // contains the brand and the brand isn't a generic word.
        if (brand in GENERIC_PKG_SEGMENTS) return emptyList()
        return accs.filter { acc ->
            val normalised = acc.name.lowercase().filter { it.isLetterOrDigit() }
            normalised.isNotEmpty() && normalised.contains(brand)
        }
    }

    /** Pick the most-likely-brand segment from a package name like
     *  `com.spotify.music`. Drops generic stems (`com`, `app`,
     *  `android`, …) and returns the first meaningful segment. */
    private fun packageBrand(packageName: String): String {
        if (packageName.isBlank()) return ""
        val parts = packageName.split('.').map { it.lowercase() }
        return parts.firstOrNull { it.length >= 3 && it !in GENERIC_PKG_SEGMENTS }.orEmpty()
    }

    private val GENERIC_PKG_SEGMENTS = setOf(
        "com", "org", "net", "io", "co", "app", "android", "google",
        "samsung", "huawei", "oneplus", "xiaomi", "oppo", "vivo",
    )

    /** Mirror of `entry_matches_host` in src/ipc.rs — same matching rule. */
    private fun entryMatchesHost(a: Account, host: String): Boolean {
        val urlHost = hostFromUrl(a.url)
        if (urlHost.isNotEmpty()) return matchesHost(urlHost, host)
        return matchesHost(a.name, host)
    }

    private fun matchesHost(saved: String, host: String): Boolean {
        val s = saved.trim().lowercase()
        val h = host.trim().lowercase()
        if (s.isEmpty() || h.isEmpty()) return false
        return s == h || h.endsWith(".$s")
    }

    /** Outcome of a silent refresh attempt — drives the UI when a
     *  sync-pushed vault file appears underneath us. */
    enum class RefreshResult { NoChange, Refreshed, NeedsUnlock }

    private fun hostFromUrl(url: String): String {
        val s = url.trim()
        if (s.isEmpty()) return ""
        val afterScheme = s.substringAfter("://", s)
        val hostPart = afterScheme.split('/', '?', '#').first()
        val noUserInfo = hostPart.substringAfterLast('@')
        // strip :port only if trailing component is digits
        val lastColon = noUserInfo.lastIndexOf(':')
        val host = if (lastColon > 0 && noUserInfo.substring(lastColon + 1).all { it.isDigit() }) {
            noUserInfo.substring(0, lastColon)
        } else {
            noUserInfo
        }
        return host.lowercase()
    }
}
