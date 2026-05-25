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

    /** Derived AES key from the most recent unlock, used for silent
     *  file re-reads when sync rewrites vault.json underneath us.
     *  Lives only as long as `accounts.value != null`; wiped on lock. */
    private var derivedKey: ByteArray? = null

    /** Last vault.json mtime we successfully read, for change detection. */
    private var lastVaultMtime: Long = 0L

    val isUnlocked: Boolean get() = accounts.value != null

    fun unlock(list: List<Account>, derivedKey: ByteArray?, vaultFile: File?) {
        accounts.value = list
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
