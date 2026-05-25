package com.example.passwort_manager

import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.mutableStateOf

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

    val isUnlocked: Boolean get() = accounts.value != null

    fun unlock(list: List<Account>) {
        accounts.value = list
        rearmAutoLock()
    }

    fun lock() {
        // Reassign rather than mutate — Compose observes the value
        // identity, and Account is a value type so we want the old
        // list to drop out of scope so its strings can be GC'd. The
        // OS still gets to keep copies in clipboard etc. — wiping
        // those is on the caller.
        accounts.value = null
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
