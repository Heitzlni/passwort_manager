package com.example.passwort_manager

import android.content.Context
import android.content.SharedPreferences

/**
 * App-level preferences backed by SharedPreferences. Holds the
 * couple of knobs the Settings screen exposes:
 *
 *   - Auto-lock timeout: how long the in-memory vault sits unlocked
 *     between actions before we wipe it (default 5 min).
 *   - Biometric unlock: whether to offer fingerprint unlock instead
 *     of master typing on every locked-screen entry.
 *
 * Initialised once in PasswortApp.onCreate so anything that touches
 * settings (VaultState's auto-lock timer, the Settings screen,
 * biometric flow) sees the same instance.
 *
 * Master password is NEVER stored here. Biometric unlock works by
 * wrapping the *derived* vault key behind the Android Keystore once
 * the user has typed the master at least once — Keystore handles
 * the protection, we don't keep the password.
 */
object AppSettings {
    private const val PREFS_NAME = "passwort_manager_prefs"
    private const val KEY_AUTO_LOCK_MINUTES = "auto_lock_minutes"
    private const val KEY_BIOMETRIC_ENABLED = "biometric_enabled"
    private const val KEY_WRAPPED_MASTER_IV = "wrapped_master_iv"
    private const val KEY_WRAPPED_MASTER_CT = "wrapped_master_ct"

    const val DEFAULT_AUTO_LOCK_MIN = 5
    private val ALLOWED_AUTO_LOCK_MIN = listOf(1, 5, 15, 30, 0) // 0 = never

    private lateinit var prefs: SharedPreferences

    fun init(context: Context) {
        if (!::prefs.isInitialized) {
            prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        }
    }

    var autoLockMinutes: Int
        get() = prefs.getInt(KEY_AUTO_LOCK_MINUTES, DEFAULT_AUTO_LOCK_MIN)
        set(value) {
            val clamped = if (value in ALLOWED_AUTO_LOCK_MIN) value else DEFAULT_AUTO_LOCK_MIN
            prefs.edit().putInt(KEY_AUTO_LOCK_MINUTES, clamped).apply()
            // Tell VaultState immediately so the change applies to the
            // currently-running unlock session.
            VaultState.setAutoLockTimeoutMs(toMillis(clamped))
        }

    var biometricEnabled: Boolean
        get() = prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, value).apply()

    /**
     * The master password is encrypted with a Keystore AES-GCM key
     * whose use requires biometric auth; we keep (iv, ciphertext) in
     * prefs. Encoded as base64 strings for SharedPreferences storage.
     */
    fun saveWrappedMaster(iv: ByteArray, ciphertext: ByteArray) {
        val b64 = android.util.Base64.NO_WRAP
        prefs.edit()
            .putString(KEY_WRAPPED_MASTER_IV, android.util.Base64.encodeToString(iv, b64))
            .putString(KEY_WRAPPED_MASTER_CT, android.util.Base64.encodeToString(ciphertext, b64))
            .apply()
    }

    fun loadWrappedMaster(): Pair<ByteArray, ByteArray>? {
        val iv = prefs.getString(KEY_WRAPPED_MASTER_IV, null) ?: return null
        val ct = prefs.getString(KEY_WRAPPED_MASTER_CT, null) ?: return null
        return try {
            android.util.Base64.decode(iv, android.util.Base64.NO_WRAP) to
                android.util.Base64.decode(ct, android.util.Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    fun clearWrappedMaster() {
        prefs.edit()
            .remove(KEY_WRAPPED_MASTER_IV)
            .remove(KEY_WRAPPED_MASTER_CT)
            .apply()
    }

    fun hasWrappedMaster(): Boolean = loadWrappedMaster() != null

    /** Human-readable label for the auto-lock choices in the UI. */
    fun autoLockLabel(minutes: Int): String = when (minutes) {
        0 -> "Never"
        1 -> "1 minute"
        else -> "$minutes minutes"
    }

    /** The set of choices the Settings screen offers. */
    fun autoLockChoices(): List<Int> = ALLOWED_AUTO_LOCK_MIN

    private fun toMillis(min: Int): Long =
        if (min <= 0) Long.MAX_VALUE / 2 else min * 60L * 1000L
}
