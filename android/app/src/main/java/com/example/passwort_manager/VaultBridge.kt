package com.example.passwort_manager

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/**
 * Bridge to the Rust crypto crate (libpasswort_jni.so).
 *
 * The Rust side returns a JSON envelope:
 *   {"ok": [<account>, ...]}  on success — array shape mirrors the
 *                             desktop client so a vault.json written on
 *                             Linux opens here unchanged.
 *   {"err": "<message>"}      on failure — bad password, corrupt vault,
 *                             parse error.
 *
 * We re-encode that into a sealed-class result so callers don't poke at
 * the JSON envelope directly.
 */
object VaultBridge {
    init {
        System.loadLibrary("passwort_jni")
    }

    /** Raw JNI entry point — see android/crypto/src/lib.rs. */
    @JvmStatic
    external fun unlockVault(vaultJson: ByteArray, password: ByteArray): String

    /** Silent re-decrypt with a previously-derived key (no password). */
    @JvmStatic
    external fun refreshVault(vaultJson: ByteArray, key: ByteArray): String

    /** Decrypt a vault file and return the accounts list + derived
     *  key, or an error. The key is cached by VaultState so we can
     *  silently re-decrypt the file when sync writes a new copy
     *  underneath us. */
    fun unlock(vaultJsonBytes: ByteArray, masterPassword: String): UnlockResult {
        val passwordBytes = masterPassword.toByteArray(Charsets.UTF_8)
        val envelope = try {
            unlockVault(vaultJsonBytes, passwordBytes)
        } catch (t: Throwable) {
            return UnlockResult.Failure("native crash: ${t.message}")
        } finally {
            passwordBytes.fill(0)
        }

        val obj = try {
            JSONObject(envelope)
        } catch (e: Exception) {
            return UnlockResult.Failure("bad response from native: ${e.message}")
        }
        if (obj.has("err")) {
            return UnlockResult.Failure(obj.optString("err", "unknown error"))
        }
        val arr = obj.optJSONArray("ok") ?: return UnlockResult.Failure("malformed response")
        val keyB64 = obj.optString("key", "")
        val key = if (keyB64.isNotEmpty()) {
            try {
                Base64.decode(keyB64, Base64.NO_WRAP)
            } catch (_: IllegalArgumentException) {
                null
            }
        } else null
        return UnlockResult.Success(parseAccounts(arr), derivedKey = key)
    }

    /** Re-decrypt the vault file with the cached key (no biometric,
     *  no password prompt). Used by the live-refresh ticker when the
     *  underlying file changes (e.g. PC sync just pushed a new copy).
     *  Returns null if the cached key no longer matches the file —
     *  caller should lock and force a master re-entry. */
    fun refresh(vaultJsonBytes: ByteArray, key: ByteArray): List<Account>? {
        val envelope = try {
            refreshVault(vaultJsonBytes, key)
        } catch (_: Throwable) {
            return null
        }
        val obj = try {
            JSONObject(envelope)
        } catch (_: Exception) {
            return null
        }
        if (obj.has("err")) return null
        val arr = obj.optJSONArray("ok") ?: return null
        return parseAccounts(arr)
    }

    private fun parseAccounts(arr: JSONArray): List<Account> {
        val out = ArrayList<Account>(arr.length())
        for (i in 0 until arr.length()) {
            val a = arr.getJSONObject(i)
            out += Account(
                name = a.optString("name"),
                url = a.optString("url"),
                username = a.optString("username"),
                password = a.optString("password"),
                totpSecret = a.optString("totp_secret"),
                notes = a.optString("notes"),
                updatedAt = a.optLong("updated_at", 0L),
            )
        }
        return out
    }
}

data class Account(
    val name: String,
    val url: String,
    val username: String,
    val password: String,
    val totpSecret: String,
    val notes: String,
    /** Vault format v2: Unix epoch seconds at last create/edit. */
    val updatedAt: Long = 0L,
)

sealed class UnlockResult {
    data class Success(val accounts: List<Account>, val derivedKey: ByteArray?) : UnlockResult()
    data class Failure(val message: String) : UnlockResult()
}
