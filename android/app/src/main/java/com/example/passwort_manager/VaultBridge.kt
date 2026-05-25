package com.example.passwort_manager

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

    /** Decrypt a vault file and return the accounts list, or an error. */
    fun unlock(vaultJsonBytes: ByteArray, masterPassword: String): UnlockResult {
        val passwordBytes = masterPassword.toByteArray(Charsets.UTF_8)
        val envelope = try {
            unlockVault(vaultJsonBytes, passwordBytes)
        } catch (t: Throwable) {
            return UnlockResult.Failure("native crash: ${t.message}")
        } finally {
            // Best-effort wipe of the password bytes we just sent over.
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
        return UnlockResult.Success(parseAccounts(arr))
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
    data class Success(val accounts: List<Account>) : UnlockResult()
    data class Failure(val message: String) : UnlockResult()
}
