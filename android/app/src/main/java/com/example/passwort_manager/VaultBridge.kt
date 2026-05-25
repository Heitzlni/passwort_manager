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

    /** Re-encrypt a fresh payload (accounts + tombstones) using the
     *  cached key + the current file's salt/kdf params, return the
     *  new on-disk vault.json content. The Kotlin caller writes it. */
    @JvmStatic
    external fun saveVault(
        currentFile: ByteArray,
        key: ByteArray,
        payloadJson: String,
    ): String

    /** Decrypt the vault with the cached `oldKey`, derive a fresh key
     *  under the new master, re-encrypt, return the new vault file
     *  bytes + the new derived key. */
    @JvmStatic
    external fun rotateMaster(
        currentFile: ByteArray,
        oldKey: ByteArray,
        newMaster: ByteArray,
    ): String

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

    /** Build the v2 VaultPayload JSON (`{accounts: [...], tombstones:
     *  [...]}`) that the Rust side and the desktop both expect. */
    fun buildPayloadJson(accounts: List<Account>, tombstones: List<Tombstone>): String {
        val obj = JSONObject()
        val accArr = JSONArray()
        for (a in accounts) {
            accArr.put(
                JSONObject().apply {
                    put("name", a.name)
                    put("url", a.url)
                    put("username", a.username)
                    put("password", a.password)
                    put("totp_secret", a.totpSecret)
                    put("notes", a.notes)
                    put("history", JSONArray()) // history only managed on desktop for now
                    put("updated_at", a.updatedAt)
                },
            )
        }
        val tombArr = JSONArray()
        for (t in tombstones) {
            tombArr.put(
                JSONObject().apply {
                    put("name", t.name)
                    put("username", t.username)
                    put("deleted_at", t.deletedAt)
                },
            )
        }
        obj.put("accounts", accArr)
        obj.put("tombstones", tombArr)
        return obj.toString()
    }

    /** Encrypt a fresh payload and return the new vault.json bytes
     *  ready for atomic write. Returns null on failure. */
    fun save(
        currentFile: ByteArray,
        key: ByteArray,
        accounts: List<Account>,
        tombstones: List<Tombstone>,
    ): ByteArray? {
        val payload = buildPayloadJson(accounts, tombstones)
        val envelope = try {
            saveVault(currentFile, key, payload)
        } catch (_: Throwable) {
            return null
        }
        val obj = try {
            JSONObject(envelope)
        } catch (_: Exception) {
            return null
        }
        if (obj.has("err")) return null
        val fileJson = obj.optString("ok", "")
        if (fileJson.isEmpty()) return null
        return fileJson.toByteArray(Charsets.UTF_8)
    }

    /** Change the master password. Returns the new file bytes and
     *  freshly-derived key on success; null on failure (typically
     *  because the supplied `oldKey` doesn't decrypt the current
     *  file, which we report to the user as "wrong current master").
     */
    fun rotate(
        currentFile: ByteArray,
        oldKey: ByteArray,
        newMaster: String,
    ): Pair<ByteArray, ByteArray>? {
        val newBytes = newMaster.toByteArray(Charsets.UTF_8)
        val envelope = try {
            rotateMaster(currentFile, oldKey, newBytes)
        } catch (_: Throwable) {
            newBytes.fill(0)
            return null
        } finally {
            newBytes.fill(0)
        }
        val obj = try {
            JSONObject(envelope)
        } catch (_: Exception) {
            return null
        }
        if (obj.has("err")) return null
        val fileJson = obj.optString("ok", "")
        val keyB64 = obj.optString("key", "")
        if (fileJson.isEmpty() || keyB64.isEmpty()) return null
        val newKey = try {
            Base64.decode(keyB64, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            return null
        }
        return fileJson.toByteArray(Charsets.UTF_8) to newKey
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

/** Marks an entry the user deleted on this device, so a cross-device
 *  sync can propagate the deletion. Matches the Rust schema and is
 *  emitted as the `tombstones` array inside the v2 VaultPayload. */
data class Tombstone(
    val name: String,
    val username: String,
    val deletedAt: Long,
)

sealed class UnlockResult {
    data class Success(val accounts: List<Account>, val derivedKey: ByteArray?) : UnlockResult()
    data class Failure(val message: String) : UnlockResult()
}
