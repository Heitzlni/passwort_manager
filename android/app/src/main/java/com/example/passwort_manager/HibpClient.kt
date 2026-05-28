package com.example.passwort_manager

import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Have I Been Pwned (HIBP) "Pwned Passwords" k-anonymous lookup —
 * Kotlin port of `src/hibp.rs`. The exact same on-the-wire protocol:
 *
 *   1. SHA-1 the password locally.
 *   2. Send the first 5 hex chars of that hash to
 *      `https://api.pwnedpasswords.com/range/<prefix>`.
 *   3. Receive a list of every full hash that starts with those 5
 *      chars plus per-hash breach counts.
 *   4. Locally check whether OUR suffix (chars 6..40) is in the list.
 *
 * HIBP never sees the full hash and never sees the password.
 */
object HibpClient {

    private const val ENDPOINT = "https://api.pwnedpasswords.com/range/"
    private const val USER_AGENT = "passwort-manager-android-hibp/0.4"
    private const val TIMEOUT_MS = 10_000

    sealed class Result {
        /** Password found in N breaches (0 means clean). */
        data class Ok(val breachCount: Long) : Result()
        data class Error(val message: String) : Result()
    }

    /** Look up a single password. Network: one HTTPS GET. */
    fun check(password: String): Result {
        if (password.isEmpty()) return Result.Ok(0)
        val sha1Hex = sha1Hex(password.toByteArray(Charsets.UTF_8)).uppercase()
        val prefix = sha1Hex.substring(0, 5)
        val suffix = sha1Hex.substring(5)

        val conn = try {
            (URL(ENDPOINT + prefix).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                setRequestProperty("User-Agent", USER_AGENT)
            }
        } catch (e: Exception) {
            return Result.Error("network: ${e.message}")
        }

        return try {
            val code = conn.responseCode
            if (code != 200) {
                Result.Error("HTTP $code from HIBP")
            } else {
                conn.inputStream.bufferedReader().use { reader ->
                    for (line in reader.lineSequence()) {
                        val trimmed = line.trim()
                        if (trimmed.isEmpty()) continue
                        val parts = trimmed.split(':', limit = 2)
                        if (parts.size != 2) continue
                        if (parts[0].equals(suffix, ignoreCase = true)) {
                            return@use Result.Ok(parts[1].trim().toLongOrNull() ?: 1L)
                        }
                    }
                    Result.Ok(0L)
                }
            }
        } catch (e: Exception) {
            Result.Error("network: ${e.message}")
        } finally {
            conn.disconnect()
        }
    }

    private fun sha1Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-1")
        val digest = md.digest(bytes)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) {
            sb.append(HEX[(b.toInt() ushr 4) and 0xf])
            sb.append(HEX[b.toInt() and 0xf])
        }
        return sb.toString()
    }

    private val HEX = "0123456789abcdef".toCharArray()
}
