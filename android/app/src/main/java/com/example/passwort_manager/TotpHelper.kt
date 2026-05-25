package com.example.passwort_manager

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 6238 TOTP — the same SHA1 / 6-digit / 30-second profile every
 * authenticator app uses by default, and the same one the Linux
 * `crypto::totp_code` produces. Implemented natively in Kotlin so we
 * don't have to round-trip through JNI for a 6-digit lookup.
 *
 * Input secret is the Base32-encoded string a user pastes from a 2FA
 * setup page (RFC 4648 alphabet, optionally with whitespace / dashes
 * / lowercase / padding — we tolerate all of them).
 */
object TotpHelper {

    private const val STEP_SECONDS = 30L
    private const val DIGITS = 6
    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    data class Code(val digits: String, val secondsRemaining: Long)

    /**
     * Compute the current TOTP for [base32Secret] at Unix time [now].
     * Returns null if the secret can't be decoded.
     */
    fun compute(base32Secret: String, now: Long): Code? {
        val key = decodeBase32(base32Secret) ?: return null
        if (key.isEmpty()) return null
        val counter = now / STEP_SECONDS
        val msg = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        val hash = mac.doFinal(msg)

        // RFC 4226 §5.3 dynamic truncation
        val offset = hash[hash.size - 1].toInt() and 0x0f
        val truncated = ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)
        val modulus = 1_000_000 // 10^DIGITS for DIGITS = 6
        val code = (truncated % modulus).toString().padStart(DIGITS, '0')
        val remaining = STEP_SECONDS - (now % STEP_SECONDS)
        return Code(code, remaining)
    }

    /** Strip whitespace / dashes / padding and decode the Base32 alphabet. */
    private fun decodeBase32(s: String): ByteArray? {
        val cleaned = s.uppercase()
            .filter { it != ' ' && it != '-' && it != '=' && !it.isWhitespace() }
        if (cleaned.isEmpty()) return null
        // Worst-case output size: ceil(input * 5 / 8). Allocate that and
        // copy out the used prefix.
        val buf = ByteArray(cleaned.length * 5 / 8)
        var bitBuffer = 0
        var bitCount = 0
        var pos = 0
        for (ch in cleaned) {
            val v = BASE32_ALPHABET.indexOf(ch)
            if (v < 0) return null  // not a valid Base32 char
            bitBuffer = (bitBuffer shl 5) or v
            bitCount += 5
            if (bitCount >= 8) {
                bitCount -= 8
                buf[pos++] = ((bitBuffer shr bitCount) and 0xff).toByte()
            }
        }
        return buf.copyOf(pos)
    }
}
