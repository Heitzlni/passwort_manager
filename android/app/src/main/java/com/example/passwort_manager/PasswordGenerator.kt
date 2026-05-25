package com.example.passwort_manager

import java.security.SecureRandom

/**
 * Random password generator — Kotlin port of `src/generator.rs`.
 * Uses OS entropy (`SecureRandom`) and rejection sampling so each
 * character of the requested alphabet is equally likely (no modulo bias).
 *
 * Default alphabet is 89 ASCII printable chars (26 lower + 26 upper +
 * 10 digits + 27 common symbols) — same as the desktop crate, so the
 * generated passwords have identical entropy on both clients.
 */
object PasswordGenerator {

    const val DEFAULT_LENGTH = 20

    private val LOWER = "abcdefghijklmnopqrstuvwxyz".toCharArray()
    private val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
    private val DIGITS = "0123456789".toCharArray()
    private val SYMBOLS = "!@#\$%^&*()-_=+[]{};:,.<>?/~".toCharArray()

    data class Charset(
        val lower: Boolean = true,
        val upper: Boolean = true,
        val digits: Boolean = true,
        val symbols: Boolean = true,
    ) {
        fun alphabet(): CharArray {
            val sb = StringBuilder()
            if (lower) sb.append(LOWER)
            if (upper) sb.append(UPPER)
            if (digits) sb.append(DIGITS)
            if (symbols) sb.append(SYMBOLS)
            return sb.toString().toCharArray()
        }
    }

    private val rng: SecureRandom = SecureRandom()

    /** Generate a password of `length` characters. Returns "" if
     *  `length` ≤ 0 or the charset is empty. */
    fun generate(length: Int, charset: Charset = Charset()): String {
        if (length <= 0) return ""
        val alpha = charset.alphabet()
        if (alpha.isEmpty()) return ""
        // Largest multiple of alpha.size that fits in 256 — bytes
        // beyond this get rejected and re-rolled so the distribution
        // stays uniform regardless of alphabet size.
        val n = alpha.size
        val maxUnbiased = (256 / n) * n
        val out = StringBuilder(length)
        val buf = ByteArray(64)
        while (out.length < length) {
            rng.nextBytes(buf)
            for (b in buf) {
                val u = b.toInt() and 0xFF
                if (u < maxUnbiased) {
                    out.append(alpha[u % n])
                    if (out.length >= length) break
                }
            }
        }
        return out.toString()
    }

    /** log2(alphabet) * length, for the strength meter. */
    fun entropyBits(length: Int, charset: Charset): Double {
        val n = charset.alphabet().size
        if (n <= 1 || length <= 0) return 0.0
        return (Math.log(n.toDouble()) / Math.log(2.0)) * length
    }
}
