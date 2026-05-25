package com.example.passwort_manager

import kotlin.math.ln

/**
 * Offline vault health analysis — Kotlin port of `src/health.rs`.
 * Flags weak passwords and detects reuse across entries. No
 * passwords are exposed; the report only carries metadata
 * (name, username, bit-estimate, reuse count).
 */
object HealthAnalyzer {

    /** Below this estimated strength a password is flagged "weak". */
    private const val WEAK_BITS = 60.0

    /** Rough entropy estimate (bits) — same formula as the desktop:
     *  detect which character classes appear, size the pool
     *  accordingly, return `len * log2(pool)`. Over-estimates
     *  user-chosen passwords (ignores dictionary words and patterns),
     *  so anything still called weak is genuinely weak. */
    fun estimateBits(pw: String): Double {
        if (pw.isEmpty()) return 0.0
        var lower = false
        var upper = false
        var digit = false
        var sym = false
        for (c in pw) {
            when {
                c in 'a'..'z' -> lower = true
                c in 'A'..'Z' -> upper = true
                c.isDigit() -> digit = true
                else -> sym = true
            }
        }
        var pool = 0
        if (lower) pool += 26
        if (upper) pool += 26
        if (digit) pool += 10
        if (sym) pool += 32
        if (pool == 0) return 0.0
        return (ln(pool.toDouble()) / ln(2.0)) * pw.length
    }

    data class EntryHealth(
        val name: String,
        val username: String,
        val bits: Int,
        val weak: Boolean,
        /** How many *other* entries share this exact password. 0 = unique. */
        val reusedWith: Int,
    )

    data class Report(
        val total: Int,
        val entries: List<EntryHealth>,
        /** Groups of indices in [entries] that share one password
         *  (each group has size >= 2). */
        val reusedGroups: List<List<Int>>,
    ) {
        fun weakCount() = entries.count { it.weak }
        fun reusedCount() = entries.count { it.reusedWith > 0 }
        fun allClear() = weakCount() == 0 && reusedGroups.isEmpty()
    }

    fun analyze(accounts: List<Account>): Report {
        // Index by exact password to find reuse.
        val byPw = HashMap<String, MutableList<Int>>()
        for ((i, a) in accounts.withIndex()) {
            byPw.getOrPut(a.password) { mutableListOf() }.add(i)
        }

        val entries = accounts.mapIndexed { i, a ->
            val groupSize = byPw[a.password]?.size ?: 1
            val bits = estimateBits(a.password)
            // Empty passwords are "weak" by length=0 and shouldn't count
            // as reuse partners (otherwise every blank entry is "reused").
            val reusedWith = if (a.password.isEmpty()) 0 else (groupSize - 1).coerceAtLeast(0)
            EntryHealth(
                name = a.name,
                username = a.username,
                bits = bits.toInt(),
                weak = bits < WEAK_BITS,
                reusedWith = reusedWith,
            )
        }

        val reusedGroups = byPw
            .filter { (pw, idxs) -> pw.isNotEmpty() && idxs.size >= 2 }
            .map { (_, idxs) -> idxs.sorted() }
            .sortedWith(compareByDescending<List<Int>> { it.size }.thenBy { it.first() })

        return Report(total = accounts.size, entries = entries, reusedGroups = reusedGroups)
    }
}
