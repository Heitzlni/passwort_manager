@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.example.passwort_manager

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Online breach-check screen using the k-anonymous HIBP API. One
 * HTTPS GET per audited entry. Only a 5-char SHA-1 prefix leaves
 * the device — HIBP never sees the password or its full hash.
 */
@Composable
fun AuditScreen(accounts: List<Account>, onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }
    val scope = rememberCoroutineScope()

    var phase by remember { mutableStateOf(AuditPhase.Idle) }
    var done by remember { mutableIntStateOf(0) }
    val results = remember { mutableStateListOf<Verdict>() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("HIBP audit") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "k-anonymous lookup: only the first 5 hex chars of each " +
                    "password's SHA-1 hash leave this device. HIBP never " +
                    "sees the password or its full hash.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            when (phase) {
                AuditPhase.Idle -> {
                    Text(
                        "Will check ${accounts.size} entries against " +
                            "haveibeenpwned.com. One HTTPS request per entry.",
                    )
                    Button(
                        onClick = {
                            phase = AuditPhase.Running
                            done = 0
                            results.clear()
                            scope.launch {
                                runAudit(accounts) { v ->
                                    results.add(v)
                                    done = results.size
                                }
                                phase = AuditPhase.Done
                            }
                        },
                    ) { Text("Run audit") }
                }
                AuditPhase.Running -> {
                    val total = accounts.size
                    LinearProgressIndicator(
                        progress = { if (total == 0) 0f else done.toFloat() / total },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text("Checking entry $done of $total…")
                    PartialResults(results)
                }
                AuditPhase.Done -> {
                    val bad = results.count { it is Verdict.Pwned }
                    val errs = results.count { it is Verdict.Failed }
                    val clean = results.count { it is Verdict.Clean }
                    Surface(
                        tonalElevation = 2.dp,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                if (bad == 0) "All clear."
                                else "$bad password${if (bad == 1) "" else "s"} found in breaches.",
                                style = MaterialTheme.typography.titleMedium,
                                color = if (bad == 0)
                                    MaterialTheme.colorScheme.primary
                                else
                                    MaterialTheme.colorScheme.error,
                            )
                            Text(
                                "$clean clean · $errs errors",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    PartialResults(results)
                }
            }
            Spacer(Modifier.height(20.dp))
        }
    }
}

private enum class AuditPhase { Idle, Running, Done }

private sealed class Verdict {
    abstract val name: String
    abstract val username: String

    data class Clean(override val name: String, override val username: String) : Verdict()
    data class Pwned(
        override val name: String,
        override val username: String,
        val count: Long,
    ) : Verdict()
    data class Failed(
        override val name: String,
        override val username: String,
        val message: String,
    ) : Verdict()
}

private suspend fun runAudit(accounts: List<Account>, onEach: (Verdict) -> Unit) {
    for (acc in accounts) {
        val verdict = withContext(Dispatchers.IO) {
            // Tiny pause between requests — being polite to the API and
            // keeping the worst-case rate well under their limits.
            delay(50)
            when (val r = HibpClient.check(acc.password)) {
                is HibpClient.Result.Ok ->
                    if (r.breachCount == 0L) Verdict.Clean(acc.name, acc.username)
                    else Verdict.Pwned(acc.name, acc.username, r.breachCount)
                is HibpClient.Result.Error ->
                    Verdict.Failed(acc.name, acc.username, r.message)
            }
        }
        onEach(verdict)
    }
}

@Composable
private fun PartialResults(results: List<Verdict>) {
    if (results.isEmpty()) return
    HorizontalDivider()
    // Pwned first, then errors, then clean — most-actionable on top.
    val sorted = results.sortedBy {
        when (it) {
            is Verdict.Pwned -> 0
            is Verdict.Failed -> 1
            is Verdict.Clean -> 2
        }
    }
    for (v in sorted) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    v.name.ifEmpty { "(unnamed)" },
                    fontWeight = FontWeight.SemiBold,
                )
                if (v.username.isNotEmpty()) {
                    Text(
                        v.username,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            when (v) {
                is Verdict.Clean -> Text(
                    "OK",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                is Verdict.Pwned -> Text(
                    "in ${v.count} breach${if (v.count == 1L) "" else "es"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                is Verdict.Failed -> Text(
                    "error",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
