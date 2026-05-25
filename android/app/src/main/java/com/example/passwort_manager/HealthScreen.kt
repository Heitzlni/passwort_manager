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

/**
 * Offline weak / reused password report. Pure-read screen — no
 * passwords leave the device, no passwords are displayed.
 */
@Composable
fun HealthScreen(accounts: List<Account>, onBack: () -> Unit) {
    androidx.activity.compose.BackHandler { onBack() }

    val report = remember(accounts) { HealthAnalyzer.analyze(accounts) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Vault health") },
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
            // ===== Summary =====
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "${report.total} entries",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    if (report.allClear()) {
                        Text(
                            "All clear — no weak or reused passwords.",
                            color = MaterialTheme.colorScheme.primary,
                        )
                    } else {
                        val parts = mutableListOf<String>()
                        if (report.weakCount() > 0) parts += "${report.weakCount()} weak"
                        if (report.reusedCount() > 0) parts += "${report.reusedCount()} reused"
                        Text(
                            parts.joinToString(", "),
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }

            Text(
                "All analysis runs locally — no passwords leave the device.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ===== Weak =====
            val weak = report.entries.withIndex()
                .filter { it.value.weak }
                .map { it.value }
                .sortedBy { it.bits }
            if (weak.isNotEmpty()) {
                HorizontalDivider()
                SectionHeader("Weak passwords")
                for (e in weak) {
                    HealthEntryRow(
                        title = e.name.ifEmpty { "(unnamed)" },
                        subtitle = buildString {
                            if (e.username.isNotEmpty()) append(e.username).append(" · ")
                            append("${e.bits} bits")
                        },
                        accent = MaterialTheme.colorScheme.error,
                    )
                }
            }

            // ===== Reused =====
            if (report.reusedGroups.isNotEmpty()) {
                HorizontalDivider()
                SectionHeader("Reused passwords")
                for ((groupIdx, group) in report.reusedGroups.withIndex()) {
                    Text(
                        "Group ${groupIdx + 1} (${group.size} entries)",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    for (i in group) {
                        val e = report.entries[i]
                        HealthEntryRow(
                            title = e.name.ifEmpty { "(unnamed)" },
                            subtitle = if (e.username.isNotEmpty()) e.username else "no username",
                            accent = MaterialTheme.colorScheme.secondary,
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }

            Spacer(Modifier.height(20.dp))
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(top = 4.dp, bottom = 2.dp),
    )
}

@Composable
private fun HealthEntryRow(
    title: String,
    subtitle: String,
    accent: androidx.compose.ui.graphics.Color,
) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(
            title,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = accent,
        )
    }
}
