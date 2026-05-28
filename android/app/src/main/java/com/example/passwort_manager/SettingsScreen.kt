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
import androidx.compose.ui.unit.dp
import java.io.File

/**
 * Single Settings screen wired to [AppSettings] + [VaultState].
 *
 * Sections:
 *   1. Vault — auto-lock timeout, biometric toggle.
 *   2. Vault file — Import (file picker — phase 2.5 step 2),
 *      Delete local vault (zeroes pref-stored biometric data and
 *      removes vault.json from app storage).
 *
 * Biometric toggle is rendered but disabled with an explanatory note
 * until the biometric flow lands.
 */
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onPickVaultFile: () -> Unit,
    onExportVault: () -> Unit,
    onChangeMaster: () -> Unit,
    onHealth: () -> Unit,
    onAudit: () -> Unit,
    onToggleBiometric: (Boolean) -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current

    var autoLock by remember { mutableIntStateOf(AppSettings.autoLockMinutes) }
    var biometric by remember { mutableStateOf(AppSettings.biometricEnabled) }
    var showAutoLockDialog by remember { mutableStateOf(false) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var deleteResultMessage by remember { mutableStateOf<String?>(null) }

    // Re-check biometric availability on every render so going to
    // Android settings to enroll a fingerprint and coming back reflects
    // the new state immediately.
    val biometricState = remember(context) { BiometricHelper.availability(context) }
    val biometricSupported = biometricState == BiometricHelper.Availability.Ready

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            SectionHeader("Vault")

            SettingRow(
                title = "Auto-lock",
                subtitle = AppSettings.autoLockLabel(autoLock) +
                    " of idle. The unlocked vault is wiped from memory after this.",
                onClick = { showAutoLockDialog = true },
            )

            SettingSwitchRow(
                title = "Biometric unlock",
                subtitle = biometricSubtitle(biometricState, biometric),
                checked = biometric,
                enabled = biometricSupported,
                onCheckedChange = {
                    biometric = it
                    AppSettings.biometricEnabled = it
                    if (!it) {
                        // Disabling wipes the stored wrapped master and
                        // the Keystore key so the next enable starts
                        // from a clean state.
                        AppSettings.clearWrappedMaster()
                        KeystoreCipher.wipeKey()
                    }
                    onToggleBiometric(it)
                },
            )

            Spacer(Modifier.height(8.dp))
            SectionHeader("Master password")

            SettingRow(
                title = "Change master password",
                subtitle = "Re-encrypts the entire vault under a new master. " +
                    "Removes biometric unlock — you'll re-enable it on the next unlock.",
                onClick = onChangeMaster,
            )

            Spacer(Modifier.height(8.dp))
            SectionHeader("Audit")

            SettingRow(
                title = "Vault health",
                subtitle = "Local-only check for weak and reused passwords. " +
                    "Nothing leaves the device.",
                onClick = onHealth,
            )

            SettingRow(
                title = "HIBP audit",
                subtitle = "Check every password against haveibeenpwned.com " +
                    "(k-anonymous — only a 5-char SHA-1 prefix leaves the device).",
                onClick = onAudit,
            )

            Spacer(Modifier.height(8.dp))
            SectionHeader("Vault file")

            SettingRow(
                title = "Import vault file…",
                subtitle = "Pick a vault.json from Downloads or any folder. " +
                    "Replaces the current local copy.",
                onClick = onPickVaultFile,
            )

            SettingRow(
                title = "Export vault…",
                subtitle = "Save the encrypted vault.json to a folder of " +
                    "your choice (Downloads, Drive, USB stick). The file is " +
                    "the same encrypted blob — useless without your master.",
                onClick = onExportVault,
            )

            SettingRow(
                title = "Delete local vault",
                subtitle = "Removes the encrypted vault file from this device. " +
                    "You'll need to import again before next unlock. Does NOT " +
                    "affect the vault on your laptop.",
                onClick = { showDeleteDialog = true },
                titleColor = MaterialTheme.colorScheme.error,
            )

            deleteResultMessage?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }

    if (showAutoLockDialog) {
        AutoLockDialog(
            current = autoLock,
            onPick = {
                autoLock = it
                AppSettings.autoLockMinutes = it
                showAutoLockDialog = false
            },
            onDismiss = { showAutoLockDialog = false },
        )
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Delete local vault?") },
            text = {
                Text(
                    "This removes the encrypted vault file from this phone. " +
                        "The vault on your laptop is unaffected. You'll need to " +
                        "import it again before you can unlock here.",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showDeleteDialog = false
                        VaultState.lock()
                        // Wrapped master is tied to this vault's master
                        // password; once the file is gone the next vault
                        // may have a different password, so wipe.
                        AppSettings.clearWrappedMaster()
                        KeystoreCipher.wipeKey()
                        val file = File(context.getExternalFilesDir(null), "vault.json")
                        val ok = file.delete() || !file.exists()
                        deleteResultMessage = if (ok)
                            "Local vault deleted."
                        else
                            "Could not delete vault file."
                    },
                ) {
                    Text("Delete", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) { Text("Cancel") }
            },
        )
    }
}

/** UX text for the biometric switch — shows enrollment state too. */
private fun biometricSubtitle(
    state: BiometricHelper.Availability,
    enabled: Boolean,
): String = when {
    state != BiometricHelper.Availability.Ready ->
        BiometricHelper.description(state)
    enabled && AppSettings.hasWrappedMaster() ->
        "Enabled — fingerprint unlocks the vault."
    enabled ->
        "Enabled — set up by unlocking once with the master password."
    else ->
        "Use fingerprint instead of typing the master password."
}

@Composable
private fun AutoLockDialog(current: Int, onPick: (Int) -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Auto-lock after") },
        text = {
            Column {
                for (choice in AppSettings.autoLockChoices()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = current == choice,
                            onClick = { onPick(choice) },
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(AppSettings.autoLockLabel(choice))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Done") }
        },
    )
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
    )
}

@Composable
private fun SettingRow(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    titleColor: androidx.compose.ui.graphics.Color = androidx.compose.ui.graphics.Color.Unspecified,
) {
    Surface(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(vertical = 12.dp)) {
            Text(
                title,
                style = MaterialTheme.typography.bodyLarge,
                color = titleColor,
            )
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SettingSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                title,
                style = MaterialTheme.typography.bodyLarge,
                color = if (enabled) androidx.compose.ui.graphics.Color.Unspecified
                else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
        )
    }
}
