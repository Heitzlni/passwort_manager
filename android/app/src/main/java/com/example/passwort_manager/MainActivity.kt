@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.example.passwort_manager

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.passwort_manager.ui.theme.Passwort_ManagerTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Passwort_ManagerTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AppRoot()
                }
            }
        }
    }
}

// ===================== App state machine =====================
//
// Phase 1 has three screens:
//   1. NoVault   — the file isn't on the phone yet; show import help.
//   2. Locked    — vault present, ask for master password.
//   3. Unlocked  — list + per-entry view. No edit yet (that's phase 3).
//
// State is held in MainActivity-scoped state objects so a config
// change (rotation, dark/light) re-renders without re-decrypting.

private sealed class Screen {
    object NoVault : Screen()
    data class Locked(val errorMsg: String? = null) : Screen()
    data class Unlocked(val selectedIndex: Int? = null) : Screen()
}

@Composable
private fun AppRoot() {
    val context = LocalContextSafe()
    val vaultFile = remember(context) { File(context.getExternalFilesDir(null), "vault.json") }

    // Snapshot the process-wide unlocked state so we route to the
    // right screen if the user re-enters the app while still unlocked
    // (or, conversely, if auto-lock fired while the app was in
    // background → we drop them back at Locked).
    val unlockedAccounts = VaultState.accounts.value
    var screen by remember {
        mutableStateOf<Screen>(
            when {
                unlockedAccounts != null -> Screen.Unlocked()
                vaultFile.exists() && vaultFile.length() > 0 -> Screen.Locked()
                else -> Screen.NoVault
            }
        )
    }
    val scope = androidx.compose.runtime.rememberCoroutineScope()

    // If VaultState locks itself (auto-lock or external trigger) while
    // we're in the Unlocked screen, kick the UI back to Locked.
    LaunchedEffect(VaultState.accounts.value) {
        val current = screen
        if (current is Screen.Unlocked && VaultState.accounts.value == null) {
            screen = Screen.Locked()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Password Manager") },
                colors = TopAppBarDefaults.topAppBarColors(),
            )
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (val s = screen) {
                is Screen.NoVault -> NoVaultScreen(
                    expectedPath = vaultFile.absolutePath,
                    onRetry = {
                        screen = if (vaultFile.exists() && vaultFile.length() > 0)
                            Screen.Locked() else Screen.NoVault
                    },
                )

                is Screen.Locked -> LockedScreen(
                    errorMsg = s.errorMsg,
                    onUnlock = { master ->
                        scope.launch {
                            val bytes = vaultFile.readBytes()
                            val result = withContext(Dispatchers.Default) {
                                VaultBridge.unlock(bytes, master)
                            }
                            screen = when (result) {
                                is UnlockResult.Success -> {
                                    VaultState.unlock(result.accounts)
                                    Screen.Unlocked()
                                }
                                is UnlockResult.Failure -> Screen.Locked(result.message)
                            }
                        }
                    },
                )

                is Screen.Unlocked -> {
                    val accounts = VaultState.accounts.value
                    if (accounts == null) {
                        // Race with auto-lock: go back to Locked.
                        screen = Screen.Locked()
                    } else if (s.selectedIndex == null) {
                        EntryListScreen(
                            accounts = accounts,
                            onTap = { idx ->
                                VaultState.touch()
                                screen = s.copy(selectedIndex = idx)
                            },
                            onLock = {
                                VaultState.lock()
                                screen = Screen.Locked()
                            },
                        )
                    } else {
                        EntryDetailScreen(
                            account = accounts[s.selectedIndex],
                            onBack = {
                                VaultState.touch()
                                screen = s.copy(selectedIndex = null)
                            },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun LocalContextSafe(): Context =
    androidx.compose.ui.platform.LocalContext.current

// ===================== Screen 1: no vault =====================

@Composable
private fun NoVaultScreen(expectedPath: String, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            "No vault on this device",
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            "Copy your encrypted vault.json onto the phone first. " +
                "From your laptop, plug in the phone over USB and run:",
        )
        SelectionContainerCompat {
            Text(
                "adb push ~/.local/share/passwort-manager/vault.json \\\n  $expectedPath",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Text(
            "Then come back and tap Retry. The file lives in this app's " +
                "private external storage — no permissions needed, and the " +
                "Linux side and Android side stay in sync if you re-push.",
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = onRetry) { Text("Retry") }
    }
}

// Minimal stand-in for SelectionContainer that doesn't pull in extra deps —
// just a Surface around the text so it visually reads as a code block.
@Composable
private fun SelectionContainerCompat(content: @Composable () -> Unit) {
    Surface(
        tonalElevation = 2.dp,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box(Modifier.padding(12.dp)) { content() }
    }
}

// ===================== Screen 2: locked =====================

@Composable
private fun LockedScreen(errorMsg: String?, onUnlock: (String) -> Unit) {
    var password by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Unlock vault", style = MaterialTheme.typography.headlineSmall)

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Master password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions.Default,
            modifier = Modifier.fillMaxWidth(),
        )

        if (errorMsg != null) {
            Text(errorMsg, color = MaterialTheme.colorScheme.error)
        }

        Button(
            onClick = {
                if (password.isNotEmpty() && !working) {
                    working = true
                    onUnlock(password)
                }
            },
            enabled = password.isNotEmpty() && !working,
        ) {
            Text(if (working) "Unlocking…" else "Unlock")
        }
        Text(
            "Argon2id with 128 MiB memory takes about half a second on this phone.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

// ===================== Screen 3a: entry list =====================

@Composable
private fun EntryListScreen(
    accounts: List<Account>,
    onTap: (Int) -> Unit,
    onLock: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "${accounts.size} entries",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.titleMedium,
            )
            TextButton(onClick = onLock) {
                Icon(Icons.Default.Lock, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text("Lock")
            }
        }
        HorizontalDivider()
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            itemsIndexed(accounts) { index, acc ->
                EntryRow(account = acc, onClick = { onTap(index) })
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun EntryRow(account: Account, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            Text(
                text = account.name.ifEmpty { "(unnamed)" },
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.SemiBold,
            )
            if (account.username.isNotEmpty()) {
                Text(
                    text = account.username,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

// LazyColumn doesn't ship `itemsIndexed` from compose-foundation in
// every version; here's a tiny inline wrapper that works on all of them.
private fun androidx.compose.foundation.lazy.LazyListScope.itemsIndexed(
    list: List<Account>,
    itemContent: @Composable (Int, Account) -> Unit,
) {
    items(list.size) { idx -> itemContent(idx, list[idx]) }
}

// ===================== Screen 3b: entry detail =====================

@Composable
private fun EntryDetailScreen(account: Account, onBack: () -> Unit) {
    val context = LocalContextSafe()
    var revealPassword by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back")
            }
            Text(
                text = account.name.ifEmpty { "(unnamed)" },
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.weight(1f),
                overflow = TextOverflow.Ellipsis,
                maxLines = 1,
            )
        }
        HorizontalDivider()
        Column(
            modifier = Modifier.fillMaxWidth().padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            FieldRow(
                label = "Username",
                value = account.username.ifEmpty { "—" },
                copyable = account.username.isNotEmpty(),
                onCopy = { copyToClipboard(context, "username", account.username) },
                masked = false,
            )
            FieldRow(
                label = "Password",
                value = if (revealPassword) account.password else "•".repeat(account.password.length.coerceAtMost(20)),
                copyable = true,
                onCopy = { copyToClipboard(context, "password", account.password) },
                masked = true,
                revealed = revealPassword,
                onToggleReveal = { revealPassword = !revealPassword },
            )
            if (account.url.isNotEmpty()) {
                FieldRow(label = "URL", value = account.url, copyable = true,
                    onCopy = { copyToClipboard(context, "url", account.url) },
                    masked = false)
            }
            if (account.notes.isNotEmpty()) {
                FieldRow(label = "Notes", value = account.notes, copyable = false,
                    onCopy = {}, masked = false)
            }
        }
    }
}

@Composable
private fun FieldRow(
    label: String,
    value: String,
    copyable: Boolean,
    onCopy: () -> Unit,
    masked: Boolean,
    revealed: Boolean = false,
    onToggleReveal: (() -> Unit)? = null,
) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(2.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = value,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = if (masked) FontFamily.Monospace else FontFamily.Default,
            )
            if (masked && onToggleReveal != null) {
                IconButton(onClick = onToggleReveal) {
                    Icon(
                        if (revealed) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = if (revealed) "Hide" else "Show",
                    )
                }
            }
            if (copyable) {
                IconButton(onClick = onCopy) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy")
                }
            }
        }
    }
}

private fun copyToClipboard(context: Context, label: String, value: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(label, value)
    cm.setPrimaryClip(clip)
}
