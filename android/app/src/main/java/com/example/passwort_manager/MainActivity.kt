@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.example.passwort_manager

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
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

class MainActivity : FragmentActivity() {
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
    data class Unlocked(val selectedIndex: Int? = null, val search: String = "") : Screen()
    /** Pushed on top of [previous] — closing it returns to that screen. */
    data class Settings(val previous: Screen) : Screen()
    /** New-entry form — opens from the list's FAB. */
    data class AddEntry(val previous: Screen) : Screen()
    /** Edit-entry form — opens from the detail screen's edit button. */
    data class EditEntry(val previous: Screen, val index: Int) : Screen()
    /** Offline weak/reused report. */
    data class Health(val previous: Screen) : Screen()
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
    var importResult by remember { mutableStateOf<String?>(null) }
    // After a master-password unlock, if biometric is enabled but
    // no wrapped master is stored yet, we stash the just-used master
    // here so a LaunchedEffect can run the enrollment prompt.
    var pendingEnrollment by remember { mutableStateOf<String?>(null) }
    // Modal dialog for "Change master password". When true the dialog
    // overlays the current screen until the user dismisses or saves.
    var showChangeMasterDialog by remember { mutableStateOf(false) }
    var changeMasterResult by remember { mutableStateOf<String?>(null) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val activity = context as? FragmentActivity

    // SAF file picker — opens the system file chooser so the user can
    // point us at a vault.json on Downloads, Drive, Nextcloud, anywhere
    // a DocumentsProvider has reached. We copy the picked content into
    // the app's private external storage (replacing any prior vault).
    val filePicker = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = androidx.activity.result.contract.ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) {
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            val msg = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openInputStream(uri).use { input ->
                        if (input == null) error("could not open picked file")
                        // Sanity-check: vault.json is small (< 5 MB for any
                        // realistic vault). Rejects accidentally-picked
                        // huge files before we slurp them.
                        val bytes = input.readBytes()
                        if (bytes.size > 5 * 1024 * 1024) {
                            error("file is too large to be a vault (${bytes.size / 1024} KB)")
                        }
                        // Reject if it doesn't even parse as JSON. Cheap,
                        // catches "user picked a random binary."
                        String(bytes).trim().let {
                            if (!it.startsWith("{")) error("doesn't look like a vault JSON file")
                        }
                        // Atomic-ish replace: write to .tmp then rename.
                        val tmp = File(vaultFile.parentFile, "vault.json.tmp")
                        tmp.outputStream().use { it.write(bytes) }
                        if (!tmp.renameTo(vaultFile)) {
                            tmp.delete()
                            error("could not replace existing vault file")
                        }
                    }
                }.fold(
                    onSuccess = { "Imported vault file." },
                    onFailure = { "Import failed: ${it.message}" },
                )
            }
            importResult = msg
            // Lock any previously-unlocked session — the new vault may
            // have a different master. Wipe biometric state for the
            // same reason: the wrapped master almost certainly no
            // longer matches the new vault's master.
            VaultState.lock()
            AppSettings.clearWrappedMaster()
            KeystoreCipher.wipeKey()
            // Route to the right post-import screen.
            screen = if (vaultFile.exists() && vaultFile.length() > 0)
                Screen.Locked() else Screen.NoVault
        }
    }

    val launchImport: () -> Unit = {
        // Accept any MIME type — Downloads-provided vault.json on Android
        // often comes back as application/octet-stream or text/plain,
        // and Drive sometimes labels it application/json.
        filePicker.launch(arrayOf("*/*"))
    }

    // If VaultState locks itself (auto-lock or external trigger) while
    // we're in the Unlocked screen, kick the UI back to Locked.
    LaunchedEffect(VaultState.accounts.value) {
        val current = screen
        if (current is Screen.Unlocked && VaultState.accounts.value == null) {
            screen = Screen.Locked()
        }
    }

    // Run biometric enrollment when triggered by a master-password
    // unlock. Stays inside a LaunchedEffect so the prompt is scoped
    // to the composition and survives recompositions.
    LaunchedEffect(pendingEnrollment) {
        val master = pendingEnrollment ?: return@LaunchedEffect
        val act = activity ?: run { pendingEnrollment = null; return@LaunchedEffect }
        runBiometricEnrollment(
            activity = act,
            master = master,
            onDone = { pendingEnrollment = null },
        )
    }

    // Live-refresh ticker — every few seconds, look at vault.json's
    // mtime; if it advanced (sync push, file-picker replace, etc.),
    // re-decrypt with the cached key and update the visible list.
    // Only runs while the vault is unlocked; the lock path clears
    // the cached key so subsequent ticks no-op.
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(3000)
            when (VaultState.refreshIfChanged(vaultFile)) {
                VaultState.RefreshResult.Refreshed -> {
                    // accounts.value already updated; just nudge state
                    // so an Unlocked(selectedIndex=N) screen recomposes
                    // and we re-check that N is still in range.
                    val s = screen
                    if (s is Screen.Unlocked) {
                        screen = s.copy()
                    }
                }
                VaultState.RefreshResult.NeedsUnlock -> {
                    // VaultState already locked; LaunchedEffect on
                    // accounts.value below will route to Locked.
                }
                VaultState.RefreshResult.NoChange -> {
                    // common path, nothing to do
                }
            }
        }
    }

    // Settings has its own Scaffold/topbar — bypass the outer one.
    if (screen is Screen.Settings) {
        val s = screen as Screen.Settings
        // System back / swipe-from-edge pops Settings back to whatever
        // we came from (list, lock screen, …), instead of leaving the
        // app the way it would without BackHandler.
        androidx.activity.compose.BackHandler { screen = s.previous }
        SettingsScreen(
            onBack = { screen = s.previous },
            onPickVaultFile = launchImport,
            onChangeMaster = { showChangeMasterDialog = true },
            onHealth = { screen = Screen.Health(previous = s) },
            onToggleBiometric = { /* Real unlock-flow wiring in phase 2.5 step 3 */ },
        )
        if (showChangeMasterDialog) {
            ChangeMasterDialog(
                onDismiss = { showChangeMasterDialog = false },
                onSubmit = { cur, new ->
                    scope.launch {
                        val r = withContext(Dispatchers.Default) {
                            VaultState.changeMaster(cur, new, vaultFile)
                        }
                        when (r) {
                            VaultState.WriteResult.Ok -> {
                                changeMasterResult = "Master password changed."
                                showChangeMasterDialog = false
                            }
                            is VaultState.WriteResult.Failed -> {
                                changeMasterResult = r.message
                            }
                        }
                    }
                },
                errorMessage = changeMasterResult?.takeIf { showChangeMasterDialog },
            )
        }
        // Toast-style status banner once the dialog is closed.
        if (!showChangeMasterDialog && changeMasterResult != null) {
            LaunchedEffect(changeMasterResult) {
                kotlinx.coroutines.delay(3000)
                changeMasterResult = null
            }
        }
        return
    }

    // Add-entry / edit-entry — both use AddEditScreen, also own
    // their own topbar.
    if (screen is Screen.AddEntry) {
        val s = screen as Screen.AddEntry
        AddEditScreen(
            initial = null,
            onCancel = { screen = s.previous },
            onSave = { acc ->
                when (val r = VaultState.addAccount(acc, vaultFile)) {
                    VaultState.WriteResult.Ok -> screen = s.previous
                    is VaultState.WriteResult.Failed ->
                        importResult = "Save failed: ${r.message}"
                }
            },
        )
        return
    }
    if (screen is Screen.Health) {
        val s = screen as Screen.Health
        val accounts = VaultState.accounts.value
        if (accounts == null) {
            screen = s.previous
            return
        }
        HealthScreen(accounts = accounts, onBack = { screen = s.previous })
        return
    }
    if (screen is Screen.EditEntry) {
        val s = screen as Screen.EditEntry
        val list = VaultState.accounts.value
        if (list == null || s.index !in list.indices) {
            // Lost the entry under us (auto-lock, deleted via sync) —
            // bail back to whatever was on top.
            screen = s.previous
            return
        }
        AddEditScreen(
            initial = list[s.index],
            onCancel = { screen = s.previous },
            onSave = { acc ->
                when (val r = VaultState.editAccount(s.index, acc, vaultFile)) {
                    VaultState.WriteResult.Ok -> screen = s.previous
                    is VaultState.WriteResult.Failed ->
                        importResult = "Save failed: ${r.message}"
                }
            },
            onDelete = {
                when (val r = VaultState.deleteAccount(s.index, vaultFile)) {
                    VaultState.WriteResult.Ok -> {
                        // After delete, jump straight to the list — the
                        // previous screen was probably this entry's
                        // detail, which is now stale.
                        screen = Screen.Unlocked()
                    }
                    is VaultState.WriteResult.Failed ->
                        importResult = "Delete failed: ${r.message}"
                }
            },
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Password Manager") },
                actions = {
                    IconButton(onClick = { screen = Screen.Settings(screen) }) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(),
            )
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (val s = screen) {
                is Screen.Settings,
                is Screen.AddEntry,
                is Screen.EditEntry,
                is Screen.Health -> {
                    // Already handled by the early-return blocks above —
                    // unreachable here but the compiler insists on
                    // exhaustiveness.
                }
                is Screen.NoVault -> NoVaultScreen(
                    expectedPath = vaultFile.absolutePath,
                    onPickFile = launchImport,
                    onRetry = {
                        screen = if (vaultFile.exists() && vaultFile.length() > 0)
                            Screen.Locked() else Screen.NoVault
                    },
                    importResult = importResult,
                )

                is Screen.Locked -> LockedScreen(
                    errorMsg = s.errorMsg,
                    biometricAvailable = activity != null
                        && AppSettings.biometricEnabled
                        && AppSettings.hasWrappedMaster()
                        && KeystoreCipher.keyExists(),
                    onBiometricUnlock = {
                        val act = activity ?: return@LockedScreen
                        runBiometricUnlock(
                            activity = act,
                            scope = scope,
                            vaultFile = vaultFile,
                            onError = { msg -> screen = Screen.Locked(msg) },
                            onResult = { newScreen -> screen = newScreen },
                        )
                    },
                    onUnlock = { master ->
                        scope.launch {
                            val bytes = vaultFile.readBytes()
                            val result = withContext(Dispatchers.Default) {
                                VaultBridge.unlock(bytes, master)
                            }
                            screen = when (result) {
                                is UnlockResult.Success -> {
                                    VaultState.unlock(result.accounts, result.derivedKey, vaultFile)
                                    // Offer biometric enrollment if the
                                    // user has the pref on but hasn't
                                    // wrapped a master yet.
                                    if (activity != null
                                        && AppSettings.biometricEnabled
                                        && !AppSettings.hasWrappedMaster()
                                    ) {
                                        pendingEnrollment = master
                                    }
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
                            search = s.search,
                            onSearchChange = { screen = s.copy(search = it) },
                            onTap = { idx ->
                                VaultState.touch()
                                screen = s.copy(selectedIndex = idx)
                            },
                            onAdd = {
                                screen = Screen.AddEntry(previous = s)
                            },
                            onLock = {
                                VaultState.lock()
                                screen = Screen.Locked()
                            },
                        )
                    } else if (s.selectedIndex >= accounts.size) {
                        // Live refresh just dropped this index — entry
                        // was deleted on PC and synced over. Pop back
                        // to the list rather than crashing.
                        screen = s.copy(selectedIndex = null)
                    } else {
                        // System back / swipe-from-edge pops detail
                        // back to the list, instead of leaving the app.
                        androidx.activity.compose.BackHandler {
                            VaultState.touch()
                            screen = s.copy(selectedIndex = null)
                        }
                        EntryDetailScreen(
                            account = accounts[s.selectedIndex],
                            onBack = {
                                VaultState.touch()
                                screen = s.copy(selectedIndex = null)
                            },
                            onEdit = {
                                screen = Screen.EditEntry(previous = s, index = s.selectedIndex)
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

/**
 * Modal dialog that gates the master-password rotation. Three
 * fields: current, new, confirm. Server-side (in VaultState) we
 * re-verify the current master by deriving its key and comparing
 * to the cached one — so an attacker who somehow has the device
 * unlocked still can't rotate the master without knowing it.
 */
@Composable
private fun ChangeMasterDialog(
    onDismiss: () -> Unit,
    onSubmit: (current: String, new: String) -> Unit,
    errorMessage: String?,
) {
    var current by remember { mutableStateOf("") }
    var newPw by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    var localError by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = { Text("Change master password") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = current,
                    onValueChange = { current = it },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    label = { Text("Current master") },
                    enabled = !working,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = newPw,
                    onValueChange = { newPw = it },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    label = { Text("New master") },
                    enabled = !working,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    label = { Text("Confirm new master") },
                    enabled = !working,
                    modifier = Modifier.fillMaxWidth(),
                )
                val msg = localError ?: errorMessage
                if (msg != null) {
                    Text(msg, color = MaterialTheme.colorScheme.error)
                }
                Text(
                    "About 1 second of Argon2id verification + re-derivation. " +
                        "Biometric unlock will need to be re-enrolled afterwards.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            Button(
                enabled = !working,
                onClick = {
                    if (current.isEmpty() || newPw.isEmpty()) {
                        localError = "Fields can't be empty."
                        return@Button
                    }
                    if (newPw != confirm) {
                        localError = "New master and confirmation don't match."
                        return@Button
                    }
                    if (newPw.length < 12) {
                        localError = "New master must be at least 12 characters."
                        return@Button
                    }
                    localError = null
                    working = true
                    onSubmit(current, newPw)
                },
            ) { Text(if (working) "Working…" else "Change") }
        },
        dismissButton = {
            TextButton(enabled = !working, onClick = onDismiss) { Text("Cancel") }
        },
    )
}

// ===================== Biometric helpers =====================

/**
 * Drives the "Unlock with fingerprint" button on LockedScreen.
 * Resolves the stored wrapped master via KeystoreCipher, runs the
 * biometric prompt, decrypts, and replays the standard unlock flow
 * via VaultBridge.
 */
private fun runBiometricUnlock(
    activity: FragmentActivity,
    scope: kotlinx.coroutines.CoroutineScope,
    vaultFile: File,
    onError: (String) -> Unit,
    onResult: (Screen) -> Unit,
) {
    val wrapped = AppSettings.loadWrappedMaster() ?: run {
        onError("No biometric master stored yet."); return
    }
    val cipher = try {
        KeystoreCipher.decryptCipher(wrapped.first)
    } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
        // The user changed their biometric enrollment. Clear so we
        // don't keep prompting with a dead key.
        AppSettings.clearWrappedMaster()
        KeystoreCipher.wipeKey()
        onError("Biometric was changed since setup. Enter master password to re-enable.")
        return
    } catch (e: Exception) {
        onError("Biometric not available: ${e.message}")
        return
    }

    BiometricUnlock.prompt(
        activity = activity,
        title = "Unlock vault",
        subtitle = "Touch the fingerprint sensor",
        negativeButton = "Use master password",
        cipher = cipher,
        onSuccess = { authedCipher ->
            val masterBytes = try {
                authedCipher.doFinal(wrapped.second)
            } catch (e: Exception) {
                onError("Biometric decrypt failed: ${e.message}")
                return@prompt
            }
            val master = String(masterBytes, Charsets.UTF_8)
            scope.launch {
                val bytes = vaultFile.readBytes()
                val result = withContext(Dispatchers.Default) {
                    VaultBridge.unlock(bytes, master)
                }
                when (result) {
                    is UnlockResult.Success -> {
                        VaultState.unlock(result.accounts, result.derivedKey, vaultFile)
                        onResult(Screen.Unlocked())
                    }
                    is UnlockResult.Failure -> {
                        // The stored master no longer matches the
                        // current vault (different vault file imported,
                        // master was changed on Linux side, etc.).
                        // Drop the wrapped state so we don't keep
                        // failing biometrics with no escape.
                        AppSettings.clearWrappedMaster()
                        onResult(
                            Screen.Locked(
                                "Stored fingerprint master no longer matches. Enter master to re-set."
                            )
                        )
                    }
                }
            }
        },
        onError = onError,
    )
}

/** Encrypt the just-used master with a fresh Keystore key + biometric. */
private fun runBiometricEnrollment(
    activity: FragmentActivity,
    master: String,
    onDone: () -> Unit,
) {
    val cipher = try {
        KeystoreCipher.encryptCipher()
    } catch (e: Exception) {
        onDone(); return
    }
    BiometricUnlock.prompt(
        activity = activity,
        title = "Save fingerprint unlock",
        subtitle = "Confirm to allow fingerprint to unlock the vault",
        negativeButton = "Not now",
        cipher = cipher,
        onSuccess = { authedCipher ->
            try {
                val ct = authedCipher.doFinal(master.toByteArray(Charsets.UTF_8))
                AppSettings.saveWrappedMaster(authedCipher.iv, ct)
            } catch (_: Exception) {
                // best effort — if it fails, biometric just isn't set
                // up, the user can retry by toggling the setting.
            }
            onDone()
        },
        onError = { onDone() },
        onCancel = { onDone() },
    )
}

// ===================== Screen 1: no vault =====================

@Composable
private fun NoVaultScreen(
    expectedPath: String,
    onPickFile: () -> Unit,
    onRetry: () -> Unit,
    importResult: String?,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            "No vault on this device",
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            "Move your encrypted vault.json from your laptop onto this phone. " +
                "Either pick it through the file chooser (recommended — works with " +
                "Downloads, Drive, Nextcloud, anything), or push it over USB:",
        )
        Spacer(Modifier.height(4.dp))
        Button(onClick = onPickFile) { Text("Pick vault file…") }
        Spacer(Modifier.height(4.dp))
        Text(
            "USB option (advanced):",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        SelectionContainerCompat {
            Text(
                "adb push ~/.local/share/passwort-manager/vault.json \\\n  $expectedPath",
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onRetry) { Text("Already pushed — refresh") }
        if (importResult != null) {
            Spacer(Modifier.height(8.dp))
            Text(importResult, color = MaterialTheme.colorScheme.primary)
        }
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
private fun LockedScreen(
    errorMsg: String?,
    biometricAvailable: Boolean,
    onBiometricUnlock: () -> Unit,
    onUnlock: (String) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Unlock vault", style = MaterialTheme.typography.headlineSmall)

        if (biometricAvailable) {
            Button(
                onClick = onBiometricUnlock,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Unlock with fingerprint") }
            Text(
                "Or type your master password:",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

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
    search: String,
    onSearchChange: (String) -> Unit,
    onTap: (Int) -> Unit,
    onAdd: () -> Unit,
    onLock: () -> Unit,
) {
    // Filter on (name + url + username), preserving the original index
    // so taps still address the vault by its real position.
    val matching: List<Pair<Int, Account>> = remember(accounts, search) {
        val q = search.trim().lowercase()
        if (q.isEmpty()) {
            accounts.mapIndexed { idx, acc -> idx to acc }
        } else {
            accounts.mapIndexedNotNull { idx, acc ->
                val haystack = (acc.name + " " + acc.url + " " + acc.username).lowercase()
                if (haystack.contains(q)) idx to acc else null
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    if (search.isEmpty())
                        "${accounts.size} entries"
                    else
                        "${matching.size} of ${accounts.size}",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleMedium,
                )
                TextButton(onClick = onLock) {
                    Icon(Icons.Default.Lock, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("Lock")
                }
            }
            OutlinedTextField(
                value = search,
                onValueChange = onSearchChange,
                singleLine = true,
                placeholder = { Text("Search by name, URL, or username") },
                trailingIcon = {
                    if (search.isNotEmpty()) {
                        IconButton(onClick = { onSearchChange("") }) {
                            Icon(Icons.Default.Close, contentDescription = "Clear")
                        }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
            )
            HorizontalDivider()
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(matching.size) { i ->
                    val (originalIdx, acc) = matching[i]
                    EntryRow(account = acc, onClick = { onTap(originalIdx) })
                    HorizontalDivider()
                }
                // Bottom spacer so the FAB doesn't cover the last row.
                item { Spacer(Modifier.height(80.dp)) }
            }
        }

        FloatingActionButton(
            onClick = onAdd,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(16.dp),
        ) {
            Icon(Icons.Default.Add, contentDescription = "Add entry")
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
private fun EntryDetailScreen(
    account: Account,
    onBack: () -> Unit,
    onEdit: () -> Unit,
) {
    val context = LocalContextSafe()
    var revealPassword by remember { mutableStateOf(false) }

    // Tick once per second so the TOTP countdown + rollover refresh.
    // Only spins up if the entry actually has a TOTP secret — saves
    // a coroutine for accounts that don't use 2FA.
    val nowSec = produceTotpTicker(enabled = account.totpSecret.isNotEmpty())

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
            IconButton(onClick = onEdit) {
                Icon(Icons.Default.Edit, contentDescription = "Edit")
            }
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
            if (account.totpSecret.isNotEmpty()) {
                TotpRow(
                    secret = account.totpSecret,
                    nowSec = nowSec,
                    onCopy = { code -> copyToClipboard(context, "totp", code) },
                )
            }
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

/**
 * Produces a 1-Hz tick of Unix seconds for live TOTP countdown.
 * Returns 0 when [enabled] is false so the consumer can short-circuit.
 */
@Composable
private fun produceTotpTicker(enabled: Boolean): Long {
    if (!enabled) return 0L
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(1000)
            now = System.currentTimeMillis() / 1000
        }
    }
    return now
}

@Composable
private fun TotpRow(secret: String, nowSec: Long, onCopy: (String) -> Unit) {
    val code = remember(nowSec, secret) { TotpHelper.compute(secret, nowSec) }
    if (code == null) {
        FieldRow(
            label = "2FA code",
            value = "stored secret isn't valid Base32",
            copyable = false,
            onCopy = {},
            masked = false,
        )
        return
    }

    Column {
        Text(
            "2FA code",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(2.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            // Show as three-then-three: "123 456" — easier to read.
            val pretty = code.digits.substring(0, 3) + " " + code.digits.substring(3)
            Text(
                text = pretty,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.headlineSmall,
                fontFamily = FontFamily.Monospace,
            )
            Text(
                "${code.secondsRemaining}s",
                style = MaterialTheme.typography.bodySmall,
                color = if (code.secondsRemaining <= 5)
                    MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            IconButton(onClick = { onCopy(code.digits) }) {
                Icon(Icons.Default.ContentCopy, contentDescription = "Copy")
            }
        }
        LinearProgressIndicator(
            progress = { code.secondsRemaining / 30f },
            modifier = Modifier.fillMaxWidth(),
        )
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
