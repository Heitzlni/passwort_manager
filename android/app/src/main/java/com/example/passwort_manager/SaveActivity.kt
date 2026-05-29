@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.example.passwort_manager

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.example.passwort_manager.ui.theme.Passwort_ManagerTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Launched by [PasswortAutofillService.onSaveRequest] after the user
 * submits a login form in another app. We pre-fill an add-entry form
 * with the captured username + password and the host (extracted from
 * either the webDomain or a `com.foo.bar`-style package name), and
 * give them three actions:
 *
 *   - Save (new entry)
 *   - Update (when a matching entry already exists for the same host)
 *   - Cancel
 *
 * If the vault is locked when save fires, we route through the same
 * master-or-biometric unlock UX [AutofillActivity] uses, then drop
 * back into the save form.
 */
class SaveActivity : FragmentActivity() {

    companion object {
        const val EXTRA_CAPTURED_USERNAME = "pwm_save_username"
        const val EXTRA_CAPTURED_PASSWORD = "pwm_save_password"
        const val EXTRA_HOST = "pwm_save_host"
        const val EXTRA_PACKAGE = "pwm_save_package"
        /** Set by PasswortCredentialProviderService when this activity is
         *  launched from the Credential Manager save flow rather than
         *  the legacy AutofillService.onSaveRequest path. Drives where
         *  we read the typed credentials from (intent extras vs the
         *  CreateCredentialRequest the framework attaches). */
        const val EXTRA_FROM_CREDENTIAL_MANAGER = "pwm_save_from_cm"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val fromCm = intent.getBooleanExtra(EXTRA_FROM_CREDENTIAL_MANAGER, false)
        val cmCreds = if (fromCm) extractCredentialManagerCredentials() else null

        val capturedUsername = cmCreds?.first
            ?: intent.getStringExtra(EXTRA_CAPTURED_USERNAME).orEmpty()
        val capturedPassword = cmCreds?.second
            ?: intent.getStringExtra(EXTRA_CAPTURED_PASSWORD).orEmpty()
        val host = intent.getStringExtra(EXTRA_HOST).orEmpty()
        val pkg = intent.getStringExtra(EXTRA_PACKAGE).orEmpty()

        if (capturedPassword.isBlank()) {
            if (fromCm) failCredentialManager("no password in create request")
            finish(); return
        }

        setContent {
            Passwort_ManagerTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    SaveFlow(
                        capturedUsername = capturedUsername,
                        capturedPassword = capturedPassword,
                        host = host,
                        pkg = pkg,
                        onDone = { saved ->
                            if (fromCm) {
                                if (saved) succeedCredentialManager()
                                else failCredentialManager("user cancelled")
                            }
                            finish()
                        },
                    )
                }
            }
        }
    }

    /** Pull username + password out of the [androidx.credentials]
     *  request the framework attaches when we're launched from the
     *  Credential Manager save picker. Returns null if the request
     *  isn't the expected password-create shape. */
    private fun extractCredentialManagerCredentials(): Pair<String, String>? {
        if (Build.VERSION.SDK_INT < 34) return null
        return try {
            val req = androidx.credentials.provider.PendingIntentHandler
                .retrieveProviderCreateCredentialRequest(intent) ?: return null
            val credReq = req.callingRequest
            if (credReq is androidx.credentials.CreatePasswordRequest) {
                credReq.id to credReq.password
            } else null
        } catch (_: Throwable) {
            null
        }
    }

    private fun succeedCredentialManager() {
        if (Build.VERSION.SDK_INT < 34) return
        try {
            val data = Intent()
            androidx.credentials.provider.PendingIntentHandler
                .setCreateCredentialResponse(
                    data,
                    androidx.credentials.CreatePasswordResponse(),
                )
            setResult(android.app.Activity.RESULT_OK, data)
        } catch (_: Throwable) { /* best effort */ }
    }

    private fun failCredentialManager(reason: String) {
        if (Build.VERSION.SDK_INT < 34) return
        try {
            val data = Intent()
            androidx.credentials.provider.PendingIntentHandler
                .setCreateCredentialException(
                    data,
                    androidx.credentials.exceptions.CreateCredentialUnknownException(reason),
                )
            setResult(android.app.Activity.RESULT_OK, data)
        } catch (_: Throwable) { /* best effort */ }
    }
}

@Composable
private fun SaveFlow(
    capturedUsername: String,
    capturedPassword: String,
    host: String,
    pkg: String,
    onDone: (saved: Boolean) -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val vaultFile = remember(context) { File(context.getExternalFilesDir(null), "vault.json") }

    // Drive a tiny state machine. The Locked → Unlocked transition is
    // also handled by VaultState.accounts becoming non-null (via the
    // unlock screen).
    val unlocked = VaultState.accounts.value != null
    var phase by remember { mutableStateOf(if (unlocked) SavePhase.Form else SavePhase.Unlock) }

    LaunchedEffect(VaultState.accounts.value) {
        if (VaultState.accounts.value != null && phase == SavePhase.Unlock) {
            phase = SavePhase.Form
        }
    }

    when (phase) {
        SavePhase.Unlock -> UnlockGate(
            vaultFile = vaultFile,
            host = host,
            onCancel = { onDone(false) },
        )
        SavePhase.Form -> SaveForm(
            capturedUsername = capturedUsername,
            capturedPassword = capturedPassword,
            host = host,
            pkg = pkg,
            vaultFile = vaultFile,
            onDone = onDone,
        )
    }
}

private enum class SavePhase { Unlock, Form }

// ===================== Phase 1: unlock the vault =====================

@Composable
private fun UnlockGate(vaultFile: File, host: String, onCancel: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? FragmentActivity
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val biometricReady = activity != null
        && AppSettings.biometricEnabled
        && AppSettings.hasWrappedMaster()
        && KeystoreCipher.keyExists()

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Unlock to save", style = MaterialTheme.typography.headlineSmall)
        if (host.isNotEmpty()) {
            Text(
                "For: $host",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (biometricReady) {
            Button(
                enabled = !busy,
                onClick = {
                    val act = activity ?: return@Button
                    busy = true
                    runSaveBiometricUnlock(
                        activity = act,
                        scope = scope,
                        vaultFile = vaultFile,
                        onError = { msg -> error = msg; busy = false },
                    )
                },
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
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                enabled = password.isNotEmpty() && !busy,
                onClick = {
                    busy = true
                    scope.launch {
                        val bytes = vaultFile.readBytes()
                        val r = withContext(Dispatchers.Default) {
                            VaultBridge.unlock(bytes, password)
                        }
                        when (r) {
                            is UnlockResult.Success -> {
                                VaultState.unlock(r.accounts, r.derivedKey, vaultFile)
                                // LaunchedEffect on accounts will flip
                                // the phase; nothing else to do here.
                            }
                            is UnlockResult.Failure -> {
                                error = r.message; busy = false
                            }
                        }
                    }
                },
            ) { Text(if (busy) "Unlocking…" else "Unlock") }
            OutlinedButton(onClick = onCancel) { Text("Cancel") }
        }
    }
}

/**
 * Biometric unlock path for the save flow — mirror of the one in
 * AutofillActivity. On success, VaultState becomes unlocked and the
 * LaunchedEffect upstairs swaps to the save form. On failure (e.g.
 * keystore key invalidated by a new fingerprint enrollment) we
 * report up so the user falls back to master password.
 */
private fun runSaveBiometricUnlock(
    activity: FragmentActivity,
    scope: kotlinx.coroutines.CoroutineScope,
    vaultFile: File,
    onError: (String) -> Unit,
) {
    val wrapped = AppSettings.loadWrappedMaster() ?: run {
        onError("No biometric master stored yet."); return
    }
    val cipher = try {
        KeystoreCipher.decryptCipher(wrapped.first)
    } catch (_: android.security.keystore.KeyPermanentlyInvalidatedException) {
        AppSettings.clearWrappedMaster()
        KeystoreCipher.wipeKey()
        onError("Biometric was changed since setup. Enter master to re-enable.")
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
                val r = withContext(Dispatchers.Default) {
                    VaultBridge.unlock(bytes, master)
                }
                when (r) {
                    is UnlockResult.Success -> {
                        VaultState.unlock(r.accounts, r.derivedKey, vaultFile)
                    }
                    is UnlockResult.Failure -> {
                        AppSettings.clearWrappedMaster()
                        onError("Stored fingerprint master no longer matches the vault.")
                    }
                }
            }
        },
        onError = onError,
    )
}

// ===================== Phase 2: the save form =====================

@Composable
private fun SaveForm(
    capturedUsername: String,
    capturedPassword: String,
    host: String,
    pkg: String,
    vaultFile: File,
    onDone: (saved: Boolean) -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val accounts = VaultState.accounts.value ?: run { onDone(false); return }

    // Detect an existing entry for the same (host, username) so we can
    // surface "Update" instead of always creating duplicates.
    val match: Pair<Int, Account>? = remember(accounts, host, capturedUsername) {
        if (host.isBlank()) return@remember null
        accounts.withIndex()
            .firstOrNull { (_, a) ->
                hostMatches(a, host) && a.username.trim().equals(capturedUsername.trim(), ignoreCase = true)
            }
            ?.let { it.index to it.value }
    }

    val defaultName = remember(host, pkg) {
        when {
            host.isNotEmpty() -> host
            pkg.isNotEmpty() -> pkg
            else -> ""
        }
    }

    var name by remember { mutableStateOf(match?.second?.name ?: defaultName) }
    var url by remember { mutableStateOf(match?.second?.url.orEmpty().ifEmpty { defaultUrlFor(host) }) }
    var username by remember { mutableStateOf(capturedUsername) }
    var password by remember { mutableStateOf(capturedPassword) }
    var revealPassword by remember { mutableStateOf(false) }
    var notes by remember { mutableStateOf(match?.second?.notes.orEmpty()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (match != null) "Update entry" else "Save new entry") },
                navigationIcon = {
                    IconButton(onClick = { onDone(false) }) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Cancel")
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
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            if (match != null) {
                Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        "An entry for \"${match.second.name}\" / ${match.second.username.ifEmpty { "(no username)" }} already exists. " +
                            "Saving will update its password — the old one is kept in history.",
                        modifier = Modifier.padding(12.dp),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            LabelledField("Name", name, { name = it })
            LabelledField("URL", url, { url = it })
            LabelledField("Username", username, { username = it })
            Column {
                Text(
                    "Password",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    singleLine = true,
                    visualTransformation = if (revealPassword)
                        androidx.compose.ui.text.input.VisualTransformation.None
                    else PasswordVisualTransformation(),
                    trailingIcon = {
                        TextButton(onClick = { revealPassword = !revealPassword }) {
                            Text(if (revealPassword) "Hide" else "Show")
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            LabelledField("Notes", notes, { notes = it }, singleLine = false)
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    enabled = !busy && name.isNotBlank() && password.isNotEmpty(),
                    onClick = {
                        busy = true
                        val result = if (match != null) {
                            VaultState.editAccount(
                                idx = match.first,
                                replacement = match.second.copy(
                                    name = name.trim(),
                                    url = url.trim(),
                                    username = username.trim(),
                                    password = password,
                                    notes = notes,
                                ),
                                vaultFile = vaultFile,
                            )
                        } else {
                            VaultState.addAccount(
                                Account(
                                    name = name.trim(),
                                    url = url.trim(),
                                    username = username.trim(),
                                    password = password,
                                    totpSecret = "",
                                    notes = notes,
                                ),
                                vaultFile = vaultFile,
                            )
                        }
                        when (result) {
                            VaultState.WriteResult.Ok -> onDone(true)
                            is VaultState.WriteResult.Failed -> {
                                error = result.message
                                busy = false
                            }
                        }
                    },
                ) {
                    Text(if (match != null) "Update" else "Save")
                }
                OutlinedButton(onClick = { onDone(false) }) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun LabelledField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    singleLine: Boolean = true,
) {
    Column {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            singleLine = singleLine,
            modifier = Modifier
                .fillMaxWidth()
                .then(if (singleLine) Modifier else Modifier.heightIn(min = 80.dp)),
        )
    }
}

// ===================== Helpers =====================

/** Same host-matching rule as [VaultState.findByHost], inlined here so
 *  SaveActivity doesn't need to expose any extra surface. */
private fun hostMatches(account: Account, host: String): Boolean {
    if (host.isBlank()) return false
    val h = host.trim().lowercase()
    val saved = hostFromUrl(account.url).ifEmpty { account.name }.trim().lowercase()
    if (saved.isEmpty()) return false
    return saved == h || h.endsWith(".$saved")
}

private fun hostFromUrl(url: String): String {
    val s = url.trim()
    if (s.isEmpty()) return ""
    val after = s.substringAfter("://", s)
    val hp = after.split('/', '?', '#').first()
    val noUser = hp.substringAfterLast('@')
    val lastColon = noUser.lastIndexOf(':')
    val host = if (lastColon > 0 && noUser.substring(lastColon + 1).all { it.isDigit() })
        noUser.substring(0, lastColon)
    else noUser
    return host.lowercase()
}

/** Sensible default URL when we just have a bare host. */
private fun defaultUrlFor(host: String): String =
    if (host.isBlank()) "" else "https://$host"
