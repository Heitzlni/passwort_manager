@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.example.passwort_manager

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.credentials.PasswordCredential
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.GetCredentialResponse
import androidx.fragment.app.FragmentActivity
import com.example.passwort_manager.ui.theme.Passwort_ManagerTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Launched by Android when the user taps one of our credential
 * entries in the Credential Manager picker. The intent carries the
 * (username, password) of the chosen entry as extras — we either
 * return them straight back (vault unlocked) or run the user
 * through unlock first (locked / biometric required).
 */
@RequiresApi(34)
class CredentialFillActivity : FragmentActivity() {

    companion object {
        const val EXTRA_USERNAME = "pwm_cred_username"
        const val EXTRA_PASSWORD = "pwm_cred_password"
        const val EXTRA_NAME = "pwm_cred_name"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val username = intent.getStringExtra(EXTRA_USERNAME).orEmpty()
        val password = intent.getStringExtra(EXTRA_PASSWORD).orEmpty()
        val name = intent.getStringExtra(EXTRA_NAME).orEmpty()
        if (password.isBlank()) {
            failAndFinish("no credential payload")
            return
        }

        // Fast path: vault unlocked AND credential plaintext was
        // already embedded in the PendingIntent (it was at entry
        // build time). Hand it back immediately.
        if (VaultState.accounts.value != null) {
            returnCredential(username, password)
            return
        }

        // Locked: render a small unlock screen first (master or
        // fingerprint), then return the credential.
        setContent {
            Passwort_ManagerTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    UnlockGate(
                        name = name,
                        onCancel = { setResult(Activity.RESULT_CANCELED); finish() },
                        onUnlocked = { returnCredential(username, password) },
                    )
                }
            }
        }
    }

    private fun returnCredential(username: String, password: String) {
        val response = GetCredentialResponse(PasswordCredential(username, password))
        val data = Intent()
        PendingIntentHandler.setGetCredentialResponse(data, response)
        setResult(Activity.RESULT_OK, data)
        finish()
    }

    private fun failAndFinish(reason: String) {
        val data = Intent()
        PendingIntentHandler.setGetCredentialException(
            data,
            GetCredentialUnknownException(reason),
        )
        setResult(Activity.RESULT_OK, data)
        finish()
    }
}

@Composable
private fun UnlockGate(
    name: String,
    onCancel: () -> Unit,
    onUnlocked: () -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? FragmentActivity
    val scope = rememberCoroutineScope()
    val vaultFile = remember(context) { File(context.getExternalFilesDir(null), "vault.json") }

    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val biometricReady = activity != null
        && AppSettings.biometricEnabled
        && AppSettings.hasWrappedMaster()
        && KeystoreCipher.keyExists()

    // If somehow the vault unlocks under us, flip immediately.
    LaunchedEffect(VaultState.accounts.value) {
        if (VaultState.accounts.value != null) onUnlocked()
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Unlock to fill", style = MaterialTheme.typography.headlineSmall)
        if (name.isNotEmpty()) {
            Text(
                name,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (biometricReady) {
            Button(
                enabled = !busy,
                onClick = {
                    val act = activity ?: return@Button
                    busy = true
                    runBiometricForCredential(
                        activity = act,
                        scope = scope,
                        vaultFile = vaultFile,
                        onError = { msg -> error = msg; busy = false },
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Unlock with fingerprint") }
            Text(
                "Or master password:",
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
                                onUnlocked()
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

private fun runBiometricForCredential(
    activity: FragmentActivity,
    scope: kotlinx.coroutines.CoroutineScope,
    vaultFile: File,
    onError: (String) -> Unit,
) {
    val wrapped = AppSettings.loadWrappedMaster() ?: run {
        onError("No biometric master stored."); return
    }
    val cipher = try {
        KeystoreCipher.decryptCipher(wrapped.first)
    } catch (_: android.security.keystore.KeyPermanentlyInvalidatedException) {
        AppSettings.clearWrappedMaster()
        KeystoreCipher.wipeKey()
        onError("Biometric changed since setup. Enter master."); return
    } catch (e: Exception) {
        onError("Biometric not available: ${e.message}"); return
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
                onError("Biometric decrypt failed: ${e.message}"); return@prompt
            }
            val master = String(masterBytes, Charsets.UTF_8)
            scope.launch {
                val bytes = vaultFile.readBytes()
                val r = withContext(Dispatchers.Default) {
                    VaultBridge.unlock(bytes, master)
                }
                when (r) {
                    is UnlockResult.Success -> VaultState.unlock(r.accounts, r.derivedKey, vaultFile)
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
