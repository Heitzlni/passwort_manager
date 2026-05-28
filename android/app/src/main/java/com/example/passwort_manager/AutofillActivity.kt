@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.example.passwort_manager

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.example.passwort_manager.ui.theme.Passwort_ManagerTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Spawned by Android when the user taps the "Tap to unlock" chip our
 * PasswortAutofillService returned in response to a locked-vault fill
 * request. We rehydrate the form context (which fields + which host)
 * from the intent extras, prompt for the master password, decrypt,
 * stash the result in [VaultState], and return a FillResponse with
 * the matching credentials via `setResult(RESULT_OK, ...)`.
 *
 * The autofill framework treats the returned `EXTRA_AUTHENTICATION_RESULT`
 * as either a Dataset (single fill) or a FillResponse (chooser). We
 * always send a FillResponse so the user can pick when there are
 * multiple matching accounts.
 */
class AutofillActivity : FragmentActivity() {

    private lateinit var autofillIds: Array<AutofillId>
    private lateinit var autofillHints: Array<String>
    private var webDomain: String = ""
    private var packageNameFromCaller: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // The autofill service stashed the parsed context for us; if
        // it's missing the intent is malformed (or we were launched by
        // a non-autofill code path) → just bail.
        @Suppress("UNCHECKED_CAST")
        autofillIds = (intent.getParcelableArrayExtra(
            PasswortAutofillService.EXTRA_AUTOFILL_IDS
        )?.map { it as AutofillId }?.toTypedArray()) ?: run {
            finish(); return
        }
        autofillHints = intent.getStringArrayExtra(
            PasswortAutofillService.EXTRA_AUTOFILL_HINTS
        ) ?: arrayOf()
        webDomain = intent.getStringExtra(PasswortAutofillService.EXTRA_WEB_DOMAIN).orEmpty()
        packageNameFromCaller = intent.getStringExtra(PasswortAutofillService.EXTRA_PACKAGE_NAME).orEmpty()

        setContent {
            Passwort_ManagerTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    UnlockForAutofill(
                        host = effectiveHost(),
                        onCancel = ::cancelAndFinish,
                        onUnlocked = { accounts -> finishWithDatasets(accounts) },
                    )
                }
            }
        }
    }

    private fun effectiveHost(): String {
        if (webDomain.isNotEmpty()) return webDomain.lowercase()
        if (packageNameFromCaller.isNotEmpty()) {
            val parts = packageNameFromCaller.split('.')
            if (parts.size >= 2) return "${parts[1]}.com".lowercase()
        }
        return ""
    }

    private fun cancelAndFinish() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }

    /** Build the FillResponse the autofill framework expects and return. */
    private fun finishWithDatasets(accounts: List<Account>) {
        // Same broader matcher the service uses — covers both webDomain
        // and package-name native-app fallbacks. Was previously stricter
        // here than in the service, which let "I just unlocked but
        // there's nothing for this host" cases short-circuit the save
        // flow too.
        val matches = VaultState.findByHostOrPackage(
            webDomain = webDomain,
            packageName = packageNameFromCaller,
        )

        // Always build a FillResponse — even when empty — so SaveInfo
        // survives the auth round-trip. Returning RESULT_CANCELED
        // makes Android drop the entire session, which kills save too.
        val builder = FillResponse.Builder()
        for (acc in matches) builder.addDataset(buildDataset(acc))

        // Re-attach SaveInfo (lost when the FillResponse was wrapped
        // by setAuthentication on the service side). Without this,
        // save would never fire after a locked-then-unlocked fill.
        attachSaveInfo(builder)

        val response = try {
            builder.build()
        } catch (_: IllegalStateException) {
            // FillResponse.Builder requires at least one dataset or
            // saveInfo — if attachSaveInfo found no password fields
            // it produced neither. In that very-rare case, cancel.
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val data = Intent().apply {
            putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
        }
        setResult(Activity.RESULT_OK, data)
        finish()
    }

    private fun attachSaveInfo(builder: FillResponse.Builder) {
        val passwordIds = autofillIds.withIndex()
            .filter { autofillHints.getOrNull(it.index) == FieldKind.Password.name }
            .map { it.value }
            .toTypedArray()
        if (passwordIds.isEmpty()) return
        val usernameIds = autofillIds.withIndex()
            .filter { autofillHints.getOrNull(it.index) == FieldKind.Username.name }
            .map { it.value }
            .toTypedArray()
        val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or
            (if (usernameIds.isNotEmpty()) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
        // FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE — see the matching
        // discussion in PasswortAutofillService.attachSaveInfo.
        val saveInfo = SaveInfo.Builder(type, passwordIds).apply {
            if (usernameIds.isNotEmpty()) setOptionalIds(usernameIds)
            setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
        }.build()
        builder.setSaveInfo(saveInfo)
    }

    private fun buildDataset(account: Account): Dataset {
        // Same reason as PasswortAutofillService.makePresentation —
        // must be a layout from our own package or autofill silently
        // refuses to render it.
        val rv = RemoteViews(packageName, R.layout.autofill_item)
        rv.setTextViewText(R.id.autofill_title, account.name.ifEmpty { "(unnamed)" })
        rv.setTextViewText(R.id.autofill_subtitle, account.username.ifEmpty { " " })
        val b = Dataset.Builder(rv)
        for ((i, id) in autofillIds.withIndex()) {
            val kind = autofillHints.getOrNull(i)
            val value = when (kind) {
                FieldKind.Username.name -> account.username.ifEmpty { account.name }
                FieldKind.Password.name -> account.password
                else -> null
            }
            if (!value.isNullOrEmpty()) {
                b.setValue(id, AutofillValue.forText(value))
            }
        }
        return b.build()
    }

    /** Same matching rule as VaultState.findByHost. */
    private fun matchesHost(a: Account, host: String): Boolean {
        if (host.isEmpty()) return false
        val urlHost = hostFromUrl(a.url)
        val key = if (urlHost.isNotEmpty()) urlHost else a.name
        val s = key.trim().lowercase()
        val h = host.trim().lowercase()
        return s.isNotEmpty() && (s == h || h.endsWith(".$s"))
    }

    private fun hostFromUrl(url: String): String {
        val s = url.trim()
        if (s.isEmpty()) return ""
        val after = s.substringAfter("://", s)
        val hp = after.split('/', '?', '#').first()
        val noUser = hp.substringAfterLast('@')
        val lastColon = noUser.lastIndexOf(':')
        return (if (lastColon > 0 && noUser.substring(lastColon + 1).all { it.isDigit() })
            noUser.substring(0, lastColon)
        else noUser).lowercase()
    }
}

@Composable
private fun UnlockForAutofill(
    host: String,
    onCancel: () -> Unit,
    onUnlocked: (List<Account>) -> Unit,
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val vaultFile = remember(context) { File(context.getExternalFilesDir(null), "vault.json") }
    val activity = context as? FragmentActivity

    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val biometricReady = activity != null
        && AppSettings.biometricEnabled
        && AppSettings.hasWrappedMaster()
        && KeystoreCipher.keyExists()

    // If the process happens to already hold an unlocked vault (rare
    // race — e.g. user just unlocked in the main app and autofill
    // fired before VaultState was checked), short-circuit.
    LaunchedEffect(Unit) {
        VaultState.accounts.value?.let(onUnlocked)
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Unlock to fill", style = MaterialTheme.typography.headlineSmall)
        if (host.isNotEmpty()) {
            Text(
                "For: $host",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (biometricReady) {
            Button(
                enabled = !busy,
                onClick = {
                    val act = activity ?: return@Button
                    busy = true
                    runAutofillBiometricUnlock(
                        activity = act,
                        scope = scope,
                        vaultFile = vaultFile,
                        onError = { msg -> error = msg; busy = false },
                        onSuccess = { accs -> onUnlocked(accs) },
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
        if (error != null) Text(error!!, color = MaterialTheme.colorScheme.error)
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
                                onUnlocked(r.accounts)
                            }
                            is UnlockResult.Failure -> {
                                error = r.message
                                busy = false
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
 * Biometric path for the autofill unlock screen — same flow as the
 * one in MainActivity, just routed to a different "what to do on
 * success" callback (push the accounts back into the autofill
 * framework instead of swapping the main UI screen).
 */
private fun runAutofillBiometricUnlock(
    activity: FragmentActivity,
    scope: kotlinx.coroutines.CoroutineScope,
    vaultFile: File,
    onError: (String) -> Unit,
    onSuccess: (List<Account>) -> Unit,
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
                        onSuccess(r.accounts)
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
