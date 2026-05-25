@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.example.passwort_manager

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
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
class AutofillActivity : ComponentActivity() {

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
        val host = effectiveHost()
        val matches = accounts.filter { matchesHost(it, host) }

        if (matches.isEmpty()) {
            // We unlocked, but the vault has nothing for this host.
            // Surface that to the user via the autofill UX by just
            // returning an empty response (no chip) and finishing.
            // The unlocked state is now live, so the next autofill
            // tap will work without re-unlock.
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val response = FillResponse.Builder().apply {
            for (acc in matches) addDataset(buildDataset(acc))
        }.build()

        val data = Intent().apply {
            putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
        }
        setResult(Activity.RESULT_OK, data)
        finish()
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

    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

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
