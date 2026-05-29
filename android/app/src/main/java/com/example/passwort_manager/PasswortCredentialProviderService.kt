package com.example.passwort_manager

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.BeginGetCredentialOption
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest

/**
 * Android 14+ Credential Manager integration. Sits alongside the
 * legacy [PasswortAutofillService]: modern apps prefer this unified
 * API (passwords + passkeys + federated identity), older apps fall
 * back to autofill.
 *
 * Three callbacks worth knowing:
 *
 *   - `onBeginGetCredentialRequest` — apps asking "do you have a
 *     credential for this site/app?". We answer with one
 *     [PasswordCredentialEntry] per matching vault entry. Each entry
 *     carries a PendingIntent that the system fires when the user
 *     taps it; the activity then returns the actual PasswordCredential.
 *
 *   - `onBeginCreateCredentialRequest` — apps asking to save a new
 *     credential (Discord "save password?" after first login). We
 *     answer with a [CreateEntry] pointing at our existing
 *     [SaveActivity] (which already knows how to take captured
 *     credentials and write them into the vault).
 *
 *   - `onClearCredentialStateRequest` — apps asking us to forget any
 *     local cache of credentials. We don't cache anything (the
 *     unlocked vault lives in VaultState, separate concern), so we
 *     just succeed.
 */
@RequiresApi(34)
class PasswortCredentialProviderService : CredentialProviderService() {

    companion object {
        private const val TAG = "PasswortCred"
        private const val SOFT_LIMIT = 8 // most entries we put in the picker
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        Log.i(TAG, "onBeginGetCredentialRequest")
        val response = try {
            buildGetResponse(request)
        } catch (e: Exception) {
            Log.w(TAG, "get failed: ${e.message}")
            BeginGetCredentialResponse.Builder().build()
        }
        callback.onResult(response)
    }

    private fun buildGetResponse(
        request: BeginGetCredentialRequest,
    ): BeginGetCredentialResponse {
        val callingPackage = request.callingAppInfo?.packageName.orEmpty()
        val callingOrigin = request.callingAppInfo?.origin.orEmpty()
        val matches = VaultState.findByHostOrPackage(
            webDomain = hostFromOrigin(callingOrigin),
            packageName = callingPackage,
        ).take(SOFT_LIMIT)

        Log.i(
            TAG,
            "  caller='$callingPackage' origin='$callingOrigin' matches=${matches.size}",
        )

        val builder = BeginGetCredentialResponse.Builder()
        for (option in request.beginGetCredentialOptions) {
            if (option !is BeginGetPasswordOption) continue
            for (acc in matches) {
                builder.addCredentialEntry(buildPasswordEntry(acc, option))
            }
        }
        return builder.build()
    }

    private fun buildPasswordEntry(
        account: Account,
        option: BeginGetPasswordOption,
    ): CredentialEntry {
        val intent = Intent(this, CredentialFillActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
            putExtra(CredentialFillActivity.EXTRA_USERNAME, account.username)
            putExtra(CredentialFillActivity.EXTRA_PASSWORD, account.password)
            putExtra(CredentialFillActivity.EXTRA_NAME, account.name)
        }
        val pi = PendingIntent.getActivity(
            this,
            account.hashCode(),
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return PasswordCredentialEntry.Builder(
            this,
            account.username.ifEmpty { account.name },
            pi,
            option,
        )
            .setDisplayName(account.name.ifEmpty { account.username })
            .build()
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        Log.i(TAG, "onBeginCreateCredentialRequest type=${request::class.simpleName}")
        val response = when (request) {
            is BeginCreatePasswordCredentialRequest -> buildCreateResponse(request)
            else -> BeginCreateCredentialResponse.Builder().build()
        }
        callback.onResult(response)
    }

    private fun buildCreateResponse(
        request: BeginCreatePasswordCredentialRequest,
    ): BeginCreateCredentialResponse {
        val callingPackage = request.callingAppInfo?.packageName.orEmpty()
        // Reuse SaveActivity — it already knows how to take captured
        // credentials and write them into the vault. The intent
        // doesn't carry username/password directly because they live
        // in the CreateCredentialRequest that the system attaches to
        // the launched intent under PendingIntentHandler.
        val intent = Intent(this, SaveActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
            putExtra(SaveActivity.EXTRA_FROM_CREDENTIAL_MANAGER, true)
            putExtra(SaveActivity.EXTRA_PACKAGE, callingPackage)
        }
        val pi = PendingIntent.getActivity(
            this,
            /* requestCode = */ 1,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val entry = CreateEntry.Builder(
            getString(R.string.app_name),
            pi,
        ).build()
        return BeginCreateCredentialResponse.Builder()
            .addCreateEntry(entry)
            .build()
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // We don't keep any device-side cache the framework knows about
        // — vault state lives in VaultState and is cleared on auto-lock.
        callback.onResult(null)
    }

    /** Pull the bare host from a web origin string like
     *  `https://discord.com:443/login` → `discord.com`. */
    private fun hostFromOrigin(origin: String): String {
        if (origin.isBlank()) return ""
        return try {
            android.net.Uri.parse(origin).host.orEmpty()
        } catch (_: Throwable) {
            ""
        }
    }
}
