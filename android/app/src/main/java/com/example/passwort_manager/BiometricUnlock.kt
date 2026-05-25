package com.example.passwort_manager

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

/**
 * Wraps the AndroidX [BiometricPrompt] so the rest of the app can ask
 * "authenticate the user and hand back a Cipher" without worrying
 * about the lifecycle gymnastics.
 *
 * Caller passes a Cipher already initialised for ENCRYPT_MODE or
 * DECRYPT_MODE via [KeystoreCipher]; the prompt only succeeds when the
 * Keystore key's per-use biometric guard is satisfied, after which the
 * Cipher inside the success callback is usable for exactly one
 * encrypt/decrypt operation.
 */
object BiometricUnlock {
    fun prompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        negativeButton: String,
        cipher: Cipher,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit,
        onCancel: () -> Unit = {},
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // User-cancelled vs hardware-failed: forward both
                    // through onCancel for cancel-like states, onError
                    // otherwise, so the UI can do the right thing.
                    when (errorCode) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED -> onCancel()

                        else -> onError(errString.toString())
                    }
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult,
                ) {
                    val authedCipher = result.cryptoObject?.cipher
                    if (authedCipher == null) {
                        onError("biometric did not return a usable cipher")
                        return
                    }
                    onSuccess(authedCipher)
                }

                override fun onAuthenticationFailed() {
                    // Single failed attempt — Android handles retry; just
                    // wait for another success or eventual error.
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeButton)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
}
