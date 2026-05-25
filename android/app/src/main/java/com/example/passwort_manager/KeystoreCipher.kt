package com.example.passwort_manager

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Owner of the Keystore-backed AES key used to wrap the master
 * password for biometric unlock. The key is configured so any use
 * (encrypt OR decrypt) requires a successful Class 3 (STRONG)
 * biometric authentication — meaning the actual encrypt/decrypt
 * call below only succeeds inside a BiometricPrompt.CryptoObject
 * callback.
 *
 * Enrolling a new fingerprint invalidates the key
 * (`setInvalidatedByBiometricEnrollment(true)`), which is the right
 * behaviour for a vault: a new fingerprint owner shouldn't inherit
 * the previous owner's wrapped master.
 */
object KeystoreCipher {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "passwort_manager_biometric_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    fun keyExists(): Boolean = keyStore().containsAlias(KEY_ALIAS)

    /** Cipher ready for ENCRYPT_MODE — pass to BiometricPrompt.CryptoObject. */
    fun encryptCipher(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        return cipher
    }

    /**
     * Cipher ready for DECRYPT_MODE bound to the IV captured at encrypt
     * time. Throws KeyPermanentlyInvalidatedException if the user added
     * or removed a biometric since the key was created — caller should
     * catch and treat as "biometric unlock no longer valid".
     */
    @Throws(KeyPermanentlyInvalidatedException::class)
    fun decryptCipher(iv: ByteArray): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            getOrCreateKey(),
            GCMParameterSpec(GCM_TAG_BITS, iv),
        )
        return cipher
    }

    fun wipeKey() {
        val ks = keyStore()
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
    }

    private fun getOrCreateKey(): SecretKey {
        val ks = keyStore()
        if (ks.containsAlias(KEY_ALIAS)) {
            return ks.getKey(KEY_ALIAS, null) as SecretKey
        }
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // Per-use auth; Class 3 (STRONG) biometric only.
                    setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG,
                    )
                }
            }
            .build()
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        kg.init(spec)
        return kg.generateKey()
    }
}
