package com.example.passwort_manager

import android.content.Context
import androidx.biometric.BiometricManager

/**
 * Thin wrapper around the AndroidX [BiometricManager] for availability
 * checks. Phase 2.5 step 3 will add the actual prompt + Keystore-wrap
 * flow that lets fingerprint unlock the vault; for now we just expose
 * "can the user use biometric at all on this device?" so the Settings
 * UI shows accurate info.
 */
object BiometricHelper {

    enum class Availability {
        Ready,                 // hardware + enrollment present
        NoHardware,            // no fingerprint / face sensor at all
        NotEnrolled,           // hardware present but user hasn't enrolled
        Unavailable,           // hardware temporarily unavailable
        SecurityUpdateNeeded,  // Android needs a security update
        Unknown,               // status couldn't be determined
    }

    fun availability(context: Context): Availability {
        val mgr = BiometricManager.from(context)
        // BIOMETRIC_STRONG = Class 3: fingerprint or stronger. Class 2
        // (BIOMETRIC_WEAK) would include face unlock on some devices,
        // which we don't want gating a password vault.
        return when (mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Availability.Ready
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> Availability.NoHardware
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Availability.Unavailable
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NotEnrolled
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> Availability.SecurityUpdateNeeded
            else -> Availability.Unknown
        }
    }

    /** Pretty user-facing message for each state, for the Settings screen. */
    fun description(state: Availability): String = when (state) {
        Availability.Ready ->
            "Use fingerprint to unlock the vault. " +
                "Coming in the next update — the toggle persists your choice now."
        Availability.NoHardware ->
            "This device has no fingerprint sensor or other strong biometric hardware."
        Availability.NotEnrolled ->
            "Hardware is present but no fingerprint is enrolled. " +
                "Add one in Android settings to enable this."
        Availability.Unavailable ->
            "Biometric hardware is temporarily unavailable."
        Availability.SecurityUpdateNeeded ->
            "Android requires a security update before biometric unlock can be used."
        Availability.Unknown ->
            "Biometric availability could not be determined."
    }
}
