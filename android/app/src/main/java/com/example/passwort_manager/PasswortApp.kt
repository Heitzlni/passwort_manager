package com.example.passwort_manager

import android.app.Application

/**
 * Application subclass. Mostly here so the autofill service and the
 * activities reliably share the same JVM (the VaultState singleton
 * lives in the process; if Android tears down our process, the next
 * call rebuilds an empty VaultState and the user re-unlocks).
 *
 * Registered in AndroidManifest.xml via `android:name`.
 */
class PasswortApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AppSettings.init(this)
        // Push the saved auto-lock value into VaultState so a vault
        // unlocked later in this process uses the user's preference.
        VaultState.setAutoLockTimeoutMs(
            if (AppSettings.autoLockMinutes <= 0) Long.MAX_VALUE / 2
            else AppSettings.autoLockMinutes * 60L * 1000L
        )
    }
}
