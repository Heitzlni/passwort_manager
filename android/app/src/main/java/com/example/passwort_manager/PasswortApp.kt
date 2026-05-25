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
        // Touching the singleton here ensures it's initialized eagerly
        // (instead of lazily on first call from an arbitrary thread).
        @Suppress("unused")
        val ignored = VaultState
    }
}
