package com.example.passwort_manager

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper

/**
 * Transparent shim activity that the accessibility-fill notification
 * launches. Pulls credentials from the intent extras, hands them to
 * the running [PasswortAccessibilityService] to inject via
 * ACTION_SET_TEXT, and finishes immediately so the foreground returns
 * to the app whose form we just filled.
 *
 * We don't render anything — `android:theme="@style/Theme.Translucent"`
 * keeps us off-screen.
 */
class FillTriggerActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val username = intent.getStringExtra(PasswortAccessibilityService.EXTRA_USERNAME).orEmpty()
        val password = intent.getStringExtra(PasswortAccessibilityService.EXTRA_PASSWORD).orEmpty()

        // Small delay so this activity actually finishes / the previous
        // (target) window regains focus before the service injects
        // text. Without the delay the service writes to *this*
        // activity's (empty) window, not the target form.
        Handler(Looper.getMainLooper()).postDelayed({
            PasswortAccessibilityService.instance?.fillCurrentForm(username, password)
        }, 250)

        // Bow out immediately.
        finish()
    }
}
