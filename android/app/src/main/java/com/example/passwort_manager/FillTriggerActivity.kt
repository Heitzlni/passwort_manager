package com.example.passwort_manager

import android.app.Activity
import android.os.Bundle

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

        // Queue the inject and bow out. The service consumes the
        // request when the next accessibility event arrives showing
        // a password field — by then the target app has actually
        // regained focus and rootInActiveWindow points at its tree.
        //
        // A fixed delay (we used to use 250ms) was racey on slower
        // devices: by the time the service ran, focus had only just
        // started transitioning back to the source app.
        PasswortAccessibilityService.instance?.queueQuickFill(username, password)

        finish()
    }
}
