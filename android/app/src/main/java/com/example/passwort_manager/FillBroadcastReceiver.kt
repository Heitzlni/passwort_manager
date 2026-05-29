package com.example.passwort_manager

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Receives the "Tap to fill" notification tap and queues the chosen
 * credentials in [PasswortAccessibilityService] without going through
 * any Activity. The previous shim activity (FillTriggerActivity) was
 * transparent but still briefly stole focus from the target app —
 * users saw a "redirect to Password Manager → back to Discord" flicker.
 * A broadcast skips that entirely.
 */
class FillBroadcastReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val username = intent.getStringExtra(PasswortAccessibilityService.EXTRA_USERNAME).orEmpty()
        val password = intent.getStringExtra(PasswortAccessibilityService.EXTRA_PASSWORD).orEmpty()
        PasswortAccessibilityService.instance?.queueQuickFill(username, password)
    }
}
