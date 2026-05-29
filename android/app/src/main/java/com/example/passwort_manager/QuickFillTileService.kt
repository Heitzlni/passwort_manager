package com.example.passwort_manager

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.TileService

/**
 * Quick Settings tile for "fill any account into the form I have
 * open right now" — even if the vault has no entry that matches
 * the current app's host. Use case: you have one email+password
 * combo saved as "Gmail", you're logging into a brand-new service
 * (YouTube, GitHub, whatever) with the same credentials, and you
 * want a one-tap way to inject them.
 *
 * Flow:
 *   1. User taps the tile.
 *   2. MainActivity opens in "pick to fill" mode (account list with
 *      a tap-to-fill behavior instead of tap-to-view).
 *   3. User taps an account — credentials are queued in the
 *      accessibility service.
 *   4. MainActivity finishes; the prior app comes back to the
 *      foreground; the accessibility service fills the focused
 *      password field on the next event.
 *   5. The normal save-on-submit detector picks up the captured
 *      credentials and offers to save them for the new app too.
 */
class QuickFillTileService : TileService() {
    override fun onClick() {
        super.onClick()
        val intent = Intent(this, MainActivity::class.java).apply {
            action = MainActivity.ACTION_PICK_AND_FILL
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        if (Build.VERSION.SDK_INT >= 34) {
            val pi = PendingIntent.getActivity(
                this,
                /* requestCode = */ 1,
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
