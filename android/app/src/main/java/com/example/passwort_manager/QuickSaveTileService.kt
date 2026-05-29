package com.example.passwort_manager

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.TileService

/**
 * Quick Settings tile users can drag into their phone's quick-settings
 * panel for one-tap "save the credentials I just typed" access. The
 * tile launches MainActivity with [MainActivity.ACTION_ADD_ENTRY],
 * which routes straight into the Add Entry form post-unlock.
 *
 * This is the always-works fallback for cases where the Android
 * Autofill Framework's save-on-submit doesn't fire (which is
 * unfortunately most cases — Discord, custom-rendered apps,
 * webviews that don't trigger session-end, etc.). The user just
 * swipes down → taps the tile → fills the form.
 *
 * Users need to add this tile to their panel once. Some OEMs (Nothing
 * OS, Pixel Launcher) auto-promote tiles to the panel after first
 * install; on others the user edits the panel manually and drags
 * "Save credential" in.
 */
class QuickSaveTileService : TileService() {
    override fun onClick() {
        super.onClick()
        val intent = Intent(this, MainActivity::class.java).apply {
            action = MainActivity.ACTION_ADD_ENTRY
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        // collapseAndStart kept the tile panel from staying open over
        // our activity. The API changed in 34: startActivityAndCollapse
        // now takes a PendingIntent. Use the new shape on 34+ to
        // avoid the deprecated warning.
        if (Build.VERSION.SDK_INT >= 34) {
            val pi = PendingIntent.getActivity(
                this,
                /* requestCode = */ 0,
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
