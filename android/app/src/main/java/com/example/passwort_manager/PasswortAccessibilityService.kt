package com.example.passwort_manager

import android.accessibilityservice.AccessibilityService
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.text.InputType
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat

/**
 * Accessibility-based autofill — the same fallback Bitwarden / 1Password
 * use when Android's official Autofill Framework drops the request on
 * the floor (50–70% of real apps, including most modern Material 3
 * apps with custom field markup).
 *
 * Why a second autofill engine: AutofillService relies on apps
 * declaring `autofillHints` or using EditText with sensible inputType.
 * Lots of apps don't do either — Compose fields without
 * `Modifier.semantics`, WebViews that swallow the events, banking
 * apps that fight autofill on purpose. AccessibilityService bypasses
 * all of that: we watch the live UI tree directly.
 *
 * Privacy trade-off (genuine): this service can observe everything
 * the user sees and types. We're careful to:
 *   - Only react to events from the app that has the password field
 *   - Never log or persist field contents anywhere except the vault
 *     (and only when the user explicitly confirms save)
 *   - Skip events when the vault is locked (nothing to suggest)
 *
 * The user has to explicitly enable us under:
 *   Einstellungen → Bedienungshilfen → Installierte Dienste →
 *   Password Manager → toggle on
 * and confirm the system warning.
 */
class PasswortAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "PasswortA11y"
        private const val FILL_CHANNEL = "fill_suggestions"
        private const val SAVE_CHANNEL = "save_suggestions"
        const val ACTION_FILL = "com.example.passwort_manager.ACTION_A11Y_FILL"
        const val ACTION_SAVE = "com.example.passwort_manager.ACTION_A11Y_SAVE"
        const val EXTRA_ACCOUNT_NAME = "pwm_a11y_account_name"
        const val EXTRA_USERNAME = "pwm_a11y_username"
        const val EXTRA_PASSWORD = "pwm_a11y_password"
        const val EXTRA_HOST = "pwm_a11y_host"

        /** Active service instance, used by FillTriggerActivity to push
         *  text into the field tree without rebuilding the lookup. */
        @Volatile
        var instance: PasswortAccessibilityService? = null
    }

    /** What we last saw on screen — used to detect "form gone → save". */
    private var lastPackageWithPassword: String? = null
    private var lastTypedUsername: String? = null
    private var lastTypedPassword: String? = null
    /** The password-input node IDs we last surfaced a fill prompt for —
     *  prevents the notification from re-firing on every UI event in
     *  the same screen state. */
    private var lastFillKey: String? = null

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
        ensureNotificationChannels()
        Log.i(TAG, "accessibility service connected")
    }

    override fun onUnbind(intent: Intent?): Boolean {
        instance = null
        return super.onUnbind(intent)
    }

    override fun onInterrupt() {
        // Required override — nothing to do.
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val ev = event ?: return
        // Only react when the vault is unlocked; otherwise we have
        // nothing to suggest.
        if (!VaultState.isUnlocked) return

        val pkg = ev.packageName?.toString().orEmpty()
        if (pkg.isEmpty() || pkg == packageName) return // skip ourselves

        when (ev.eventType) {
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED,
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED,
            AccessibilityEvent.TYPE_VIEW_FOCUSED -> {
                handleEvent(pkg)
            }
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                handleTextChanged(ev, pkg)
            }
        }
    }

    /** Scan the active window's UI tree for a password field. If
     *  found, look up matching credentials and surface a fill
     *  notification. If we previously saw a password field for [pkg]
     *  and it's gone now, surface a save notification with the
     *  captured values. */
    private fun handleEvent(pkg: String) {
        val root = rootInActiveWindow ?: return
        val pwNode = findPasswordField(root)

        if (pwNode != null) {
            // Form present — clear any stale "form gone" tracking that
            // would have triggered save.
            checkForFillSuggestion(root, pwNode, pkg)
        } else if (lastPackageWithPassword == pkg &&
            !lastTypedPassword.isNullOrEmpty()
        ) {
            // We previously had a password field in this package's
            // window, now it's gone. Treat as submit.
            offerSave(pkg)
            clearCaptureTracking()
        }
    }

    private fun handleTextChanged(event: AccessibilityEvent, pkg: String) {
        val source = event.source ?: return
        try {
            val text = source.text?.toString().orEmpty()
            if (text.isEmpty()) return

            // Is this the password field?
            if (isPasswordNode(source)) {
                lastTypedPassword = text
                lastPackageWithPassword = pkg
                return
            }

            // Look for an adjacent password sibling — if it exists,
            // this is the username field.
            if (lastPackageWithPassword == pkg) {
                // We're already capturing for this package; bind
                // text-changes on text-class nodes as the username.
                if (isTextLikeNode(source)) {
                    lastTypedUsername = text
                }
            }
        } finally {
            // Don't recycle on API 33+ — the framework owns the node.
            // On older API we'd recycle here; the deprecation makes
            // it a no-op in current targets.
        }
    }

    private fun checkForFillSuggestion(
        root: AccessibilityNodeInfo,
        pwNode: AccessibilityNodeInfo,
        pkg: String,
    ) {
        // Find the username field in the same form.
        val userNode = findUsernameField(root, pwNode)
        val webDomain = extractWebDomain(root)
        val matches = VaultState.findByHostOrPackage(
            webDomain = webDomain,
            packageName = pkg,
        )

        // De-dupe: if we already surfaced a notification for this
        // exact (pwNode-id, match-set), don't re-fire.
        val key = "$pkg|${pwNode.viewIdResourceName}|${matches.firstOrNull()?.name.orEmpty()}"
        if (key != lastFillKey) {
            lastFillKey = key
            if (matches.isNotEmpty()) {
                showFillNotification(matches.first(), webDomain.ifEmpty { pkg })
            }
        }

        // Track the capture target for later save AND re-read the
        // current values from the live tree. This is the recovery
        // path for when TYPE_VIEW_TEXT_CHANGED events arrived
        // partially or out of order (the "test.test2 captured as
        // test." bug). When the form goes away, we want the latest
        // truth, not an incremental log.
        lastPackageWithPassword = pkg
        userNode?.text?.toString()?.takeIf { it.isNotEmpty() }?.let {
            lastTypedUsername = it
        }
        pwNode.text?.toString()?.takeIf { it.isNotEmpty() }?.let {
            lastTypedPassword = it
        }
    }

    /** Push the saved (username, password) into the focused fields
     *  via ACTION_SET_TEXT. Called from [FillTriggerActivity] when
     *  the user taps our notification. */
    fun fillCurrentForm(username: String, password: String) {
        val root = rootInActiveWindow ?: return
        val pwNode = findPasswordField(root) ?: return
        val userNode = findUsernameField(root, pwNode)

        if (userNode != null && username.isNotEmpty()) {
            setText(userNode, username)
        }
        setText(pwNode, password)
        Log.i(TAG, "filled (user=${username.isNotEmpty()}, pw=true)")
    }

    private fun setText(node: AccessibilityNodeInfo, text: String) {
        val args = android.os.Bundle().apply {
            putCharSequence(
                AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                text,
            )
        }
        node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    private fun clearCaptureTracking() {
        lastPackageWithPassword = null
        lastTypedUsername = null
        lastTypedPassword = null
        lastFillKey = null
    }

    // ===================== Tree walking =====================

    private fun findPasswordField(root: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        return findFirst(root) { isPasswordNode(it) && it.isEditable && it.isVisibleToUser }
    }

    /** Heuristic: the username field is the text field nearest above
     *  the password field. We walk back through the focusable parents,
     *  then forward through their first-level children, picking the
     *  first text-like editable that's not the password. */
    private fun findUsernameField(
        root: AccessibilityNodeInfo,
        pwNode: AccessibilityNodeInfo,
    ): AccessibilityNodeInfo? {
        // Collect candidate text inputs in tree order, return the last
        // one before the password (i.e. the nearest preceding).
        val pwId = pwNode.uniqueIdSafe()
        val candidates = mutableListOf<AccessibilityNodeInfo>()
        var foundPw = false
        walkPreorder(root) { node ->
            if (node.uniqueIdSafe() == pwId) {
                foundPw = true
                return@walkPreorder !foundPw
            }
            if (isTextLikeNode(node) && node.isEditable && node.isVisibleToUser) {
                candidates += node
            }
            true
        }
        return candidates.lastOrNull()
    }

    private fun extractWebDomain(root: AccessibilityNodeInfo): String {
        // Some browsers expose the URL bar's text via accessibility.
        // Walk and look for nodes that look like URL bars.
        var found = ""
        walkPreorder(root) { node ->
            val id = node.viewIdResourceName.orEmpty().lowercase()
            if (id.contains("url_bar") || id.contains("location_bar") ||
                id.contains("address_bar")
            ) {
                found = node.text?.toString().orEmpty()
                return@walkPreorder false
            }
            true
        }
        return hostFromUrlString(found)
    }

    private fun hostFromUrlString(s: String): String {
        if (s.isBlank()) return ""
        val trimmed = s.trim()
        val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        return try {
            android.net.Uri.parse(withScheme).host.orEmpty()
        } catch (_: Throwable) { "" }
    }

    private fun walkPreorder(
        node: AccessibilityNodeInfo,
        visitor: (AccessibilityNodeInfo) -> Boolean,
    ) {
        if (!visitor(node)) return
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            walkPreorder(child, visitor)
        }
    }

    private fun findFirst(
        root: AccessibilityNodeInfo,
        predicate: (AccessibilityNodeInfo) -> Boolean,
    ): AccessibilityNodeInfo? {
        var found: AccessibilityNodeInfo? = null
        walkPreorder(root) { node ->
            if (predicate(node)) { found = node; false } else true
        }
        return found
    }

    private fun isPasswordNode(node: AccessibilityNodeInfo): Boolean {
        // Newer API: AccessibilityNodeInfo.isPassword().
        if (node.isPassword) return true
        // Older fallback via input type.
        val it = node.inputType
        val variation = it and InputType.TYPE_MASK_VARIATION
        val cls = it and InputType.TYPE_MASK_CLASS
        if (cls != InputType.TYPE_CLASS_TEXT) return false
        return variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
    }

    private fun isTextLikeNode(node: AccessibilityNodeInfo): Boolean {
        if (node.isPassword) return false
        val it = node.inputType
        val cls = it and InputType.TYPE_MASK_CLASS
        if (cls == 0) {
            // No input type — but className says EditText / TextInput.
            val cn = node.className?.toString().orEmpty()
            return cn.contains("EditText", ignoreCase = true) ||
                cn.contains("TextInput", ignoreCase = true)
        }
        return cls == InputType.TYPE_CLASS_TEXT
    }

    // ===================== Notification UX =====================

    private fun ensureNotificationChannels() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (nm.getNotificationChannel(FILL_CHANNEL) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        FILL_CHANNEL,
                        "Autofill suggestions",
                        NotificationManager.IMPORTANCE_HIGH,
                    ).apply {
                        description = "Tap to autofill saved credentials into the focused form."
                    },
                )
            }
            if (nm.getNotificationChannel(SAVE_CHANNEL) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        SAVE_CHANNEL,
                        "Save credential prompts",
                        NotificationManager.IMPORTANCE_DEFAULT,
                    ).apply {
                        description = "Tap to save a newly-entered credential to the vault."
                    },
                )
            }
        }
    }

    private fun showFillNotification(account: Account, host: String) {
        val intent = Intent(this, FillTriggerActivity::class.java).apply {
            action = ACTION_FILL
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
            putExtra(EXTRA_ACCOUNT_NAME, account.name)
            putExtra(EXTRA_USERNAME, account.username)
            putExtra(EXTRA_PASSWORD, account.password)
            putExtra(EXTRA_HOST, host)
        }
        val pi = PendingIntent.getActivity(
            this, account.hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif = NotificationCompat.Builder(this, FILL_CHANNEL)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("Fill ${account.name}")
            .setContentText(if (account.username.isNotEmpty())
                "Tap to fill ${account.username}@$host"
            else "Tap to fill credentials for $host")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(account.hashCode(), notif)
    }

    private fun offerSave(pkg: String) {
        val username = lastTypedUsername.orEmpty()
        val password = lastTypedPassword.orEmpty()
        if (password.isEmpty()) return

        // Skip the prompt entirely if we already have an exact match
        // in the vault — no point asking the user to "save" the same
        // credential they just used to log in. We check (host, user,
        // password) all three — if any differ, we still fire so the
        // SaveActivity can offer an "Update / Save as new" choice.
        val matches = VaultState.findByHostOrPackage(
            webDomain = "",
            packageName = pkg,
        )
        val exactMatch = matches.any { acc ->
            acc.username.trim().equals(username.trim(), ignoreCase = true) &&
                acc.password == password
        }
        if (exactMatch) return

        val intent = Intent(this, SaveActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
            putExtra(SaveActivity.EXTRA_CAPTURED_USERNAME, username)
            putExtra(SaveActivity.EXTRA_CAPTURED_PASSWORD, password)
            putExtra(SaveActivity.EXTRA_HOST, pkg)
            putExtra(SaveActivity.EXTRA_PACKAGE, pkg)
        }
        val pi = PendingIntent.getActivity(
            this, pkg.hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif = NotificationCompat.Builder(this, SAVE_CHANNEL)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("Save credential?")
            .setContentText("Save ${if (username.isNotEmpty()) "$username " else ""}for $pkg")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(("save_" + pkg).hashCode(), notif)
    }
}

private fun AccessibilityNodeInfo.uniqueIdSafe(): String {
    return viewIdResourceName?.takeIf { it.isNotEmpty() } ?: hashCode().toString()
}
