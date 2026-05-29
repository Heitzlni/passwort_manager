package com.example.passwort_manager

import android.accessibilityservice.AccessibilityService
import android.app.Notification
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
        // The channel IDs are versioned ("…_v2") because notification
        // channel settings (lockscreen visibility, importance, sound)
        // are immutable after creation. Bumping the suffix is the only
        // way to ship a new default — old channels are deleted in
        // ensureNotificationChannels.
        private const val FILL_CHANNEL = "fill_suggestions_v2"
        private const val SAVE_CHANNEL = "save_suggestions_v2"
        private val LEGACY_CHANNELS = listOf("fill_suggestions", "save_suggestions")
        /** Characters Android substitutes for hidden password chars in
         *  AccessibilityNodeInfo.getText() — '•', '●', '*', '·', '○',
         *  plus a couple of other common bullets seen in the wild. */
        private val MASK_GLYPHS = setOf('•', '●', '*', '·', '○', '∙', '◌', '⬤')

        /** Lowercase substrings we treat as "this clickable was the
         *  Login / Sign-in button". Used to fire save-on-submit even
         *  when the form doesn't disappear immediately after the
         *  click (apps with a "logging in…" spinner before transition,
         *  Compose apps that keep the form composed during navigation). */
        private val LOGIN_KEYWORDS = listOf(
            "login", "log in", "log-in",
            "sign in", "sign-in", "signin",
            "anmelden", "einloggen", "weiter",
            "se connecter", "iniciar sesión",
            "submit", "continue", "next",
        )

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
    /** Set of system / on-device-UI packages whose forms we don't want
     *  to react to. Their "passwords" aren't user-domain credentials —
     *  they're the SIM PIN, lock pattern, etc. */
    private val systemPackageBlocklist = setOf(
        "android",
        "com.android.systemui",
        "com.android.settings",
        "com.android.keyguard",
        "com.android.inputmethod.latin",
        "com.android.permissioncontroller",
        "com.google.android.gms",
        "com.google.android.googlequicksearchbox",
        "com.google.android.apps.nexuslauncher",
        // Nothing OS launcher / system UI variants
        "com.nothing.launcher",
        "com.nothing.systemui",
    )

    /** "Quick-fill" pending request: when the user picks an account in
     *  our picker activity, we stash its (username, password) here so
     *  the next AccessibilityEvent firing on a password field will
     *  inject them, regardless of host match. Cleared as soon as it
     *  fires or 30s elapse — we don't want stale credentials lurking. */
    @Volatile
    private var pendingFillRequest: PendingFill? = null

    private data class PendingFill(
        val username: String,
        val password: String,
        val expiresAtMillis: Long,
    )

    /** Active notification IDs by package, so we can cancel a stale
     *  "Tap to fill" once the user has clearly moved past it (typed
     *  something themselves, navigated to a different app, etc.). */
    private val activeFillNotifByPkg = mutableMapOf<String, Int>()

    /** Main-looper handler used by [handleClicked]'s short
     *  "wait-for-the-last-text-change" delay before firing save. */
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

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
        // SystemUI / lockscreen / launcher passcodes are not credentials
        // we should save — they're the device PIN itself.
        if (pkg in systemPackageBlocklist) return

        // Window switch — the prior package's "Tap to fill" prompt is
        // about a screen that's no longer in front of the user. Drop it.
        if (ev.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            cancelStaleFillNotifs(currentPkg = pkg)
        }

        when (ev.eventType) {
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED,
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED,
            AccessibilityEvent.TYPE_VIEW_FOCUSED -> {
                handleEvent(pkg)
            }
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                handleTextChanged(ev, pkg)
            }
            AccessibilityEvent.TYPE_VIEW_CLICKED -> {
                handleClicked(ev, pkg)
            }
        }
    }

    /** Heuristic submit detector. Apps that show a "logging in…"
     *  spinner before navigating, or apps that simply leave the form
     *  composed while transitioning, don't reliably fire a
     *  TYPE_WINDOW_STATE_CHANGED when the user submits. Catching the
     *  click on a button labeled Login / Sign in / Anmelden tells us
     *  the user pressed submit — fire save unconditionally (after a
     *  small delay so the password's last TEXT_CHANGED can land). */
    private fun handleClicked(event: AccessibilityEvent, pkg: String) {
        if (lastPackageWithPassword != pkg) return
        val src = event.source ?: return
        val label = (src.text?.toString() ?: src.contentDescription?.toString() ?: "")
            .lowercase()
            .trim()
        if (label.isEmpty() || label.length > 40) return // not a button label
        if (LOGIN_KEYWORDS.none { label.contains(it) }) return
        val pw = lastTypedPassword.orEmpty()
        val user = lastTypedUsername.orEmpty()
        if (pw.isEmpty() && user.isEmpty()) return
        mainHandler.postDelayed({
            if (lastPackageWithPassword != pkg) return@postDelayed
            if (lastTypedPassword.isNullOrEmpty() && lastTypedUsername.isNullOrEmpty()) {
                return@postDelayed
            }
            offerSave(pkg)
            clearCaptureTracking()
        }, 600L)
    }

    /** Cancels active fill notifications for every package except
     *  the one currently in front. Called on window changes so a
     *  "Tap to fill (Discord)" prompt doesn't survive the user
     *  switching to Maps. */
    private fun cancelStaleFillNotifs(currentPkg: String) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val stale = activeFillNotifByPkg.entries.filter { it.key != currentPkg }
        for ((pkg, id) in stale) {
            nm.cancel(id)
            activeFillNotifByPkg.remove(pkg)
        }
    }

    /** Scan the active window's UI tree for a password field. If
     *  found, look up matching credentials and surface a fill
     *  notification. If we previously saw a password field for [pkg]
     *  and it's gone now, treat that as a submit and offer save. */
    private fun handleEvent(pkg: String) {
        val root = rootInActiveWindow ?: return
        val pwNode = findPasswordField(root)

        if (pwNode != null) {
            // Quick-fill priority: user picked an account in our
            // picker and bounced back to the original app — silently
            // inject without showing a notification.
            consumePendingFillRequest(root, pwNode)
            checkForFillSuggestion(root, pwNode, pkg)
        } else if (
            lastPackageWithPassword == pkg &&
            !lastTypedPassword.isNullOrEmpty()
        ) {
            offerSave(pkg)
            clearCaptureTracking()
        }
    }

    private fun consumePendingFillRequest(
        root: AccessibilityNodeInfo,
        pwNode: AccessibilityNodeInfo,
    ) {
        val req = pendingFillRequest ?: return
        if (System.currentTimeMillis() > req.expiresAtMillis) {
            pendingFillRequest = null
            return
        }
        val userNode = findUsernameField(root, pwNode)
        if (userNode != null && req.username.isNotEmpty()) {
            setText(userNode, req.username)
        }
        setText(pwNode, req.password)
        pendingFillRequest = null
        Log.i(TAG, "consumed pending quick-fill request")
    }

    /** Public entry point — the picker activity calls this when the
     *  user selects an account. The credentials are queued for the
     *  next visible password field across any app. */
    fun queueQuickFill(username: String, password: String) {
        if (password.isEmpty()) return
        pendingFillRequest = PendingFill(
            username = username,
            password = password,
            // 30s gives the user time to dismiss the picker, swap
            // apps, focus the field, etc. — beyond that the request
            // is almost certainly forgotten and should not autofill
            // some other form by accident.
            expiresAtMillis = System.currentTimeMillis() + 30_000L,
        )
    }

    private fun handleTextChanged(event: AccessibilityEvent, pkg: String) {
        val source = event.source ?: return
        val text = source.text?.toString().orEmpty()
        if (text.isEmpty()) return

        if (isPasswordNode(source)) {
            // Skip pure-mask strings (the framework occasionally
            // dispatches "•••••" mid-flight) so we don't clobber a
            // real value already captured. Otherwise store whatever
            // we got — perfect characters when the OS doesn't mask
            // event-time text, partial mask when it does (the user
            // can fix it in SaveActivity).
            if (!looksLikePasswordMask(text)) {
                lastTypedPassword = text
            }
            lastPackageWithPassword = pkg
            // The user is actively typing — they don't need our
            // "Tap to fill" suggestion anymore.
            cancelFillNotifFor(pkg)
            return
        }

        // Adjacent text input — treat as the username if we've already
        // seen a password field for this package.
        if (lastPackageWithPassword == pkg && isTextLikeNode(source)) {
            lastTypedUsername = text
        }
    }

    /** True if [s] consists entirely of a single mask glyph the OS
     *  substitutes for hidden password characters. We use this to
     *  skip events that would otherwise overwrite a real value with
     *  bullets. Non-all-mask strings (e.g. "•••••3") are still
     *  stored — the user can correct them in the save form. */
    private fun looksLikePasswordMask(s: String): Boolean {
        if (s.length < 2) return false
        val first = s[0]
        if (first !in MASK_GLYPHS) return false
        return s.all { it == first }
    }

    private fun cancelFillNotifFor(pkg: String) {
        val id = activeFillNotifByPkg.remove(pkg) ?: return
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.cancel(id)
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
        // username from the live tree. This recovers the truncation
        // case where TYPE_VIEW_TEXT_CHANGED events arrived partially
        // ("test.test2" → "test."). We deliberately do NOT re-read
        // the password field's .text: Android returns its masked form
        // ("•••••") which would clobber the real characters we got
        // off the text-change events. The password stays whatever we
        // last captured from TEXT_CHANGED.
        lastPackageWithPassword = pkg
        val userText = userNode?.text?.toString().orEmpty()
        if (
            userText.isNotEmpty() &&
            !looksLikePasswordMask(userText) &&
            userText != lastTypedPassword
        ) {
            lastTypedUsername = userText
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

    /** True if [s] contains any mask glyph anywhere — distinct from
     *  [looksLikePasswordMask] which only matches strings entirely made
     *  of one mask char. A typical partial capture is "•••••3" — most
     *  chars masked, last one through; this returns true for it. */
    private fun containsMaskGlyph(s: String): Boolean =
        s.any { it in MASK_GLYPHS }

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
            // Drop pre-v2 channels so they stop appearing in the system
            // notification settings list as orphans.
            for (legacy in LEGACY_CHANNELS) nm.deleteNotificationChannel(legacy)
            if (nm.getNotificationChannel(FILL_CHANNEL) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        FILL_CHANNEL,
                        "Autofill suggestions",
                        NotificationManager.IMPORTANCE_HIGH,
                    ).apply {
                        description = "Tap to autofill saved credentials into the focused form."
                        // Hide content on the lockscreen — we never want
                        // "Fill account@host" to show before the phone is
                        // unlocked.
                        lockscreenVisibility = Notification.VISIBILITY_SECRET
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
                        lockscreenVisibility = Notification.VISIBILITY_SECRET
                    },
                )
            }
        }
    }

    private fun showFillNotification(account: Account, host: String) {
        // Broadcast (not Activity) so the target app keeps focus while
        // the inject happens — no transparent-Activity flicker.
        val intent = Intent(this, FillBroadcastReceiver::class.java).apply {
            action = ACTION_FILL
            putExtra(EXTRA_ACCOUNT_NAME, account.name)
            putExtra(EXTRA_USERNAME, account.username)
            putExtra(EXTRA_PASSWORD, account.password)
            putExtra(EXTRA_HOST, host)
        }
        val pi = PendingIntent.getBroadcast(
            this, account.hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif = NotificationCompat.Builder(this, FILL_CHANNEL)
            .setSmallIcon(R.drawable.ic_lock_status)
            .setColor(0xFF9C82FF.toInt())
            .setContentTitle("Fill ${account.name}")
            .setContentText(if (account.username.isNotEmpty())
                "Tap to fill ${account.username}@$host"
            else "Tap to fill credentials for $host")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setAutoCancel(true)
            // Auto-dismiss after 20s — by then the user has either
            // tapped, started typing (which cancels via the text-change
            // path), or moved on.
            .setTimeoutAfter(20_000L)
            .setContentIntent(pi)
            .build()
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val notifId = ("fill_" + host + "_" + account.hashCode()).hashCode()
        // Track so we can cancel proactively when the user is clearly
        // past needing this suggestion.
        activeFillNotifByPkg[lastPackageWithPassword.orEmpty().ifEmpty { host }] = notifId
        nm.notify(notifId, notif)
    }

    private fun offerSave(pkg: String) {
        // Form's gone — any "Tap to fill" prompt from before submit is
        // now stale (the field it was filling no longer exists).
        cancelFillNotifFor(pkg)
        val username = lastTypedUsername.orEmpty()
        val rawPassword = lastTypedPassword.orEmpty()
        // Nothing typed at all — not a real form submit, just a
        // window churn. Skip.
        if (rawPassword.isEmpty() && username.isEmpty()) return

        // Partial capture: the OS masked some characters before our
        // event handler saw them ("•••••3"). Don't try to save garbage —
        // open the form with the password blanked + a "type it" banner
        // so the user can correct it. Username is preserved (never
        // masked) and host matching still drives Update-vs-New.
        val partial = rawPassword.isEmpty() || containsMaskGlyph(rawPassword)
        val password = if (partial) "" else rawPassword

        if (!partial) {
            // Skip the prompt entirely if we already have an exact
            // match in the vault — no point asking the user to "save"
            // the same credential they just used to log in. Only valid
            // when we have a real password to compare; partial-capture
            // skips this shortcut so the user can still pick Update.
            val matches = VaultState.findByHostOrPackage(
                webDomain = "",
                packageName = pkg,
            )
            val exactMatch = matches.any { acc ->
                acc.username.trim().equals(username.trim(), ignoreCase = true) &&
                    acc.password == password
            }
            if (exactMatch) return
        }

        val intent = Intent(this, SaveActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
            putExtra(SaveActivity.EXTRA_CAPTURED_USERNAME, username)
            putExtra(SaveActivity.EXTRA_CAPTURED_PASSWORD, password)
            putExtra(SaveActivity.EXTRA_HOST, pkg)
            putExtra(SaveActivity.EXTRA_PACKAGE, pkg)
            putExtra(SaveActivity.EXTRA_CAPTURE_PARTIAL, partial)
        }
        val pi = PendingIntent.getActivity(
            this, pkg.hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notif = NotificationCompat.Builder(this, SAVE_CHANNEL)
            .setSmallIcon(R.drawable.ic_lock_status)
            .setColor(0xFF9C82FF.toInt())
            .setContentTitle("Save credential?")
            .setContentText("Save ${if (username.isNotEmpty()) "$username " else ""}for $pkg")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setAutoCancel(true)
            // Auto-dismiss after 30s — if the user hasn't tapped by
            // then they've moved on; the shade should stay clean.
            .setTimeoutAfter(30_000L)
            .setContentIntent(pi)
            .build()
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(("save_" + pkg).hashCode(), notif)
    }
}

private fun AccessibilityNodeInfo.uniqueIdSafe(): String {
    return viewIdResourceName?.takeIf { it.isNotEmpty() } ?: hashCode().toString()
}
