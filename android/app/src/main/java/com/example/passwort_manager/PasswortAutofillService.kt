package com.example.passwort_manager

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.v1.InlineSuggestionUi

/**
 * Android Autofill Framework integration.
 *
 * Fill path:
 *   The OS calls `onFillRequest` whenever a user focuses an input
 *   field in any app that supports autofill (every browser, every
 *   app with a password input). We walk the form, extract the web
 *   domain or package name, find matching entries in [VaultState],
 *   and answer with a list of [Dataset]s — one per credential match.
 *   If the vault is locked we return an authentication intent that
 *   opens [AutofillActivity] instead.
 *
 * Save path:
 *   We attach a [SaveInfo] to every FillResponse so Android calls
 *   our `onSaveRequest` after the user submits a form whose fields
 *   we recognised. [SaveActivity] picks up the typed values, shows
 *   a pre-filled add-entry form, and persists via [VaultState] (the
 *   same write path the in-app "+" button uses).
 */
class PasswortAutofillService : AutofillService() {

    companion object {
        private const val TAG = "PasswortAutofill"
        const val EXTRA_AUTOFILL_IDS = "pwm_autofill_ids"
        const val EXTRA_AUTOFILL_HINTS = "pwm_autofill_hints"
        const val EXTRA_WEB_DOMAIN = "pwm_web_domain"
        const val EXTRA_PACKAGE_NAME = "pwm_package_name"
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        Log.i(TAG, "onFillRequest called, contexts=${request.fillContexts.size}")
        // Newest context is the most relevant — Android may stack a few.
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            Log.i(TAG, "  → exit: no AssistStructure in any context")
            callback.onSuccess(null)
            return
        }

        val parsed = parseStructure(structure)
        Log.i(
            TAG,
            "  parsed: host='${parsed.host()}' fields=${parsed.fields.size}",
        )
        if (parsed.fields.isEmpty()) {
            Log.i(TAG, "  → exit: no username/password fields detected in this form")
            callback.onSuccess(null)
            return
        }

        // Pull inline-presentation specs from the request. Modern
        // Android (API 30+) prefers chip-above-keyboard "inline"
        // presentations to the legacy RemoteViews-only chips;
        // Nothing OS 4 in particular *requires* inline presentations
        // to display the chip at all. If the framework didn't pass
        // any specs (older Android, or some IMEs don't support
        // inline) we still attach RemoteViews and the user can
        // long-press → 3-dots → Autofill to see them.
        val inlineSpecs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            request.inlineSuggestionsRequest?.inlinePresentationSpecs.orEmpty()
        } else emptyList()

        val accounts = VaultState.accounts.value
        if (accounts == null) {
            Log.i(TAG, "  → vault locked, returning auth fill response")
            callback.onSuccess(buildAuthFillResponse(parsed, inlineSpecs.firstOrNull()))
            return
        }

        val matches = VaultState.findByHostOrPackage(
            webDomain = parsed.webDomain,
            packageName = parsed.packageName,
        )

        Log.i(
            TAG,
            "  webDomain='${parsed.webDomain}' pkg='${parsed.packageName}' matches=${matches.size}",
        )

        if (matches.isEmpty()) {
            Log.i(TAG, "  → no direct matches; still attaching save-info + close")
            // We don't have a credential to offer, but we want save
            // info attached so submit-time saves still work.
            val emptyBuilder = FillResponse.Builder()
            attachSaveInfo(emptyBuilder, parsed)
            VaultState.touch()
            // Only return the response if there's at least a SaveInfo
            // on it; an empty FillResponse with neither datasets nor
            // saveInfo throws.
            val passwordFields = parsed.fields.any { it.kind == FieldKind.Password }
            callback.onSuccess(if (passwordFields) emptyBuilder.build() else null)
            return
        }

        val builder = FillResponse.Builder()
        for ((i, acc) in matches.withIndex()) {
            val spec = inlineSpecs.getOrNull(i) ?: inlineSpecs.lastOrNull()
            builder.addDataset(buildDataset(acc, parsed, spec))
        }
        attachSaveInfo(builder, parsed)
        VaultState.touch()
        Log.i(
            TAG,
            "  → returning FillResponse with ${matches.size} datasets (inline=${inlineSpecs.size})",
        )
        callback.onSuccess(builder.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Walk the structure to read out what the user actually typed.
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess()
            return
        }
        val parsed = parseStructure(structure)
        val (typedUsername, typedPassword) = readTypedValues(structure, parsed)

        // Without a password there's nothing useful to save.
        if (typedPassword.isNullOrBlank()) {
            Log.i(TAG, "onSaveRequest: no password typed, dropping")
            callback.onSuccess()
            return
        }
        Log.i(
            TAG,
            "onSaveRequest: host=${parsed.host()} hasUsername=${!typedUsername.isNullOrBlank()}",
        )

        // Launch SaveActivity with the captured credentials. The
        // activity decides whether to update an existing entry or
        // create a new one, prompts the user, and persists via
        // VaultState. We hand back success to Android immediately —
        // there's no useful "did the user save?" signal we need to
        // forward.
        val intent = Intent(this, SaveActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
            putExtra(SaveActivity.EXTRA_CAPTURED_USERNAME, typedUsername.orEmpty())
            putExtra(SaveActivity.EXTRA_CAPTURED_PASSWORD, typedPassword)
            putExtra(SaveActivity.EXTRA_HOST, parsed.host())
            putExtra(SaveActivity.EXTRA_PACKAGE, parsed.packageName)
        }
        startActivity(intent)
        callback.onSuccess()
    }

    /**
     * Walk the saved structure and pull out the typed username and
     * password by looking up nodes whose autofillId matches the
     * parsed username / password targets.
     */
    private fun readTypedValues(
        structure: AssistStructure,
        parsed: ParsedStructure,
    ): Pair<String?, String?> {
        val usernameIds = parsed.fields.filter { it.kind == FieldKind.Username }
            .map { it.id }.toHashSet()
        val passwordIds = parsed.fields.filter { it.kind == FieldKind.Password }
            .map { it.id }.toHashSet()
        var username: String? = null
        var password: String? = null

        fun visit(node: AssistStructure.ViewNode) {
            val id = node.autofillId
            if (id != null) {
                val value = node.autofillValue
                if (value != null && value.isText) {
                    val text = value.textValue?.toString()
                    if (text != null) {
                        if (passwordIds.contains(id) && password == null) password = text
                        else if (usernameIds.contains(id) && username == null) username = text
                    }
                }
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) {
            visit(structure.getWindowNodeAt(i).rootViewNode)
        }
        return username to password
    }

    /** Build a one-row Dataset that fills the form's recognized fields. */
    private fun buildDataset(
        account: Account,
        parsed: ParsedStructure,
        inlineSpec: InlinePresentationSpec?,
    ): Dataset {
        val presentation = makePresentation(
            label = account.name.ifEmpty { "(unnamed)" },
            sub = account.username,
        )
        val builder = Dataset.Builder(presentation)
        if (inlineSpec != null) {
            val inline = makeInlinePresentation(
                label = account.name.ifEmpty { "(unnamed)" },
                sub = account.username,
                spec = inlineSpec,
            )
            if (inline != null) builder.setInlinePresentation(inline)
        }
        for (f in parsed.fields) {
            val value = when (f.kind) {
                FieldKind.Username -> account.username.ifEmpty { account.name }
                FieldKind.Password -> account.password
            }
            if (value.isNotEmpty()) {
                builder.setValue(f.id, AutofillValue.forText(value))
            }
        }
        return builder.build()
    }

    /**
     * Locked-vault path: hand back a FillResponse whose only DATASET
     * carries auth — not the entire response. The difference matters
     * for the save flow: with FillResponse.setAuthentication() the
     * whole response is "pending" and Android drops SaveInfo if the
     * user doesn't authenticate, killing save-on-submit when locked.
     * With Dataset.setAuthentication() the chip still gates the fill
     * behind unlock, but the response-level SaveInfo is registered
     * immediately and fires on submit regardless of whether the user
     * ever tapped the chip.
     */
    private fun buildAuthFillResponse(
        parsed: ParsedStructure,
        inlineSpec: InlinePresentationSpec?,
    ): FillResponse {
        val intent = Intent(this, AutofillActivity::class.java).apply {
            putExtra(EXTRA_AUTOFILL_IDS, parsed.fields.map { it.id }.toTypedArray())
            putExtra(EXTRA_AUTOFILL_HINTS, parsed.fields.map { it.kind.name }.toTypedArray())
            putExtra(EXTRA_WEB_DOMAIN, parsed.webDomain)
            putExtra(EXTRA_PACKAGE_NAME, parsed.packageName)
        }
        // FLAG_MUTABLE so Android can attach the inline-presentation
        // metadata; FLAG_CANCEL_CURRENT keeps this single-use.
        val flags =
            PendingIntent.FLAG_CANCEL_CURRENT or
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE
                else 0
        val pi = PendingIntent.getActivity(this, /* requestCode = */ 0, intent, flags)

        val presentation = makePresentation(
            label = "Password Manager",
            sub = "Tap to unlock",
        )

        // Build the dataset with placeholder values (Android requires
        // at least one setValue per dataset). The values are null
        // because the vault is locked and we don't have them yet —
        // the auth path will return real ones.
        val dataset = Dataset.Builder(presentation).apply {
            if (inlineSpec != null) {
                val inline = makeInlinePresentation(
                    label = "Password Manager",
                    sub = "Tap to unlock",
                    spec = inlineSpec,
                )
                if (inline != null) setInlinePresentation(inline)
            }
            for (field in parsed.fields) {
                setValue(field.id, null)
            }
            setAuthentication(pi.intentSender)
        }.build()

        val builder = FillResponse.Builder().addDataset(dataset)
        attachSaveInfo(builder, parsed)
        return builder.build()
    }

    /**
     * Tell Android we'd like to be notified when this form is
     * submitted, so we can offer to save the typed credentials.
     * Required ids = password fields (so save fires only when a
     * password was actually entered); username fields are optional
     * (captured if present, don't gate the prompt). No SaveInfo →
     * Android never calls `onSaveRequest`, which is the trap the
     * earlier phases fell into.
     */
    private fun attachSaveInfo(builder: FillResponse.Builder, parsed: ParsedStructure) {
        val passwordIds = parsed.fields.filter { it.kind == FieldKind.Password }
            .map { it.id }.toTypedArray()
        if (passwordIds.isEmpty()) return
        val usernameIds = parsed.fields.filter { it.kind == FieldKind.Username }
            .map { it.id }.toTypedArray()
        val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or
            (if (usernameIds.isNotEmpty()) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
        // FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE is required for modern
        // single-activity Fragment-based apps (Discord, basically
        // anything written in the last 5 years): without it, the
        // default save trigger is "Activity.finish()", which those
        // apps never call — login swaps a Fragment in place and the
        // Activity stays alive forever, so save would never fire.
        // With the flag, Android fires save when the form's fields
        // become invisible (typical after submit), which is what we
        // actually want.
        val saveInfo = SaveInfo.Builder(type, passwordIds).apply {
            if (usernameIds.isNotEmpty()) setOptionalIds(usernameIds)
            setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
        }.build()
        builder.setSaveInfo(saveInfo)
    }

    /**
     * Simple one-row RemoteViews layout — title + subtitle. Must use
     * a layout from OUR package (`R.layout.autofill_item`); the
     * autofill picker can't inflate system-package layouts like
     * `android.R.layout.*` (the response gets accepted but nothing
     * renders, exactly the silent-fail we hit).
     */
    private fun makePresentation(label: String, sub: String): RemoteViews {
        val rv = RemoteViews(packageName, R.layout.autofill_item)
        rv.setTextViewText(R.id.autofill_title, label)
        rv.setTextViewText(R.id.autofill_subtitle, sub.ifEmpty { " " })
        return rv
    }

    /**
     * Build the inline (chip-above-keyboard) presentation. Returns
     * null if the spec is missing, the SDK is too old, or the builder
     * throws — calling code falls back to RemoteViews only in that
     * case (which means manual long-press → Autofill still works, but
     * the auto-chip won't appear).
     */
    private fun makeInlinePresentation(
        label: String,
        sub: String,
        spec: InlinePresentationSpec,
    ): InlinePresentation? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        return try {
            // The inline slice needs a PendingIntent for the
            // long-press "attribution" action — we point it at
            // MainActivity so a long-press on the chip opens our app.
            val pi = PendingIntent.getActivity(
                this,
                /* requestCode = */ 0,
                Intent(this, MainActivity::class.java)
                    .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_IMMUTABLE,
            )
            val slice = InlineSuggestionUi.newContentBuilder(pi)
                .setTitle(label)
                .setSubtitle(sub.ifEmpty { " " })
                .build()
                .slice
            InlinePresentation(slice, spec, /* pinned = */ false)
        } catch (t: Throwable) {
            Log.w(TAG, "inline presentation failed: ${t.message}")
            null
        }
    }
}

// ===================== Structure parsing =====================

/** Fields we know how to fill. */
enum class FieldKind { Username, Password }

data class TargetField(val id: AutofillId, val kind: FieldKind)

data class ParsedStructure(
    val webDomain: String,
    val packageName: String,
    val fields: List<TargetField>,
) {
    fun allIds(): Array<AutofillId> = fields.map { it.id }.toTypedArray()

    fun host(): String {
        if (webDomain.isNotEmpty()) return webDomain.lowercase()
        // Fallback for native apps: turn "com.spotify.music" into
        // "spotify.com" — crude, but covers a lot of common cases. The
        // serious version is an affiliations database (1Password
        // bundles one); we'll add that later.
        if (packageName.isNotEmpty()) {
            val parts = packageName.split('.')
            if (parts.size >= 2) {
                // com.<brand>.<rest> → <brand>.com
                return "${parts[1]}.com".lowercase()
            }
        }
        return ""
    }
}

/**
 * Walk the AssistStructure and pull out:
 *   - the form's webDomain (for browser forms — always populated when
 *     the page provided a URL),
 *   - the app's package name (the source application),
 *   - every input field that looks like it wants a username or password.
 *
 * Detection happens in two passes. The first pass uses Android's
 * autofillHints, HTML attributes, inputType, and id/hint heuristics
 * — the rigorous path. The second pass "promotes" plausible-but-
 * unclassified text fields when the first pass found a password
 * field but no username (very common pattern: the username is
 * unmarked, the password is marked). This catches apps whose login
 * forms our classifier alone would silently drop (Discord's current
 * login screen is the motivating example).
 */
fun parseStructure(structure: AssistStructure): ParsedStructure {
    val fields = mutableListOf<TargetField>()
    val candidates = mutableListOf<AutofillId>()
    var webDomain = ""
    val packageName = structure.activityComponent?.packageName.orEmpty()

    for (i in 0 until structure.windowNodeCount) {
        val root = structure.getWindowNodeAt(i).rootViewNode
        if (webDomain.isEmpty()) {
            webDomain = findWebDomain(root)
        }
        walk(root, fields, candidates)
    }

    val hasPassword = fields.any { it.kind == FieldKind.Password }
    val hasUsername = fields.any { it.kind == FieldKind.Username }

    if (hasPassword && !hasUsername && candidates.isNotEmpty()) {
        // Common case: site/app marked its password but not its email
        // field. Promote the first plausible text input as Username.
        // Inserted at index 0 so it shows up before the password in
        // the dataset values (matches form order).
        val classifiedIds = fields.map { it.id }.toHashSet()
        val promoted = candidates.firstOrNull { it !in classifiedIds }
        if (promoted != null) {
            fields.add(0, TargetField(promoted, FieldKind.Username))
        }
    }

    if (fields.isEmpty() && candidates.size >= 2) {
        // Last resort: no classifier hit but at least two plausible
        // text inputs exist. Assume the first is username and the
        // second is password. False positives are filtered out by
        // the host-match step (we only fill if a vault entry matches
        // the calling host/package).
        fields += TargetField(candidates[0], FieldKind.Username)
        fields += TargetField(candidates[1], FieldKind.Password)
    }

    return ParsedStructure(webDomain = webDomain, packageName = packageName, fields = fields)
}

private fun walk(
    node: AssistStructure.ViewNode,
    out: MutableList<TargetField>,
    candidates: MutableList<AutofillId>,
) {
    val id = node.autofillId
    if (id != null) {
        val kind = classify(node)
        if (kind != null) {
            out += TargetField(id, kind)
        } else if (looksLikeTextInput(node)) {
            candidates += id
        }
    }
    for (i in 0 until node.childCount) {
        walk(node.getChildAt(i), out, candidates)
    }
}

/**
 * Heuristic: "this node might be a text input we just couldn't
 * classify." Used by the promotion / last-resort fallback. Filters
 * out obviously non-input nodes (containers, images, labels) so we
 * don't pull garbage into the dataset.
 */
private fun looksLikeTextInput(node: AssistStructure.ViewNode): Boolean {
    val cls = node.className.orEmpty()
    if (cls.contains("EditText", ignoreCase = true)) return true
    if (cls.contains("TextInput", ignoreCase = true)) return true
    // Compose text fields land here under various inner-class names.
    if (cls.contains("Compose", ignoreCase = true) && cls.contains("Text")) return true
    // Browser/webview-rendered input — has htmlInfo even without classify.
    val html = node.htmlInfo
    if (html != null && html.tag.equals("input", ignoreCase = true)) {
        // Skip obvious non-text input types (submit/checkbox/radio/etc.).
        val type = html.attributes
            ?.firstOrNull { it.first.equals("type", ignoreCase = true) }
            ?.second
            ?.lowercase()
            ?: "text"
        return type in setOf(
            "text", "email", "tel", "url", "search", "password", "",
        )
    }
    // Native field with a text-class inputType — could be text without
    // any of the more specific variations we already handle.
    val inputClass = node.inputType and 0x000F
    return inputClass == 0x00000001 // TYPE_CLASS_TEXT
}

private fun classify(node: AssistStructure.ViewNode): FieldKind? {
    // 1) Explicit hints — the gold standard. Android-native apps set these.
    val hints = node.autofillHints
    if (hints != null) {
        for (h in hints) {
            when (h) {
                View.AUTOFILL_HINT_USERNAME,
                View.AUTOFILL_HINT_EMAIL_ADDRESS -> return FieldKind.Username
                View.AUTOFILL_HINT_PASSWORD -> return FieldKind.Password
            }
        }
    }

    // 2) HTML attributes — what *browsers* expose for web form fields.
    //    Chrome / DuckDuckGo / Edge / Brave / Startpage all flatten the
    //    rendered HTML into ViewNode.htmlInfo. Native fields don't have
    //    this, so the absence is benign for the native path.
    val htmlAttrs = node.htmlInfo?.attributes
    if (htmlAttrs != null) {
        var htmlType = ""
        var label = ""
        var name = ""
        var idAttr = ""
        var autocomplete = ""
        // android.util.Pair (not Kotlin's Pair) — no destructuring,
        // so access via .first / .second.
        for (pair in htmlAttrs) {
            val k = pair.first?.lowercase() ?: continue
            val v = pair.second?.lowercase() ?: continue
            when (k) {
                "type" -> htmlType = v
                "label" -> label = v
                "name" -> name = v
                "id" -> idAttr = v
                "autocomplete" -> autocomplete = v
                "aria-label" -> if (label.isEmpty()) label = v
                "placeholder" -> if (label.isEmpty()) label = v
            }
        }

        // Strongest HTML signal: type=password.
        if (htmlType == "password") return FieldKind.Password
        // autocomplete="…password…" — both current-password and new-password.
        if (autocomplete.contains("password")) return FieldKind.Password
        // autocomplete="username" / "email" → username field.
        if (autocomplete.contains("username") || autocomplete == "email"
            || autocomplete.contains("email")
        ) {
            return FieldKind.Username
        }

        // type=email is unambiguous; type=text + label hint covers the rest.
        if (htmlType == "email") return FieldKind.Username

        // Label / aria-label / name / id heuristic (German + English).
        val all = listOf(label, name, idAttr).joinToString(" ")
        if (all.contains("passwort") || all.contains("password") || all.contains("kennwort")
            || all.contains("passwd")
        ) {
            return FieldKind.Password
        }
        if (all.contains("benutzer") || all.contains("username") || all.contains("user")
            || all.contains("login") || all.contains("email") || all.contains("e-mail")
            || all.contains("anmelden")
        ) {
            return FieldKind.Username
        }

        // type=text with no other signal — probably a username if we got
        // here through a login form, but we don't know that at per-node
        // scope. Leave it unclassified; the form-level walker in
        // parseStructure() can promote it.
    }

    // 3) Input type — password fields are reliably marked on native EditText.
    val inputType = node.inputType
    val cls = inputType and 0x000F        // input class
    val variation = inputType and 0x0FF0
    val TYPE_CLASS_TEXT = 0x00000001
    val TYPE_TEXT_VARIATION_PASSWORD = 0x00000080
    val TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090
    val TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0
    val TYPE_TEXT_VARIATION_EMAIL_ADDRESS = 0x00000020
    val TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS = 0x000000d0

    if (cls == TYPE_CLASS_TEXT) {
        if (variation == TYPE_TEXT_VARIATION_PASSWORD
            || variation == TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            || variation == TYPE_TEXT_VARIATION_WEB_PASSWORD
        ) {
            return FieldKind.Password
        }
        if (variation == TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            || variation == TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
        ) {
            return FieldKind.Username
        }
    }

    // 4) Native heuristic fallback — Android idEntry / hint text.
    val identifiers = listOfNotNull(
        node.idEntry,
        node.hint,
        node.contentDescription?.toString(),
    ).joinToString(" ").lowercase()

    if (identifiers.contains("password") || identifiers.contains("passwd")
        || identifiers.contains("passwort")
    ) {
        return FieldKind.Password
    }
    if (identifiers.contains("username") || identifiers.contains("user")
        || identifiers.contains("email") || identifiers.contains("login")
        || identifiers.contains("benutzer")
    ) {
        return FieldKind.Username
    }
    return null
}

private fun findWebDomain(node: AssistStructure.ViewNode): String {
    val wd = node.webDomain
    if (!wd.isNullOrEmpty()) return wd
    for (i in 0 until node.childCount) {
        val found = findWebDomain(node.getChildAt(i))
        if (found.isNotEmpty()) return found
    }
    return ""
}
