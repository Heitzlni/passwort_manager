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
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

/**
 * Android Autofill Framework integration.
 *
 * The OS calls `onFillRequest` whenever a user focuses an input field
 * in any app that supports autofill (every browser, every app with a
 * password input). We walk the form, extract the web domain or package
 * name, find matching entries in [VaultState], and answer with a list
 * of [Dataset]s — one per credential match. The user sees them as
 * chips above the keyboard.
 *
 * If the vault is locked we instead answer with an "authentication"
 * intent that opens [AutofillActivity]; that activity returns the
 * dataset list once unlock succeeds.
 *
 * We intentionally do NOT implement onSaveRequest in phase 2 — phase 3
 * adds the write path. Until then Android will just not offer
 * "save with Password Manager" prompts.
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

        val accounts = VaultState.accounts.value
        if (accounts == null) {
            Log.i(TAG, "  → vault locked, returning auth fill response")
            callback.onSuccess(buildAuthFillResponse(parsed))
            return
        }

        val host = parsed.host()
        val matches = if (host.isNotEmpty()) {
            VaultState.findByHost(host)
        } else {
            emptyList()
        }

        Log.i(TAG, "  host='$host' matches=${matches.size}")

        if (matches.isEmpty()) {
            Log.i(TAG, "  → exit: no vault entries match host '$host'")
            callback.onSuccess(null)
            return
        }

        val builder = FillResponse.Builder()
        for (acc in matches) {
            builder.addDataset(buildDataset(acc, parsed))
        }
        VaultState.touch()
        Log.i(TAG, "  → returning FillResponse with ${matches.size} datasets")
        callback.onSuccess(builder.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Phase 3 territory — Android shouldn't ask us for save because
        // we don't declare SaveInfo on fill responses. Just succeed
        // silently if it ever does.
        callback.onSuccess()
    }

    /** Build a one-row Dataset that fills the form's recognized fields. */
    private fun buildDataset(account: Account, parsed: ParsedStructure): Dataset {
        val presentation = makePresentation(
            label = account.name.ifEmpty { "(unnamed)" },
            sub = account.username,
        )
        val builder = Dataset.Builder(presentation)
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
     * Locked-vault path: hand back a FillResponse whose only "entry"
     * is an Authenticate row. Tapping it kicks Android into the
     * authentication intent (our [AutofillActivity]), which replays
     * the same parsed-structure context, asks for the master, and on
     * success returns a real FillResponse via its activity result.
     */
    private fun buildAuthFillResponse(parsed: ParsedStructure): FillResponse {
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
        return FillResponse.Builder()
            .setAuthentication(parsed.allIds(), pi.intentSender, presentation)
            .build()
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
 * We rely on Android's autofillHints first; if the app didn't set any
 * we fall back to inputType / hint-text heuristics. This matches
 * what every other password manager does.
 */
fun parseStructure(structure: AssistStructure): ParsedStructure {
    val fields = mutableListOf<TargetField>()
    var webDomain = ""
    val packageName = structure.activityComponent?.packageName.orEmpty()

    for (i in 0 until structure.windowNodeCount) {
        val root = structure.getWindowNodeAt(i).rootViewNode
        if (webDomain.isEmpty()) {
            webDomain = findWebDomain(root)
        }
        walk(root, fields)
    }

    return ParsedStructure(webDomain = webDomain, packageName = packageName, fields = fields)
}

private fun walk(node: AssistStructure.ViewNode, out: MutableList<TargetField>) {
    val id = node.autofillId
    if (id != null) {
        val kind = classify(node)
        if (kind != null) {
            out += TargetField(id, kind)
        }
    }
    for (i in 0 until node.childCount) {
        walk(node.getChildAt(i), out)
    }
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
