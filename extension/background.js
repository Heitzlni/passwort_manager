// Background page:
// - Single connection to the native messaging host (which relays to passwortd).
// - Per-RPC serialization (the host processes one request at a time).
// - Buffer of "captured" credentials reported by content scripts; the popup
//   and the in-page banner pull these on demand so the user can save them.
// - Broadcasts `vault_state_changed` to all tabs after a successful unlock
//   or lock, so existing pages can update their fill UI live.
// - Expires captured credentials after 5 minutes so they don't sit in
//   memory indefinitely if the user never saves them.

const HOST = "passwort_manager";
const CAPTURE_TTL_MS = 5 * 60 * 1000;

let port = null;
let pending = null;
const queue = [];

// Map<origin, {origin, username, password, capturedAt}>
const captured = new Map();
// Map<tabId, {origin, username, password, capturedAt}> — same data keyed by
// tab so the banner can follow the user across cross-origin redirects in
// the same tab (Google login -> youtube.com, etc.).
const tabCaptures = new Map();

function connect() {
    if (port) return;
    port = browser.runtime.connectNative(HOST);
    port.onMessage.addListener((msg) => {
        if (!pending) return;
        const { resolve } = pending;
        pending = null;
        resolve(msg);
        pump();
    });
    port.onDisconnect.addListener((p) => {
        port = null;
        const errMsg =
            (p && p.error && p.error.message) ||
            "native host disconnected (is passwortd running?)";
        if (pending) {
            pending.reject(new Error(errMsg));
            pending = null;
        }
        for (const item of queue) item.reject(new Error(errMsg));
        queue.length = 0;
    });
}

function pump() {
    if (pending || queue.length === 0) return;
    const next = queue.shift();
    pending = next;
    try {
        connect();
        port.postMessage(next.req);
    } catch (e) {
        pending = null;
        next.reject(e);
        pump();
    }
}

function send(req) {
    return new Promise((resolve, reject) => {
        queue.push({ req, resolve, reject });
        pump();
    }).then((resp) => {
        if (resp && resp.kind === "ok" && (req.op === "unlock" || req.op === "lock")) {
            broadcastToTabs({ type: "vault_state_changed" });
        }
        return resp;
    });
}

async function broadcastToTabs(msg) {
    try {
        const tabs = await browser.tabs.query({});
        for (const t of tabs) {
            browser.tabs.sendMessage(t.id, msg).catch(() => {});
        }
    } catch {
        // ignore
    }
}

function refreshBadge() {
    // Only count captures where we have an actual password — partial captures
    // (just a username from step 1 of a multi-step login) shouldn't badge.
    let n = 0;
    for (const c of captured.values()) if (c.password) n++;
    browser.action.setBadgeText({ text: n > 0 ? String(n) : "" });
    browser.action.setBadgeBackgroundColor({ color: "#7c6dd8" });
}

setInterval(() => {
    const now = Date.now();
    let changed = false;
    for (const [origin, cred] of captured.entries()) {
        if (now - cred.capturedAt > CAPTURE_TTL_MS) {
            captured.delete(origin);
            changed = true;
        }
    }
    for (const [tabId, cap] of tabCaptures.entries()) {
        if (now - cap.capturedAt > CAPTURE_TTL_MS) {
            tabCaptures.delete(tabId);
        }
    }
    if (changed) refreshBadge();
}, 60 * 1000);

// Drop the per-tab capture when the tab itself goes away.
browser.tabs.onRemoved.addListener((tabId) => {
    tabCaptures.delete(tabId);
});

// Pull the host out of a tab url, but only for http(s). Other schemes
// (about:, moz-extension:, file:) shouldn't bind to a vault entry.
function tabOrigin(tabUrl) {
    if (!tabUrl) return null;
    try {
        const u = new URL(tabUrl);
        if (u.protocol === "https:" || u.protocol === "http:") {
            return u.hostname.toLowerCase();
        }
    } catch {}
    return null;
}

browser.runtime.onMessage.addListener((msg, sender) => {
    if (!msg) return;

    if (msg.type === "rpc") {
        // Bind every content-script RPC to the tab's true origin so the
        // daemon refuses cross-host reads — a compromised script on
        // evil.com can't ask for paypal.com credentials even though we
        // share one native-host connection. We *overwrite* any origin
        // field the caller set (don't trust untrusted input). The popup
        // has no sender.tab and stays unrestricted.
        const payload = { ...msg.payload };
        const origin = sender && sender.tab ? tabOrigin(sender.tab.url) : null;
        if (origin) {
            payload.origin = origin;
        } else {
            delete payload.origin;
        }
        return send(payload);
    }

    if (msg.type === "captured_submit") {
        if (!msg.origin) return;
        // Merge with any existing partial capture for this origin AND for
        // this tab. Multi-step logins (Google: email page → password page)
        // only have one of the two fields available at any given moment,
        // so we accumulate as the user advances rather than overwriting.
        const tabId = sender.tab ? sender.tab.id : null;
        const prevByOrigin = captured.get(msg.origin) || { username: "", password: "" };
        const prevByTab = tabId != null ? tabCaptures.get(tabId) : null;
        const prev = prevByTab || prevByOrigin;
        const merged = {
            origin: msg.origin,
            username: msg.username || prev.username || "",
            password: msg.password || prev.password || "",
            capturedAt: Date.now(),
        };
        captured.set(msg.origin, merged);
        if (tabId != null) tabCaptures.set(tabId, merged);
        refreshBadge();
        return Promise.resolve({ ok: true });
    }

    if (msg.type === "list_captured") {
        return Promise.resolve(Array.from(captured.values()));
    }

    // The capture (if any) attached to the sender's tab. Lets the in-page
    // banner follow the user across cross-origin redirects.
    if (msg.type === "list_tab_capture") {
        if (!sender.tab) return Promise.resolve(null);
        const cap = tabCaptures.get(sender.tab.id);
        if (cap && cap.password) return Promise.resolve(cap);
        return Promise.resolve(null);
    }

    // For the popup: it doesn't have its own tab, so it explicitly passes
    // the active tab id.
    if (msg.type === "get_tab_capture") {
        if (typeof msg.tabId !== "number") return Promise.resolve(null);
        const cap = tabCaptures.get(msg.tabId);
        if (cap && cap.password) return Promise.resolve(cap);
        return Promise.resolve(null);
    }

    if (msg.type === "discard_captured") {
        captured.delete(msg.origin);
        // Drop any per-tab entries for this origin so the banner doesn't
        // re-pop on the same flow. Also drop the sender tab's entry if any
        // (user explicitly dismissed it from this tab).
        for (const [tabId, cap] of tabCaptures.entries()) {
            if (cap.origin === msg.origin) tabCaptures.delete(tabId);
        }
        if (sender.tab) tabCaptures.delete(sender.tab.id);
        refreshBadge();
        return Promise.resolve({ ok: true });
    }

    if (msg.type === "clear_captured") {
        captured.clear();
        tabCaptures.clear();
        refreshBadge();
        return Promise.resolve({ ok: true });
    }

    return Promise.reject(new Error("unknown message type: " + msg.type));
});
