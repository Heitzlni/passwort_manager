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
    const n = captured.size;
    browser.browserAction.setBadgeText({ text: n > 0 ? String(n) : "" });
    browser.browserAction.setBadgeBackgroundColor({ color: "#7c6dd8" });
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
    if (changed) refreshBadge();
}, 60 * 1000);

browser.runtime.onMessage.addListener((msg) => {
    if (!msg) return;

    if (msg.type === "rpc") {
        return send(msg.payload);
    }

    if (msg.type === "captured_submit") {
        if (!msg.origin || !msg.password) return;
        captured.set(msg.origin, {
            origin: msg.origin,
            username: msg.username || "",
            password: msg.password,
            capturedAt: Date.now(),
        });
        refreshBadge();
        return Promise.resolve({ ok: true });
    }

    if (msg.type === "list_captured") {
        return Promise.resolve(Array.from(captured.values()));
    }

    if (msg.type === "discard_captured") {
        captured.delete(msg.origin);
        refreshBadge();
        return Promise.resolve({ ok: true });
    }

    if (msg.type === "clear_captured") {
        captured.clear();
        refreshBadge();
        return Promise.resolve({ ok: true });
    }

    return Promise.reject(new Error("unknown message type: " + msg.type));
});
