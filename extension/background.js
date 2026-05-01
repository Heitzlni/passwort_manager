// Background page:
// - Single connection to the native messaging host (which relays to passwortd).
// - Per-RPC serialization (the host processes one request at a time).
// - Buffer of "captured" credentials reported by content scripts; the popup
//   pulls these on demand so the user can choose to save them.

const HOST = "passwort_manager";

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
    });
}

function refreshBadge() {
    const n = captured.size;
    browser.browserAction.setBadgeText({ text: n > 0 ? String(n) : "" });
    browser.browserAction.setBadgeBackgroundColor({ color: "#7c6dd8" });
}

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
