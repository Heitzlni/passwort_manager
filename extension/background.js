// Background page: keeps a single connection to the native messaging host
// (which in turn talks to passwortd). Serializes RPCs since the host
// processes one request at a time.

const HOST = "passwort_manager";

let port = null;
let pending = null;
const queue = [];

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

browser.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "rpc") {
        return send(msg.payload);
    }
    return Promise.reject(new Error("unknown message type"));
});
