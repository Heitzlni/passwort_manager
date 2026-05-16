// Popup logic.

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === "class") e.className = v;
        else if (k === "style") e.style.cssText = v;
        else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v);
    }
    for (const c of children) {
        if (c == null) continue;
        e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return e;
}

async function rpc(payload) {
    try {
        return await browser.runtime.sendMessage({ type: "rpc", payload });
    } catch (e) {
        return { kind: "error", code: "transport", message: e.message || String(e) };
    }
}

async function listCaptured() {
    try {
        return await browser.runtime.sendMessage({ type: "list_captured" });
    } catch {
        return [];
    }
}

async function discardCaptured(origin) {
    try {
        await browser.runtime.sendMessage({ type: "discard_captured", origin });
    } catch {}
}

async function currentTab() {
    const [t] = await browser.tabs.query({ active: true, currentWindow: true });
    return t;
}

function originOf(urlStr) {
    try {
        return new URL(urlStr).hostname;
    } catch {
        return "";
    }
}

// Hostname-aware match: a saved name matches a host iff
// it equals the host OR the host is a subdomain of it (host ends with "." + saved).
// This avoids `notexample.com` matching a saved `example.com`.
function nameMatchesHost(saved, host) {
    if (!saved || !host) return false;
    const s = saved.toLowerCase();
    const h = host.toLowerCase();
    return s === h || h.endsWith("." + s);
}

// Effective-root match for surfacing captured credentials across same-org
// redirects (e.g. accounts.google.com → myaccount.google.com).
const MULTI_PART_TLDS = new Set([
    "co.uk", "org.uk", "ac.uk", "co.jp", "co.kr", "com.au",
    "com.br", "co.in", "co.za", "com.mx", "com.tr", "co.nz",
]);
function effectiveRoot(host) {
    if (!host) return "";
    const parts = host.toLowerCase().split(".");
    if (parts.length < 2) return host;
    if (parts.length >= 3 && MULTI_PART_TLDS.has(parts.slice(-2).join("."))) {
        return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
}
function originRelated(a, b) {
    if (!a || !b) return false;
    if (a === b) return true;
    return effectiveRoot(a) === effectiveRoot(b);
}

// Hostname of a stored entry URL. Accepts bare hosts (no scheme) by
// assuming https. Empty string if there's no usable URL.
function hostOf(urlStr) {
    if (!urlStr) return "";
    let s = String(urlStr).trim();
    if (!s) return "";
    if (!s.includes("://")) s = "https://" + s;
    try {
        return new URL(s).hostname.toLowerCase();
    } catch {
        return "";
    }
}

// Match an entry to the active tab's host. Prefer the explicit URL
// field (reliable); fall back to the entry name for pre-url entries,
// which historically doubled as a pseudo-host. Either way the host
// rule is the same: exact host or a subdomain of it.
function entryMatchesHost(entry, host) {
    if (!host) return false;
    const urlHost = hostOf(entry.url);
    if (urlHost) return nameMatchesHost(urlHost, host);
    return nameMatchesHost(entry.name, host);
}

function showError(msg) {
    $("#banner").innerHTML = "";
    $("#banner").appendChild(el("div", { class: "error" }, msg));
}

function showInfo(msg) {
    $("#banner").innerHTML = "";
    $("#banner").appendChild(el("div", { class: "info" }, msg));
}

function clearBanner() {
    $("#banner").innerHTML = "";
}

async function refresh() {
    clearBanner();
    const status = await rpc({ op: "status" });
    if (status.kind === "error") {
        $("#status").textContent = "(error)";
        $("#content").innerHTML = "";
        $("#content").appendChild(
            el(
                "div",
                { class: "muted" },
                "Cannot reach the daemon. Make sure passwortd is running."
            )
        );
        showError(status.message || "transport error");
        return;
    }

    if (status.unlocked) {
        const idle = status.idle_secs ?? 0;
        const cap = status.auto_lock_secs ?? 0;
        const remaining =
            cap > 0 ? Math.max(0, cap - idle) : null;
        const suffix = remaining != null ? ` · auto-locks in ${formatSecs(remaining)}` : "";
        $("#status").textContent =
            `unlocked · ${status.account_count} account${status.account_count === 1 ? "" : "s"}${suffix}`;
        await renderUnlocked();
    } else {
        $("#status").textContent = "locked";
        renderLogin();
    }
}

function formatSecs(s) {
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m`;
    return `${Math.floor(m / 60)}h${m % 60}m`;
}

function renderLogin() {
    const root = $("#content");
    root.innerHTML = "";

    const pw = el("input", { type: "password", placeholder: "Master password" });
    const btn = el(
        "button",
        {
            onclick: async () => {
                if (!pw.value) {
                    showError("password required");
                    return;
                }
                const r = await rpc({ op: "unlock", password: pw.value });
                pw.value = "";
                if (r.kind === "ok") refresh();
                else showError(r.message || "unlock failed");
            },
        },
        "Unlock"
    );
    pw.addEventListener("keydown", (e) => {
        if (e.key === "Enter") btn.click();
    });

    root.append(el("label", {}, "Master password"), pw, el("div", { class: "row" }, btn));
    setTimeout(() => pw.focus(), 50);
}

async function renderUnlocked() {
    const tab = await currentTab();
    const origin = tab ? originOf(tab.url) : "";

    const root = $("#content");
    root.innerHTML = "";
    root.appendChild(el("div", { class: "muted" }, origin || "(no http origin)"));

    // Captured-this-session credentials. First try the per-tab capture
    // (covers cross-origin redirects: log in on google → land on youtube),
    // then fall back to any related-origin capture from any tab.
    let capturedForOrigin = null;
    if (tab && typeof tab.id === "number") {
        try {
            capturedForOrigin = await browser.runtime.sendMessage({
                type: "get_tab_capture",
                tabId: tab.id,
            });
        } catch {
            capturedForOrigin = null;
        }
    }
    if (!capturedForOrigin) {
        const captured = await listCaptured();
        capturedForOrigin = captured.find(
            (c) => c.password && originRelated(c.origin, origin)
        );
    }

    if (capturedForOrigin) {
        const saveBtn = el(
            "button",
            {
                onclick: async () => {
                    const r = await rpc({
                        op: "save",
                        name: capturedForOrigin.origin,
                        username: capturedForOrigin.username || "",
                        password: capturedForOrigin.password,
                    });
                    if (r.kind === "ok") {
                        await discardCaptured(capturedForOrigin.origin);
                        showInfo(`Saved "${capturedForOrigin.origin}".`);
                        refresh();
                    } else {
                        await maybeHandleLocked(r);
                        showError(r.message || "save failed");
                    }
                },
            },
            "Save"
        );
        const dismissBtn = el(
            "button",
            {
                class: "ghost",
                onclick: async () => {
                    await discardCaptured(capturedForOrigin.origin);
                    refresh();
                },
            },
            "Dismiss"
        );
        const userPart = capturedForOrigin.username
            ? ` (${capturedForOrigin.username})`
            : "";
        root.appendChild(el("hr"));
        root.appendChild(el("label", {}, "Captured from this page"));
        root.appendChild(
            el(
                "div",
                { class: "captured" },
                el(
                    "span",
                    { class: "muted", style: "flex: 1;" },
                    `${capturedForOrigin.origin}${userPart}`
                ),
                saveBtn,
                dismissBtn
            )
        );
    }

    // Section: matches for current origin (proper hostname match, not substring)
    root.appendChild(el("hr"));
    root.appendChild(el("label", {}, "On this site"));
    const list = await rpc({ op: "list_entries" });

    if (list.kind === "error") {
        await maybeHandleLocked(list);
        return;
    }
    const allEntries = list.kind === "entries" ? list.entries : [];
    const matches = origin
        ? allEntries.filter((e) => entryMatchesHost(e, origin))
        : [];

    if (matches.length === 0) {
        root.appendChild(
            el(
                "div",
                { class: "muted", style: "margin-top: 8px;" },
                origin ? "No saved accounts for this site." : "Open a website tab to see matches."
            )
        );
    } else {
        for (const entry of matches) {
            const fillBtn = el(
                "button",
                { class: "small", onclick: () => fillOnTab(tab, entry.name) },
                "Fill"
            );
            const copyBtn = el(
                "button",
                { class: "ghost small", onclick: () => copyPassword(entry.name) },
                "Copy"
            );
            const pwnedBtn = el(
                "button",
                {
                    class: "ghost small",
                    title: "Check this password against haveibeenpwned.com (k-anonymous)",
                    onclick: () => checkPwned(entry.name),
                },
                "Pwned?"
            );
            const totpBtn = el(
                "button",
                {
                    class: "ghost small",
                    title: "Get the current 2FA code: copies it and fills it into the page's code field if there is one",
                    onclick: () => useTotp(tab, entry.name),
                },
                "2FA"
            );
            const label = entry.username
                ? el(
                      "span",
                      { class: "name" },
                      el("strong", {}, entry.username),
                      " · ",
                      el("span", { class: "muted" }, entry.name)
                  )
                : el("span", { class: "name" }, entry.name);
            root.appendChild(
                el("div", { class: "account" }, label, fillBtn, copyBtn, pwnedBtn, totpBtn)
            );
        }
    }

    // Section: manual save (still useful even without capture)
    root.appendChild(el("hr"));
    root.appendChild(el("label", {}, "Save this page manually"));
    const nameInput = el("input", { type: "text" });
    nameInput.value = origin;
    const userInput = el("input", { type: "text", placeholder: "Username (optional)" });
    const pwInput = el("input", { type: "password", placeholder: "Password to save" });

    const saveBtn = el(
        "button",
        {
            onclick: async () => {
                if (!nameInput.value) return showError("name required");
                if (!pwInput.value) return showError("password required");
                const r = await rpc({
                    op: "save",
                    name: nameInput.value,
                    username: userInput.value || "",
                    password: pwInput.value,
                });
                pwInput.value = "";
                if (r.kind === "ok") {
                    showInfo(`Saved "${nameInput.value}".`);
                    refresh();
                } else {
                    await maybeHandleLocked(r);
                    showError(r.message || "save failed");
                }
            },
        },
        "Save"
    );

    const readBtn = el(
        "button",
        {
            class: "ghost",
            onclick: async () => {
                if (!tab) return;
                try {
                    const r = await browser.tabs.sendMessage(tab.id, {
                        type: "read_password",
                    });
                    if (r && r.password) {
                        pwInput.value = r.password;
                        showInfo("Read password from page.");
                    } else {
                        showError("no password field on this page");
                    }
                } catch {
                    showError("content script not loaded — try reloading the tab");
                }
            },
        },
        "Read from page"
    );

    const generateBtn = el(
        "button",
        {
            class: "ghost",
            title: "Generate a random 20-char password (~131 bits of entropy)",
            onclick: () => {
                pwInput.type = "text"; // reveal so user can see what was put in
                pwInput.value = generatePassword();
                showInfo("Generated. Click Save to store it.");
            },
        },
        "✨ Generate"
    );

    root.append(
        el("label", {}, "Name"),
        nameInput,
        el("label", {}, "Username"),
        userInput,
        el("label", {}, "Password"),
        pwInput,
        el("div", { class: "row" }, saveBtn, readBtn, generateBtn)
    );

    // Footer: lock + audit-all
    root.appendChild(el("hr"));
    root.appendChild(
        el(
            "div",
            {
                class: "row",
                style: "justify-content: space-between; margin-top: 0;",
            },
            el(
                "button",
                {
                    class: "ghost",
                    onclick: async () => {
                        await rpc({ op: "lock" });
                        refresh();
                    },
                },
                "Lock"
            ),
            el(
                "button",
                {
                    class: "ghost",
                    title: "Check every saved password against haveibeenpwned.com. Takes a few seconds per entry.",
                    onclick: () => auditAll(),
                },
                "Audit all"
            )
        )
    );
}

// Fetch the current 2FA code (computed by the daemon — the secret never
// reaches the browser), copy it to the clipboard, and try to fill it into
// a one-time-code field on the page if there is one.
async function useTotp(tab, name) {
    const r = await rpc({ op: "totp", name });
    if (r.kind === "error") {
        if (r.code === "no_totp") {
            return showError(`"${name}" has no 2FA secret saved.`);
        }
        if (await maybeHandleLocked(r)) return;
        return showError(r.message || "could not get 2FA code");
    }
    if (r.kind !== "totp") return showError("unexpected response");
    const pretty =
        r.code.length === 6 ? `${r.code.slice(0, 3)} ${r.code.slice(3)}` : r.code;
    try {
        await navigator.clipboard.writeText(r.code);
    } catch {
        /* clipboard may be blocked; the fill path below still works */
    }
    let filled = false;
    if (tab) {
        try {
            const resp = await browser.tabs.sendMessage(tab.id, {
                type: "fill_totp",
                code: r.code,
            });
            filled = !!(resp && resp.filled);
        } catch {
            /* no content script on this page (e.g. about:) — copy still done */
        }
    }
    showInfo(
        `2FA ${pretty} — ${r.remaining}s left. ${
            filled ? "Filled on page and copied." : "Copied to clipboard."
        }`
    );
}

async function checkPwned(name) {
    showInfo(`Checking "${name}"…`);
    const r = await rpc({ op: "pwned_one", name });
    if (r.kind === "error") {
        if (r.code === "hibp_disabled") {
            return showError("HIBP check is disabled. Enable it in config.json (hibp_enabled: true).");
        }
        await maybeHandleLocked(r);
        return showError(r.message || "check failed");
    }
    if (r.kind !== "pwned_report" || !r.results || r.results.length === 0) {
        return showError("unexpected response");
    }
    const e = r.results[0];
    if (e.error) return showError(`${name}: ${e.error}`);
    if (e.breach_count === 0) {
        showInfo(`✓ "${name}" — not in any known breach.`);
    } else {
        showError(`⚠ "${name}" — appears in ${e.breach_count} breach${e.breach_count === 1 ? "" : "es"}. Change it.`);
    }
}

async function auditAll() {
    showInfo("Auditing all entries — this takes a few seconds…");
    const r = await rpc({ op: "pwned_all" });
    if (r.kind === "error") {
        if (r.code === "hibp_disabled") {
            return showError("HIBP check is disabled. Enable it in config.json (hibp_enabled: true).");
        }
        await maybeHandleLocked(r);
        return showError(r.message || "audit failed");
    }
    if (r.kind !== "pwned_report") return showError("unexpected response");
    const bad = r.results.filter((x) => x.breach_count && x.breach_count > 0);
    const errs = r.results.filter((x) => x.error);
    const root = $("#content");
    root.innerHTML = "";
    root.appendChild(el("h3", {}, "Audit results"));
    root.appendChild(
        el(
            "div",
            { class: "muted" },
            `${r.results.length - bad.length - errs.length} clean · ${bad.length} compromised · ${errs.length} errors`
        )
    );
    if (bad.length > 0) {
        root.appendChild(el("hr"));
        root.appendChild(el("label", { style: "color:#e06c75" }, "Compromised — change these:"));
        for (const e of bad) {
            const u = e.username ? ` (${e.username})` : "";
            root.appendChild(
                el(
                    "div",
                    { class: "account" },
                    el("span", { class: "name" }, `${e.name}${u}`),
                    el("span", { class: "muted small" }, `${e.breach_count} breaches`)
                )
            );
        }
    }
    if (errs.length > 0) {
        root.appendChild(el("hr"));
        root.appendChild(el("label", {}, "Errors:"));
        for (const e of errs) {
            root.appendChild(
                el("div", { class: "muted small" }, `${e.name}: ${e.error}`)
            );
        }
    }
    root.appendChild(el("hr"));
    root.appendChild(
        el(
            "button",
            { class: "ghost", onclick: () => refresh() },
            "Back"
        )
    );
}

// If a response is a "locked" error, refresh the popup to show the unlock form.
async function maybeHandleLocked(resp) {
    if (resp && resp.kind === "error" && resp.code === "locked") {
        await refresh();
        return true;
    }
    return false;
}

async function fillOnTab(tab, name) {
    if (!tab) return showError("no active tab");
    const got = await rpc({ op: "get", name });
    if (got.kind !== "credential") {
        if (await maybeHandleLocked(got)) return;
        return showError(got.message || "not found");
    }
    try {
        const r = await browser.tabs.sendMessage(tab.id, {
            type: "fill_password",
            username: got.username || "",
            password: got.password,
        });
        if (r && r.filled) showInfo(`Filled "${name}".`);
        else showError((r && r.reason) || "fill failed");
    } catch {
        showError("content script not loaded — try reloading the tab");
    }
}

// Random password generator. Uses crypto.getRandomValues + rejection
// sampling so each character of the alphabet is equally likely (no modulo
// bias). Mirrors src/generator.rs on the Rust side.
const GEN_ALPHABET =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?/~";
const GEN_DEFAULT_LENGTH = 20;
function generatePassword(length = GEN_DEFAULT_LENGTH) {
    const n = GEN_ALPHABET.length;
    const max = Math.floor(256 / n) * n;
    const buf = new Uint8Array(64);
    let out = "";
    while (out.length < length) {
        crypto.getRandomValues(buf);
        for (const b of buf) {
            if (b < max) {
                out += GEN_ALPHABET[b % n];
                if (out.length >= length) break;
            }
        }
    }
    return out;
}

async function copyPassword(name) {
    const got = await rpc({ op: "get", name });
    if (got.kind !== "credential") {
        if (await maybeHandleLocked(got)) return;
        return showError(got.message || "not found");
    }
    try {
        await navigator.clipboard.writeText(got.password);
        showInfo(`Copied password for "${name}". Clear your clipboard when done.`);
    } catch {
        showError("clipboard write failed");
    }
}

refresh();
