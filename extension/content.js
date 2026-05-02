// Content script — Bitwarden-style in-page UX.
//
// On every page:
//   * If the vault is unlocked AND we have credentials matching the host,
//     a small "P" badge appears overlaid on the right edge of each password
//     input. Clicking it opens a dropdown of matching account names; click
//     one to fill the username (if any) and password.
//   * If a previous form submission left a captured credential in the
//     background buffer, a save banner appears in the top-right corner
//     asking "Save password?" with Save / Not now buttons. If the vault
//     is locked, the banner morphs into an inline unlock form.
//   * On any form submit with a password field, we capture username +
//     password and post them to the background. If the page navigates,
//     the next page's content script picks up the captured cred and
//     shows the banner there.
//
// All injected UI uses Shadow DOM (banner, dropdown) or `all: revert`
// inline styles (the small badge) so the page's CSS can't style or read it.

const ORIGIN = location.hostname;
const STATE = {
    unlocked: false,
    matches: [], // saved {name, username} entries matching the current host
};
const DECORATED = new WeakSet(); // password fields already given a badge
const AUTOFILLED = new WeakSet(); // password fields already auto-filled this load
let bannerHost = null;
let menuHost = null;
let onMenuOutsideClick = null;
let mutationDebounce = null;

// =================== boot ===================

(async function main() {
    if (window.top !== window) return; // skip iframes for now
    installSubmitListener();
    installRuntimeListener();
    installMutationObserver();
    await refresh();
    await maybeShowSaveBanner();
})();

// =================== background RPC ===================

function sendBg(msg) {
    return browser.runtime.sendMessage(msg).catch(() => null);
}

async function rpc(payload) {
    const r = await sendBg({ type: "rpc", payload });
    return r || { kind: "error", code: "transport", message: "no response" };
}

function matchesHost(saved, host) {
    if (!saved || !host) return false;
    const s = saved.toLowerCase();
    const h = host.toLowerCase();
    return s === h || h.endsWith("." + s);
}

async function refresh() {
    closeMenu();
    removeAllBadges();
    const status = await rpc({ op: "status" });
    STATE.unlocked = status.kind === "status" && status.unlocked === true;
    if (!STATE.unlocked) {
        STATE.matches = [];
        return;
    }
    const list = await rpc({ op: "list_entries" });
    STATE.matches =
        list.kind === "entries" ? list.entries.filter((e) => matchesHost(e.name, ORIGIN)) : [];
    if (STATE.matches.length > 0) {
        decoratePasswordFields();
        await maybeAutofill();
    }
}

// Auto-fill on page load (and on later DOM mutations, e.g. SPA login flows
// like Google's two-step page). We fill password and/or username
// independently — many real login flows show only one at a time. We never
// overwrite typed input, and we never overwrite the same field twice.
async function maybeAutofill() {
    if (STATE.matches.length !== 1) return;
    const match = STATE.matches[0];

    const pwField = visibleFirst('input[type="password"]');
    const standaloneUser = pwField ? null : findStandaloneUsernameField();

    // Nothing relevant to fill right now.
    if (!pwField && !standaloneUser) return;
    if (pwField && AUTOFILLED.has(pwField)) {
        // password already filled this load; nothing else to do here
        return;
    }
    if (standaloneUser && AUTOFILLED.has(standaloneUser)) return;

    // Fetch the credential lazily; only once.
    const cred = await rpc({ op: "get", name: match.name });
    if (cred.kind !== "credential") return;

    if (pwField) {
        if (!pwField.value) {
            AUTOFILLED.add(pwField);
            setFieldValue(pwField, cred.password);
        }
        const userField = findUsernameField(pwField);
        if (userField && !userField.value && cred.username) {
            AUTOFILLED.add(userField);
            setFieldValue(userField, cred.username);
        }
    } else if (standaloneUser && !standaloneUser.value && cred.username) {
        AUTOFILLED.add(standaloneUser);
        setFieldValue(standaloneUser, cred.username);
    }
}

// Picks the first visible match for a CSS selector — `document.querySelector`
// would happily return a hidden one.
function visibleFirst(selector) {
    for (const el of document.querySelectorAll(selector)) {
        if (isVisible(el)) return el;
    }
    return null;
}

// Heuristic for "the username/email field" on a page that has *no* password
// field (e.g. step 1 of Google's two-step login). Tries the strongest
// signals first (autocomplete attribute, type="email") before name/id hints.
function findStandaloneUsernameField() {
    const selectors = [
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
        'input[type="email"]',
        'input[name*="email" i]',
        'input[name*="user" i]',
        'input[id*="email" i]',
        'input[id*="user" i]',
    ];
    for (const sel of selectors) {
        for (const el of document.querySelectorAll(sel)) {
            if (!isVisible(el)) continue;
            const t = (el.type || "text").toLowerCase();
            if (t === "text" || t === "email" || t === "tel" || t === "") {
                return el;
            }
        }
    }
    return null;
}

// =================== fill badge (small "P" overlay) ===================

function decoratePasswordFields() {
    const fields = document.querySelectorAll('input[type="password"]');
    for (const f of fields) {
        if (DECORATED.has(f)) continue;
        if (!isVisible(f)) continue;
        addBadge(f);
    }
}

function isVisible(el) {
    if (!el || !el.getBoundingClientRect || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
}

function addBadge(pwField) {
    DECORATED.add(pwField);

    const badge = document.createElement("div");
    badge.setAttribute("data-pwm-badge", "1");
    badge.style.cssText = `
        all: revert;
        position: absolute;
        z-index: 2147483646;
        width: 22px;
        height: 22px;
        background: #7c6dd8;
        color: white;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, system-ui, sans-serif;
        font-size: 11px;
        font-weight: 700;
        cursor: pointer;
        box-shadow: 0 2px 5px rgba(0,0,0,0.25);
        user-select: none;
        pointer-events: auto;
        line-height: 1;
    `;
    badge.textContent = "P";
    badge.title = "Fill from Password Manager";

    function position() {
        if (!pwField.isConnected) {
            badge.remove();
            cleanup();
            return;
        }
        const rect = pwField.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) {
            badge.style.display = "none";
            return;
        }
        badge.style.display = "flex";
        badge.style.left = `${window.scrollX + rect.right - 26}px`;
        badge.style.top = `${window.scrollY + rect.top + (rect.height - 22) / 2}px`;
    }

    function cleanup() {
        window.removeEventListener("scroll", position, true);
        window.removeEventListener("resize", position);
    }

    window.addEventListener("scroll", position, true);
    window.addEventListener("resize", position);

    badge.addEventListener("mousedown", (e) => e.preventDefault());
    badge.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        toggleMenu(badge, pwField);
    });

    position();
    document.body.appendChild(badge);
}

function removeAllBadges() {
    closeMenu();
    document.querySelectorAll("[data-pwm-badge]").forEach((b) => b.remove());
}

// =================== fill dropdown menu ===================

function toggleMenu(anchor, pwField) {
    if (menuHost) {
        closeMenu();
        return;
    }

    menuHost = document.createElement("div");
    menuHost.setAttribute("data-pwm-menu", "1");
    menuHost.style.cssText = `
        all: revert;
        position: absolute;
        z-index: 2147483647;
        pointer-events: auto;
    `;

    const shadow = menuHost.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
        <style>
            :host { display: block; }
            .menu {
                background: #1e1e22;
                color: #dcddde;
                border: 1px solid #33333a;
                border-radius: 6px;
                padding: 4px 0;
                min-width: 220px;
                font-family: -apple-system, system-ui, "Segoe UI", sans-serif;
                font-size: 13px;
                box-shadow: 0 4px 14px rgba(0,0,0,0.4);
            }
            .item {
                padding: 7px 12px;
                cursor: pointer;
            }
            .item:hover { background: #33333a; }
            .empty { padding: 8px 12px; color: #8e8e96; font-style: italic; }
        </style>
        <div class="menu" id="m"></div>
    `;
    const m = shadow.getElementById("m");
    if (STATE.matches.length === 0) {
        const e = document.createElement("div");
        e.className = "empty";
        e.textContent = "No matches.";
        m.appendChild(e);
    } else {
        for (const entry of STATE.matches) {
            const item = document.createElement("div");
            item.className = "item";
            item.textContent = entry.username
                ? `${entry.username} — ${entry.name}`
                : entry.name;
            item.addEventListener("mousedown", (e) => e.preventDefault());
            item.addEventListener("click", async (e) => {
                e.preventDefault();
                e.stopPropagation();
                closeMenu();
                await fillFromVault(pwField, entry.name);
            });
            m.appendChild(item);
        }
    }

    const rect = anchor.getBoundingClientRect();
    menuHost.style.left = `${window.scrollX + rect.left}px`;
    menuHost.style.top = `${window.scrollY + rect.bottom + 4}px`;
    document.body.appendChild(menuHost);

    onMenuOutsideClick = (e) => {
        if (!menuHost) return;
        const path = e.composedPath ? e.composedPath() : [];
        if (path.includes(menuHost) || path.includes(anchor)) return;
        closeMenu();
    };
    setTimeout(() => document.addEventListener("click", onMenuOutsideClick, true), 0);
}

function closeMenu() {
    if (menuHost) {
        menuHost.remove();
        menuHost = null;
    }
    if (onMenuOutsideClick) {
        document.removeEventListener("click", onMenuOutsideClick, true);
        onMenuOutsideClick = null;
    }
}

async function fillFromVault(pwField, name) {
    const r = await rpc({ op: "get", name });
    if (r.kind !== "credential") {
        if (r.code === "locked") refresh();
        return;
    }
    const userField = findUsernameField(pwField);
    if (userField && r.username) setFieldValue(userField, r.username);
    setFieldValue(pwField, r.password);
}

// =================== submit capture ===================

function installSubmitListener() {
    document.addEventListener(
        "submit",
        (event) => {
            const form = event.target;
            if (!(form instanceof HTMLFormElement)) return;
            const pwField = form.querySelector('input[type="password"]');
            if (!pwField || !pwField.value) return;
            const userField = findUsernameField(pwField);
            sendBg({
                type: "captured_submit",
                origin: ORIGIN,
                username: userField ? userField.value || "" : "",
                password: pwField.value,
            });
            // Show the banner here too in case the page doesn't navigate.
            setTimeout(() => maybeShowSaveBanner(), 250);
        },
        true
    );
}

// =================== save banner (Shadow DOM) ===================

async function maybeShowSaveBanner() {
    const captured = (await sendBg({ type: "list_captured" })) || [];
    const here = captured.find((c) => c.origin === ORIGIN);
    if (!here) return;
    showSaveBanner(here);
}

function showSaveBanner(captured) {
    if (bannerHost) return;

    bannerHost = document.createElement("div");
    bannerHost.setAttribute("data-pwm-banner", "1");
    bannerHost.style.cssText = `
        all: revert;
        position: fixed;
        top: 16px;
        right: 16px;
        z-index: 2147483647;
        pointer-events: auto;
    `;

    const shadow = bannerHost.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
        <style>
            :host { display: block; }
            .banner {
                background: #1e1e22;
                color: #dcddde;
                border: 1px solid #7c6dd8;
                border-radius: 8px;
                padding: 14px 16px;
                width: 320px;
                font-family: -apple-system, system-ui, "Segoe UI", sans-serif;
                font-size: 13px;
                box-shadow: 0 8px 24px rgba(0,0,0,0.5);
            }
            .title { font-weight: 600; font-size: 14px; margin-bottom: 4px; }
            .subtitle { color: #8e8e96; font-size: 12px; margin-bottom: 12px; word-break: break-all; }
            .actions { display: flex; gap: 8px; }
            button {
                all: revert;
                background: #7c6dd8;
                color: white;
                border: none;
                padding: 6px 14px;
                border-radius: 5px;
                cursor: pointer;
                font: 500 13px -apple-system, system-ui, sans-serif;
                line-height: 1.2;
            }
            button:hover { background: #8e7eea; }
            button.ghost {
                background: transparent;
                color: #8e8e96;
                border: 1px solid #33333a;
            }
            button.ghost:hover {
                color: #dcddde;
                border-color: #7c6dd8;
                background: transparent;
            }
            input {
                all: revert;
                width: 100%;
                background: #18181c;
                color: #dcddde;
                border: 1px solid #33333a;
                border-radius: 5px;
                padding: 7px 9px;
                font: 13px -apple-system, system-ui, sans-serif;
                box-sizing: border-box;
                margin-bottom: 8px;
            }
            input:focus { outline: none; border-color: #7c6dd8; }
            .err { color: #e06c75; font-size: 11px; margin-top: 8px; min-height: 14px; }
        </style>
        <div class="banner" id="b"></div>
    `;
    document.body.appendChild(bannerHost);

    renderSaveStep(shadow, captured);
}

function renderSaveStep(shadow, captured) {
    const b = shadow.getElementById("b");
    const userPart = captured.username ? ` (${captured.username})` : "";
    b.innerHTML = "";
    b.appendChild(makeDiv("title", "Save password?"));
    b.appendChild(makeDiv("subtitle", `${captured.origin}${userPart}`));
    const actions = makeDiv("actions");
    const saveBtn = makeButton("Save", false, async () => {
        await trySave(shadow, captured);
    });
    const dismissBtn = makeButton("Not now", true, async () => {
        await sendBg({ type: "discard_captured", origin: captured.origin });
        closeBanner();
    });
    actions.appendChild(saveBtn);
    actions.appendChild(dismissBtn);
    b.appendChild(actions);
    b.appendChild(makeDiv("err"));
    saveBtn.id = "save";
}

async function trySave(shadow, captured) {
    const errEl = shadow.querySelector(".err");
    errEl.textContent = "";
    const status = await rpc({ op: "status" });
    if (status.kind !== "status" || !status.unlocked) {
        renderUnlockStep(shadow, captured);
        return;
    }
    const r = await rpc({
        op: "save",
        name: captured.origin,
        username: captured.username || "",
        password: captured.password,
    });
    if (r.kind === "ok") {
        await sendBg({ type: "discard_captured", origin: captured.origin });
        showSaved(shadow);
        setTimeout(closeBanner, 1500);
        refresh();
    } else if (r.code === "locked") {
        renderUnlockStep(shadow, captured);
    } else {
        errEl.textContent = r.message || "save failed";
    }
}

function renderUnlockStep(shadow, captured) {
    const b = shadow.getElementById("b");
    b.innerHTML = "";
    b.appendChild(makeDiv("title", "Vault is locked"));
    b.appendChild(makeDiv("subtitle", `Unlock to save the credential for ${captured.origin}.`));
    const pw = document.createElement("input");
    pw.type = "password";
    pw.placeholder = "Master password";
    b.appendChild(pw);
    const actions = makeDiv("actions");
    const unlockBtn = makeButton("Unlock & Save", false, async () => {
        const errEl = shadow.querySelector(".err");
        errEl.textContent = "";
        const r = await rpc({ op: "unlock", password: pw.value });
        pw.value = "";
        if (r.kind !== "ok") {
            errEl.textContent = r.message || "unlock failed";
            return;
        }
        const s = await rpc({
            op: "save",
            name: captured.origin,
            username: captured.username || "",
            password: captured.password,
        });
        if (s.kind === "ok") {
            await sendBg({ type: "discard_captured", origin: captured.origin });
            showSaved(shadow);
            setTimeout(closeBanner, 1500);
            refresh();
        } else {
            errEl.textContent = s.message || "save failed";
        }
    });
    const cancelBtn = makeButton("Cancel", true, () => closeBanner());
    actions.appendChild(unlockBtn);
    actions.appendChild(cancelBtn);
    b.appendChild(actions);
    b.appendChild(makeDiv("err"));
    pw.addEventListener("keydown", (e) => {
        if (e.key === "Enter") unlockBtn.click();
    });
    setTimeout(() => pw.focus(), 0);
}

function showSaved(shadow) {
    const b = shadow.getElementById("b");
    b.innerHTML = "";
    b.appendChild(makeDiv("title", "Saved."));
    b.appendChild(makeDiv("subtitle", "Visit the site again and click the badge to fill."));
}

function closeBanner() {
    if (bannerHost) {
        bannerHost.remove();
        bannerHost = null;
    }
}

function makeDiv(cls, text) {
    const d = document.createElement("div");
    if (cls) d.className = cls;
    if (text != null) d.textContent = text;
    return d;
}

function makeButton(label, ghost, onClick) {
    const b = document.createElement("button");
    if (ghost) b.className = "ghost";
    b.textContent = label;
    b.addEventListener("click", onClick);
    return b;
}

// =================== runtime listener (popup → content) ===================

function installRuntimeListener() {
    browser.runtime.onMessage.addListener((msg) => {
        if (!msg || !msg.type) return;

        if (msg.type === "fill_password") {
            const pwField = document.querySelector('input[type="password"]');
            if (!pwField) {
                return Promise.resolve({ filled: false, reason: "no password field" });
            }
            const userField = findUsernameField(pwField);
            if (msg.username && userField) setFieldValue(userField, msg.username);
            setFieldValue(pwField, msg.password);
            return Promise.resolve({ filled: true });
        }

        if (msg.type === "read_password") {
            const pwField = document.querySelector('input[type="password"]');
            return Promise.resolve({ password: pwField ? pwField.value || null : null });
        }

        if (msg.type === "vault_state_changed") {
            refresh();
            return Promise.resolve();
        }
    });
}

// =================== mutation observer (SPA-injected fields) ===================

function installMutationObserver() {
    if (!document.body) {
        document.addEventListener("DOMContentLoaded", installMutationObserver);
        return;
    }
    const obs = new MutationObserver(() => {
        if (mutationDebounce) return;
        mutationDebounce = setTimeout(async () => {
            mutationDebounce = null;
            if (STATE.unlocked && STATE.matches.length > 0) {
                decoratePasswordFields();
                // Critical for SPA login flows (Google, etc.): the password
                // field appears after the email step's "Next" button, so the
                // initial maybeAutofill saw nothing useful.
                await maybeAutofill();
            }
        }, 250);
    });
    obs.observe(document.body, { childList: true, subtree: true });
}

// =================== shared helpers ===================

function findUsernameField(pwField) {
    const form = pwField.closest("form");
    const scope = form || document;
    const candidates = Array.from(scope.querySelectorAll("input"));
    let last = null;
    for (const i of candidates) {
        if (i === pwField) break;
        const t = (i.type || "text").toLowerCase();
        if (t === "text" || t === "email" || t === "tel" || t === "username") {
            last = i;
        }
    }
    return last;
}

function setFieldValue(field, value) {
    field.value = value;
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
}
