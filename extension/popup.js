// Popup logic: status, login, list-for-origin, fill, copy, save.

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
        return { kind: "error", message: e.message || String(e) };
    }
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
        const root = $("#content");
        root.innerHTML = "";
        root.appendChild(
            el(
                "div",
                { class: "muted" },
                "Cannot reach the daemon. Make sure passwortd is running."
            )
        );
        showError(status.message);
        return;
    }

    if (status.unlocked) {
        $("#status").textContent = `unlocked · ${status.account_count} account${
            status.account_count === 1 ? "" : "s"
        }`;
        await renderUnlocked();
    } else {
        $("#status").textContent = "locked";
        renderLogin();
    }
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

    // Section: matches for current origin
    const list = await rpc({ op: "list", filter: origin });
    const matches = list.kind === "names" ? list.names : [];

    if (matches.length === 0) {
        root.appendChild(
            el(
                "div",
                { class: "muted", style: "margin-top: 8px;" },
                origin ? "No saved accounts for this site." : "Open a website tab to see matches."
            )
        );
    } else {
        for (const name of matches) {
            const fillBtn = el(
                "button",
                { class: "small", onclick: () => fillOnTab(tab, name) },
                "Fill"
            );
            const copyBtn = el(
                "button",
                { class: "ghost small", onclick: () => copyPassword(name) },
                "Copy"
            );
            root.appendChild(
                el(
                    "div",
                    { class: "account" },
                    el("span", { class: "name" }, name),
                    fillBtn,
                    copyBtn
                )
            );
        }
    }

    // Section: save
    root.appendChild(el("hr"));
    root.appendChild(el("label", {}, "Save this page"));

    const nameInput = el("input", { type: "text" });
    nameInput.value = origin;
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
                    password: pwInput.value,
                });
                pwInput.value = "";
                if (r.kind === "ok") {
                    showInfo(`Saved "${nameInput.value}".`);
                    refresh();
                } else {
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

    root.append(
        el("label", {}, "Name"),
        nameInput,
        el("label", {}, "Password"),
        pwInput,
        el("div", { class: "row" }, saveBtn, readBtn)
    );

    // Footer: lock
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
            )
        )
    );
}

async function fillOnTab(tab, name) {
    if (!tab) return showError("no active tab");
    const got = await rpc({ op: "get", name });
    if (got.kind !== "credential") return showError(got.message || "not found");
    try {
        const r = await browser.tabs.sendMessage(tab.id, {
            type: "fill_password",
            password: got.password,
        });
        if (r && r.filled) showInfo(`Filled password for "${name}".`);
        else showError((r && r.reason) || "fill failed");
    } catch {
        showError("content script not loaded — try reloading the tab");
    }
}

async function copyPassword(name) {
    const got = await rpc({ op: "get", name });
    if (got.kind !== "credential") return showError(got.message || "not found");
    try {
        await navigator.clipboard.writeText(got.password);
        showInfo(`Copied password for "${name}". Clear your clipboard when done.`);
    } catch {
        showError("clipboard write failed");
    }
}

refresh();
