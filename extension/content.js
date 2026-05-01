// Content script: runs on every page. Listens for fill/read commands from
// the popup (relayed via tabs.sendMessage) and pokes the page's DOM.

browser.runtime.onMessage.addListener((msg) => {
    if (!msg || !msg.type) return;

    if (msg.type === "fill_password") {
        const pwField = document.querySelector('input[type="password"]');
        if (!pwField) {
            return Promise.resolve({ filled: false, reason: "no password field" });
        }
        const userField = findUsernameField(pwField);
        if (msg.username && userField) {
            setFieldValue(userField, msg.username);
        }
        setFieldValue(pwField, msg.password);
        return Promise.resolve({ filled: true });
    }

    if (msg.type === "read_password") {
        const pwField = document.querySelector('input[type="password"]');
        return Promise.resolve({
            password: pwField ? pwField.value || null : null,
        });
    }
});

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
