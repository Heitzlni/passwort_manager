# Password Manager — Browser Extension

Talks to the local Rust password-manager daemon via Firefox's
[native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging).

## How the pieces fit together

```
+-----------+   stdin/stdout   +---------------------+   unix socket   +-----------+
|  Firefox  | <--------------> | passwort-native-host| <-------------> | passwortd |
| extension |  4-byte LE len   |   (this binary)     |    NDJSON       | (daemon)  |
+-----------+   + JSON body    +---------------------+                 +-----------+
```

* The extension sends RPCs (`{op:"unlock"|"list"|"get"|"save"|...}`) by `postMessage`.
* The native host wraps the JSON with a 4-byte little-endian length prefix
  (the protocol Firefox enforces) and pipes it to the daemon as NDJSON.
* The daemon owns the unlocked vault in memory and persists changes to
  the AES-256-GCM blob on disk.

## Setup (development / first time)

1. **Install the binaries and the native messaging manifest:**
   ```sh
   cd ..
   ./packaging/install-native-host.sh
   ```
   This builds `passwortd`, `passwortctl`, and `passwort-native-host` to
   `~/.local/bin/`, and writes the Firefox manifest to
   `~/.mozilla/native-messaging-hosts/passwort_manager.json`.

2. **Start the daemon** (once per session — you can put it in a startup script):
   ```sh
   passwortd &
   ```

3. **Load the extension as a temporary add-on:**
   * Open Firefox and visit `about:debugging#/runtime/this-firefox`.
   * Click **Load Temporary Add-on…** and pick `extension/manifest.json`.
   * The extension stays loaded until Firefox is restarted.

4. **Use it:**
   * Click the toolbar icon → enter your master password to unlock.
   * Visit any site with a saved account — the popup shows a **Fill** button
     for each match.
   * On a site without a saved account: type the password into the field on
     the page, click the icon, hit **Read from page** → **Save**.

## Permanent install

Firefox refuses to load unsigned extensions permanently in stable/Beta
builds. Options:

* **Firefox Developer Edition** (or **Nightly** / **ESR Unbranded**): set
  `xpinstall.signatures.required = false` in `about:config`, then install the
  packed `.xpi`. (`zip -r passwort-manager.xpi extension` to pack.)
* **Sign through addons.mozilla.org**: submit the .xpi at
  https://addons.mozilla.org/developers/ for self-distribution signing.

## Troubleshooting

* **Popup says "Cannot reach the daemon"** — start the daemon: `passwortd &`.
* **Native host disconnects** — check `~/.mozilla/native-messaging-hosts/passwort_manager.json`
  exists and that its `path` points to a valid binary you can run.
* **`browser.runtime.connectNative` fails silently** — open the
  Browser Console (`Ctrl+Shift+J`) for the real error.
