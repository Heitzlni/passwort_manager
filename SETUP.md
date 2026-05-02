# Setup

For someone installing this on a fresh Linux machine. Tested on Ubuntu / Linux Mint with GNOME and KDE; should work on any distro with `systemd` and a recent Firefox.

## Quickest path

In a terminal in the repo directory:

```sh
./setup.sh
```

This:
1. Checks `cargo` (Rust) is installed; tells you how to install it if not.
2. Checks the system libraries the GUI / clipboard need; suggests an `apt install` line if anything's missing.
3. Builds all four binaries in release mode (~1–2 min the first time).
4. Installs:
   * the GUI app (`passwort-manager`) into `~/.local/bin/`, plus its icon and `.desktop` launcher;
   * the daemon (`passwortd`), CLI (`passwortctl`), native-messaging host (`passwort-native-host`) into `~/.local/bin/`;
   * the Firefox native-messaging manifest at `~/.mozilla/native-messaging-hosts/passwort_manager.json`;
   * the systemd user service that auto-starts the daemon at every login.
5. Starts the daemon immediately.

## What's left for you

Two clicks worth of manual work — Firefox really doesn't let an external installer add an extension.

### 1 · Set the master password (one time only)

Open the **Password Manager** entry in your application launcher (or run `passwort-manager` in a terminal). Pick a master password (8+ characters). Done — close the app.

### 2 · Load the Firefox extension

1. Open `about:debugging#/runtime/this-firefox` in Firefox.
2. Click **Load Temporary Add-on…**.
3. Select `extension/manifest.json` from this repo.

The icon should appear in your toolbar (if not, click the `»` overflow on the right and pin it).

### Permanent extension install (optional)

Stable Firefox unloads unsigned extensions on restart. To avoid the per-restart reload:

* **Firefox Developer Edition / Nightly / ESR Unbranded**: in `about:config`, set `xpinstall.signatures.required = false`. Pack the extension as `passwort.xpi`:
  ```sh
  cd extension && zip -r ../passwort.xpi . && cd ..
  ```
  Drag `passwort.xpi` onto Firefox to install.
* **Submit to addons.mozilla.org** for free signing (one-time submission, then redistributable).

## Daily flow afterwards

* Reboot → log in → daemon auto-starts.
* Open Firefox → click Password Manager toolbar icon → enter master password (one prompt per unlock session).
* Use any saved login: badge appears next to the password field, click → fill.
* Log into a new site: save banner appears after submit, click Save.
* The vault auto-locks after 10 minutes idle. Unlock again the same way.
* No terminal involved.

## Settings

Edit `~/.config/systemd/user/passwortd.service` and add lines under `[Service]` to change behavior:

```ini
# 30-minute auto-lock (default 10 min)
Environment=PASSWORT_IDLE_TIMEOUT_SECS=1800

# Disable auto-lock entirely (less secure)
Environment=PASSWORT_IDLE_TIMEOUT_SECS=0

# Use a custom vault path (defaults to ~/.local/share/passwort-manager/vault.json)
Environment=PASSWORT_VAULT_PATH=/path/to/vault.json
```

Then reload:

```sh
systemctl --user daemon-reload
systemctl --user restart passwortd
```

## Uninstall

```sh
./packaging/uninstall.sh
```

Removes the binaries, GUI launcher, Firefox manifest, and disables/removes the systemd service. **Your encrypted vault is deliberately left in place.** To delete it as well:

```sh
rm -rf ~/.local/share/passwort-manager
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cargo` not found | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` (or `sudo apt install cargo`) |
| `systemctl --user start passwortd` fails with `218/CAPABILITIES` | Edit `~/.config/systemd/user/passwortd.service` and remove the `Protect*` / `ReadWritePaths` lines. The binary still applies its own hardening internally. |
| Extension popup says "Cannot reach the daemon" | `systemctl --user status passwortd` to check; restart with `systemctl --user restart passwortd`. |
| Extension popup says "vault not initialized" | You haven't created your vault yet — open the GUI app and set a master password. |
| Build fails with `winit` type-inference errors | This project pins `eframe = "0.27"` in `Cargo.toml` to avoid a known issue in winit 0.30. Don't bump it past 0.27 unless you also bump winit past 0.30.13. |
| GUI launches with a black/missing window | Some Wayland sessions need `WINIT_UNIX_BACKEND=x11 passwort-manager` (X11 fallback). |
| Run from inside VS Code's snap'd terminal and see "different vault" | The binaries already detect snap-redirected `XDG_DATA_HOME` and ignore it; if you've somehow ended up with two vault files, the real one is `~/.local/share/passwort-manager/vault.json`. |

## What `setup.sh` actually does, in case you want to do it by hand

```sh
# 1. Build
cargo build --release --bin passwort_manager --bin passwortd \
                       --bin passwortctl --bin passwort_native_host

# 2. Install GUI app
./packaging/install.sh

# 3. Install daemon + native messaging host + systemd service
./packaging/install-native-host.sh

# 4. Verify
systemctl --user status passwortd
passwortctl status   # should print "locked"
```
