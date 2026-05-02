# Setup

For someone installing this on a fresh Linux machine. Tested on Ubuntu / Linux Mint with GNOME and KDE; should work on any distro with `systemd` and a recent Firefox.

There are two paths depending on what you downloaded:

* **A:** Release tarball (`passwort-manager-X.Y.Z-linux-x86_64.tar.gz`) — pre-built, no Rust needed.
* **B:** Source repo (this directory cloned from GitHub) — `setup.sh` will offer to install Rust for you if it's missing.

Both paths run the same `./setup.sh` afterwards.

---

## Path A — release tarball

```sh
tar xzf passwort-manager-*-linux-x86_64.tar.gz
cd passwort-manager-*-linux-x86_64
./setup.sh
```

`setup.sh` notices the pre-built binaries in `bin/` and skips the Rust build entirely. If any system libraries are missing, it offers to `sudo apt install` them for you.

## Path B — source repo

```sh
./setup.sh
```

If Rust isn't installed, `setup.sh` offers to install it via the official `rustup` script (no sudo, lands in `~/.cargo`). Then it builds the four binaries (1–2 min the first time, seconds after) and installs everything.

## What `setup.sh` actually does

1. Checks for `cargo` (skipped if pre-built binaries are present).
2. Detects missing system libraries on Debian/Ubuntu and offers an `apt install`.
3. Builds the four binaries in release mode (skipped if pre-built).
4. Installs:
   * GUI app (`passwort-manager`) into `~/.local/bin/`, with icon and `.desktop` launcher;
   * Daemon (`passwortd`), CLI (`passwortctl`), native messaging host (`passwort-native-host`) into `~/.local/bin/`;
   * Firefox native messaging manifest at `~/.mozilla/native-messaging-hosts/passwort_manager.json`;
   * Systemd user service that auto-starts the daemon at every login.
5. Starts the daemon immediately.

## Two manual steps left after `setup.sh`

Firefox really doesn't let any external program touch its profile, so the extension install is on you.

### 1 · Set the master password (one time only)

Open the **Password Manager** entry in your application launcher (or run `passwort-manager` in a terminal). Pick a master password (≥ 8 characters). Done — close the app.

### 2 · Load the Firefox extension

1. Open `about:debugging#/runtime/this-firefox` in Firefox.
2. Click **Load Temporary Add-on…**.
3. Select `extension/manifest.json` from this repo.

The icon should appear in your toolbar.

### Permanent extension install (avoid the per-restart reload)

Stable Firefox unloads unsigned extensions on restart. Two real options:

* **Firefox Developer Edition / Nightly / ESR Unbranded.** In `about:config`, set `xpinstall.signatures.required = false`. Pack the extension as `passwort.xpi`:
  ```sh
  cd extension && zip -r ../passwort.xpi . && cd ..
  ```
  Drag `passwort.xpi` onto Firefox to install permanently.
* **Submit to addons.mozilla.org** for free signing. One-time submission, then redistributable as a real signed `.xpi` that installs in any Firefox.

## Daily flow afterwards

* Reboot → log in → daemon auto-starts.
* Open Firefox → click Password Manager toolbar icon → enter master password (one prompt per unlock session).
* Use any saved login: badge appears next to the password field, click → fill.
* Log into a new site: save banner appears after submit, click Save.
* The vault auto-locks after 10 minutes idle. Unlock again the same way.
* No terminal involved.

## Building a release tarball yourself

If you change the code and want to ship it to friends without making them install Rust:

```sh
./package-release.sh
```

Produces `passwort-manager-<version>-linux-<arch>.tar.gz` at the repo root. Anyone on the same architecture (typically `x86_64`) can extract that, run `./setup.sh`, and they're done — no cargo needed.

## Settings

Edit `~/.config/systemd/user/passwortd.service` and add lines under `[Service]`:

```ini
# 30-minute auto-lock (default 10 min)
Environment=PASSWORT_IDLE_TIMEOUT_SECS=1800

# Disable auto-lock entirely (less secure)
Environment=PASSWORT_IDLE_TIMEOUT_SECS=0

# Custom vault path (default ~/.local/share/passwort-manager/vault.json)
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

Removes the binaries, GUI launcher, Firefox manifest, and disables/removes the systemd service. **Your encrypted vault is deliberately left in place.** To wipe it:

```sh
rm -rf ~/.local/share/passwort-manager
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cargo` not found and you said "no" to installing it | Re-run `./setup.sh` and let it install Rust, or download the release tarball instead. |
| `systemctl --user start passwortd` fails with `218/CAPABILITIES` | Older systemd. Edit `~/.config/systemd/user/passwortd.service` and remove the `Protect*` / `ReadWritePaths` lines. The binary still hardens itself internally. |
| Extension popup says "Cannot reach the daemon" | `systemctl --user status passwortd` to check; restart with `systemctl --user restart passwortd`. |
| Extension popup says "vault not initialized" | You haven't created your vault yet — open the GUI app and set a master password. |
| Build fails with `winit` type-inference errors | This project pins `eframe = "0.27"` in `Cargo.toml` to dodge a winit 0.30 bug. Don't bump it past 0.27 unless you also pin winit accordingly. |
| GUI launches with a black/missing window | Some Wayland sessions need `WINIT_UNIX_BACKEND=x11 passwort-manager` (X11 fallback). |
| Run from inside VS Code's snap'd terminal and see "different vault" | The binaries already detect snap-redirected `XDG_DATA_HOME` and ignore it; if you've ended up with two vault files, the real one is `~/.local/share/passwort-manager/vault.json`. |
