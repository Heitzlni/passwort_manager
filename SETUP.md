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

### 2 · Install the Firefox extension

The extension is **signed by Mozilla** via AMO submission, so it installs permanently in any stable Firefox — no developer mode needed.

**Preferred path (once it's publicly listed on AMO):**

1. Open `addons.mozilla.org` in Firefox, search for **"Password Manager"** (the one for this project).
2. Click **Add to Firefox** → **Add**.
3. Done — toolbar icon appears.

**While the AMO public listing is still pending Mozilla review:**

The signed `.xpi` is checked into this repo at [releases/passwort-manager-0.4.0.xpi](releases/passwort-manager-0.4.0.xpi). To install:

1. Save it to disk (right-click → "Save Link As..." on the file viewer, or just clone the repo).
2. In Firefox: drag-and-drop the `.xpi` file onto a Firefox window → **Hinzufügen** ("Add").

Mozilla already signed it during AMO submission, so it sticks across restarts like any normal extension.

Either way, the icon appears in your toolbar and stays there across Firefox restarts.

> **Snap-Firefox gotcha (Ubuntu 22.04+):** snap Firefox is sandboxed and
> can't read files outside its allowed paths. If you're installing the
> downloaded `.xpi`, save it to `~/Downloads/` (which the snap can
> read), then drag it onto Firefox from there. `install-native-host.sh`
> already detects snap Firefox and writes the native messaging
> manifest to *both* `~/.mozilla/...` and
> `~/snap/firefox/common/.mozilla/...` so the daemon side works either way.

### Developer / contributor install (load from source, no signing)

If you've cloned the repo and want to load the extension straight from the source tree (e.g. you're editing `extension/content.js` and want to see the changes), there's a per-session loader:

1. Type **exactly this** into Firefox's address bar (the URL is important — `about:addons` will *not* work, you'll get a misleading "addon is damaged" error):

   ```
   about:debugging#/runtime/this-firefox
   ```
2. Click **Load Temporary Add-on…**.
3. Select `extension/manifest.json` from this repo.

This re-loads every time Firefox restarts, but it gives you instant edit-and-reload while developing. For daily use, install the signed version above.

## Daily flow afterwards

* Reboot → log in → daemon auto-starts.
* Open Firefox → click Password Manager toolbar icon → enter master password (one prompt per unlock session).
* Use any saved login: badge appears next to the password field, click → fill.
* Log into a new site: save banner appears after submit, click Save.
* The vault auto-locks after 10 minutes idle. Unlock again the same way.
* No terminal involved.

## Auto-type for native apps (Steam, Discord, etc.)

Browser extensions can't see native apps. For non-browser logins the workflow is:

1. Add the credential once via the GUI app (name = e.g. "Steam", username, password).
2. On the app's login screen, click the password field.
3. Press the global hotkey (default **Ctrl+Alt+P**).
4. A small picker pops up; type to filter, Enter to pick (or click).
5. The manager re-focuses the original window and types `<username><Tab><password>`. You hit Enter / click Sign-In yourself.

Requires `xdotool`:

```sh
sudo apt install xdotool
```

The auto-type helper (`passwort-autotype`) starts automatically next time you log in (via an `~/.config/autostart` entry). To start it now without re-logging in:

```sh
nohup passwort-autotype >/dev/null 2>&1 &
```

The hotkey is configurable in `~/.config/passwort-manager/config.json`:

```json
{
    "hotkey": {
        "modifiers": ["ctrl", "alt"],
        "key": "p"
    }
}
```

Valid modifiers: `ctrl`, `alt`, `shift`, `super`. Valid keys: `a`–`z`, `0`–`9`, `f1`–`f12`, `space`, `enter`. The helper polls the file every 2 s, so changes apply without a restart.

### Wayland setup (auto-type)

X11 sessions: nothing extra to do — `passwort-autotype` registers Ctrl+Alt+P (and Ctrl+Alt+S for "save credential from active app") as global hotkeys at login.

Wayland sessions: there's no portable cross-compositor global-hotkey API yet, so `passwort-autotype` exits cleanly at login with a help message and you wire up the hotkey yourself in your compositor's settings. Both pieces still work — just split:

1. **Install `ydotool`** (kernel-level synthetic typing — works on every Wayland compositor):
   ```sh
   sudo apt install ydotool
   ```
2. **Let your user use `/dev/uinput`.** ydotoold ships as a system service that already runs as root on most distros, so this is usually already done; if `passwortctl fill` reports `couldn't reach ydotoold daemon`, run:
   ```sh
   sudo systemctl enable --now ydotool
   ```
   On distros where ydotoold runs as your user (rather than root), add yourself to the `input` group: `sudo usermod -aG input $USER`, then log out + back in.
3. **Bind a hotkey in your compositor** to the standalone CLI commands the password manager exposes:
   - **GNOME**: Settings → Keyboard → "View and Customize Shortcuts" → Custom Shortcuts → "+":
     - Name: `Password Manager fill`
     - Command: `/home/<user>/.local/bin/passwortctl fill`
     - Shortcut: whatever you like (Ctrl+Alt+P matches the X11 default)
   - **KDE**: System Settings → Shortcuts → Custom Shortcuts → Edit → New → Global Shortcut → Command/URL → same command path
   - **Sway / Hyprland / River** (config-file based):
     ```
     bindsym Ctrl+Alt+p exec passwortctl fill
     bindsym Ctrl+Alt+s exec passwortctl quick-save
     ```

Pressing the bound hotkey opens the picker; pick an entry, hit Enter, and `ydotool` types `<username><Tab><password>` into whatever was focused before. Skip step 3 entirely if you only ever use the browser extension — that path doesn't need any of this.

**Limitations on Wayland:** the compositor doesn't expose the active window's title to non-privileged apps, so the X11-only "fast path" (auto-pick by window title) is disabled. The picker always shows; pick an entry and continue.

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
