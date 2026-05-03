# Password Manager

A local-first password manager for Linux, written in Rust.

Built as a learning project. Encrypts everything with AES-256-GCM and an Argon2id-derived key, stores it in a single file under `~/.local/share/passwort-manager/`, and ships with a GUI app, a background daemon, a Firefox extension that does the usual save / fill / autofill, and a global-hotkey auto-type helper for native apps like Steam or Discord.

```
+--------------+   AES-256-GCM   +-----------------+
|   GUI app    | <─────file──── |  vault.json     |
| (passwort-   |                 |  (encrypted)    |
|  manager)    |                 +-----------------+
+--------------+                          ▲
       │ unlocks once per session         │ same file
       ▼                                  │
+--------------+   Unix socket    +---------------+
|  passwortd   | <──── auth ────  |  passwortctl  |   CLI
|  (daemon,    |   (per-client    +---------------+
|   in memory) |    API token)
+--------------+   ▲           ▲
                   │           │
        +----------+           +-----------+
        │                                  │
+----------------+                +------------------+
| passwort-      |                | passwort-native- |
| autotype       |                | host             |
| (Ctrl+Alt+J    |                | (stdio bridge to |
|  global hotkey)|                |  Firefox)        |
+----------------+                +--------┬---------+
                                           │
                                  +--------▼---------+
                                  | Firefox extension│
                                  | (save / fill /   │
                                  |  autofill)       │
                                  +------------------+
```

## What it does

- **Local-only encrypted vault.** AES-256-GCM, Argon2id (64 MiB / 3 iter / 4 lanes). Master password never leaves the machine.
- **GUI app** with add / edit / delete / change-master, live TOTP codes, and a settings page for the auto-type hotkeys.
- **Firefox extension** that auto-fills logins, captures password submissions, shows a save banner across cross-origin redirects, supports multi-step logins (Google, etc.) and multiple accounts per site.
- **Global hotkey auto-type** (default `Ctrl+Alt+J`) for native apps. Auto-picks the right credential when the active window's title matches; otherwise shows a fuzzy-search picker. Plus a "quick-save" hotkey (default `Ctrl+Alt+S`) that opens a small dialog pre-filled with the window title.
- **TOTP / 2FA support** — store Base32 secrets, see live 6-digit codes in the GUI with a 30-second countdown.
- **Per-client IPC auth.** Even processes running as your user can't read your vault until you approve them via `passwortctl approve <id>`. Same trust model as KeePassXC.
- **Auto-locks** after 10 minutes idle OR when your desktop session locks.
- **Process hardening**: `mlockall`, no core dumps, `prctl(PR_SET_DUMPABLE, 0)`, `Zeroize` on every key and decrypted account field, atomic writes with `O_NOFOLLOW` and 0600 perms.

## Install

```sh
./setup.sh
```

Builds everything in release mode and installs the GUI launcher, daemon (auto-starts at every login via systemd), CLI, native messaging host, Firefox manifest, and auto-type helper. Detects missing system libraries on Debian/Ubuntu and offers to `apt install` them.

After that you have **one** prerequisite step (set master password in the GUI) and **one** Firefox step (load the extension via `about:debugging#/runtime/this-firefox`). See [SETUP.md](SETUP.md) for the full walkthrough including the snap-Firefox gotcha and the Manifest V3 details.

## Daily flow

- Reboot → log in → daemon auto-starts (locked).
- Open Firefox → click the toolbar icon → enter master password (one prompt per unlock session).
- Use any saved site: badge appears next to the password field, click → fill.
- Log into a new site: save banner appears after submit, click Save.
- For native apps (Steam, Discord, ...): click the password field, press `Ctrl+Alt+J`, pick or auto-fill.

## Project layout

```
src/
  main.rs            # GUI / CLI / picker / quick-save dispatcher
  lib.rs             # module roots
  crypto.rs          # AES-GCM + Argon2id helpers, TOTP
  storage.rs         # vault file I/O, atomic writes, schema
  session.rs         # in-memory unlocked vault, add/edit/delete/persist
  vault.rs           # text-mode (--cli) menus
  gui.rs             # eframe GUI: main window, modals, picker, quick-save
  ipc.rs             # daemon protocol + dispatcher + auth gate
  auth.rs            # per-client API-token allowlist
  native_host.rs     # browser native-messaging bridge
  autotype.rs        # global-hotkey listener + xdotool auto-type
  config.rs          # ~/.config/passwort-manager/config.json (hotkeys)
  bin/
    passwortd.rs           # background daemon
    passwortctl.rs         # CLI client
    passwort_native_host.rs# browser bridge
    passwort_autotype.rs   # hotkey listener (supervisor + child)

extension/             # Firefox WebExtension (Manifest V3)
packaging/             # install scripts, .desktop, systemd service, manifests
setup.sh               # one-shot installer
package-release.sh     # build a self-contained tarball for distribution
SETUP.md               # full setup + troubleshooting
```

## Build from source

```sh
cargo build --release
```

Produces `passwort_manager`, `passwortd`, `passwortctl`, `passwort_native_host`, `passwort_autotype` in `target/release/`. `setup.sh` handles installing them.

## Distribute a binary release

```sh
./package-release.sh
# → passwort-manager-<version>-linux-x86_64.tar.gz  (~5 MB)
```

Recipients extract and run `./setup.sh` — no Rust toolchain required.

## Caveats / limitations

- **Linux + X11 only.** Daemon and GUI work on Wayland, but the auto-type helper relies on X11-grabbed hotkeys and `xdotool` for keystroke synthesis. Wayland support would need `xdg-desktop-portal` global shortcuts and `wtype`/`ydotool`.
- **Firefox extension is unsigned.** It loads as a temporary add-on (vanishes on Firefox restart). Permanent install requires submitting to addons.mozilla.org for signing — see SETUP.md.
- **No native-app credential capture.** Native apps don't expose form fields the way browsers do. You add native-app entries through the GUI; auto-type fills them later.
- **No 2FA app sync, no breach checks, no vault sync.** Encrypted file is portable so manual backup to e.g. Syncthing works.

## License

Personal / educational. Use at your own risk.
