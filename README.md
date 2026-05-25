# Password Manager

A local-first password manager for **Linux + Android**, written in Rust.

Built as a learning project. Encrypts everything with AES-256-GCM and an Argon2id-derived key, stores it in a single file under `~/.local/share/passwort-manager/`, and ships with:

- A GUI app, a background daemon, a CLI, a Firefox extension, and a global-hotkey auto-type helper on Linux.
- A native Android app with system **Autofill Framework** integration (fill works in every browser, every native app that supports system autofill) and biometric unlock.
- Two-way USB sync between the two — newer-wins on conflicts, deletions propagate, no cloud.

```
+--------------+   AES-256-GCM   +-----------------+
|   GUI app    | <─────file──── |  vault.json     |  <─┐
| (passwort-   |                 |  (encrypted)    |    │ same file
|  manager)    |                 +-----------------+    │ on phone
+--------------+                          ▲             │
       │ unlocks once per session         │             │
       ▼                                  │             ▼
+--------------+   Unix socket    +---------------+   +------------------+
|  passwortd   | <──── auth ────  |  passwortctl  |   |  Android app     |
|  (daemon,    |   (per-client    +---------------+   |  (Kotlin +       |
|   in memory) |    API token)                        |   Compose +      |
+--------------+   ▲           ▲                      |   Rust JNI)      |
                   │           │                      |  - unlock        |
        +----------+           +-----------+          |  - autofill      |
        │                                  │          |  - biometric     |
+----------------+                +------------------+|  - TOTP          |
| passwort-      |                | passwort-native- ||  - live refresh  |
| autotype       |                | host             |+--------▲---------+
| (Ctrl+Alt+J    |                | (stdio bridge to |         │ adb push/pull
|  global hotkey)|                |  Firefox)        |         │ (USB)
+----------------+                +--------┬---------+         │
                                           │         ┌─────────┘
                                  +--------▼---------┐
                                  | Firefox extension│
                                  | (save / fill /   │
                                  |  autofill)       │
                                  +------------------+
```

## What it does

### Linux

- **Local-only encrypted vault.** AES-256-GCM, Argon2id (128 MiB / 3 iter / 4 lanes). Master password never leaves the machine.
- **GUI app** with add / edit / delete / change-master, live TOTP codes, vault health (weak / reused passwords), HIBP audit (k-anonymous), and import from KeePassXC / Bitwarden / 1Password / Chrome / Firefox.
- **Firefox extension** that auto-fills logins, captures password submissions, shows a save banner across cross-origin redirects, supports multi-step logins (Google, etc.) and multiple accounts per site. Origin-bound on the daemon side so a compromised page can't read off-host credentials.
- **Global hotkey auto-type** (default `Ctrl+Alt+J`) for native apps. Auto-picks the right credential when the active window's title matches; otherwise shows a fuzzy-search picker. Plus a "quick-save" hotkey (default `Ctrl+Alt+S`) that opens a small dialog pre-filled with the window title.
- **TOTP / 2FA support** — store Base32 secrets, see live 6-digit codes in the GUI with a 30-second countdown.
- **Per-client IPC auth.** Even processes running as your user can't read your vault until you approve them via `passwortctl approve <id>`. Same trust model as KeePassXC.
- **Auto-locks** after 10 minutes idle OR when your desktop session locks.
- **Process hardening**: `mlockall`, no core dumps, `prctl(PR_SET_DUMPABLE, 0)`, `Zeroize` on every key and decrypted account field, atomic writes with `O_NOFOLLOW` and 0600 perms.
- **Automatic rotating backups** (encrypted, 15 most recent).

### Android

- **Same vault format** as Linux. The Rust crypto crate (`crypto.rs`) is cross-compiled to `aarch64-linux-android` as a `.so` and called from Kotlin via JNI — byte-for-byte the same Argon2id + AES-GCM, so a `vault.json` round-trips between laptop and phone unchanged.
- **System Autofill Framework** integration. Tap a username or password field in *any* browser (Firefox, Chrome with the third-party-autofill flag flipped, DuckDuckGo, Brave) or a native app, our service is consulted, a chip appears above the keyboard, one tap fills. Field classification reads `autofillHints` for native apps and `htmlInfo` attributes for browser web forms (German + English keywords).
- **Biometric unlock.** Fingerprint instead of typing the master every time, gated by a Settings toggle. The master is wrapped behind an Android Keystore AES-GCM key with `setUserAuthenticationRequired(true)` and `setInvalidatedByBiometricEnrollment(true)`, so enrolling a new fingerprint invalidates the cached master.
- **Live TOTP** display with 1 Hz countdown, monospace pretty-print (`123 456`), copy button, red text in the last 5 seconds.
- **Storage Access Framework** file picker for importing `vault.json` from Downloads / Drive / Nextcloud — no `adb push` required for normal users.
- **Live refresh after sync.** Within ~3 seconds of a PC-initiated sync rewriting `vault.json` on the phone, the in-memory account list silently re-decrypts and the displayed list updates — no manual lock/unlock.
- **System back-button navigation** (and edge-swipe) navigates intra-app (Settings → list, detail → list) instead of leaving.
- **No cloud, no network** at all from the Android app. Sync is the only off-device flow and it's USB to your own laptop.

### Cross-device sync

- **PC-initiated**, button in the Linux GUI's toolbar (`Sync phone`).
- Phone plugged in via USB → click → ~1–2 seconds → both vaults end up identical.
- **Two-way merge** on `(name, username)` identity; newer `updated_at` wins on conflict; **deletions propagate** via tombstones (so deleting "Old Reddit" on PC won't have phone silently re-add it).
- No third-party software needed; uses the `adb` that ships with Android Studio.

## Install (Linux)

```sh
./setup.sh
```

Builds everything in release mode and installs the GUI launcher, daemon (auto-starts at every login via systemd), CLI, native messaging host, Firefox manifest, and auto-type helper. Detects missing system libraries on Debian/Ubuntu and offers to `apt install` them.

After that you have **one** prerequisite step (set master password in the GUI) and **one** Firefox step (load the extension via `about:debugging#/runtime/this-firefox`). See [SETUP.md](SETUP.md) for the full walkthrough.

## Install (Android)

The Android client is a standard Android Studio project under [android/](android/).

Quick path:

1. Install Android Studio (it ships the SDK + NDK + adb).
2. Open `android/` as a project in Android Studio, click the green ▶ Run with your phone connected via USB and USB-debugging enabled.
3. Import your vault — either in-app via **Settings → Import vault file…** (Storage Access Framework), or push from terminal:
   ```sh
   adb push ~/.local/share/passwort-manager/vault.json \
            /sdcard/Android/data/com.example.passwort_manager/files/vault.json
   ```
4. Enable autofill — phone's **Settings → Passwörter und Konten → Bevorzugter Dienst → Password Manager**.
5. (Optional) Enable biometric in the app's Settings.

The Rust crypto crate is built automatically by Gradle via `cargo-ndk`. You need `cargo`, `rustup target add aarch64-linux-android`, and `cargo install cargo-ndk` once on your dev machine.

## Daily flow

- **Linux**: reboot → log in → daemon auto-starts (locked). Click toolbar icon → master password → use any saved site (badge appears next to the password field, click → fill). For native apps: click password field, `Ctrl+Alt+J`, pick or auto-fill.
- **Android**: open app → fingerprint → vault unlocks. Browser autofill works without re-opening the app — system handles it.
- **Add a credential on PC**: GUI → New → save. Then either keep going on PC, or click **Sync phone** to push the change.
- **Phone visible change**: within ~3 seconds of the sync, the phone's list refreshes silently.

## Project layout

```
src/                          # Linux Rust
  main.rs            # GUI / CLI / picker / quick-save dispatcher
  lib.rs             # module roots
  crypto.rs          # AES-GCM + Argon2id helpers, TOTP
  storage.rs         # vault file I/O, atomic writes, schema, payload v2
  session.rs         # in-memory unlocked vault, add/edit/delete/persist, merge_with
  sync.rs            # two-way merge algorithm + adb pull/push orchestration
  vault.rs           # text-mode (--cli) menus
  gui.rs             # eframe GUI: main window, modals, picker, quick-save
  ipc.rs             # daemon protocol + dispatcher + auth gate + origin binding
  auth.rs            # per-client API-token allowlist
  native_host.rs     # browser native-messaging bridge
  autotype.rs        # global-hotkey listener + xdotool/ydotool auto-type
  config.rs          # ~/.config/passwort-manager/config.json (hotkeys + toolbar)
  health.rs          # offline weak/reused password analysis
  hibp.rs            # HIBP k-anonymous breach check
  importers.rs       # CSV / Bitwarden JSON import
  inbox.rs           # "save while locked" sealed inbox (X25519 + AES-GCM)
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

android/                      # Android client
  crypto/              # Rust JNI crate (cdylib for aarch64-linux-android)
    src/lib.rs           # mirrors src/crypto.rs, exposes Java_…_unlockVault / refreshVault
  app/
    src/main/java/com/example/passwort_manager/
      MainActivity.kt        # entrypoint, screen state machine, live-refresh ticker
      AutofillActivity.kt    # unlock screen pushed by the autofill service
      PasswortAutofillService.kt  # AutofillService implementation
      VaultBridge.kt         # Kotlin → Rust JNI wrapper
      VaultState.kt          # process-singleton unlocked-vault store with auto-lock
      SettingsScreen.kt      # auto-lock, biometric, import, delete
      KeystoreCipher.kt      # biometric-gated AES key in Android Keystore
      BiometricUnlock.kt     # androidx.biometric.BiometricPrompt wrapper
      AppSettings.kt         # SharedPreferences-backed prefs + wrapped master
      TotpHelper.kt          # RFC 6238 TOTP in Kotlin
  app/build.gradle.kts # Gradle config + cargoNdkBuild task that drives the Rust build
```

## Build from source (Linux)

```sh
cargo build --release
```

Produces `passwort_manager`, `passwortd`, `passwortctl`, `passwort_native_host`, `passwort_autotype` in `target/release/`. `setup.sh` handles installing them.

## Build from source (Android)

```sh
# one-time setup
rustup target add aarch64-linux-android
cargo install cargo-ndk

cd android/
./gradlew :app:installDebug   # builds Rust + Kotlin and pushes to a USB-connected phone
```

## Distribute a Linux binary release

```sh
./package-release.sh
# → passwort-manager-<version>-linux-x86_64.tar.gz  (~5 MB)
```

Recipients extract and run `./setup.sh` — no Rust toolchain required.

## Caveats / limitations

- **Linux side: X11 hotkeys.** Daemon and GUI work on Wayland, but the auto-type helper relies on X11-grabbed hotkeys for the `Ctrl+Alt+J` / `Ctrl+Alt+S` triggers. On Wayland, bind your compositor's hotkey to `passwortctl fill` / `passwortctl quick-save` instead.
- **Firefox extension is unsigned.** It loads as a temporary add-on (vanishes on Firefox restart). Permanent install requires submitting to addons.mozilla.org for signing — see SETUP.md.
- **Chrome on Android needs a flag flip** to use third-party autofill instead of Google's. Search `chrome://flags` for "third-party password manager" → enable → relaunch. Firefox / DuckDuckGo / Brave honor the system default out of the box.
- **Sync requires the same master password** on both sides (and that you've previously pushed your PC vault onto the phone at least once — fresh-master flow isn't implemented).
- **Phone is read-only** for the moment. Add / edit / delete happens on Linux and propagates via sync. Write support on Android is the next phase.
- **No automatic background sync.** Sync only runs when you click the button. Cloud / Syncthing-style background sync is intentionally not in scope.

## License

Personal / educational. Use at your own risk.
