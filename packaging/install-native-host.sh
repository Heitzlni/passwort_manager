#!/usr/bin/env bash
# Install the passwort-manager native messaging host.
#
# Usage:
#   install-native-host.sh                    # Firefox only
#   install-native-host.sh --chrome <ID>      # Firefox + Chrome (extension ID required)
set -euo pipefail

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$REPO_DIR"

CHROME_ID=""
DO_CHROME=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --chrome)
            DO_CHROME=1
            CHROME_ID="${2:-}"
            shift 2
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 1
            ;;
    esac
done

BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

# Source vs. pre-built (release tarball ships bin/ at repo root).
PREBUILT_DIR="$REPO_DIR/bin"
if [[ -x "$PREBUILT_DIR/passwortd" \
   && -x "$PREBUILT_DIR/passwortctl" \
   && -x "$PREBUILT_DIR/passwort_native_host" \
   && -x "$PREBUILT_DIR/passwort_autotype" ]]; then
    install -m 755 "$PREBUILT_DIR/passwortd"             "$BIN_DIR/passwortd"
    install -m 755 "$PREBUILT_DIR/passwortctl"           "$BIN_DIR/passwortctl"
    install -m 755 "$PREBUILT_DIR/passwort_native_host"  "$BIN_DIR/passwort-native-host"
    install -m 755 "$PREBUILT_DIR/passwort_autotype"     "$BIN_DIR/passwort-autotype"
else
    if ! command -v cargo >/dev/null 2>&1; then
        echo "ERROR: 'cargo' is not installed and no pre-built binaries in $PREBUILT_DIR" >&2
        exit 1
    fi
    echo "Building passwortd, passwortctl, passwort_native_host, passwort_autotype..."
    cargo build --release --bin passwortd --bin passwortctl \
                          --bin passwort_native_host --bin passwort_autotype
    install -m 755 "$REPO_DIR/target/release/passwortd"             "$BIN_DIR/passwortd"
    install -m 755 "$REPO_DIR/target/release/passwortctl"           "$BIN_DIR/passwortctl"
    install -m 755 "$REPO_DIR/target/release/passwort_native_host"  "$BIN_DIR/passwort-native-host"
    install -m 755 "$REPO_DIR/target/release/passwort_autotype"     "$BIN_DIR/passwort-autotype"
fi

# XDG autostart entry for passwort-autotype. We use autostart instead of a
# systemd user service because the autotype helper needs the graphical
# session env (DISPLAY etc.), which user systemd services don't get by
# default.
AUTOSTART_DIR="$HOME/.config/autostart"
mkdir -p "$AUTOSTART_DIR"
sed "s|BINARY_PATH|$BIN_DIR/passwort-autotype|g" \
    "$REPO_DIR/packaging/autostart/passwort-autotype.desktop" \
    > "$AUTOSTART_DIR/passwort-autotype.desktop"
chmod 644 "$AUTOSTART_DIR/passwort-autotype.desktop"
echo "Auto-type autostart entry: $AUTOSTART_DIR/passwort-autotype.desktop"

# Firefox manifest
FX_DIR="$HOME/.mozilla/native-messaging-hosts"
mkdir -p "$FX_DIR"
sed "s|BINARY_PATH|$BIN_DIR/passwort-native-host|g" \
    "$REPO_DIR/packaging/native-messaging/passwort_manager.firefox.json" \
    > "$FX_DIR/passwort_manager.json"
chmod 644 "$FX_DIR/passwort_manager.json"
echo "Firefox manifest installed: $FX_DIR/passwort_manager.json"

# Chrome manifest (only if --chrome given)
if [[ $DO_CHROME -eq 1 ]]; then
    if [[ -z "$CHROME_ID" ]]; then
        echo "--chrome requires an extension ID" >&2
        exit 1
    fi
    for CH_DIR in "$HOME/.config/google-chrome/NativeMessagingHosts" \
                  "$HOME/.config/chromium/NativeMessagingHosts" \
                  "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"; do
        if [[ -d "$(dirname "$CH_DIR")" ]]; then
            mkdir -p "$CH_DIR"
            sed -e "s|BINARY_PATH|$BIN_DIR/passwort-native-host|g" \
                -e "s|EXTENSION_ID|$CHROME_ID|g" \
                "$REPO_DIR/packaging/native-messaging/passwort_manager.chrome.json" \
                > "$CH_DIR/passwort_manager.json"
            chmod 644 "$CH_DIR/passwort_manager.json"
            echo "Chrome-family manifest installed: $CH_DIR/passwort_manager.json"
        fi
    done
fi

# Install + enable the systemd user service so the daemon auto-starts at login.
SERVICE_INSTALLED=0
if command -v systemctl >/dev/null 2>&1; then
    SD_DIR="$HOME/.config/systemd/user"
    mkdir -p "$SD_DIR"
    install -m 644 "$REPO_DIR/packaging/systemd/passwortd.service" "$SD_DIR/passwortd.service"

    # Stop any manually-started passwortd so the service can take over the socket.
    pkill -x passwortd 2>/dev/null || true
    sleep 0.4

    if systemctl --user daemon-reload 2>/dev/null \
       && systemctl --user enable --now passwortd.service 2>/dev/null; then
        SERVICE_INSTALLED=1
    fi
fi

echo
echo "Done."
echo "  Daemon binary:    $BIN_DIR/passwortd"
echo "  Native host:      $BIN_DIR/passwort-native-host"
echo "  Auto-type helper: $BIN_DIR/passwort-autotype  (starts on next login)"
if [[ $SERVICE_INSTALLED -eq 1 ]]; then
    echo "  Service:          enabled (passwortd.service, starts at login,"
    echo "                    already running)"
    echo
    echo "You're set. Open Firefox, click the Password Manager toolbar icon,"
    echo "and enter your master password."
    echo
    echo "Auto-type helper: starts automatically next time you log in."
    echo "To start it now without re-logging in:"
    echo "  nohup passwort-autotype >/dev/null 2>&1 &"
    echo
    echo "Default global hotkey is Ctrl+Alt+P. Requires xdotool installed."
else
    echo
    echo "Systemd user service couldn't be enabled. To start the daemon:"
    echo "  passwortd &"
    echo "Then unlock the vault:"
    echo "  passwortctl unlock"
fi
echo
echo "If you haven't already, load the browser extension in extension/."
