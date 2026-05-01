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

echo "Building passwortd, passwortctl, passwort_native_host..."
cargo build --release --bin passwortd --bin passwortctl --bin passwort_native_host

BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
install -m 755 "$REPO_DIR/target/release/passwortd"             "$BIN_DIR/passwortd"
install -m 755 "$REPO_DIR/target/release/passwortctl"           "$BIN_DIR/passwortctl"
install -m 755 "$REPO_DIR/target/release/passwort_native_host"  "$BIN_DIR/passwort-native-host"

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

echo
echo "Done."
echo "  Daemon binary: $BIN_DIR/passwortd"
echo "  Native host:   $BIN_DIR/passwort-native-host"
echo
echo "Start the daemon (once per boot/session):"
echo "  passwortd &"
echo "Then unlock the vault:"
echo "  passwortctl unlock"
echo
echo "Now load the browser extension in extension/ to talk to it."
