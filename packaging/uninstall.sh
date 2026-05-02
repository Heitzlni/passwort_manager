#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
SD_DIR="$HOME/.config/systemd/user"

# Stop and disable the systemd user service if installed
if command -v systemctl >/dev/null 2>&1 && [[ -f "$SD_DIR/passwortd.service" ]]; then
    systemctl --user disable --now passwortd.service 2>/dev/null || true
    rm -f "$SD_DIR/passwortd.service"
    systemctl --user daemon-reload 2>/dev/null || true
fi

rm -f "$BIN_DIR/passwort-manager"
rm -f "$BIN_DIR/passwortd"
rm -f "$BIN_DIR/passwortctl"
rm -f "$BIN_DIR/passwort-native-host"
rm -f "$APP_DIR/passwort-manager.desktop"
rm -f "$ICON_DIR/passwort-manager.svg"
rm -f "$HOME/.mozilla/native-messaging-hosts/passwort_manager.json"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi

echo "Uninstalled."
echo
echo "Your encrypted vault at \$XDG_DATA_HOME/passwort-manager/ was NOT removed."
echo "To delete it as well, run:"
echo "  rm -rf \"\${XDG_DATA_HOME:-\$HOME/.local/share}/passwort-manager\""
