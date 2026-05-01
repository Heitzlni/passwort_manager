#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"

rm -f "$BIN_DIR/passwort-manager"
rm -f "$APP_DIR/passwort-manager.desktop"
rm -f "$ICON_DIR/passwort-manager.svg"

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
