#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$REPO_DIR"

BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"

echo "Building release binary (this can take a minute)..."
cargo build --release

mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR"

install -m 755 "$REPO_DIR/target/release/passwort_manager" "$BIN_DIR/passwort-manager"
install -m 644 "$REPO_DIR/packaging/passwort-manager.svg" "$ICON_DIR/passwort-manager.svg"

sed "s|BINARY_PATH|$BIN_DIR/passwort-manager|g" \
    "$REPO_DIR/packaging/passwort-manager.desktop" \
    > "$APP_DIR/passwort-manager.desktop"
chmod 644 "$APP_DIR/passwort-manager.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi

echo
echo "Installed."
echo "  Binary : $BIN_DIR/passwort-manager"
echo "  Icon   : $ICON_DIR/passwort-manager.svg"
echo "  Entry  : $APP_DIR/passwort-manager.desktop"
echo "  Vault  : \$XDG_DATA_HOME/passwort-manager/vault.json (default: ~/.local/share/passwort-manager/vault.json)"
echo
echo "Open it from your application launcher (search for \"Password Manager\")."
echo "If \"passwort-manager\" isn't found in your shell, ensure ~/.local/bin is on PATH."
