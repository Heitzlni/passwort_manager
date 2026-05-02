#!/usr/bin/env bash
# Password Manager — one-shot setup.
# Builds, installs everything, enables the systemd user service that
# auto-starts the daemon at every login. Tells you the 1-2 GUI-only steps
# that genuinely can't be scripted.

set -euo pipefail

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$REPO_DIR"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
err()  { printf '\033[31m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }

bold "Password Manager — setup"
echo

# 1. Rust toolchain
if ! command -v cargo >/dev/null 2>&1; then
    err "cargo (Rust) not found."
    echo
    echo "Install Rust first, then re-run this script:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "or on Debian/Ubuntu:"
    echo "  sudo apt install -y cargo"
    exit 1
fi
ok "cargo present ($(cargo --version | awk '{print $2}'))"

# 2. System libraries (Debian/Ubuntu detection only — other distros: skip)
if command -v dpkg >/dev/null 2>&1; then
    MISSING=()
    for pkg in libxcb1 libxcb-render0 libxcb-shape0 libxcb-xfixes0 \
               libxkbcommon0 libgl1 libfontconfig1; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            MISSING+=("$pkg")
        fi
    done
    if [[ "${#MISSING[@]}" -gt 0 ]]; then
        warn "Missing system libraries the GUI / clipboard need:"
        echo "  ${MISSING[*]}"
        echo
        echo "Install with:"
        echo "  sudo apt install -y ${MISSING[*]}"
        echo
        if [[ -t 0 ]]; then
            read -r -p "Continue anyway? [y/N] " ans
            [[ "$ans" =~ ^[Yy]$ ]] || exit 1
        fi
    else
        ok "system libraries present"
    fi
fi

# 3. Build everything in release mode
bold "Building (a couple minutes the first time, seconds after)..."
cargo build --release --bin passwort_manager \
                       --bin passwortd \
                       --bin passwortctl \
                       --bin passwort_native_host
ok "build complete"
echo

# 4. Install GUI (binary, icon, .desktop)
bold "Installing GUI app..."
"$REPO_DIR/packaging/install.sh" >/dev/null
ok "GUI installed"

# 5. Install daemon + CLI + native host + Firefox manifest + systemd service
bold "Installing daemon, native bridge, and systemd service..."
"$REPO_DIR/packaging/install-native-host.sh" >/dev/null
ok "daemon + bridge installed"
echo

# 6. Verify the systemd service is up
if command -v systemctl >/dev/null 2>&1 && \
   systemctl --user is-active passwortd.service >/dev/null 2>&1; then
    ok "passwortd is running (and will auto-start at every login)"
else
    warn "passwortd is not running. Try:  systemctl --user start passwortd"
fi
echo

bold "Two manual steps left"
echo
echo "  1. Create your vault (one time only):"
echo "     Open 'Password Manager' from your app launcher and choose a"
echo "     master password (≥ 8 characters). You can also run:"
echo "       passwort-manager"
echo
echo "  2. Load the Firefox extension:"
echo "     - Visit about:debugging#/runtime/this-firefox"
echo "     - Click 'Load Temporary Add-on…'"
echo "     - Select:"
echo "         $REPO_DIR/extension/manifest.json"
echo
echo "     (Firefox unloads unsigned extensions on restart. To install"
echo "      permanently, see SETUP.md → 'Permanent extension install'.)"
echo
ok "All set."
