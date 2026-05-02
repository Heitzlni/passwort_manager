#!/usr/bin/env bash
# Password Manager — one-shot setup.
# Auto-detects pre-built binaries shipped in `bin/` (release tarball) and
# skips the cargo build entirely. If you cloned the source repo instead,
# offers to install Rust + missing system libs for you.

set -euo pipefail

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$REPO_DIR"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
err()  { printf '\033[31m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }

# Ask user yes/no, default Yes. In non-interactive shells, default Yes.
ask_yes() {
    local prompt="$1"
    if [[ ! -t 0 ]]; then return 0; fi
    read -r -p "$prompt [Y/n] " ans
    [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]
}

bold "Password Manager — setup"
echo

# 1. Decide whether we'll build or use pre-built binaries
PREBUILT="no"
if [[ -x "$REPO_DIR/bin/passwortd" ]]; then
    PREBUILT="yes"
    ok "Found pre-built binaries in bin/ — skipping cargo build."
fi

# 2. Rust toolchain (only needed if we don't have pre-built)
if [[ "$PREBUILT" == "no" ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
        err "Rust toolchain (cargo) not found."
        echo
        echo "rustup is the official installer. Running it will install Rust into"
        echo "  ~/.cargo  and  ~/.rustup  (no sudo needed)."
        if ask_yes "Install Rust now via rustup?"; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            # Bring cargo onto PATH for this shell
            # shellcheck source=/dev/null
            source "$HOME/.cargo/env"
            ok "rustup installed."
        else
            echo "Aborted. Install Rust yourself, then re-run ./setup.sh."
            exit 1
        fi
    fi
    ok "cargo present ($(cargo --version | awk '{print $2}'))"
fi

# 3. System libraries (Debian/Ubuntu detection only — other distros: skip)
if command -v dpkg >/dev/null 2>&1; then
    MISSING=()
    for pkg in libxcb1 libxcb-render0 libxcb-shape0 libxcb-xfixes0 \
               libxkbcommon0 libgl1 libfontconfig1; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            MISSING+=("$pkg")
        fi
    done
    if [[ "${#MISSING[@]}" -gt 0 ]]; then
        warn "Missing system libraries (needed for the GUI / clipboard):"
        echo "  ${MISSING[*]}"
        echo
        if command -v apt-get >/dev/null 2>&1 && ask_yes "Install them now with sudo apt install?"; then
            sudo apt-get update
            sudo apt-get install -y "${MISSING[@]}"
            ok "system libraries installed"
        else
            warn "Skipping. Install them manually before launching the GUI:"
            echo "  sudo apt install ${MISSING[*]}"
        fi
    else
        ok "system libraries present"
    fi
fi

# 4. Build (only if we didn't ship pre-built)
if [[ "$PREBUILT" == "no" ]]; then
    bold "Building (a couple minutes the first time, seconds after)..."
    cargo build --release --bin passwort_manager \
                           --bin passwortd \
                           --bin passwortctl \
                           --bin passwort_native_host
    ok "build complete"
fi
echo

# 5. Install GUI app
bold "Installing GUI app..."
"$REPO_DIR/packaging/install.sh" >/dev/null
ok "GUI installed"

# 6. Install daemon + CLI + native host + Firefox manifest + systemd service
bold "Installing daemon, native bridge, and systemd service..."
"$REPO_DIR/packaging/install-native-host.sh" >/dev/null
ok "daemon + bridge installed"
echo

# 7. Verify systemd service
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
echo "     master password (≥ 8 characters). Or run:"
echo "       passwort-manager"
echo
echo "  2. Load the Firefox extension:"
echo "     - Visit  about:debugging#/runtime/this-firefox"
echo "     - Click  'Load Temporary Add-on…'"
echo "     - Select:"
echo "         $REPO_DIR/extension/manifest.json"
echo
echo "     (Firefox unloads unsigned extensions on restart. To install"
echo "      permanently, see SETUP.md → 'Permanent extension install'.)"
echo
ok "All set."
