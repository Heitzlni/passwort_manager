#!/usr/bin/env bash
# package-release.sh — build a self-contained release tarball.
#
# Output: passwort-manager-<version>-linux-<arch>.tar.gz at the repo root.
# The tarball ships pre-built (and stripped) binaries in `bin/`, so a user
# who downloads it can run `./setup.sh` without needing Rust at all.

set -euo pipefail

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$REPO_DIR"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }

VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
ARCH="$(uname -m)"
NAME="passwort-manager-${VERSION}-linux-${ARCH}"

bold "Building release binaries (clean release build)..."
cargo build --release --bin passwort_manager \
                       --bin passwortd \
                       --bin passwortctl \
                       --bin passwort_native_host \
                       --bin passwort_autotype

bold "Staging tarball at /tmp/${NAME}/"
STAGE="/tmp/${NAME}"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin"

# Pre-built binaries (stripped to shrink download size)
for b in passwort_manager passwortd passwortctl passwort_native_host passwort_autotype; do
    cp "target/release/$b" "$STAGE/bin/$b"
    strip "$STAGE/bin/$b" 2>/dev/null || true
done

# Everything the installer / extension / docs need.
# Source is included too — small, useful for inspection / rebuild.
cp -r src packaging extension Cargo.toml Cargo.lock "$STAGE/"
cp setup.sh SETUP.md .gitignore "$STAGE/"
printf '%s\n' "$VERSION" > "$STAGE/VERSION"

OUT="$REPO_DIR/${NAME}.tar.gz"
rm -f "$OUT"
( cd /tmp && tar czf "$OUT" "$NAME" )
rm -rf "$STAGE"

SIZE="$(du -h "$OUT" | cut -f1)"
echo
ok "Created: ${NAME}.tar.gz (${SIZE})"
echo
echo "Distribute this single file. Recipients run:"
echo "  tar xzf ${NAME}.tar.gz && cd ${NAME} && ./setup.sh"
echo
echo "No Rust toolchain required on their end — bin/ ships pre-built."
echo "They still need a one-time apt install of:"
echo "  libxcb1 libxcb-render0 libxcb-shape0 libxcb-xfixes0"
echo "  libxkbcommon0 libgl1 libfontconfig1"
echo "(setup.sh detects this and offers to do it automatically.)"
