#!/bin/bash
#
# sepw installer — fetch source, compile, install. Works via:
#   curl -fsSL https://raw.githubusercontent.com/PinLin/sepw/main/install.sh | bash
#
# A Secure Enclave binary must be compiled and signed locally (Apple Silicon's
# linker ad-hoc signs automatically), so we build from source rather than ship a
# binary. Installs to /usr/local/bin by default (uses sudo if needed); override
# with PREFIX, e.g.  PREFIX="$HOME/.local" sh -c "$(curl -fsSL .../install.sh)"
#
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/PinLin/sepw/main"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"

if [[ "$(uname)" != "Darwin" ]]; then
  echo "Error: sepw only runs on macOS." >&2; exit 1
fi
if ! command -v swiftc >/dev/null 2>&1; then
  echo "==> Xcode command line tools not found — installing them..."
  xcode-select --install 2>/dev/null || true
  echo "    Complete the dialog that just opened; this will continue once it finishes."
  until command -v swiftc >/dev/null 2>&1; do sleep 5; done
  echo "    Command line tools ready."
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Downloading source..."
if [[ -f "$(dirname "$0")/sepw.swift" ]]; then
  cp "$(dirname "$0")/sepw.swift" "$TMP/sepw.swift"      # local clone
else
  curl -fsSL "$REPO_RAW/sepw.swift" -o "$TMP/sepw.swift" # remote
fi

echo "==> Compiling..."
swiftc -O "$TMP/sepw.swift" -o "$TMP/sepw" \
  -framework Security -framework LocalAuthentication

echo "==> Installing to $BINDIR ..."
if mkdir -p "$BINDIR" 2>/dev/null && [[ -w "$BINDIR" ]]; then
  install -m 0755 "$TMP/sepw" "$BINDIR/sepw"
else
  echo "    (needs elevated permission, using sudo)"
  sudo install -d -m 0755 "$BINDIR"
  sudo install -m 0755 "$TMP/sepw" "$BINDIR/sepw"
fi

echo
echo "Installed: $BINDIR/sepw"
if ! command -v sepw >/dev/null 2>&1; then
  echo "Note: $BINDIR is not on your PATH. Add it, or rerun with PREFIX=\"\$HOME/.local\"."
fi
echo
echo "Next:"
echo "  sepw add <name>   # add an entry (key is created on first use)"
echo "  sepw get <name>   # read it back (requires Touch ID or login password)"
