#!/usr/bin/env bash
# Download a local Go toolchain for libXray (does not replace /usr/local/go).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO_VERSION="${DATAGATE_GO_VERSION:-1.26.3}"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64) GO_ARCH=arm64 ;;
  x86_64) GO_ARCH=amd64 ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

TARBALL="go${GO_VERSION}.darwin-${GO_ARCH}.tar.gz"
URL="https://go.dev/dl/${TARBALL}"
TOOLS="$ROOT/.tools"
mkdir -p "$TOOLS"

if [[ -x "$TOOLS/go/bin/go" ]]; then
  CURRENT="$("$TOOLS/go/bin/go" env GOVERSION 2>/dev/null || true)"
  if [[ "$CURRENT" == "go${GO_VERSION}" ]]; then
    echo "Go ${GO_VERSION} already at $TOOLS/go"
    "$TOOLS/go/bin/go" version
    exit 0
  fi
fi

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

echo "Downloading ${URL}..."
curl -fsSL "$URL" -o "$TMP/$TARBALL"
rm -rf "$TOOLS/go"
tar -C "$TOOLS" -xzf "$TMP/$TARBALL"
echo "Installed $($TOOLS/go/bin/go version) at $TOOLS/go"
