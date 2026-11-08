#!/usr/bin/env bash
# Build libXray as an iOS (arm64 device) c-archive for the packet tunnel extension.
# Output: build-libxray/libXray.a and build-libxray/libXray.h
# Same libXray revision and flags as DataGateMac/scripts/build-libxray.sh, but for GOOS=ios.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIBXRAY="$ROOT/libXray"
OUT="$ROOT/build-libxray"
GO_ROOT="${DATAGATE_GO_ROOT:-$ROOT/.tools/go}"

if [[ ! -d "$LIBXRAY/cgo_bridge" ]]; then
  echo "libXray submodule missing. Run: git submodule update --init libXray" >&2
  exit 1
fi
if [[ ! -x "$GO_ROOT/bin/go" ]]; then
  echo "Go toolchain not found at $GO_ROOT (need 1.27.3+ for libXray). Install with: scripts/bootstrap-go.sh" >&2
  exit 1
fi

export PATH="$GO_ROOT/bin:$PATH"
echo "Using $(go version)"

SDK_PATH="$(xcrun --sdk iphoneos --show-sdk-path)"
FLAGS="-isysroot ${SDK_PATH} -miphoneos-version-min=17.0 -arch arm64"

mkdir -p "$OUT"
rm -f "$OUT/libXray.a" "$OUT/libXray.h"

export GOOS=ios
export GOARCH=arm64
export CC="$(xcrun --sdk iphoneos --find clang)"
export CXX="$(xcrun --sdk iphoneos --find clang++)"
export CGO_ENABLED=1
export CGO_CFLAGS="$FLAGS"
export CGO_CXXFLAGS="$FLAGS"
export CGO_LDFLAGS="${FLAGS}"

echo "Building libXray c-archive (${GOOS}/${GOARCH})..."
(
  cd "$LIBXRAY"
  go build \
    -trimpath \
    -buildvcs=false \
    -ldflags "-s -w -buildid=" \
    -o "$OUT/libXray.a" \
    -buildmode=c-archive \
    ./cgo_bridge
)

if [[ ! -f "$OUT/libXray.a" || ! -f "$OUT/libXray.h" ]]; then
  echo "libXray build did not produce libXray.a / libXray.h in $OUT" >&2
  exit 1
fi
ls -lh "$OUT/libXray.a" "$OUT/libXray.h"
