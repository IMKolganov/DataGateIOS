#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
swiftc "$ROOT/DataGateIOS/OpenVpnModels.swift" "$ROOT/DataGateIOS/XrayClientProfile.swift" \
  "$ROOT/tests/VpnConfigChecks.swift" -o "$WORKDIR/vpn-config-checks"
"$WORKDIR/vpn-config-checks"
