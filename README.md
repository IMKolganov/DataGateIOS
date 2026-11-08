<p align="center">
  <img src="assets/logo.png" width="120" alt="DataGate" />
</p>

<h1 align="center">DataGate</h1>
<p align="center"><strong>iOS VPN client — OpenVPN TCP over WSS and Xray/VLESS</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-iOS%2017%2B-blue?logo=apple" alt="iOS 17+" />
  <img src="https://img.shields.io/badge/Swift-6.2-orange?logo=swift" alt="Swift 6.2" />
  <img src="https://img.shields.io/badge/OpenVPN-WSS-green" alt="OpenVPN over WSS" />
</p>

---

## What is this?

**DataGate** is a native iOS app that connects to your VPN backend and establishes an **OpenVPN TCP-over-WSS** or **Xray/VLESS** tunnel. The app selects an online server supported by iOS and allowed by the user's quota plan from the v3 server list, then issues and downloads the matching device profile.

- **App** gets config and WSS URL from your API, manages auth (e.g. Google Sign-In) and UI.
- **Network Extension** runs either the OpenVPN core with a local TCP↔WSS bridge or libXray with the supplied VLESS share link.

Details: [OpenVPN over WSS — Architecture](WSS_OPENVPN_ARCHITECTURE.md).

## Features

| Feature | Description |
|--------|-------------|
| **OpenVPN TCP over WSS** | Tunnel traffic over WebSocket Secure; no direct VPN port exposure. UDP-over-WSS is not supported on iOS. |
| **Xray/VLESS** | Download a client link from the backend and run it through libXray in the packet tunnel. |
| **Google Sign-In** | Optional OAuth login; token used for API and VPN config. |
| **Server list (Access)** | View VPN servers and status from your backend. |
| **Statistics** | Overview series and traffic stats from your API. |
| **Themes** | Light and dark appearance. |

## Requirements

- **iOS 17.0+**
- **Xcode 26+**
- **Swift 6.2+**
- **CMake** (for building mbedTLS), e.g. `brew install cmake`

## Setup

### 1. Clone and open

```bash
git clone --recurse-submodules <repo-url>
cd DataGateIOS
```

### 2. API and auth config

Copy the example config and set your values:

```bash
cp DataGateIOS/Config.example.plist DataGateIOS/Config.plist
```

Edit `DataGateIOS/Config.plist`:

- **APIBaseURL** — base URL of your API (required)
- **GIDClientID** — Google Sign-In client ID (optional; leave empty if not using Google Sign-In)

`Config.plist` is in `.gitignore` and is not committed.

### 3. mbedTLS (VPN extension)

The VPN extension uses mbedTLS. Build and install once:

```bash
./update_mbedtls.sh
```

The script will:

- Clone mbedTLS 3.6.5
- Build `libmbedtls.a`, `libmbedx509.a`, `libmbedcrypto.a` for iOS (arm64)
- Copy them to `DataGateVPNExtension/libs/`
- Update headers in `DataGateVPNExtension/mbedtls-include/`

`DataGateVPNExtension/libs/` is in `.gitignore`; each developer runs the script locally.

### 4. Build libXray and check VPN configuration

```bash
scripts/bootstrap-go.sh
scripts/build-libxray-ios.sh
bash scripts/test-vpn-config.sh
```

The native libraries are built for an arm64 iOS device.

### 5. Generate and build in Xcode

```bash
brew install xcodegen asio fmt cmake
xcodegen generate
pod install
open DataGateIOS.xcworkspace
```

Select the **DataGateIOS** scheme and a device, then build (⌘B).

## Project layout

| Path | Description |
|------|-------------|
| **DataGateIOS/** | Main app (Swift, SwiftUI). |
| **DataGateVPNExtension/** | Network Extension: OpenVPN, WSS bridge, mbedTLS. |
| **native-openvpn3/** | OpenVPN3 core (submodule or vendored). |
| **assets/** | Logo and images for the repo (e.g. README). |

## License

See the repository license file.
