<p align="center">
  <img src="assets/logo.png" width="120" alt="DataGate" />
</p>

<h1 align="center">DataGate</h1>
<p align="center"><strong>iOS VPN client — OpenVPN over WebSocket Secure (WSS)</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-iOS%2017%2B-blue?logo=apple" alt="iOS 17+" />
  <img src="https://img.shields.io/badge/Swift-5.9-orange?logo=swift" alt="Swift 5.9" />
  <img src="https://img.shields.io/badge/OpenVPN-WSS-green" alt="OpenVPN over WSS" />
</p>

---

## What is this?

**DataGate** is a native iOS app that connects to your VPN backend and establishes an **OpenVPN** tunnel. Traffic is carried over **WebSocket Secure (WSS)** from the device to your server, which then forwards it to the real OpenVPN server. That lets you run OpenVPN behind HTTPS/WSS (e.g. nginx) and avoid direct UDP/TCP to the VPN port.

- **App** gets config and WSS URL from your API, manages auth (e.g. Google Sign-In) and UI.
- **Network Extension** runs the OpenVPN core and a local TCP↔WSS bridge inside the system tunnel process.

Details: [OpenVPN over WSS — Architecture](WSS_OPENVPN_ARCHITECTURE.md).

## Features

| Feature | Description |
|--------|-------------|
| **OpenVPN over WSS** | Tunnel traffic over WebSocket Secure; no direct VPN port exposure. |
| **Google Sign-In** | Optional OAuth login; token used for API and VPN config. |
| **Server list (Access)** | View VPN servers and status from your backend. |
| **Statistics** | Overview series and traffic stats from your API. |
| **Themes** | Light and dark appearance. |

## Requirements

- **iOS 17.0+**
- **Xcode 15+**
- **Swift 5.9+**
- **CMake** (for building mbedTLS), e.g. `brew install cmake`

## Setup

### 1. Clone and open

```bash
git clone <repo-url>
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

### 4. Build in Xcode

Open `DataGateIOS.xcodeproj`, select the **DataGateIOS** scheme and a device or simulator, then build (⌘B).

## Project layout

| Path | Description |
|------|-------------|
| **DataGateIOS/** | Main app (Swift, SwiftUI). |
| **DataGateVPNExtension/** | Network Extension: OpenVPN, WSS bridge, mbedTLS. |
| **native-openvpn3/** | OpenVPN3 core (submodule or vendored). |
| **assets/** | Logo and images for the repo (e.g. README). |

## License

See the repository license file.
