# DataGateIOS

iOS app for secure VPN connections via OpenVPN.

## Features

- OpenVPN VPN connections
- Google Sign-In
- Server status and connection statistics
- Dark/Light theme

## Requirements

- iOS 17.0+
- Xcode 15+
- Swift 5.9+
- CMake (for building mbedTLS)

## Setup

### 1. Clone and open project

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

### 3. mbedTLS libraries (VPN extension)

The VPN extension uses mbedTLS; prebuilt libs are not in the repo. Build and install them once:

```bash
./update_mbedtls.sh
```

The script will:

- Clone mbedTLS 3.6.5
- Build `libmbedtls.a`, `libmbedx509.a`, `libmbedcrypto.a` for iOS (arm64)
- Copy them to `DataGateVPNExtension/libs/`
- Update headers in `DataGateVPNExtension/mbedtls-include/`

You need **CMake** installed (e.g. `brew install cmake`).

`DataGateVPNExtension/libs/` is in `.gitignore`; each developer runs the script locally.

### 4. Build in Xcode

Open `DataGateIOS.xcodeproj`, choose the DataGateIOS scheme and a device/simulator, then build (⌘B).

## Project layout

- **DataGateIOS/** — main app (Swift, SwiftUI)
- **DataGateVPNExtension/** — Network Extension (OpenVPN, mbedtls)
- **native-openvpn3/** — OpenVPN3 core (submodule or vendored)

## License

See repository license file.
