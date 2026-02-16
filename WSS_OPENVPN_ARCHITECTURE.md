# OpenVPN over WSS (WebSocket Secure) — Architecture

## Goal

- OpenVPN client connects to **localhost** (127.0.0.1), not directly to the VPN server.
- The app receives **config** and **WSS URL** from your backend.
- Tunnel traffic is carried over **WSS** between the device and the backend; the backend forwards to the real OpenVPN server.

## Why localhost?

- OpenVPN3 uses TCP or UDP to a `remote host port`. It does not speak WebSocket.
- So we need a **local proxy** that:
  - Listens on `127.0.0.1:<port>` (localhost).
  - Accepts the connection from OpenVPN (in the extension).
  - Forwards bytes **over WSS** to the backend (and back).

So the flow is: **OpenVPN → local TCP → WSS bridge → backend → real OpenVPN server**.

## Where it runs on iOS

- **App** and **Network Extension** are different processes. The extension cannot connect to a socket opened by the app.
- So the **TCP server and WSS client must run inside the Network Extension**:
  1. Extension starts.
  2. Extension starts a TCP server on `127.0.0.1:0` (kernel assigns a free port).
  3. Extension opens a WSS connection to the URL provided by the backend.
  4. Extension rewrites the OpenVPN config so that `remote` is `127.0.0.1 <local_port>`.
  5. Extension starts OpenVPN with this config; OpenVPN connects to `127.0.0.1:<local_port>`.
  6. Extension bridges: TCP ↔ WSS (read from TCP → send WSS binary frames; receive WSS → write to TCP).

**Yes, this is possible on iOS** with the extension doing both the WSS client and the local TCP server.

## Data flow

```
[Device]
  App                    Extension
   |                         |
   |  providerConfiguration  |
   |  (config, wssUrl)       |
   |------------------------>|
   |                         | 1) Start TCP server 127.0.0.1:port
   |                         | 2) Connect WSS to backend
   |                         | 3) Rewrite config: remote 127.0.0.1 port
   |                         | 4) Start OpenVPN with modified config
   |                         | 5) OpenVPN connects to 127.0.0.1:port
   |                         | 6) Bridge: TCP <-> WSS
   |                         |
   |                         |<===== WSS (binary frames) =====>| Backend
   |                         |                                 | (forwards to
   |                         |                                 |  OpenVPN server)
```

## Backend contract (you will provide endpoints later)

1. **Config + WSS URL**
   - Either:
     - **REST:** `GET/POST /api/vpn/config` (or similar) returns e.g.:
       ```json
       {
         "config": "<full .ovpn content>",
         "wssUrl": "wss://your-backend.com/vpn/tunnel",
         "protocol": "tcp"
       }
       ```
     - Or the app already has a WSS connection and the backend sends config + wssUrl in a message.

2. **WSS tunnel**
   - URL: e.g. `wss://your-backend.com/vpn/tunnel` (or per-session URL with token).
   - Frames: **binary** only. Each frame = chunk of OpenVPN TCP (or UDP encapsulated) bytes.
   - Backend: receives bytes from client WSS, forwards to real OpenVPN server (TCP); reads from OpenVPN server, sends back to client over WSS.

3. **Optional**
   - Auth: token in WSS URL query or in first message.
   - Ping/pong or heartbeat if your backend requires it.

## App changes (when endpoints are ready)

- Before starting the tunnel:
  - Call your backend (REST or WSS) to get **config** and **wssUrl**.
  - Build `providerConfiguration` with at least:
    - `config` — full .ovpn string (can still contain original `remote`; extension will rewrite to 127.0.0.1).
    - `wssUrl` — WebSocket URL for the tunnel.
  - Optionally: `useWSS` = true so the extension knows to start the bridge.
- Then start the tunnel as now: `startVPNTunnel(options: nil)`.

## Extension changes (to implement)

1. **Read providerConfiguration**
   - Read `config`, `wssUrl`, and optional `useWSS`.

2. **If `useWSS` / `wssUrl` is set**
   - Start a **TCP server** on `127.0.0.1:0`, get the assigned port.
   - Start **WSS client** (e.g. `NSURLSessionWebSocketTask`, iOS 13+) to `wssUrl`.
   - **Rewrite config**: replace or add `remote 127.0.0.1 <local_port>` (and set proto tcp if your WSS carries TCP OpenVPN).
   - **Bridge loop** (two directions):
     - From TCP → WSS: read from accepted socket, send as WSS binary frames.
     - From WSS → TCP: on WSS receive, write to the same socket.
   - Start OpenVPN with the modified config (same as now).

3. **If no WSS**
   - Keep current behaviour: use `config` as-is and connect directly to the server (current flow).

## Technical notes

- **NSURLSessionWebSocketTask**: use for WSS in the extension (no extra deps). For ping/pong or more control, a small wrapper or Starscream (if you add it to the extension target) is an option.
- **TCP server in extension**: use CFSocket or `socket()` + `listen()` + `accept()` on a thread or dispatch queue; pass the accepted fd to the bridge.
- **OpenVPN protocol**: if the backend speaks OpenVPN over TCP, use `proto tcp` in the config and a single TCP stream over WSS. If the backend expects UDP, you would need to encapsulate UDP in WSS (e.g. length-prefixed packets); backend contract must define that.

## Summary

| Question | Answer |
|----------|--------|
| Can OpenVPN connect to localhost on iOS? | Yes — in the extension we start a TCP server on 127.0.0.1 and point the config at it. |
| Can we get config and URL from the backend? | Yes — app gets them (REST or WSS), passes in `providerConfiguration`. |
| Can we use WSS in the extension? | Yes — e.g. `NSURLSessionWebSocketTask` (iOS 13+). |
| Who does the WSS ↔ TCP bridge? | The extension (same process as OpenVPN). |

When you have the endpoints (config API + WSS URL and frame format), the next step is to implement the bridge and config rewrite in the extension and the config/fetch flow in the app.
