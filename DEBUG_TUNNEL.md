# Debugging iOS VPN tunnel (NEPacketTunnelProvider)

Issue: VPN connects, packets flow packetFlow ↔ OpenVPN3, but no internet (connectivity check times out).

## What is already in the code

### 1. `[TUNNEL DEBUG]` logs in Extension

After connecting, check **Extension Logs** in the app (or in Xcode console for the extension process):

- **FROM_DEVICE** — first 5 packets **from device into tunnel** (what iOS feeds into packetFlow).
  - Expected: `10.50.29.2 -> 8.8.8.8 proto=17` (DNS), `10.50.29.2 -> <site IP> proto=6` (TCP), etc.
  - If you only see `10.50.29.2 -> 10.50.29.1` — traffic may be going to the gateway (ARP/some service) instead of the internet.
  - If **no FROM_DEVICE entries** or very few — iOS is **not routing** app traffic into the tunnel (routing/settings issue).

- **TO_DEVICE** — first 5 packets **from tunnel to device** (responses we write to packetFlow).
  - Expected: `8.8.8.8 -> 10.50.29.2 proto=17`, TCP responses, etc.
  - If there is FROM_DEVICE but no TO_DEVICE — requests go into the tunnel but responses do not come back or are not written.

- **includedRoutes** — when settings are applied, the route list is logged.
  - There should be a default route, e.g. `0.0.0.0/255.255.255.255` or similar (one default entry).
  - If there is no default — internet traffic will not go through the tunnel.

- **excludedRoutes** — if present, logged as WARNING.
  - If 0.0.0.0/0 or a wide range is in excluded — some traffic may bypass the tunnel or be lost.

## Step-by-step debugging

1. **Connect VPN**, wait for "Connected", open **Extension Logs** in the app.
2. **Find the block** with the newly applied settings:
   - `🔧 Updating network settings from OpenVPN3: tunnelRemote=..., IPv4=..., DNS=..., matchDomains=...`
   - Right below it: `[TUNNEL DEBUG] includedRoutes(N): ...` — verify there is a default (0.0.0.0/...).
3. **Find lines** `[TUNNEL DEBUG] FROM_DEVICE`:
   - Are there any packets?
   - Where do they go: 10.50.29.1, 8.8.8.8, external IPs? proto=6 (TCP) / 17 (UDP)?
4. **Find lines** `[TUNNEL DEBUG] TO_DEVICE`:
   - Are there responses? Do src/dst pairs match FROM_DEVICE (in reverse)?
5. **Trigger some internet activity** (open a site in Safari, refresh an app that uses network) and check logs again — do new FROM_DEVICE/TO_DEVICE entries appear?

## Interpretation

| Situation | Conclusion |
|-----------|------------|
| No FROM_DEVICE or only to 10.50.29.1 | iOS is not routing app traffic into the tunnel. Check includedRoutes (must have default), matchDomains, that setTunnelNetworkSettings is called once and startCompletionHandler is called after it. |
| FROM_DEVICE to 8.8.8.8 and external IPs, no TO_DEVICE | Requests go into the tunnel and OpenVPN3, but responses do not return or are not written to packetFlow. Check server side (NAT/firewall) and packetFlow write code. |
| FROM_DEVICE and TO_DEVICE present, pairs symmetric | Packets flow both ways. Then the issue may be that the app (Safari/other) is not using this tunnel (e.g. different interface), or timing/call order. |
| includedRoutes without default | Add default route in OpenVPNAdapter when building settings. |

## Additional notes

- **Xcode console**: running the app from Xcode and selecting the **DataGateVPNExtension** process in the console shows all NSLog/printf from the extension in real time.
- **Apple TN3120 / TN3134**: technical notes on Network Extension and packet tunnel — call order, when to call startCompletionHandler, how to set routes and DNS.
