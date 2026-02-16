# No internet when VPN is connected — diagnostics

## What the logs show

- **Packets are flowing:** logs show two-way exchange (packetFlow ↔ OpenVPN3). Traffic goes into the tunnel and comes back.
- **Tunnel settings look correct:** gateway=10.50.29.1, IP=10.50.29.2, DNS=8.8.8.8, matchDomains=(nil=all). One default route, no duplicates.

**Conclusion:** the problem is most likely **not DNS or the gateway on the device**. From iOS and the extension’s perspective the tunnel is set up correctly and traffic enters it.

## Most likely cause: VPN server

Often “no internet” with a working tunnel is because the **OpenVPN server is not doing NAT/forwarding of traffic to the internet**.

On the server (e.g. 185.70.197.119):

1. **Enable IP forwarding:**
   ```bash
   sysctl -w net.ipv4.ip_forward=1
   ```
   (and make it persistent in config, e.g. in `/etc/sysctl.conf`.)

2. **Configure NAT/masquerade** from the tunnel interface (e.g. `tun0`) to the external interface:
   ```bash
   iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
   # or specify the tunnel subnet:
   iptables -t nat -A POSTROUTING -s 10.50.29.0/24 -o eth0 -j MASQUERADE
   ```

Without this, packets reach the server but do not go out to the internet and responses do not return to the client.

## How to check: DNS vs routing

1. **Check by IP (bypass DNS):**  
   With VPN on, open in the browser by IP, e.g.:
   - `http://142.250.185.46` (one of Google’s IPs)
   - or `http://1.1.1.1`

   - If pages **open by IP** — the issue is DNS (resolution not going through / not via tunnel).
   - If **by IP it also does not open** — the issue is routing/NAT on the server (traffic not leaving to the internet).

2. **Check from another client:**  
   Connect to the same OpenVPN server from a PC (OpenVPN GUI, Tunnelblick, etc.). If the PC has internet and iOS does not — then dig further on the iOS/extension side.

## Summary

| Symptom | Likely cause |
|---------|--------------|
| Packets in logs, pages do not open | Server not doing NAT/forward to internet |
| Opens by IP, not by name | DNS issue |
| Does not open by IP either | Routing/NAT on server |

After configuring NAT and `ip_forward` on the server, reconnect VPN and test again.
