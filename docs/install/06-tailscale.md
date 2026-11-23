# Optional native Tailscale access

Part of [Installation](../INSTALL.md).

## 12. Optional native Tailscale access

WAF-Proxy can add private tailnet listeners without changing the LAN/WAN deployment. The
feature is off by default and only becomes available when the host has a native Tailscale
interface (`tailscale0`) with a `100.64.0.0/10` IPv4 address.

### 12.1 Install and connect Tailscale

Use Tailscale's official package instructions for your distribution, then authenticate the
host:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4
```

`install.sh` detects an existing Tailscale interface after installing WAF-Proxy and prints its
address, but it intentionally does **not** install Tailscale, run `tailscale up`, or handle an
auth key. This avoids piping a remote installer into a root shell and keeps an unattended
`--yes` install from blocking on browser authentication. Start `tailscaled` before `wafproxy`
(the systemd unit is ordered after `tailscaled.service` when both exist).

### 12.2 Enable the listeners

Complete the normal LAN wizard and sign in. Open **Tailscale** in the console:

- **Admin console over Tailscale** adds the existing HTTP console on
  `http://<tailnet-ip>:<gui-port>`. It accepts only `100.64.0.0/10` sources and does not change
  the LAN listener or its RFC1918 rule. The link is inside WireGuard and is not exposed on the
  WAN.
- **Proxy app traffic over Tailscale** adds the normal TLS/SNI proxy on
  `<tailnet-ip>:<wan-port>`. Remote devices continue to use the app's normal hostname and
  certificate; the WAF still runs its full policy and forwards to the LAN upstream.
- **Answer split DNS on the tailnet** starts a small authoritative responder on
  `<tailnet-ip>:53` (UDP and TCP). It answers A queries only for hostnames that already exist
  as proxies, with the WAF's tailnet address. It is not a recursive resolver.

Click **Save Tailscale settings**, then **Restart service**. Both listeners use the ports from
**Settings → Network** (`gui_port` and `wan_port`). They cannot share a port on the same
tailnet address; the page rejects that combination.

The LAN/WAN bindings must use concrete interface addresses, not a wildcard such as `:8080` or
`:8443`. A wildcard listener already owns the port, so the tailnet listener cannot be added. Set
`WAFPROXY_LISTEN_GUI` and `WAFPROXY_LISTEN_WAN` to the host's actual LAN/WAN addresses — the
native installer and the shipped compose defaults do this — before enabling these switches. The
Tailscale page reports the bind problem.

### 12.3 Tailscale ACL

Tailscale access rules are default-deny when a policy is configured. Add a grant (replace
`wafproxy` with the host's MagicDNS name, or use its `100.x` address) and keep the source group
narrow:

```json
{
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["wafproxy"],
      "ip": ["tcp:443", "tcp:8443", "udp:53", "tcp:53"]
    }
  ]
}
```

Remove the DNS ports if you turn the responder off. If your tailnet uses tags instead of user
devices, use the appropriate tag or group in `src`; do not open the ports to the public
internet. The admin console still requires its password and authenticator after the ACL
allows the connection.

### 12.4 Split DNS and verification

Tailscale split DNS (a restricted nameserver) forwards queries for a domain to a DNS server;
it cannot store a direct A-record override. In the Tailscale admin console:

1. **DNS → Nameservers → Add nameserver → Custom**.
2. Enter the WAF's tailnet IPv4 address (the value shown on the Tailscale page).
3. Enable **Restrict to search domain** and enter the WAF base domain, for example
   `example.duckdns.org`.
4. Make sure the client uses Tailscale DNS (normally **Use Tailscale DNS** / **Override local
   DNS**).

Then verify from a tailnet device:

```bash
dig +short app.example.duckdns.org @100.x.y.z
# 100.x.y.z
curl -v https://app.example.duckdns.org/
```

The reply must be the WAF's tailnet address. The app's public DNS can continue to point at the
WAN for non-Tailscale clients. The certificate is still issued through the normal DNS-01
provider; Tailscale is only the private path to the WAF.

### 12.5 Failure and security notes

- If `tailscale0` disappears or has no IPv4 address at boot, WAF-Proxy logs a warning and keeps
  the LAN/WAN listeners running. A configured tailnet listener is not started; the Tailscale
  page shows the error. Restore Tailscale and restart.
- A failed extra bind (for example port 53 already used by a host DNS server) is reported on the
  page but does not take down the WAN listener. Turn off the embedded DNS responder and point
  split DNS at an existing resolver if necessary.
- Tailscale clients appear in **Logs** and bans as their `100.x` address, not their LAN address.
- The admin tailnet listener is HTTP inside WireGuard. It does not use Tailscale identity
  headers and is not a replacement for password + TOTP.
- No Tailscale Funnel, public exposure, subnet routing, or exit-node behavior is added. The
  feature does not install Tailscale or edit the tailnet policy.
