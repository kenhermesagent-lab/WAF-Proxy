# Optional Cloudflare Tunnel and Access

Part of [Installation](../INSTALL.md).

## 13. Optional Cloudflare Tunnel and Access

WAF-Proxy can publish the admin console through Cloudflare Tunnel, so there is no
port forward, no public IP and no certificate to manage on the console listener.
The feature is off by default; the **Cloudflare** page explains each step in
place and only enable the connector when you are ready.

Two paths can exist at once: the tunnel, and a port forward you already have.
The page does not require you to remove the forward, but tells you when the
hostname still answers from this host directly, because that path bypasses
Access.

### 13.1 Install the connector

On a native install, open **Cloudflare → 1 · Install the connector** and press
**Install connector**. The console asks the root helper to add Cloudflare's
package repository and install `cloudflared`; the package's own systemd unit is
disabled because the console starts and stops the process as the token and the
Enable switch change.

Without the helper, the page shows the same commands to run by hand:

```bash
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install -y cloudflared
sudo systemctl disable --now cloudflared
```

In Docker the console cannot install host packages. Install `cloudflared` on the
host and run it there with the tunnel token; the tunnel does not need to be
inside the container.

`cloudflared` is in the host package catalog, so **Settings → Updates** upgrades
it with the other packages. A new version does not restart the connector in the
middle of traffic: the page notices the drift and offers **Restart**.

### 13.2 Create the tunnel and paste the token

In the Cloudflare dashboard open **Networks → Tunnels**, create a tunnel
(environment `cloudflared`) and copy its connector token. Paste it under
**3 · Paste the tunnel token** and press **Save token**. The token is sealed with
the console's data key and never returned by the API again; the page shows only
its last four characters.

This is *token mode*: the tunnel is managed remotely, so there is no ingress file
in the console to edit. Hostnames live in the dashboard.

### 13.3 Publish the console hostname

Open the tunnel's **Public Hostname** tab and add one entry:

| Field | Value |
| --- | --- |
| Hostname | the console hostname from **Sites** |
| Service | `http://127.0.0.1:<gui-port>` (usually `8443`) |

The console listener is plain HTTP on loopback by default, so no TLS options are
needed. If you enabled TLS on the console listener, use `https://127.0.0.1:<gui-port>`
instead and turn on **No TLS Verify** for the public hostname, because its
certificate is for the public name rather than loopback. Only publish the console
hostname; app hostnames are a later step and are not managed on this page yet.

### 13.4 Put Access in front

A tunnel hostname is public by itself. In **Zero Trust → Access → Applications**
add a self-hosted application for the console hostname with an Allow policy for
your email address or group. If you want the tunnel checks to reach the console
without a sign-in, add a Bypass policy for `/api/health`; otherwise the origin
check reports that Access answered instead.

With Access on you sign in twice: Cloudflare first, then the console's password
and authenticator. That is expected: Access protects the hostname, and the
console's own accounts still decide what a person may do. A service token lets
monitoring call `/api/health` without an interactive login.

### 13.5 Enable and verify

Turn on **Enable Cloudflare Tunnel** and save. The connector starts with the
saved token and the status row moves from *starting* to *connected*. Then press
**Run checks**:

| Check | Passes when |
| --- | --- |
| Connector installed | `cloudflared` is on the host |
| Tunnel token saved | a sealed token is stored |
| Connector connected | the connector registered with the edge |
| Hostname points at Cloudflare | every DNS answer is a Cloudflare address |
| No direct origin record | no non-Cloudflare address answers for the hostname |
| Request reaches the edge | the response carries `CF-Ray` |
| Traffic reaches this console | `/api/health` returned the console's origin marker |
| Access protects the console | the console root redirects to `cloudflareaccess.com` |

### 13.6 Client addresses

While the tunnel is enabled, the WAF trusts `CF-Connecting-IP` from the connector
and uses that address in policies, logs and bans, so a Cloudflare visitor is not
filtered as `127.0.0.1`. The header is stripped before the request reaches an
upstream, and it is only trusted from the connector's loopback peer. Turn the
switch off if another proxy in front of the tunnel sets its own
`X-Forwarded-For` and should win instead.

### 13.7 Troubleshooting

| Symptom | Cause |
| --- | --- |
| Connector stays *starting*, then errors | the token is wrong or the tunnel was deleted |
| `cloudflared` missing after install | apt could not reach Cloudflare's repository; the installer output is on the page |
| Origin check fails while Access check passes | Access intercepts `/api/health`; add the Bypass policy or use a service token |
| Everything passes but the console asks for a certificate | not this path: the console listener is plain HTTP, and ACME does not run for a tunnelled hostname |
| Direct-origin check fails | a DNS answer points at this host; remove the port-forward record if the tunnel is meant to be the only path |
