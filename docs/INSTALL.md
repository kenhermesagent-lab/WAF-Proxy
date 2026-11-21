# Installation

This is the production path for the reference deployment:

```
Internet → Firewalla 192.168.191.1 → DNAT 443 → 192.168.191.2:443 (this stack)
                                                        ↓ source 192.168.101.2
                                              backends 192.168.101.0/24
```

Only `443/tcp` is exposed. The admin GUI binds to the LAN address only.

There are two supported deployment modes for the same binary: **Docker Compose** (§2–§10) and a
**systemd service** on the host (§11, with host package updates in §13). The wizard, database and
configuration are identical; pick the one that matches how the host is managed.

## 1. Host prerequisites

- Linux. The Docker path needs Docker Engine 24+ and Compose v2; the systemd path needs Go 1.27
  to build the binary and systemd to run it.
- One or two interfaces. The reference deployment uses two (or two VLANs), one on the WAN
  subnet and one on the LAN. A **single-NIC host works too**: enter its address for both WAN
  and LAN (see §3), and firewall the GUI port from the WAN side.
- `nftables` usable inside the container. The image grants `NET_ADMIN` and
  `NET_BIND_SERVICE` through file capabilities, so do **not** enable
  `no-new-privileges` on the container — it makes the kernel ignore those capabilities.
- The host firewall must allow `443/tcp` to the WAN address and the GUI port on the LAN
  address.
- Optional GeoIP: place `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` (or the DB-IP Lite
  equivalents) in the data volume (`/data` in the container). Country and ASN policy is
  reported as unavailable without them.

## 2. Start the stack

```bash
git clone <this repo> waf-proxy-docker
cd waf-proxy-docker
cp .env.example deploy/.env
# edit deploy/.env: TZ, optional CrowdSec settings
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs -f wafproxy
```

The image builds the React SPA and embeds it in the Go binary. First boot has no saved
binding, so the process listens on `:8443` (proxy) and `:8080` (GUI) **on all interfaces**.
This is intentional: the wizard writes the real addresses to SQLite, and the listeners move
on the next start. Until the wizard is complete, anyone who can reach port 8080 can claim
the administrator account — finish setup before exposing the host, or set
`WAFPROXY_LISTEN_GUI` to a LAN address in `deploy/.env` for the first boot (the shipped
compose file passes `WAFPROXY_LISTEN_GUI` and `WAFPROXY_LISTEN_WAN` into the container).

## 3. Complete the wizard

Open `http://<host-ip>:8080` from the LAN and fill in:

| Field | Reference value |
|---|---|
| Admin username | `admin` |
| Password | 12+ characters, stored as argon2id |
| Base domain | `kendk.duckdns.org` |
| WAN IP / port | `192.168.191.2` / `443` |
| LAN IP / GUI port | `192.168.101.2` / `8443` |
| DuckDNS token | optional, stored AES-256-GCM encrypted |
| ACME email | Let's Encrypt account contact |

Both addresses must be configured on the host; the listeners bind them directly from the
database. On a host with one NIC the WAN and LAN address are the same — the host's address
that the router DNATs to. The proxy then binds `443` on the NIC shared with the GUI, so only
forward `443` (and streaming ports) from the WAN and firewall the GUI port. The interface
counters show that one NIC twice, and the stealth ping drop applies to the whole NIC, so
leave it off unless dropping LAN ICMP is acceptable.

If a stored address is missing at boot (a DHCP change, or the wizard was filled in before the
interface came up), the listener falls back to the first-boot `:8443` / `:8080` addresses and
logs `stored WAN/GUI address is not configured on this host` instead of exiting. Fix the
address in **Settings** and restart.

The fallback GUI address is the first-boot `:8080`, so after the fallback the admin login
listens on **all interfaces**, not just the LAN. The log says so explicitly
(`admin GUI is bound to all interfaces until the stored address is fixed in Settings`);
fix the address promptly and keep `8080` blocked at the WAN firewall in the meantime.

The wizard returns the TOTP secret and ten recovery codes **once**. Save both. Then restart:

```bash
docker compose -f deploy/docker-compose.yml restart wafproxy
```

The GUI is now `http://192.168.101.2:8443` and every login requires password + TOTP (or a
recovery code).

## 4. Firewalla and DuckDNS

1. DuckDNS keeps the A record for `kendk.duckdns.org`; DuckDNS mirrors A/AAAA and the single
   TXT record to `*.kendk.duckdns.org`, so subdomains resolve without extra records.
2. On the Firewalla, create a port forward: WAN `443` → `192.168.191.2:443`.
   **Do not enable SNAT/masquerade on that rule**; the proxy needs real client IPs for
   GeoIP, bans and rate limits.
3. Do not forward port 80. ACME uses DNS-01 only.
4. Optional second layer: block the bare apex `kendk.duckdns.org` at the Firewalla. The
   proxy already closes it without a response.

Because DuckDNS stores exactly one TXT record per domain, request **one wildcard
certificate** (`*.kendk.duckdns.org` plus the apex as SAN). The certificate manager
serialises ACME orders so two challenges cannot overwrite each other.

## 5. First certificate

GUI → **Certificates** → **Request certificate**:

- Domains: `*.kendk.duckdns.org,kendk.duckdns.org`
- Provider: `duckdns`
- Credentials: leave blank if the wizard stored the token, otherwise paste
  `{"token":"..."}`.

Issuance is asynchronous; the row moves from `pending` to `issued` and shows the expiry.
Renewal happens automatically inside 30 days. Use the staging toggle in Settings while
testing to avoid Let's Encrypt rate limits.

## 6. First proxy

GUI → **Proxies** → **New proxy**:

- Hostname: `app.kendk.duckdns.org` (single-label subdomain of the base domain; the apex is
  reserved and blackholed)
- Upstream: `http://192.168.101.10:8080`
- Protection profile: `Generic Web` (or `WordPress`, `API-only`, …)
- WAF mode: `Detect only` for the first 48 hours if the app is unknown, then `Inherit` or
  `Block`.

Verify:

```bash
curl -v https://app.kendk.duckdns.org/
curl -v https://kendk.duckdns.org/        # connection closed, no response
```

## 7. Optional CrowdSec

```bash
docker compose -f deploy/docker-compose.yml --profile crowdsec up -d
docker exec crowdsec cscli bouncers add wafproxy
# put the key in deploy/.env as WAFPROXY_CROWDSEC_KEY, then
docker compose -f deploy/docker-compose.yml up -d wafproxy
```

The access log written to `/logs/access.log` is tailed by the sidecar with the stock nginx
parser. Decisions arrive over the LAPI stream and are applied as `source=crowdsec` bans.

## 8. Optional streaming (Plex, Jellyfin)

Media players validate the server's own certificates (Plex clients check the `*.plex.direct`
names that encode its address), which this gateway cannot mint. The **Streaming** page
therefore runs one **transparent TCP relay per application** on its own WAN port instead of an
HTTP reverse proxy: TLS passes through untouched and the server sees every client as coming
from the proxy's LAN address. That single address is what goes in the server's trusted list,
so “allow only this, refuse everything else” stays intact.

The shipped catalog has a section each for **Plex** (`32400`) and **Jellyfin** (`8096`);
adding another application is a catalog entry plus a settings row, and unknown entries still
render with the generic firewall steps.

1. GUI → **Streaming** → the application's section → enable.
2. **Listen address** = an address assigned to this host (`192.168.191.2` in the two-NIC
   reference; on a single-NIC host the LAN address the router forwards to), **port** = the
   port clients will use (any free port works, defaults are 32400 and 8096), **server** =
   the LAN address and port of that application (`192.168.101.10:32400`,
   `192.168.101.11:8096`).
3. **Allowed sources** is optional: empty accepts any client the firewall lets through; a
   CIDR restricts further. **Max connections** caps concurrent streams.
4. **Save and apply** binds the port immediately. There is no Docker restart to do while the
   stack uses `network_mode: host`. A port already used by the GUI, the HTTP proxy or another
   streaming section is refused with a clear message.
5. On the Firewalla: WAN `32400/tcp` → `192.168.191.2:32400` (and the same for 8096),
   **DNAT only, no SNAT**. The listener address must not appear as the source, or the server
   cannot trust it.
6. In the application:
   - **Plex**: Settings → Network → *List of IP addresses and networks that are allowed
     without auth* → add `192.168.101.2/32`, and keep the list strict.
   - **Jellyfin**: Settings → Networking → *Known proxies* → add `192.168.101.2`. Jellyfin has
     no IP whitelist of its own; use the allow list above when only some clients should
     connect.

Everything the relay carries is encrypted end to end, so the WAF and access gate cannot
inspect it. The source allowlist, the connection cap and the ban engine do apply: a banned
address is refused on accept, a stream that is already running is cut when the ban lands, and
both show up in **Logs** as `stream` events (rule `stream-ban`). A retrying banned host
produces at most one event a minute per application, with the number of attempts it folded
in, so a loop cannot flood the log. Keep HTTP apps on their own hostnames for inspection.

`deploy/.env` is not mounted into the container by default, so the GUI cannot rewrite it in
the shipped stack. To let it mirror `PLEX_*` values there, mount the file and point the
container at it (the file must already exist):

```yaml
    environment:
      WAFPROXY_ENV_FILE: /config/.env
    volumes:
      - ./.env:/config/.env
```

The Streaming page can also restart the container (`POST /api/system/restart`), which is only
needed when the port is published by Docker rather than with host networking.

## 9. Upgrade

Back up first (Settings → Download JSON exports configuration without secrets).

```bash
git pull
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
```

The schema is applied idempotently on boot. Restore the JSON if a configuration was lost;
gate modes are reset to `off` and certificates must be re-issued because private keys are
not exported.

## 10. Uninstall

```bash
docker compose -f deploy/docker-compose.yml down
# configuration and database:
docker volume rm wafproxy_data
```

This is destructive. Export the backup first if the configuration may be reused.

## 11. Bare metal with systemd

The native deployment runs the same `/usr/local/bin/wafproxy` under systemd. Use it when the
host already manages nftables and the container layer is not wanted; the Docker Compose path
above remains the reference deployment and is unchanged.

### 11.1 Build and install

Build on the host (Go 1.27; the console is embedded from `internal/webui/dist`, which is
committed, so `make ui` is only needed after changing `web/`):

```bash
git clone https://github.com/kenhermesagent-lab/WAF-Proxy-Docker.git waf-proxy-docker
cd waf-proxy-docker
make build
sudo ./deploy/install.sh
```

The installer lists the interfaces that have a global IPv4 address and asks which is **WAN**
and which is **LAN**, then asks for the WAN and GUI ports (defaults 443 and 8443). For
unattended installs pass `--wan-iface`, `--lan-iface`, `--wan-port`, `--gui-port` and `--yes`.
The LAN address must be RFC1918 because the admin listener rejects non-private clients.

Install `nftables` first (`apt install nftables` or `dnf install nftables`); the unit expects
the `nft` binary and the host firewall is yours to configure.

`install.sh` is idempotent. It creates the `wafproxy` system user, `/var/lib/wafproxy`
(database, master key, GeoIP files) and `/var/log/wafproxy` (access log), installs
`/usr/local/bin/wafproxy` and `/etc/systemd/system/wafproxy.service`, enables the unit and
starts it. On upgrade it keeps `/etc/wafproxy/wafproxy.env` and the data directory.

The unit runs as `wafproxy` with `CAP_NET_BIND_SERVICE` and `CAP_NET_ADMIN` in both the bounding
and ambient sets, and `NoNewPrivileges=yes`; that is how it binds 443 and runs `nft` without
root. It does not need `setcap` on the binary, and `ProtectSystem=strict` leaves only
`/var/lib/wafproxy` and `/var/log/wafproxy` writable.

### 11.2 Two interfaces

`install.sh` writes the selected addresses to `/etc/wafproxy/wafproxy.env`:

```ini
WAFPROXY_LISTEN_WAN=192.168.191.2:443
WAFPROXY_LISTEN_GUI=192.168.101.2:8443
WAFPROXY_WAN_IFACE=<wan-iface>
WAFPROXY_LAN_IFACE=<lan-iface>
WAFPROXY_GUI_PRIVATE_ONLY=true
```

On a dual-homed host:

- **WAN interface** (for example `192.168.191.2`): proxy listener `443` and any streaming ports.
- **LAN interface** (for example `192.168.101.2`): admin GUI `8443` and egress to backends.
- **Router**: DNAT `443` to `192.168.191.2:443`, no SNAT, exactly as in §4.

Both addresses must be assigned to the host before running the installer. If a stored address
is later missing (DHCP change or a renamed NIC), the listener falls back to the env address and
logs a warning. On a single-NIC host choose the same interface twice, as described in §3.

The admin listener only accepts clients from `10/8`, `172.16/12`, `192.168/16` and loopback.
The bind is already LAN-only; the client check is a second layer in case the host firewall or
routing changes. Loopback stays allowed for an SSH tunnel and local health checks; IPv6 ULA is
not RFC1918 and is not accepted by this check.

The wizard receives the installer’s addresses prefilled through `GET /api/setup/status`, so
reviewing them and completing the wizard cannot silently move the GUI back to another
interface. Complete the wizard as in §3, save the TOTP secret and recovery codes, then restart
so the stored addresses are used:

```bash
sudo systemctl restart wafproxy
```

The GUI is now `http://192.168.101.2:8443`, the proxy is on `192.168.191.2:443`, and later edits
to the env file no longer move the listeners (change them in **Settings** and restart). On an
existing install, the addresses already stored in SQLite take precedence over the installer’s
env file; re-run the installer only to update the binary/unit, and change moved interfaces in
**Settings**.

If you install the unit by hand instead of running `install.sh`, the shipped env file still
binds both listeners to loopback. Set `WAFPROXY_LISTEN_GUI` and `WAFPROXY_LISTEN_WAN`, or use
`ssh -L 8080:127.0.0.1:8080 <this-host>` and add `WAFPROXY_GUI_PRIVATE_ONLY=true` before
starting the service.

### 11.3 Firewall and nftables

Allow `443/tcp` (and streaming ports) to the WAN address, and the GUI port on the LAN only. The
ban engine creates and owns its `inet wafproxy` table; it does not replace the host firewall.
Check it with `sudo nft list table inet wafproxy`; **Settings** reports `active` while the
process can manage it. If `nft` is missing or the capabilities were removed, the console shows
the reason and bans fall back to the proxy layer.

For GeoIP, copy `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` (or the DB-IP Lite equivalents) into
`/var/lib/wafproxy`, owned by `wafproxy`, and restart.

### 11.4 CrowdSec (optional)

Install CrowdSec on the same host and point it at `/var/log/wafproxy/access.log` with the stock
nginx parser (copy `deploy/crowdsec/acquis.d/wafproxy.yaml` and change the path), then:

```bash
cscli bouncers add wafproxy
# put the key in /etc/wafproxy/wafproxy.env as WAFPROXY_CROWDSEC_KEY
sudo systemctl restart wafproxy
```

### 11.5 Upgrade, logs and uninstall

```bash
git pull
make build
sudo ./deploy/install.sh            # keeps the env file and /var/lib/wafproxy

journalctl -u wafproxy -f           # service log
sudo env WAFPROXY_DATA_DIR=/var/lib/wafproxy wafproxy unban 203.0.113.7

sudo systemctl disable --now wafproxy wafproxy-updates
# destructive: also remove the state, logs, units and binaries
sudo rm -rf /var/lib/wafproxy /var/log/wafproxy /etc/wafproxy
sudo rm -f /usr/local/bin/wafproxy /usr/local/bin/wafproxy-updated
sudo rm -f /etc/systemd/system/wafproxy.service /etc/systemd/system/wafproxy-updates.service
sudo systemctl daemon-reload
```

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
`:8443`. A wildcard listener already owns the port, so the tailnet listener cannot be added. This
mainly affects Docker Compose, whose defaults are wildcard binds: set `WAFPROXY_LISTEN_GUI` and
`WAFPROXY_LISTEN_WAN` to the host's actual LAN/WAN addresses (or use the native installer, which
already does this) before enabling these switches. The Tailscale page reports the bind problem.

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

## 13. Host updates on systemd

The **Updates** page is available on the native systemd deployment. It is deliberately
read-only in Docker: packages inside the WAF-Proxy image are updated by rebuilding the image
and recreating the container, not by changing the host from inside the container.

### 13.1 What is tracked

The page uses a fixed catalog of the host packages the native service needs:

| Package | Used for |
|---|---|
| `ca-certificates` | ACME and upstream TLS trust roots |
| `nftables` | Kernel-mode ban enforcement (`nft`) |
| `tzdata` | Host time-zone data used by the console |

It shows the installed version, the candidate version from the apt index, and whether the
candidate comes from a distribution security repository. High and critical advisories are
matched with the [OSV database](https://osv.dev/) for the installed package version; low and
medium advisories are intentionally not shown on this page. A security-repository update with
no published CVSS record is shown as a security update with an unknown severity instead of
being hidden.

Checking advisories sends only the package name, distribution version and installed version to
`api.osv.dev`. It does not send hostnames, proxy traffic, credentials, settings or certificates.

Go modules and the React console are compiled into the WAF-Proxy binary. They are listed as
application dependencies on the page but are not changed by the host upgrade helper; deploy a
new WAF-Proxy release to update them.

### 13.2 The privileged helper

The console service runs with `NoNewPrivileges=yes`, so it cannot use `sudo`. `install.sh`
installs two pieces instead:

- `/usr/local/bin/wafproxy-updated` — a root-owned helper service;
- `/etc/systemd/system/wafproxy-updates.service` — the unit that starts it.

The helper listens on `/run/wafproxy-updates/updates.sock` with mode `0660`, owned by
`root:wafproxy`. It accepts only `check` (apt index refresh) and `apply` for an exact package
from the compiled catalog. Package names are validated again by both the console and the
helper; arbitrary package names, shell commands and options are rejected. The console still
keeps its reduced capabilities and never runs apt itself.

```bash
sudo systemctl status wafproxy-updates
sudo journalctl -u wafproxy-updates -f
```

If the helper is missing or stopped, the Updates page lists installed and candidate versions
but disables the Update buttons and shows the reason. Re-run `sudo ./deploy/install.sh` after
building to install/repair it.

### 13.3 Checking and applying

1. Open **Updates** and click **Check for updates**. This asks the helper to run
   `apt-get update`, then rebuilds the inventory.
2. A high/critical advisory is shown with its CVE/OSV identifier and summary. The package row
   also shows a security badge and the available version.
3. Click **Update** on one package, confirm, and wait for apt to finish. The page refreshes and
   shows the helper output.

Only one helper operation runs at a time. The distribution package manager remains the
authority: if no newer candidate exists, the page reports that instead of inventing a version.
Applying an update does not automatically restart WAF-Proxy; if the package maintainer requires
a service restart, the package output will say so and the operator should restart the relevant
service.

### 13.4 Docker

Docker does not expose an update button for host packages. Use the normal image upgrade:

```bash
git pull
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
```

The Updates page in a container explains this limitation and shows the compiled application
version. It never tries to run apt against the host from inside the container.
