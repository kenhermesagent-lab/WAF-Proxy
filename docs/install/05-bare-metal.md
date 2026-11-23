# Run it on bare metal with systemd

Part of [Installation](../INSTALL.md).

## 11. Bare metal with systemd

The native deployment runs the same binary from `/var/lib/waf-proxy/bin/wafproxy`, with
`/usr/local/bin/wafproxy` kept as a symlink, under systemd. Use it when the
host already manages nftables and the container layer is not wanted; the Docker Compose path
above remains the reference deployment and is unchanged.

### 11.1 Build and install

Build on the host (Go 1.27; the console is embedded from `internal/webui/dist`, which is
committed, so `make ui` is only needed after changing `web/`):

```bash
git clone https://github.com/kenhermesagent-lab/WAF-Proxy.git WAF-Proxy
cd WAF-Proxy
make build
sudo ./deploy/install.sh
```

The installer lists the interfaces that have a global IPv4 address and asks which is **WAN**
and which is **LAN**, then asks for the WAN and GUI ports (defaults 443 and 8443). For
unattended installs pass `--wan-iface`, `--lan-iface`, `--wan-port`, `--gui-port` and `--yes`.
The LAN address must be RFC1918 because the admin listener rejects non-private clients.

Install `nftables` first (`apt install nftables` or `dnf install nftables`); the unit expects
the `nft` binary and the host firewall is yours to configure.

`install.sh` is idempotent. It creates the `wafproxy` system user, `/var/lib/waf-proxy/data`
(database, master key, GeoIP files) and `/var/log/wafproxy` (access log), installs
the binaries and helper scripts under `/var/lib/waf-proxy/bin` and `/var/lib/waf-proxy/lib`,
links `/usr/local/bin/wafproxy` to `bin/wafproxy`, installs
`/etc/systemd/system/wafproxy.service`, enables the unit and starts it. On upgrade it keeps
`/etc/wafproxy/wafproxy.env` and the data directory.

Everything the install owns lives in one root, `/var/lib/waf-proxy`:

| Path | Contents |
|---|---|
| `bin/` | `wafproxy`, `wafproxy-updated` |
| `lib/` | fixed helper scripts |
| `src/` | root-owned git checkout the Update button pulls and builds |
| `data/` | SQLite database, master key, GeoIP files, feeds, backups — owner `wafproxy` |

Releases up to 1.13 used `/usr/local/waf-proxy` for the program files and `/var/lib/wafproxy`
for the state. The installer moves both into the new root on the first run after upgrading and
keeps the old state directory as `/var/lib/wafproxy.pre-1.14`; delete it once the console is
healthy. It also clones the checkout it was run from into `/var/lib/waf-proxy/src` (with the
original `origin` URL) and records that path in `/etc/wafproxy/self-update.conf`, so the
**Update application** button builds the managed checkout instead of a home directory.

The unit runs as `wafproxy` with `CAP_NET_BIND_SERVICE` and `CAP_NET_ADMIN` in both the bounding
and ambient sets, and `NoNewPrivileges=yes`; that is how it binds 443 and runs `nft` without
root. It does not need `setcap` on the binary, and `ProtectSystem=strict` leaves only
`/var/lib/waf-proxy/data` and `/var/log/wafproxy` writable.

### 11.2 Two interfaces

`install.sh` writes the selected addresses to `/etc/wafproxy/wafproxy.env`:

```ini
WAFPROXY_LISTEN_WAN=192.168.1.20:443
WAFPROXY_LISTEN_GUI=192.168.1.10:8443
WAFPROXY_WAN_IFACE=<wan-iface>
WAFPROXY_LAN_IFACE=<lan-iface>
WAFPROXY_GUI_PRIVATE_ONLY=true
```

On a dual-homed host:

- **WAN interface** (for example `192.168.1.20`): proxy listener `443` and any streaming ports.
- **LAN interface** (for example `192.168.1.10`): admin GUI `8443` and egress to backends.
- **Router**: DNAT `443` to `192.168.1.20:443`, no SNAT, exactly as in §4.

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

The GUI is now `http://192.168.1.10:8443`, the proxy is on `192.168.1.20:443`, and later edits
to the env file no longer move the listeners (change them in **Settings** and restart). On an
existing install, the addresses already stored in SQLite take precedence over the installer’s
env file; re-run the installer only to update the binary/unit, and change moved interfaces in
**Settings**.

If you install the unit by hand instead of running `install.sh`, the shipped env file still
binds both listeners to loopback. Set `WAFPROXY_LISTEN_GUI` and `WAFPROXY_LISTEN_WAN`, or use
`ssh -L 8080:127.0.0.1:8080 <this-host>` and add `WAFPROXY_GUI_PRIVATE_ONLY=true` before
starting the service.

### Trusted proxies

Addresses, access profiles, rate limits, the ban engine and the audit log all act on the client
address. It is the socket peer unless `WAFPROXY_TRUSTED_PROXIES` names the CIDRs of a proxy or
tunnel in front of this host; only then is `X-Forwarded-For` believed, and the right-most entry
that is not itself a trusted proxy wins. Nothing is trusted by default, so a spoofed header from
a directly connected client is still discarded.

Set it when the console or the sites are reached through another hop (a reverse proxy on the
same host, a container network, Cloudflare Tunnel). Leaving it empty behind a tunnel makes every
client look like `127.0.0.1`: the LAN check passes for traffic that is not on the LAN, and a
single decoy hit bans the tunnel.

`WAFPROXY_MAX_INFLIGHT` (default `128`) caps requests in flight; each may buffer a body up to the
profile limit, so this is the memory ceiling for request bodies. Requests past it receive `503`,
and **Dashboard → Request budget** shows the current count and how many were refused.

### 11.3 Firewall and nftables

Allow `443/tcp` (and streaming ports) to the WAN address, and the GUI port on the LAN only. The
ban engine creates and owns its `inet wafproxy` table; it does not replace the host firewall.
Check it with `sudo nft list table inet wafproxy`; **Settings** reports `active` while the
process can manage it. If `nft` is missing or the capabilities were removed, the console shows
the reason and bans fall back to the proxy layer.

For GeoIP, use **Settings → GeoIP database → Install database**. It downloads and validates the
DB-IP Lite city and ASN files into `/var/lib/waf-proxy/data` and reloads them without a restart.
Alternatively copy `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` (or the DB-IP Lite equivalents)
into `/var/lib/waf-proxy/data`, owned by `wafproxy`, and restart.

### 11.4 CrowdSec (optional)

On a native install the console can do this for you. Open **CrowdSec → Automatic install** and
click **Install and configure CrowdSec**. The root helper installs the engine from the CrowdSec
repository, adds `crowdsecurity/nginx`, writes `/etc/crowdsec/acquis.d/wafproxy.yaml` pointing
at `/var/log/wafproxy/access.log`, adds the `crowdsec` user to the `wafproxy` group so it can
read the log, creates the bouncer key, writes the engine's LAPI URL and that key into the console
and enables the bouncer. The installer chooses the key itself, checks it against the Local API
(`/v1/decisions` must answer 200) and only then reports success, so **Bouncer configuration** already
shows a working key saved. Re-running the installer creates a fresh key and replaces the saved one.

The card also asks for a CrowdSec console enrollment key before it starts (app.crowdsec.net → Security
Engines → Add security engine). The installer enrolls the engine in the same run, the page then asks
you to approve it in the portal and offers **Restart CrowdSec**, which runs `systemctl restart crowdsec`
as root so the accepted enrollment takes effect. **Install without linking** is there for operators
who do not want a Cloud account; enrollment can be added later from the same page.

The only manual step is linking the engine to a CrowdSec account under **CrowdSec Cloud**:
app.crowdsec.net → **Security Engines** → **Add security engine**, paste the enrollment key into
the page, then accept the pending engine in the console and run
`sudo systemctl restart crowdsec` on the host. The page reads `cscli console status`, so it reports
whether the console accepted the engine rather than only that the request was sent: **pending
acceptance** until you accept it, **accepted by console** afterwards.

The page also shows the plan, Central API, **Decision management** and PAPI subscription rows the same command
reports. Decision management is the one that matters for blocklists: while it is inactive, the console cannot
push decisions to the engine, and nothing will be enforced no matter how many blocklists are subscribed. Once
it is active, the blocklists the engine pulls are listed read-only under **Threat intel → CrowdSec console
blocklists**, with the number of decisions each one contributes.

The button needs the privileged helper (`wafproxy-updates.service`) that `deploy/install.sh`
installs; without it the page explains that and stays read-only. It is hidden inside a
container, where the Compose sidecar in section 7 is the supported path.

To do it by hand instead, point the engine at `/var/log/wafproxy/access.log` with the stock
nginx parser (copy `deploy/crowdsec/acquis.d/wafproxy.yaml` and change the path), then:

```bash
sudo cscli bouncers add wafproxy
# open the CrowdSec page, enter the LAPI URL (stock default http://127.0.0.1:8080)
# and the key, then Save and apply
```

The page can test the key and enable/disable the bouncer without a restart. The legacy
`WAFPROXY_CROWDSEC_URL` / `WAFPROXY_CROWDSEC_KEY` environment values remain first-boot
defaults.

### 11.5 Upgrade, logs and uninstall

Use **Updates → Update application** for the in-console rebuild, or the manual path:

```bash
cd /var/lib/waf-proxy/src           # the checkout the Update button also builds
sudo git checkout -- internal/webui/dist   # a local build edits the committed bundle
sudo git clean -fdq internal/webui/dist    # and leaves new asset names behind
sudo git pull --ff-only             # or: sudo git fetch --tags && sudo git checkout vX.Y.Z
sudo ./deploy/wafproxy-self-update.sh      # build, install both binaries, restart

journalctl -u wafproxy -f           # service log
sudo env WAFPROXY_DATA_DIR=/var/lib/waf-proxy/data wafproxy unban 203.0.113.7
```

To remove the native installation, use the uninstall script rather than deleting paths by
hand. It prompts first and refuses to run without a terminal unless `--yes` is supplied:

```bash
sudo ./deploy/uninstall.sh
# unattended
sudo ./deploy/uninstall.sh --yes
# keep the config, database and logs for a later reinstall
sudo ./deploy/uninstall.sh --keep-data
```

It stops and disables `wafproxy.service`, `wafproxy-updates.service` and any installed
`wafproxy-docker-updates.service`, removes the unit files, the `/usr/local/bin` and
`/usr/local/lib/wafproxy` links, deletes the app-owned `inet wafproxy` nftables table, and removes
`/var/lib/waf-proxy` (`bin`, `lib`, `src` and `data`), `/etc/wafproxy`, `/var/log/wafproxy`, any
pre-1.14 `/var/lib/wafproxy` directory, the runtime helper socket and the `wafproxy` user/group.
With `--keep-data`, the data directory, config, logs and user/group are kept.

The script intentionally does **not** remove shared OS packages (`nftables`, `ca-certificates`,
`tzdata`), the Go toolchain, Tailscale, CrowdSec, Docker, host firewall/router rules, or the
repository checkout. System journal entries for the removed units may remain until the host's
normal journal rotation.

If the script cannot run because systemd is unavailable, stop the services and remove the exact
paths listed above manually; do not delete unrelated host files.
