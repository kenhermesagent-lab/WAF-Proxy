# Installation

This is the production path for the reference deployment:

```
Internet → Firewalla 192.168.191.1 → DNAT 443 → 192.168.191.2:443 (this stack)
                                                        ↓ source 192.168.101.2
                                              backends 192.168.101.0/24
```

Only `443/tcp` is exposed. The admin GUI binds to the LAN address only.

## 1. Host prerequisites

- Linux with Docker Engine 24+ and Compose v2.
- Two interfaces (or VLANs): one on the WAN subnet, one on the LAN subnet.
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
the administrator account — finish setup before exposing the host, or override
`WAFPROXY_LISTEN_GUI` with a LAN address for the first boot.

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

## 8. Optional Plex

Plex clients validate certificates for the `*.plex.direct` names that encode the server's
address, which this gateway cannot mint. The Plex page therefore runs a **transparent TCP
relay** on its own WAN port instead of an HTTP reverse proxy: TLS passes through untouched
and the Plex server sees every client as coming from the proxy's LAN address. That single
address is what goes in Plex's whitelist, so “allow only this, refuse everything else” stays
intact.

1. GUI → **Plex** → enable.
2. **Listen address** = the WAN address (`192.168.191.2`), **port** = the port clients will
   use (`32400` by default, any free port works), **Plex server** = `192.168.101.10:32400`.
3. **Allowed sources** is optional. Leave it empty to accept any client the firewall lets
   through; set a CIDR to restrict further. **Max connections** caps concurrent streams.
4. **Save and apply** binds the port immediately. There is no Docker restart to do while the
   stack uses `network_mode: host`.
5. On the Firewalla: WAN `32400/tcp` → `192.168.191.2:32400`, **DNAT only, no SNAT**. The
   proxy's own WAN address must not appear as the source, or Plex cannot whitelist it.
6. In Plex: Settings → Network → *List of IP addresses and networks that are allowed without
   auth* → add `192.168.101.2/32` (this proxy's LAN address). Keep the list strict.

Everything the relay carries is encrypted end to end, so the WAF and access gate cannot
inspect it. The source allowlist, the connection cap and the ban engine do apply: a banned
address is refused on accept, a stream that is already running is cut when the ban lands,
and both show up in **Logs** as `plex` events (rule `plex-ban`). Keep HTTP apps on their own
hostnames for inspection.

`deploy/.env` is not mounted into the container by default, so the GUI cannot rewrite it in
the shipped stack. To let it mirror `PLEX_*` values there, mount the file and point the
container at it (the file must already exist):

```yaml
    environment:
      WAFPROXY_ENV_FILE: /config/.env
    volumes:
      - ./.env:/config/.env
```

The Plex page can also restart the container (`POST /api/system/restart`), which is only
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
