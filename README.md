# WAF-Proxy-Docker

Self-hosted reverse proxy with an integrated WAF, IPS-style ban engine, CrowdSec bouncer,
bot challenge, GeoIP/ASN policy, threat feeds, live attack globe, notifications and a
per-proxy access gate. One Go binary, one React SPA, one Docker Compose stack.

**Status: `1.0.0`.** The full design lives in [PLAN.md](PLAN.md); this README describes what
is actually in the release. See [Scope notes](#scope-notes) for deliberately excluded items.

## What it does

| Area | Implemented |
|---|---|
| Reverse proxy | HTTPS/HTTP2 with SNI + Host routing, WebSocket passthrough, weighted round-robin, active health checks, redirects/aliases, gzip, conservative GET cache, streaming. |
| TLS | DNS-01 wildcard certificates via lego (DuckDNS, Cloudflare, Route53, DigitalOcean, Hetzner, OVH, GoDaddy, RFC2136), per-proxy assignment, auto-renew at 30 days, serialised orders. |
| Request pipeline | Permanent ban → whitelist → country → ASN → decoy → threat feed → temporary ban → rate limit → method → bot challenge → access gate → WAF → upstream. |
| Bans | Temporary and permanent, reason + source required, nftables DROP (IPv4/IPv6), kernel expiry, promotion, GUI lists, CLI unban. |
| WAF | Coraza v3 + embedded OWASP CRS, five profiles, per-proxy `off/detect/block`, paranoia/anomaly tuning, method allowlists, per-rule exceptions. |
| Threat intel | Nine built-in feeds plus custom feeds, ETag caching, CIDR aggregation, 5× growth freeze, last-good retention. |
| CrowdSec | LAPI decision stream → local bans, removals honoured, optional sidecar with access-log acquisition. |
| Bot protection | JavaScript proof-of-work challenge, four levels, 24 h cookie, auto-ban after repeated failures. |
| Access gate | Per-proxy passphrase, accounts or accounts+TOTP, per-proxy allowlist, escalation ladder and account lockout. |
| Observability | WAN/LAN bps/pps, conntrack sessions, per-proxy counters, SSE live stream, canvas attack globe, filterable events, audit log, hourly rollups. |
| Notifications | Telegram, SMTP/Gmail, generic webhook; 5-minute ban digest, instant critical alerts, dedupe and retry. |
| Admin security | LAN-only GUI, argon2id, mandatory TOTP, recovery codes, CSRF, login limits, session idle/absolute expiry, CSP, encrypted secrets at rest. |
| Backup | Additive JSON export/import of settings, proxies, routes, policies, feeds and bans (secrets excluded by design). |

The GUI is a dark single-page app: Dashboard (metrics + globe), Proxies, Policies (bans,
countries, ASN, decoys), Threat intel, Certificates, Access gate, Notifications, Logs and
Settings.

## Requirements

- Linux host with Docker Engine + Compose v2. Host networking and nftables are used, so
  Docker Desktop on macOS/Windows is not a supported target.
- `443/tcp` reachable from the edge firewall; no port 80.
- A dual-homed host for the intended WAN/LAN split (`192.168.191.2` / `192.168.101.2` in the
  reference deployment).
- Optional: GeoIP MMDB files in the data directory for country/ASN policy
  (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, `dbip-city-lite.mmdb`,
  `dbip-asn-lite.mmdb`).
- Optional: CrowdSec sidecar profile.

## Quick start

```bash
git clone <this repo> waf-proxy-docker
cd waf-proxy-docker
cp .env.example deploy/.env          # set TZ and optionally the CrowdSec key
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs -f wafproxy
```

First boot listens on `:8080` for the GUI and `:8443` for the proxy, on all interfaces,
because no network binding exists yet. Whoever reaches the GUI first can claim the admin
account, so complete setup before exposing the host (or set `WAFPROXY_LISTEN_GUI` to a LAN
address for the first boot). Open `http://<host>:8080`, complete the wizard with the real
WAN/LAN addresses, then restart so the listeners move:

```bash
docker compose -f deploy/docker-compose.yml restart wafproxy
```

After the restart the GUI is on the LAN address (`http://192.168.101.2:8443` in the reference
deployment) and the proxy is on `WAN_IP:443`.

1. **Certificates** → Request certificate → provider `duckdns`, domains
   `*.your-base-domain,your-base-domain`. The token from the wizard is reused.
2. **Proxies** → New proxy → `app.your-base-domain` → upstream
   `http://192.168.101.10:8080` → protection profile.
3. Point the Firewalla DNAT at `WAN_IP:443` (`DNAT only, no SNAT`, so client IPs survive).
4. Verify from outside: `curl -v https://app.your-base-domain/`.

Full walkthrough: [docs/INSTALL.md](docs/INSTALL.md).

## Emergency recovery

The GUI listener is exempt from all bans and stays LAN-only. If it is unreachable:

```bash
docker exec wafproxy unban 203.0.113.7      # takes effect within 30 s
```

There is no command that disables the WAF or gate globally; use the GUI on the LAN.

## Documentation

- [PLAN.md](PLAN.md) — architecture, pipeline, data model, phases, risks
- [docs/INSTALL.md](docs/INSTALL.md) — deployment, Firewalla/DuckDNS, upgrades
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — runbook, troubleshooting, capacity
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — measured numbers and methodology
- [CHANGELOG.md](CHANGELOG.md) — release history
- [VERSION](VERSION) — `1.0.0`

## Scope notes

Deliberately **not** in 1.0.0 (tracked in PLAN.md §13): AbuseIPDB enrichment, decoy
hostnames, tarpit, HTTP basic auth/mTLS per proxy, brotli, per-proxy bandwidth charts,
CSV export, encrypted backup archives, exotic notification channels beyond the generic
webhook, full packet IPS, HTTP/3, HA and multi-user roles.

Two honesty notes that matter operationally:

- **Subdomain names are not a secrecy boundary.** Every certificate is published to
  Certificate Transparency logs, so `*.your-base-domain` is discoverable. The protection
  comes from 443-only exposure, no default vhost, DROP-by-default, WAF and the ban engine.
- **Without a GeoIP database, country and ASN policy report “unavailable” and are skipped.**
  The GUI shows the state rather than silently allowing traffic.

## Development

```bash
make ui          # npm ci + vite build into internal/webui/dist
make build       # static Go binary with version ldflags
make test        # go test ./...
make vet         # go vet ./...
make run         # run from source with ./data
```

The Docker build compiles the SPA first, then embeds it in the Go binary.
