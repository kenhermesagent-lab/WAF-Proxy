# WAF-Proxy

A self-hosted web application firewall and reverse proxy for a home lab or small edge. It
terminates TLS, screens every request through a managed rule set, gates private sites behind a
passphrase or per-site accounts, forwards streaming services without inspection, and puts all of
it — traffic, decisions, bans and certificates — in one console.

Written in Go with an embedded SQLite database and a React console; ships as a container or a
systemd service. Version 1.28.0.

## Contents

- [What it does](#what-it-does)
- [How a request is handled](#how-a-request-is-handled)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [First boot](#first-boot)
- [Single NIC](#single-nic)
- [The console](#the-console)
- [Configuration and transport](#configuration-and-transport)
- [Security model and limitations](#security-model-and-limitations)
- [Operations](#operations)
- [Development](#development)
- [Documentation](#documentation)

## What it does

**Protection**

- OWASP CRS through Coraza, with per-site WAF profiles (paranoia level, anomaly threshold, body
  limit, method allowlist, per-rule exceptions) and response inspection that can flag or block a
  malicious upstream answer before it reaches the browser.
- A request pipeline that applies permanent and temporary bans, whitelists, country and ASN
  policy, decoy hostnames, threat feeds, rate limits, bot filtering and a proof-of-work challenge
  before the WAF sees the request.
- Named blocklists and whitelists (IPs, CIDRs, countries) that attach to access profiles and to
  streaming forwarders, with the deciding list named in every event.
- Keyless threat feeds plus local uploads, CrowdSec LAPI bouncer, and a ban engine backed by
  nftables with escalating temporary bans and permanent bans.
- Access gates per site: a shared passphrase, named accounts, or accounts plus TOTP, with an
  allowlist, lockout that survives an IP change, and a session cookie bound to the client network.

**Front door**

- TLS with SNI, per-site minimum versions, certificates via DNS-01, HTTP-01 or TLS-ALPN-01,
  uploaded PEM pairs, an internal CA for `*.home.arpa` installs, DuckDNS updates, and automatic
  renewal with backoff; HTTP/2 and WebSocket pass-through.
- Proxies with per-site load balancing (`weighted_rr`, `least_conn`, `least_latency`, `ip_hash`,
  `sticky_cookie`), per-upstream connection caps, configurable health probes with passive ejection,
  per-site and per-client request budgets, per-site upstream timeouts with bounded idempotent
  retries, ordered request/response header rewriting, method/header/query/regex routes with per-rule upstreams and timeouts, redirects and maintenance mode; a shared response cache with per-host
  quotas and purge; drain readiness; application presets for Nextcloud, Jellyfin, Plex, Home Assistant, Proxmox VE,
  Vaultwarden, Gitea/Forgejo, Grafana, n8n, BookStack, the *arr suite and more.
- Streaming forwarders (Plex, Jellyfin and similar) that relay bytes without HTTP inspection,
  optionally enforcing the same lists as a proxied site.

**Operations**

- Dashboard with live traffic, an attack globe, top sources and upstream health; statistics,
  event log with a request simulator ("Why?"), anomaly events and uptime history.
- Scheduled backups to a local directory, SFTP, FTP or a Git remote, optionally encrypted with
  AES-256-GCM under a passphrase; manual JSON and YAML downloads use the same passphrase.
- Declarative YAML export/import of settings, WAF and protection profiles, access lists, access
  profiles, proxies and policies. References are names, so a file restores onto another install.
- Tamper-evident audit log (SHA-256 chain with an anchored head), full CSV export, and notifications
  through webhooks.
- MCP gateway for AI agents with per-tool token scopes; a metrics endpoint guarded by a bearer
  token; Tailscale-aware listeners; one-click self-update with rollback.

**Console**

- Password + TOTP sign-in with single-use recovery codes, CSRF tokens, strict CSP, secrets sealed
  at rest, an optional admin source allowlist, and RBAC with Administrator, Operator, Read-only
  and Viewer roles plus custom roles.

## Headless commands

- `wafproxy setup --password …` creates the first administrator without a browser.
- `wafproxy recover --password … --reset-totp` resets a locked-out account.
- `wafproxy backup --keep 7` writes an encrypted backup and prunes older ones.
- `wafproxy unban <ip|cidr>` removes a ban while the console is unreachable.

## How a request is handled

```
Internet ──► router DNAT 443 ──► WAN listener (TLS, SNI)
                                     │
        permanent ban → whitelist → country → ASN → decoy → threat feed
             → temporary ban → rate limit → method → bot challenge
             → access gate → WAF → upstream (balanced per site)
```

With response inspection on, the answer is checked on the way back: up to the profile's body
limit is buffered and run through the CRS response rules, and a match is refused with the uniform
502 before the status line is written. SSE, WebSocket upgrades, range requests, compressed,
bodyless and oversized responses are forwarded untouched and logged as `response-skipped` with
the reason. It is off by default because it delays the first byte by up to one buffer.

Every decision that blocks, bans or challenges produces one event row (source, country, ASN, host,
path, stage, rule) that feeds the dashboard, the globe, Logs, Sources and notifications. Allowed
requests are sampled rather than logged, so the event table stays small on a busy site.

## Requirements

- **Linux**, deployed with Docker Engine 24+ / Compose v2, or as a systemd service
  (`make build && sudo ./deploy/install.sh`). Host networking and nftables are used, so Docker
  Desktop on macOS or Windows is not a supported target. The systemd path needs Go 1.27 to build.
- **`443/tcp`** reachable from the edge firewall. Port 80 is optional and only needed for the
  HTTP-01 certificate challenge; DNS-01 and TLS-ALPN-01 need no extra port.
- **One or two interfaces.** The intended deployment is dual-homed (WAN and LAN); a single-NIC
  host works too — see [Single NIC](#single-nic).
- nftables inside the container. The image grants `NET_ADMIN` and `NET_BIND_SERVICE` through file
  capabilities; do **not** add `no-new-privileges`, which makes the kernel ignore them.
- **Optional:** GeoIP for country and ASN policy — install DB-IP Lite from **Settings → GeoIP
  database**, or place `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` in the data volume.
- **Optional:** the CrowdSec sidecar profile and its LAPI bouncer.
- **Optional:** a native Tailscale installation (`tailscale0`) for private admin and application
  access. WAF-Proxy needs no Tailscale sidecar or auth key.

Sizing guidance for 4 vCPU/8 GB and 8 vCPU/16–32 GB hosts is in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Quick start

```bash
git clone https://github.com/kenhermesagent-lab/WAF-Proxy.git WAF-Proxy
cd WAF-Proxy
cp .env.example deploy/.env
# edit deploy/.env: TZ, the GUI bind address, optional CrowdSec and metrics token
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs -f wafproxy
```

The image builds the React console and embeds it in the Go binary. Before the first start, set in
`deploy/.env`:

```ini
# This host's real LAN address. The console listens only here.
WAFPROXY_LISTEN_GUI=10.0.0.10:8080
# Refuse console requests from anything but a private network.
WAFPROXY_GUI_PRIVATE_ONLY=true
# Only if a tunnel or proxy fronts this host: the CIDRs whose X-Forwarded-For may name the client.
WAFPROXY_TRUSTED_PROXIES=
```

## First boot

Open the console on the LAN address and port from `deploy/.env` and complete the wizard: base
domain, administrator name and a 12+ character password, WAN and LAN addresses, ports, and
optionally a DuckDNS token and ACME email. The wizard shows the authenticator secret and ten
recovery codes **once**; store them before continuing. Both bind addresses are required, because
an empty address would put the console on every interface.

The setup endpoint is unauthenticated until the administrator exists, which is why Compose keeps
the console on loopback. Complete setup before exposing the port, and keep
`WAFPROXY_GUI_PRIVATE_ONLY=true` unless a trusted reverse proxy terminates access in front of it.

Then add a proxy, pick a certificate, and point a hostname at the WAN address. The
[installation guide](docs/INSTALL.md) walks through the router, DNS and the first certificate.

## Single NIC

A host with one address and one interface uses that address for both WAN and LAN, and the console
is firewalled from the WAN side. The WAN listener terminates TLS on 443; the LAN egress address is
the same address, so upstreams are reached over that interface. Enter the address in both fields
in the wizard and in **Settings → Network**, and do not forward the console port from the router.

## The console

| Page | What it covers |
|---|---|
| Dashboard | Needs-attention queue, live requests and byte rates, attack globe with country drill-down, top sources, upstream health |
| Statistics | Request/block totals, per-site series, countries, stages, uptime |
| Proxies | Hostnames, upstreams, routes, health checks, maintenance, presets, per-site **360** view |
| Streaming | Byte-relay forwarders for Plex, Jellyfin and similar, with optional lists |
| Policies | Global profile with policy **Preflight**, WAF and protection profiles, blocklists/whitelists, access profiles, bot filter |
| Sources | Threat feeds, local lists, CrowdSec status, bans, per-address investigation |
| Logs | Event search, filters, saved views, live tail, bulk source actions, incident report, the **Why?** request simulator |
| Anomaly events | Requests that tripped a rule but were not blocked |
| Activity | The audit log with before/after diffs and rollback of edits |
| Readiness | A scored hardening checklist, each gap linking to the control that fixes it |
| Access gate | Site accounts, TOTP, gate settings |
| Threat intel | Feed health and rollup |
| Certificates | Issue, renew, inspect; DNS-01, HTTP-01, TLS-ALPN-01 |
| AI Agent Access | MCP endpoint, tokens and their per-tool scopes |
| Notifications | Webhook routing |
| Updates | Version, release check, one-click update |
| Tailscale | Listener on the tailnet address |
| Settings | Network, protection, retention, backup, GeoIP, audit, YAML/JSON transport |
| Account | Password, authenticator rotation, recovery codes, administrators and roles |

**Investigating a source.** Any address in the log, dashboard, attack map, source explorer or ⌘K
search opens one drawer: totals for 1h/24h/7d/30d, block share, hosts, first and last seen, threat-intel
matches, recent requests and the ban state. Administrators with `policies.write` can ban for 24 hours
with a reason or release the ban; the drawer is read-only for other roles.

## Configuration and transport

**YAML configuration.** **Settings → Download YAML** exports the declarative half of the install:
settings, WAF and protection profiles, access lists, access profiles, proxies and policies.
Bans, feeds, certificates and secrets are excluded. Every reference between rows is a name, so
the file imports onto an empty install and resolves to the entities created from the same file.
**Import YAML** is additive: existing hostnames and profiles are skipped and every problem is
listed in the response.

```bash
curl -fsS -b cookies.txt https://console.example.com/api/config/export.yaml -o wafproxy.yaml
curl -fsS -b cookies.txt -X POST --data-binary @wafproxy.yaml \
  -H 'Content-Type: application/yaml' https://console.example.com/api/config/import.yaml
```

A passphrase of 16+ characters in the field beside either download button seals that file with
AES-256-GCM, and **Import YAML** opens an encrypted file with the same passphrase. The scheduled
backup uses the same format and the passphrase configured on the backup card.

**Backups.** The schedule writes a JSON document to a local directory, SFTP, FTP or a Git remote,
keeps a chosen number of files, and can be encrypted. Restoring is additive as well; encrypted
files ask for the passphrase and are decrypted before parsing. Bans, feeds, certificates and
secrets are not part of the document.

## Security model and limitations

- The console is **plain HTTP on a private address**. Put it behind an SSH tunnel, a LAN-only
  address or Tailscale; do not publish it. TLS terminates on the WAN listener, not the console.
- **Only 443 is exposed by design.** Port 80 exists only if HTTP-01 is used. The proxy refuses
  unknown hostnames rather than serving a default vhost.
- **Secrets are sealed with a master key** at `master.key` in the data directory. The key is
  created on first boot; the database alone does not disclose tokens, passwords or TOTP secrets.
  Back up the key with the database, and treat both as sensitive.
- **The update helper runs as root** and builds from the checkout you recorded. A compromised
  admin session can make it install code; this is documented design rather than privilege
  escalation, and the rollback exists for failed builds.
- **Streaming forwarders are a byte relay**, not an inspected proxy. They enforce their lists at
  connection time and then stay out of the traffic.
- **Bans are kernel state.** A permanent ban is absolute for its address; decoy hostnames ban
  permanently by design.
- **Auditing is tamper-evident, not tamper-proof.** The hash chain and anchored head detect edits
  or truncation in the database file, not an attacker who can rewrite every row.
- **GeoIP is optional.** Without a database, country and ASN policy reports "unavailable" and is
  skipped instead of pretending to be active.
- **Subdomains are not a secrecy boundary.** Certificates are published to Certificate
  Transparency logs, so a wildcard's names are discoverable.
- **Not included:** AbuseIPDB enrichment, tarpit, per-site HTTP basic auth/mTLS, brotli, per-site
  bandwidth history, HTTP/3, HA and multi-user roles beyond the built-in RBAC.

## Operations

- `GET /api/health` is public and reports the version and liveness; the console uses it to detect a
  stopped service.
- `GET /metrics` serves Prometheus counters and requires `Authorization: Bearer
  $WAFPROXY_METRICS_TOKEN` (32+ characters). Without the variable it answers 403.
- **Audit.** Every administrator action is recorded; **Verify chain** checks the hash chain and the
  anchored head, and the CSV export downloads the whole table.
- **Updates.** The **Update** button and `deploy/wafproxy-self-update.sh` pull, build, install and
  roll back on failure. A Docker host can install `deploy/install-docker-updater.sh` for the same
  action without exposing the Docker socket to the console.
- **Agent gateway.** The MCP endpoint is documented in [docs/MCP.md](docs/MCP.md); tokens are
  limited per tool and can be revoked from **AI Agent Access**.

## Development

```bash
make ui             # npm ci + Vite build into internal/webui/dist
make build          # static Go binary with version ldflags
make test           # go test ./...
make vet            # go vet ./...
make run            # run from source against ./data
make perf           # WAF hot-path throughput and p50/p95/p99
make perf-gate      # compare the benchmarks with perf/baseline.json
make sbom           # CycloneDX document of the build graph into dist/
make verify-release # VERSION and the newest CHANGELOG section agree
```

Go 1.27 and Node 22 are what CI uses. CI runs gofmt, `go vet`, race tests, the Go build, the
console typecheck/build and its component tests, a production dependency audit, release metadata
and SBOM checks, the performance gate, and a container image build.
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the source of truth. `make perf-record`
re-records the performance baseline after a deliberate change.

## Documentation

- [SECURITY.md](SECURITY.md) — supported versions, private vulnerability reporting, delivered fixes
- [docs/README.md](docs/README.md) — documentation index, split by task
- [docs/INSTALL.md](docs/INSTALL.md) — installation hub: Docker, DNS/TLS, first site, bare metal, Tailscale
- [docs/openapi.yaml](docs/openapi.yaml) — generated reference for every admin API route
- [docs/MCP.md](docs/MCP.md) — agent gateway, tool reference, containment playbook
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — runbook, troubleshooting, capacity
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — measured numbers and methodology
- [CHANGELOG.md](CHANGELOG.md) — release history

## License

[MIT](LICENSE) © 2026 kenhermesagent-lab. Use it, modify it and redistribute it; keep the
copyright notice and take it as-is, with no warranty.
