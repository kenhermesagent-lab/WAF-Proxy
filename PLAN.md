# WAF-Proxy-Docker — Project Plan

A self-hosted reverse proxy with an integrated WAF, IPS-style ban engine, bot protection,
GeoIP policy, live attack visualisation, and a modern dark GUI. Greenfield Go + React
implementation, inspired by Zoraxy, deployed as a single Docker Compose stack.

**Status:** implemented and released as `1.0.0`; `1.1.0` closes the remaining feature gaps
(credential rotation, decoy hostnames, event routing, CrowdSec status, CSV export, IP explorer).
**Plan version:** 1 (2026-11-19)

---

## 1. Goals

| # | Goal |
|---|------|
| G1 | Reverse proxy with Zoraxy-class features: HTTP/HTTPS, SNI routing, WebSocket, redirects/aliases, load balancing + health checks, caching, compression, access lists, mTLS, blacklists. |
| G2 | Modern dark GUI covering every feature; no config-file-only settings. |
| G3 | WAF (ModSecurity/CRS-compatible) with protection profiles and per-proxy modes. |
| G4 | IPS-style ban engine (fail2ban behaviour built in) + CrowdSec integration + open-source threat feeds. |
| G5 | Bot protection: rate limit → JS challenge → CAPTCHA → automatic blacklist. |
| G6 | DoS policies, attack/scan detection, global defaults + per-proxy overrides. |
| G7 | TLS: Let's Encrypt wildcard via DNS-01, per-proxy certificate assignment, auto-renewal. |
| G8 | Observability: inbound/outbound bandwidth per interface and per proxy, source IP, GeoIP, sessions, 7-day history. |
| G9 | Notifications: Telegram + Gmail/SMTP on day 1; Slack/Teams/WhatsApp later. |
| G10 | Admin TOTP 2FA always; optional per-proxy access gate (shared passphrase, or accounts + TOTP). |
| G11 | True blackhole/stealth mode (DROP, not REJECT) for banned traffic, scans and the bare apex hostname. |
| G12 | Live attack globe showing source → target arcs with attack classification. |
| G13 | Fingerprint hardening: no stack, version or internal-topology leakage in any response. |
| G14 | Optional per-proxy access gate with progressive IP bans and account lockout. |

## 2. Non-goals (v1.0)

- Multi-tenant or multi-user administration (single admin only; SSO/multi-user post-1.0).
- Full packet IPS (Suricata/Snort) — optional sidecar after 1.0, off by default.
- Kubernetes manifests, HA clustering, horizontal scaling.
- HTTP/3 (QUIC) termination — evaluated post-1.0.
- SMTP relay/server, DNS server, or certificate authority duties.

---

## 3. Deployment constraints

| Constraint | Decision |
|---|---|
| Runtime | Docker Compose (reference) or the same binary as a systemd service; single host. |
| Inbound ports | **443/tcp only.** No port 80 listener. No HTTP-01 by default. |
| Address binding | Configured in the setup wizard, not in YAML. `WAN_IP:443` and `LAN_IP` are explicit. |
| Network layout | Dual-homed VM: one interface on WAN (`192.168.191.0/24`), one on LAN (`192.168.101.0/24`). |
| Edge device | Firewalla `192.168.191.1` forwards 443 → `192.168.191.2:443`. DNAT only, **no SNAT**, so real client IPs are preserved. |
| Backends | `192.168.101.0/24`, reached with source IP `192.168.101.2`. |
| GUI exposure | LAN interface only by default (`192.168.101.2:8443`), never on WAN. |
| Wildcard movement | Never in `.env` by hand: written by the wizard to an encrypted settings store. |

### 3.1 Target topology

```
                    Internet
                       |
                 [ Firewalla ]
                 192.168.191.1
                       |  DNAT 443 -> 192.168.191.2:443  (no SNAT)
        ---------------- WAN 192.168.191.0/24 ----------------
                       |
                192.168.191.2  <-- WAF-Proxy WAN listener (443 only)
                       |
                 [ WAF-Proxy container ]
                  |                  |
        GUI 192.168.101.2:8443   egress 192.168.101.2
                       |
        ---------------- LAN 192.168.101.0/24 ----------------
             |                |                |
       192.168.101.10   192.168.101.11   192.168.101.12
          app-1            app-2           nas
```

Docker networking: two `macvlan` networks pinned to the physical interfaces, so the container owns
`192.168.191.2` and `192.168.101.2` directly and the firewall/backends see real L2 traffic.
`network_mode: host` remains a documented fallback for hosts where macvlan is unavailable
(e.g. some nested-virtualisation setups); the wizard detects and offers it.

### 3.2 Session / flow visibility

- Interface counters: `/sys/class/net/<iface>/statistics/*` sampled at 1 s.
- Sessions: `/proc/net/nf_conntrack` parsed for state counts, plus an in-process counter of active
  proxy connections per upstream. No packet capture required.
- KNOWN LIMITATION: with a single NIC, the WAN/LAN split collapses to combined totals. The UI
  labels the split as unavailable rather than inventing numbers.

---

## 4. Domain and TLS strategy

Base domain: `kendk.duckdns.org` (DuckDNS, dynamic A record).
Each proxy is a subdomain: `app.kendk.duckdns.org`, `wiki.kendk.duckdns.org`, …

### 4.1 What DuckDNS actually allows (verified)

- DuckDNS mirrors the A/AAAA **and** TXT records of `kendk.duckdns.org` to
  `*.kendk.duckdns.org`, so arbitrary subdomains resolve without extra records. This makes the
  subdomain scheme work.
- DuckDNS stores **exactly one TXT record per domain**, shared by all sub-subdomains. Two
  concurrent `_acme-challenge` validations therefore overwrite each other.
- Therefore: issue **one wildcard certificate** (`*.kendk.duckdns.org`) instead of per-hostname
  certificates when the provider is DuckDNS, and **serialise** ACME orders. The certificate manager
  enforces a single in-flight order per DNS zone for every provider, not just DuckDNS.
- Other providers (Cloudflare, Route53, DigitalOcean, Hetzner, OVH, GoDaddy) allow multiple TXT
  records, so per-hostname certificates also work there.

### 4.2 Apex blackhole — what is and is not possible

The apex `kendk.duckdns.org` must keep its A record, because that record is what DuckDNS mirrors to
the wildcard. It cannot be made to disappear at the DNS layer without breaking every subdomain.

So the apex is blackholed **at the proxy**:

- `Host: kendk.duckdns.org` (and any SNI that is not an enabled proxy) → immediate TCP close / 444,
  no body, no `Server` header, no redirect. The connection is logged as `unknown_host` and feeds
  scan detection.
- Unknown SNI never reaches an upstream and never gets a certificate.
- Optional: DNAT-drop the apex at the Firewalla as a second layer.

### 4.3 Honest note on attack surface

Random subdomains reduce opportunistic noise (broad IP scanners, `Host: localhost` probes, default
vhost scanners). They are **not** a secrecy boundary: every certificate is published to Certificate
Transparency logs, so `crt.sh` reveals all enabled subdomains. The real reduction comes from:
443-only exposure, no default vhost, DROP-by-default, per-proxy WAF profiles, and the ban engine —
not from unguessable names. The GUI will label it that way, so nobody relies on it for security.

### 4.4 Domain model

| Item | Value |
|---|---|
| Apex | `kendk.duckdns.org` — blackholed, no proxy may be created on it |
| Proxy hostnames | single-label subdomain only (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`) |
| Wildcard | `*.kendk.duckdns.org` reserved for the certificate; never a proxy name |
| Certificate default | `*.kendk.duckdns.org` + `kendk.duckdns.org` (SAN) |
| Override | per-proxy certificate from the same or another provider |

---

## 5. Architecture

### 5.1 Components (one Go binary + one SPA + two sidecars)

| Component | Responsibility |
|---|---|
| `proxy` core | Listeners, SNI/host router, reverse proxy, LB, caching, compression, access lists, mTLS. |
| `policy` engine | Ordered evaluation of allow/block lists before any routing. |
| `ban` engine | Temp/permanent bans, kernel sync via nftables, expiry, promotion, reasons. |
| `waf` | Coraza v3 + embedded OWASP CRS, profiles, rule overrides, audit events. |
| `intel` | Threat-feed loader, CIDR aggregation, anti-poisoning guardrails, IoC watch. |
| `botguard` | Rate-limit escalation, JS challenge, optional Turnstile/CAPTCHA, auto-blacklist. |
| `acme` | certmagic + libdns providers, wildcard issuance, renewal, per-proxy assignment. |
| `geo` | MaxMind/DB-IP lookup, country allow/block, globe coordinates. |
| `metrics` | Interface counters, conntrack sessions, 1 s buckets, retention/rollup. |
| `notify` | Telegram, SMTP, digest scheduler, dedupe/cooldown, alert history. |
| `api` | REST + WebSocket, session auth, TOTP, CSRF, audit log. |
| `store` | SQLite (WAL) migrations, encrypted secret columns. |
| `web` | React SPA, dark theme, charts, globe. |
| `crowdsec` (sidecar) | Scenarios/decisions, community blocklist, LAPI. |
| `geoip-update` (sidecar) | MMDB refresh (geoipupdate or DB-IP lite fallback). |

### 5.2 Request pipeline (strict order)

```
 0. kernel: nftables DROP set            (already-banned IPs, silent)
 1. whitelist: IP / CIDR / country       (always wins, per-proxy additions allowed)
 2. blacklist: country
 3. ASN policy                           (block hosting/VPS/cloud ASNs)
 4. decoy paths                          (/.env, /.git, /wp-login -> 404 + instant ban)
 5. feeds + IoC lists                    (block / challenge / log per feed)
 6. temp ban                             (from ban engine)
 7. permanent ban                        (from ban engine)
 8. DoS policy                           (per-IP + global + per-proxy rates)
 9. bot guard                            (JS challenge -> CAPTCHA -> blacklist after N fails)
10. access gate                          (passphrase or accounts + TOTP, if enabled)
11. WAF                                  (CRS, profile mode off/detect/block)
12. route -> load balance -> upstream
```

Rules:

- Per-proxy config may only make a decision **stricter** than global. It cannot un-ban, cannot
  whitelist over a global permanent ban, and cannot disable a global country blacklist.
- A whitelist entry is the only thing that can bypass a country/feed block, and doing so is logged
  at `WARN` with the entry ID.
- Every decision records `stage`, `rule`, `source`, `reason` so the GUI, logs and alerts agree.

### 5.3 Tech stack

| Layer | Choice | Why |
|---|---|---|
| Backend | Go 1.24+, `net/http`, `httputil.ReverseProxy`, custom SNI listener | Same class as Zoraxy; single static binary, low memory. |
| Proxy internals | `certmagic` + `libdns` providers | Mature ACME + renewal + storage; easy provider additions. |
| WAF | `coraza/v3` + embedded `coreruleset` | ModSecurity-compatible, pure Go, no nginx module build. |
| Bans | `nftables` set with per-element timeout + `google/nftables` | Temp bans expire in-kernel, no cron sweep. |
| Store | SQLite via `modernc.org/sqlite` | cgo-free static build, WAL concurrency. |
| Auth | `argon2id`, `pquerna/otp`, signed session cookies | No external IdP; TOTP by default. |
| Geo | `oschwald/maxminddb-golang` + DB-IP Lite fallback | Works without a MaxMind licence key on day 1. |
| Frontend | React 19 + TypeScript + Vite + Tailwind + TanStack Query | Fast dark SPA, no framework lock-in. |
| Charts | Recharts (bandwidth) + `globe.gl` / three.js (globe) | Canvas/WebGL, 60 fps at expected volume. |
| Realtime | WebSocket (events + metrics ticks) | Single multiplexed socket, token-authenticated. |

### 5.4 Repository layout

```
.
├── cmd/wafproxy/            main
├── internal/
│   ├── acme/  api/  ban/  botguard/  config/  geo/  intel/
│   ├── lb/    metrics/  notify/  policy/  proxy/  store/  version/
│   └── waf/
├── migrations/              SQLite migrations (embedded)
├── web/                     React SPA (Vite)
├── deploy/
│   ├── docker-compose.yml   production
│   ├── docker-compose.dev.yml
│   ├── crowdsec/            acquisition + scenarios
│   └── geoip/
├── docs/                    ops notes, runbooks
├── scripts/                 release.sh, bench.sh, seed-feeds.sh
├── PLAN.md  CHANGELOG.md  VERSION  Makefile  Dockerfile
```

---

### 5.5 Fingerprint hardening — what we hide, what we cannot

**Stripped or normalized on every response**

- `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`,
  `X-Drupal-Cache`, `X-Runtime`, `X-Varnish`, `Via`, `X-Cache`, `X-Debug-Token`, and upstream
  request IDs (the proxy generates its own).
- One canonical header set with fixed ordering and casing, identical for every upstream, so the
  header shape is not an oracle either.
- **Upstream errors are never forwarded.** `502/504` always return the generic proxy error page.
  Upstream IPs, hostnames, dial errors, stack traces and panic text are logged server-side only.
  This is the biggest leak of all: `dial tcp 192.168.101.10:8080: connect: refused` hands an
  attacker the entire internal layout.
- `Date` and any timing headers come from the proxy, not the backend.
- Stack-naming cookies (`PHPSESSID`, `JSESSIONID`, `laravel_session`, `wordpress_*`,
  `_django_session`) are rewritten to opaque names in `strict` fingerprint mode — opt-in per proxy,
  because it can break apps.

**Uniform responses**

- Every proxy-generated rejection uses the **same status, same body, same size**: unknown host,
  blocked IP, blocked country, banned, gate failure, WAF block. No `404` vs `403` oracle for path
  enumeration.
- Response-time floor plus jitter (25–60 ms) on rejections, so a fast in-memory deny is not
  measurably quicker than an allowed request.
- Constant-time credential comparison and a single failure message: no "user not found" vs
  "wrong password".
- `TRACE` disabled; `OPTIONS` answered by the proxy from a fixed allowlist; absolute-URI request
  targets rejected; duplicate/conflicting framing headers rejected.

**What cannot be fully hidden (documented, not pretended)**

- Certificates still come from Let's Encrypt, `JA3`/`JA4` still look like a Go TLS stack, and CT
  logs still publish every hostname. A determined attacker will identify this as a Go reverse proxy.
  The goal is removing *cheap* identification, not achieving invisibility.
- HTML meta generators, asset paths, API shapes and the app's own 404 pages live inside the app.
  The GUI flags detected markers (`X-Powered-By`, `PHPSESSID`, WordPress paths) and tells the
  operator where to fix them at the source.
- Optional response-body rewriting (generator tags, version strings) exists but is **off by
  default**: it buffers responses, costs CPU, and can corrupt compressed or signed content.

**Fixed header profile** (uniform, so the set is not itself a fingerprint)

`Strict-Transport-Security` (only on HSTS-eligible proxies), `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, minimal `Permissions-Policy`, `Cross-Origin-Opener-Policy:
 same-origin`. CSP is per-proxy opt-in because it breaks apps.

**TLS policy**

TLS 1.2 minimum with 1.3 preferred, modern cipher suites, `ALPN h2,http/1.1`, session tickets
rotated (or disabled), OCSP stapling, renegotiation disabled, no 0-RTT by default (replay risk).

---

## 6. Data model (SQLite, WAL)

| Table | Key columns |
|---|---|
| `users` | id, username, password_hash (argon2id), totp_secret_enc, created_at |
| `sessions` | id, user_id, ip, ua, csrf, expires_at, last_seen |
| `settings` | key, value_enc, updated_at (network bindings, ACME account, master-key-wrapped values) |
| `dns_credentials` | id, provider, label, creds_enc, created_at |
| `certificates` | id, domains, wildcard, provider_id, status, issued_at, expires_at, key_enc |
| `proxies` | id, hostname, enabled, cert_id, profile_id, totp_enabled, totp_secret_enc, notes |
| `upstreams` | id, proxy_id, url, weight, health_state, last_check_at, last_latency_ms |
| `routes` | id, proxy_id, kind (proxy/redirect/alias), match, target, strip_prefix, headers_json |
| `protection_profiles` | id, name, crs_paranoia, mode, rule_overrides_json, bot_level, rate_policy_json |
| `policies` | id, scope (global/proxy), proxy_id, kind (ip/country/feed), list_json, action, priority, enabled |
| `bans` | id, ip_or_cidr, reason, source, permanent, hits, created_by, created_at, expires_at |
| `feeds` | id, name, url, format, action, interval_s, enabled, etag, last_fetch_at, last_count, state |
| `feed_matches` | day, feed_id, hits (rollup; raw matches live in `events`) |
| `events` | ts, proxy_id, src_ip, src_country, method, host, path, status, bytes_in, bytes_out, latency_ms, stage, rule_id, rule_msg, action |
| `metrics_1s` | ts, iface, rx_bps, tx_bps, rx_pps, tx_pps |
| `metrics_rollup` | hour, proxy_id, reqs, bytes_in, bytes_out, blocked |
| `alerts` | id, channel, kind, payload_json, state, attempts, sent_at, dedupe_key |
| `audit_log` | id, user_id, action, detail_json, ip, ts |

Retention: `events` 7 days (configurable 1–30), `metrics_1s` 24 h then hourly rollups,
`audit_log` 90 days. A nightly job rolls up and vacuums; disk usage is shown in the GUI.

Indexes: `events(ts)`, `events(src_ip, ts)`, `events(proxy_id, ts)`, `events(stage, ts)`,
`bans(ip_or_cidr)`, `bans(expires_at)`.

---

## 7. Phases

Ten phases, ten releases: Phase 0 ships `0.1.0`, and each completed phase bumps the minor version up
to `1.0.0` at Phase 9. Fixes and small add-ons inside a phase bump the patch number
(`0.4.1`, `0.4.2`). See §8 for the release contract.

| Phase | Version | Theme |
|---|---|---|
| 0 | 0.1.0 | Foundation, setup wizard, admin auth |
| 1 | 0.2.0 | Proxy core (Zoraxy parity) |
| 2 | 0.3.0 | TLS / ACME / wildcard certs |
| 3 | 0.4.0 | Policies, bans, blackhole, GeoIP, netflow |
| 4 | 0.5.0 | WAF + protection profiles |
| 5 | 0.6.0 | Threat intel feeds + IoC watch |
| 6 | 0.7.0 | CrowdSec + bot protection |
| 7 | 0.8.0 | Observability + attack globe |
| 8 | 0.9.0 | Notifications |
| 9 | 1.0.0 | Access gate, backup/restore, hardening |

---

### Phase 0 — Foundation `0.1.0`

**Build**

- Repo skeleton per §5.4; `go.mod`; Vite + React + TS + Tailwind with the dark design system
  (tokens, spacing, table/form primitives, empty states, toasts).
- `Dockerfile` (multi-stage → distroless), `deploy/docker-compose.yml`, dev compose with hot reload,
  `Makefile` (`dev`, `build`, `test`, `lint`, `release`), `.env.example`.
- SQLite store + embedded migrations + `settings` KV.
- **Setup wizard (first run, 4 steps):**
  1. Network: detect interfaces, propose `WAN 192.168.191.2 :443`, `LAN egress 192.168.101.2`,
     GUI bind `LAN only :8443`; validate that the WAN IP exists on an interface and 443 is free.
  2. Domain: base domain (`kendk.duckdns.org`), DuckDNS token (stored encrypted), subdomain rules.
  3. Admin: username, argon2id password, TOTP enrolment (QR + recovery codes).
  4. Review: writes settings, prints the one-time bootstrap token to the container log.
- Auth: login, TOTP verify, session cookie (`HttpOnly`, `SameSite=Lax`, `Secure`), CSRF token,
  login rate limit (5/min/IP), idle + absolute timeout, logout-all.
- API: `/api/health`, `/api/version`, `/api/setup/*`, `/api/auth/*`; structured JSON logs.
- Shell UI: nav (Policies, Proxies, Certificates, Live, Logs, Settings), version in footer.
- Release tooling: `VERSION` file, `internal/version` via `-ldflags`, `scripts/release.sh`,
  CHANGELOG format, CI guard that a push to `main` changes `VERSION` + CHANGELOG.

**Done when** — fresh `docker compose up -d` on a clean host → wizard completes in the browser →
login requires TOTP → `curl /api/version` reports `0.1.0` → container runs as non-root and answers
only on the configured addresses.

---

### Phase 1 — Proxy core `0.2.0`

**Build**

- SNI + `Host` router; HTTP/1.1 and HTTP/2; TLS termination (temporary self-signed until Phase 2);
  WebSocket and upgrade passthrough; keep-alive tuning; request/response streaming.
- Upstream pools: round-robin, least-connections, weighted; active health checks (interval, timeout,
  expected status) + passive ejection with recovery; retry budget; per-route timeouts.
- Routes: proxy, 301/302 redirect, alias, path prefix strip/rewrite, header add/set/remove.
- Compression (gzip, brotli) with content-type and min-size rules; response caching (memory, optional
  disk) with `Cache-Control`/`Vary` respect and per-proxy TTL.
- Access control: IP/CIDR allow lists, HTTP basic auth, mTLS client-certificate verification.
- GUI: proxy CRUD (hostname → upstreams → TLS → profile → advanced), route editor, live upstream
  state badges, per-proxy request/session counters, config validation before save, dry-run diff.
- Apex and unknown-SNI handling staged here: TCP close, logged as `unknown_host` (used in Phase 3).

**Done when** — `app.kendk.duckdns.org` serves HTTPS with WebSocket to two backends, one killed
mid-traffic fails over in <2 s, redirects and path rewriting work, and no response leaks
`Server`/`X-Powered-By`.

---

### Phase 2 — TLS, ACME, certificates `0.3.0`

**Build**

- certmagic store in SQLite (`certificates.key_enc`), account key creation, staging toggle.
- DNS-01 as default (443-only); HTTP-01 available but off unless the operator enables a port-80 listener.
- Providers via `libdns`: Cloudflare, DuckDNS, Route53, DigitalOcean, Hetzner, OVH, GoDaddy,
  RFC2136 (generic), plus a manual DNS fallback that shows the TXT value to paste.
- Single in-flight order **per DNS zone**; on DuckDNS force the wildcard certificate
  (`*.kendk.duckdns.org` + apex SAN) because only one TXT record exists.
- Per-proxy certificate assignment (wildcard default, per-hostname override), auto-renew at 30 days,
  exponential retry, expiry warnings at 14/7/3/1 days.
- GUI: Certificates page (domain, SANs, issuer, expiry, status, provider, last error, force-renew,
  download fullchain), assignment dropdown inside the proxy editor, provider credential manager.
- Hot reload of renewed certificates without dropping connections.

**Done when** — wildcard certificate is issued for `kendk.duckdns.org` via DuckDNS DNS-01, assigned
to two proxies, survives a forced renewal, renews on schedule, and a failed challenge surfaces an
actionable error (not just "ACME failed").

---

### Phase 3 — Policies, bans, blackhole, GeoIP, netflow `0.4.0`

This is the phase that implements the "policies on top, proxies after" model.

**Build**

- Policy engine with priority + scope (global / proxy), full evaluation order from §5.2.
- Ban engine: temp bans (TTL, hit counter, auto-promotion at threshold), permanent bans, promotion
  and unban actions, mandatory `reason` field, `source` (`scan`, `waf`, `bot`, `crowdsec`, `feed`,
  `manual`), full audit.
- Kernel enforcement: nftables set `wafproxy_block` with per-element timeout, IPv4 + IPv6, synced on
  change and on start; `DROP` (no RST, no ICMP unreachable). Degrades to proxy-level blocking with a
  visible warning if `NET_ADMIN`/nftables is unavailable.
- Stealth settings: `drop not reject`, `ignore WAN ICMP echo`, `close unknown hosts`, `tarpit scanners`
  (hold scan sockets 10 s, configurable, capped concurrency).
- GeoIP: DB-IP Lite bundled/auto-updated by default, MaxMind GeoLite2 optional with licence key;
  country block list, country allow-list mode, per-proxy extras, test-IP → country resolver in the UI.
- **ASN policy**: block traffic from hosting/VPS/cloud ASNs, which is where most commodity scanners
  live. Ship a curated default list, allow one-click toggling, and a per-proxy override. For a
  friend-group deployment with residential/mobile users this removes the bulk of bot noise *before*
  the WAF is reached.
- **Decoy paths**: `/.env`, `/.git/*`, `/wp-login.php`, `/wp-admin`, `/phpmyadmin`,
  `/server-status`, `/actuator/*`, `/config.php.bak`, `/.aws/credentials` → uniform `404` **and an
  instant permanent ban** with `source=decoy`. No legitimate user of these apps ever requests them.
- **Sensitive-path deny list** (configurable, no auto-ban): VCS metadata, editor droppings,
  backups, `server-status`, `phpinfo`.
- **IPv6 parity**: bans, country policy, ASN policy and feeds all cover IPv6 — the nftables set holds
  both address families. Scanners reach IPv6 just as easily; an IPv4-only ban engine is a bug.
- **Per-proxy IP allowlist mode**: "only these IPs/CIDRs may connect" for apps that never leave the
  house. Default off, one click on.
- **Emergency unban**: bans never apply to the LAN GUI listener, and
  `docker exec wafproxy unban <ip>` exists for total lockout recovery.
- Dual-NIC netflow: per-interface bps/pps at 1 s, WAN/LAN split, conntrack session counts by state,
  per-proxy active sessions, 24 h in-memory ring + hourly rollups.
- GUI: **Policies** section first in the nav —
  `Feeds` (Phase 5 placeholder), `Temp Bans`, `Permanent`, `Countries`, `Stealth` —
  then **Proxies**. Ban tables show IP/CIDR, reason, source, hits, age, expiry, actions; filter by
  source/state; bulk unban; import/export permanent list as text (one CIDR per line).
- Promoted autobans and manual entries both write to the permanent file surfaced in the GUI.

**Done when** — a manually banned IP gets no response at all (verified with `curl` timeout and
`nmap` showing `filtered`), the ban row shows reason + source, country blocking works on the live
path, a whitelisted IP passes a blocked country, and WAN/LAN graphs show distinct values on a
dual-NIC host.

---

### Phase 4 — WAF and protection profiles `0.5.0`

**Build**

- Coraza v3 + embedded OWASP CRS; per-proxy mode `off / detect / block`.
- Protection profiles (shipped, editable, cloneable): **Generic Web**, **WordPress**, **API-only**,
  **Static / CDN**, **Admin panel (strict)**. Each carries paranoia level, anomaly threshold,
  enabled rule groups, allowed methods, body size limit, and per-rule exceptions.
- Rule overrides per proxy: disable rule IDs with a required justification, list them on the proxy page.
- **Request smuggling defenses**: reject `Content-Length` + `Transfer-Encoding` together,
  duplicate or conflicting length headers, invalid chunk framing, and whitespace before a header
  colon. Cap header count/size and enforce a header read timeout. This is a proxy-specific risk and
  belongs here, not only in CRS.
- **Host header hygiene**: strict hostname validation against configured proxies, ignore
  `X-Forwarded-Host`/`Forwarded` for routing, reject absolute-URI request targets and route confusion.
- **Method allowlist** per proxy: `GET/HEAD/POST` by default; `PUT/DELETE/PATCH/PROPFIND` opt-in.
- **Body and concurrency caps**: max request body, per-IP concurrent connections, slow-client
  (slowloris) timeouts, per-IP bandwidth quota.
- **Detect-first onboarding**: new proxies start in `detect` for 48 h, then the GUI recommends the
  profile that fits the observed traffic; switching to `block` is one click.
- **Upstream SSRF guard**: upstream targets may not resolve to loopback, link-local or cloud
  metadata addresses (`169.254.169.254`) unless explicitly allowed with a warning.
- Attack classification: map CRS rule IDs to human labels used by logs, alerts and the globe —
  `php-injection`, `unix-shell`, `sqli`, `xss`, `lfi`, `rce`, `scanner`, `protocol-violation`,
  `session-fixation`, `ssrf`, `log4shell`, `webshell`.
- Audit events written to `events` with `stage=waf`, matched rule, severity, and a truncated
  (1 KB, secrets redacted) request snippet.
- GUI: Protection Profiles page, WAF hits table with filters, per-proxy mode selector, false-positive
  workflow ("this rule is wrong for this path" → pre-filled exception).

**Done when** — a PHP webshell payload is blocked with `403` and logged as `php-injection`; the same
payload in `detect` mode passes through but is recorded; enabling the WordPress profile on a
WordPress backend produces no false positives on login, admin and REST endpoints.

---

### Phase 5 — Threat intel and IoC watch `0.6.0`

**Build**

- Feed loader: HTTP GET with `ETag`/`If-Modified-Since`, gzip, timeout, retry with backoff, size cap;
  parse `ip`, `cidr`, and `host` lines; skip comments/blank; dedupe + CIDR aggregation; atomic swap
  of the in-memory table so requests never see a half-loaded list; last-good list retained on failure.
- Built-in sources (individually toggleable): FireHOL L1/L2, Spamhaus DROP + EDROP, Tor exit list,
  EmergingThreats compromised, Feodo Tracker, URLhaus hosts, DShield low-port scanners,
  AI-crawler/scraper list.
- Custom URL feeds with per-feed interval (5 min – 24 h) and action (`block / challenge / log`).
- AbuseIPDB: optional, API key, **daily** fetch of the blacklist only (never per-request lookups);
  displayed as enrichment with confidence score.
- Anti-poisoning guardrails: freeze a feed and alert if its size grows >5× in one refresh, if it
  matches >10% of recent traffic, or if it would block >1000 distinct client IPs/hour.
- **Decoy hostnames**: an optional extra hostname on 443 (e.g. `admin.kendk.duckdns.org`) serving a
  fake admin login that never accepts credentials, feeding every hit straight into the ban engine.
- **Threat Intel page** (`Policies > Threat Intel`): per-source status (size, last refresh, next
  refresh, matches 24 h, state), IoC match feed, "promote match to ban", custom-feed editor,
  test-an-IP box showing which list matches and why.
- Memory/observability: `/api/intel/stats` (entries, bytes, load time, match rate) shown in the GUI.

**Done when** — 100k+ entries across three feeds load in <200 ms with no request stalls, a matching
request is blocked and logged with its feed name, a simulated poisoned feed is frozen instead of
applied, and a feed outage keeps serving the last-good list.

---

### Phase 6 — CrowdSec and bot protection `0.7.0`

**Build**

- `crowdsec` sidecar + Go bouncer: LAPI decisions streamed and applied as bans (`source=crowdsec`),
  community blocklist subscribed by default, `cscli` status mirrored read-only in the GUI.
- Acquisition: the proxy's JSON access/audit log, tailed by CrowdSec with custom parsers so scenarios
  see hostname, path, status and WAF verdict.
- Scenarios enabled: HTTP 404 scan, HTTP probing, HTTP brute-force (login paths), crawl-non-statics,
  plus a custom "WAF-blocked burst" scenario.
- Bot guard: per-proxy level `off / light / standard / aggressive`; JS challenge (proof-of-work-lite,
  cookie for 24 h), optional Cloudflare Turnstile or self-hosted CAPTCHA, verified-crawler allowlist
  (reverse-DNS + forward-confirmed Googlebot/Bingbot), auto-blacklist after N failures in T min.
- Challenge page: dark, tiny (<8 KB), no external assets, accessible, no fingerprint harvesting.
- GUI: Bot Protection settings, challenge pass/fail stats, "why was this challenged" explainer,
  allow/deny lists for user agents and paths.

**Done when** — a CrowdSec decision blocks the IP within seconds; a real browser passes the challenge
in one step while `curl` gets the challenge page; repeated failures promote to a ban visible in
`Temp Bans` with `source=bot`; verified Googlebot is never challenged.

---

### Phase 7 — Observability and attack globe `0.8.0`

**Build**

- Retention engine: `events` 7 days default (1–30 configurable), 1 s metrics → hourly rollups after
  24 h, nightly vacuum, disk-usage card with a hard-stop threshold.
- Dashboards: WAN/LAN in/out bps + pps, total and per-proxy requests, blocked vs allowed, top source
  IPs, top countries, top attacked hostnames, top WAF rules, latency p50/p95, active sessions.
- Source-IP explorer: per-IP timeline (requests, bytes in/out, verdicts, countries, ASN optional),
  one-click ban/whitelist.
- **Attack globe**: WebGL globe with arcs from attacker country → your WAN location for the last 60 s,
  colour-coded by category (WAF block, bot fail, DoS limit, country block, ban hit), capped at 200
  concurrent arcs, click → attack detail (full request, matched rule, payload excerpt, action buttons).
  Streams over the existing WebSocket; falls back to a flat map under `prefers-reduced-motion` or
  without WebGL.
- Search: filter by time range, proxy, IP, country, status, stage, rule, verdict; CSV export.
- Performance guard: event ingest batched (500 rows or 250 ms), globe aggregation server-side so the
  browser receives ≤5 messages/s regardless of attack volume.

**Done when** — 1000 events/min ingest without drops, globe holds 60 fps with 200 arcs, a 7-day
filtered query returns in <300 ms, and rollups keep the DB under a stable size.

---

### Phase 8 — Notifications `0.9.0`

**Build**

- Channels: **Telegram** (bot token + chat ID, HTML formatting) and **SMTP/Gmail** (host, port,
  STARTTLS, app password, from/to). Slack and Teams webhooks ship as disabled-by-default extras
  (same webhook code path as Telegram, ~1 file each); WhatsApp deferred.
- Event routing matrix: ban added, permanent ban added, feed frozen, certificate expiring/failed,
  CrowdSec decision burst, proxy/upstream down, service started, disk threshold.
- **Digest-first delivery**: feed/autoban additions batched every 5 minutes into one message
  (`14 new bans: 1.2.3.4 (scan), …` + GUI link). Instant delivery only for permanent bans, certificate
  failures, feed freezes and upstream-down. Dedupe per IP per 24 h, per-event cooldown, retry with
  backoff, per-channel rate limit.
- GUI: channels page with "send test", per-event toggles, delivery history, failed-send inspector,
  secret fields write-only (never returned by the API).

**Done when** — a burst of 50 autobans produces exactly one digest message, a permanent ban arrives
instantly, a bad SMTP password shows a clear failure in the UI without leaking the secret, and a
revoked Telegram token degrades gracefully with retries.

---

### Phase 9 — Access gate, backup, hardening `1.0.0`

**Build**

- **Access gate (built-in forward auth)**, off by default, enabled per proxy:
  - Modes: `shared passphrase` (one secret for the friend group), `accounts` (username +
    argon2id + optional per-user TOTP), or `accounts + TOTP required`.
  - Login page served by the proxy on the proxy's own hostname — dark, tiny, no external assets,
    no stack markers. Cookie scoped to that hostname only, `HttpOnly`/`Secure`/`SameSite=Lax`,
    configurable TTL, "remember this device" with a rotating token.
  - Per-proxy user allowlist: only listed accounts may enter that proxy; one account can span
    several proxies with independent sessions.
  - Auth endpoints get their own tighter limits (5/min/IP, 20/min/account), separate from the
    global DoS policy.
  - **Escalation ladder (defaults):** 3 failures from an IP in 10 min → 15 min temp ban;
    10 failures in 24 h → 24 h ban; the same IP offending across 3+ distinct days → permanent ban
    with notification. Account-level lockout after 5 failures in 15 min, which stops credential
    stuffing even when the attacker rotates IPs.
  - **Immediate permanent ban only** for decoy-path hits and confirmed feed/CrowdSec matches.
  - Why not 3 strikes → permanent: mobile and CGNAT clients share IPs with strangers, so an
    IP-based permanent ban hits innocent people — sometimes another friend behind the same carrier
    NAT — and three fat-fingered password attempts would lock you out of your own app. The ladder
    reaches the same outcome for real attackers without that blast radius.
  - Recovery: every ban is liftable from the LAN GUI, the GUI listener is exempt from bans, the CLI
    can unban on a fully locked-out host, and TOTP has one-time recovery codes.
- Backup/restore: encrypted archive (SQLite, certificates, settings, permanent ban list, feed config);
  restore with schema migration; export/import of permanent bans as plain text.
- Upgrade path: schema migrations with rollback notes, `VERSION` check on boot, UI warning on
  version/schema mismatch.
- Hardening pass: non-root container, read-only root FS except the data volume, capability drop
  (`NET_ADMIN` only when stealth is enabled), no secrets in logs, redaction tests, CSP + security
  headers on the GUI, dependency audit, `govulncheck`, `npm audit`.
- Docs: install, Firewalla/DuckDNS walkthrough, hardening checklist, troubleshooting, capacity guide.
- Benchmarks: requests/s, added latency with WAF on/off, memory at 1k/5k rps, feed match cost,
  ban lookup cost. Published in `docs/BENCHMARKS.md`.

**Done when** — the gate protects exactly one proxy in `accounts + TOTP` mode while others stay open;
three bad logins produce a 15-minute temp ban and a notified row (not a permanent ban); three decoy
hits produce instant permanent bans; a locked-out friend is unbanned from the LAN GUI in under a
minute; a backup taken on 1.0.0 restores onto a clean host; the container runs without root and with
a read-only root FS; the benchmark table is filled with real numbers.

---

## 8. Versioning and release contract

Format: `MAJOR.MINOR.PATCH` (SemVer).

| Change | Bump | Example |
|---|---|---|
| Phase completed / shipped feature set | **MINOR** | `0.4.0` → `0.5.0` |
| Fix or add-on inside a shipped phase | **PATCH** | `0.4.0` → `0.4.1` |
| Breaking config/schema/API change | **MINOR** (pre-1.0) / **MAJOR** (post-1.0) | `1.0.0` → `1.1.0` |

Rules:

1. `VERSION` is the single source of truth. Nothing merges to `main` without bumping it.
2. Every `main` push carries a matching `CHANGELOG.md` section and an annotated git tag `vX.Y.Z`.
3. Phase boundaries are the only place MINOR bumps happen; everything else is PATCH.
4. Pre-release suffixes (`-rc.1`) are for branches only, never for `main`.
5. The version is compiled in (`-ldflags -X …/internal/version.Version`), exposed at `/api/version`,
   printed in the UI footer and in `/api/health`, and set as the `org.opencontainers.image.version`
   label so `docker inspect` agrees with the GUI.
6. Container tags per release: `X.Y.Z`, `X.Y`, `latest`. `latest` only ever points at a `main` tag.
7. The release script refuses to run on a dirty tree, a version already tagged, or a missing
   CHANGELOG entry.

Release flow per phase:

```
git switch -c phase-N-<theme>
# build + tests + docs
./scripts/release.sh 0.N.0     # bumps VERSION, opens CHANGELOG section, builds image
git commit -am "release: 0.N.0 — <theme>"
git tag -a v0.N.0 -m "0.N.0 <theme>"
git push origin HEAD:main --follow-tags
```

---

## 9. Resource budget (target: small home/lab host)

| Item | Idle | Under load | Notes |
|---|---|---|---|
| Go proxy + API | 80–150 MB | +40–60 MB per 1k rps | TLS + WAF included |
| Feed table (100k entries) | 5–15 MB | — | 1M ≈ 30–50 MB |
| WAF (Coraza + CRS) | 20–40 MB | +5–10% CPU at 1k rps | per-proxy profiles compiled once |
| nftables set (200k) | ~15 MB kernel | O(1) lookup | temp bans expire in-kernel |
| SQLite (7 days) | — | 0.5–2 GB disk | depends on volume + retention |
| CrowdSec sidecar | 60–120 MB | +5% CPU | optional in dev |
| GeoIP MMDB | 60–120 MB disk | shared mmap | DB-IP Lite or GeoLite2 |
| SPA (browser) | 40–80 MB | globe +GPU | fallback map without WebGL |
| **Stack total** | **~300–600 MB RAM** | **1–2 vCPU** | excludes Suricata (not in v1) |

Deliberately excluded from v1: Suricata/Snort full packet IPS. It needs packet capture, elevated
capabilities, 500 MB–2 GB+ RAM and continuous ruleset churn. The ban engine + Coraza + CrowdSec cover
the same threats for a fraction of that; Suricata remains an optional post-1.0 sidecar.

---

### 9.1 Host sizing — 2–4 vCPU / 8 GB RAM / 50 GB disk

**Verdict: yes, comfortable.** Recommended floor is 2 vCPU / 4 GB / 30 GB; this spec is the
sweet spot for a home/lab edge proxy.

| Resource | Why this is enough |
|---|---|
| **vCPU** | 2 vCPU handles steady home-lab traffic (hundreds of rps, bursts of a few thousand during a scan). 4 vCPU is worth having because TLS handshakes, CRS evaluation and DoS bursts are spiky — protection must keep working *during* the burst, not after it. |
| **RAM** | Stack steady state is 300–600 MB. The surplus is best spent on page cache (SQLite reads) and on absorbing CrowdSec/globe bursts. Set container limits so the kernel OOM killer never targets the proxy. |
| **Disk** | 50 GB is ample with 7-day retention; see the breakdown below. |

Disk estimate, 50 GB budget:

| Item | Size |
|---|---|
| OS (Ubuntu minimal) | 6–12 GB |
| Images + overlays (app, CrowdSec, GeoIP updater) | 1–2 GB |
| SQLite `events`, ~1M rows/day × 7 days | 5–10 GB |
| JSON access logs, 7 days gzip | ~1 GB |
| GeoIP MMDB (current + previous) | ~0.25 GB |
| CrowdSec database | < 0.5 GB |
| Encrypted backups (events excluded) | 0.5–1 GB |
| Build cache / headroom | remainder |

Host requirements and tuning:

- **SSD/NVMe mandatory** — SQLite WAL is random-I/O bound. Local ext4/xfs, not NFS or SMB.
- Put the data volume on its own path so it can be grown independently of the OS.
- Enable the Phase 7 disk-threshold guard: above the limit, sample *allowed* requests (blocked
  requests stay fully audited) rather than dropping events silently.
- Exclude `events` from backups, or every backup becomes multi-GB. Back up settings, certs and
  permanent bans instead.
- `docker builder prune` after image builds; build cache is the most common way a 50 GB disk fills.
- Raise `net.netfilter.nf_conntrack_max` to 262144 (and `nf_conntrack_buckets` to 65536) on an 8 GB
  host. The default 65536 entries can be exhausted by a scan flood, which then looks like an outage.

What would outgrow this VM: full packet capture (Suricata/pcap), sustained event volume above
~10M/day, or running the SPA build toolchain on the same host as production.

## 10. Security model

- Single admin, argon2id password, TOTP required at login, recovery codes shown once.
- Sessions: `HttpOnly`, `Secure`, `SameSite=Lax`, rotating CSRF token, absolute + idle expiry,
  "log out everywhere".
- GUI binds to the LAN address only; the wizard refuses to bind the admin UI to the WAN address
  without an explicit confirmation + warning.
- Secrets (DuckDNS token, DNS provider credentials, SMTP password, Telegram token, TOTP secrets)
  encrypted at rest with AES-256-GCM using a master key from `MASTER_KEY`; write-only in the API.
- Container: non-root, read-only root filesystem, `NET_ADMIN` granted only when stealth enforcement
  is enabled, no `SYS_ADMIN`, no host PID namespace.
- Default-deny: no default vhost, unknown SNI closed, apex blackholed, DROP not REJECT.
- Every admin mutation is written to `audit_log` with actor, IP and before/after payload.
- No telemetry, no phone-home, no outbound traffic except the feeds/providers/notification endpoints
  the operator configured.

---

## 11. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| DuckDNS single TXT record | Concurrent ACME challenges fail | One wildcard cert, serialised orders per zone |
| Apex cannot be DNS-blackholed | Apex resolves to WAN IP | Proxy-level close for apex/unknown SNI + optional Firewalla drop |
| CT logs expose subdomains | Subdomain scheme is discoverable | Treated as noise reduction, not secrecy; rely on WAF/ban/stealth |
| Scanners hitting every IP:443 | Constant noise | DROP default, no default vhost, feeds, CrowdSec |
| CRS false positives break apps | Outage | `detect`-first workflow, profiles, per-rule exceptions, one-click report |
| nftables unavailable in container | Bans only at proxy layer | Detect at boot, warn in GUI, document `NET_ADMIN` + host `nft` requirement |
| macvlan unsupported (nested virt) | Can't bind two IPs | Wizard detects, offers `network_mode: host` fallback |
| 7-day event table outgrows disk | Host fills up | Rollups, sampling for allowed requests, disk threshold alarm + ingest pause |
| Feed poisoning / bad list | Self-inflicted outage | Size/spike/match-rate guardrails, freeze + alert, last-good retention |
| CGNAT/shared IPs make IP bans punish bystanders | Friends locked out, support burden | Escalation ladder, account-level lockout, LAN unban, per-proxy allowlists |
| Fingerprint hardening breaks an app (cookie rename, body rewrite) | Broken app | Both opt-in per proxy, with a one-click revert |
| WAF only inspects the first N KB of a body | Large uploads carry uninspected payloads | Per-proxy upload cap, documented inspect limit, streaming scan for multipart |
| Access gate treated as the only defence | Vulnerable app stays vulnerable | Gate is additive; WAF and patching still required; GUI states this next to the toggle |
| LE rate limits | Failed issuance blocks new proxies | Staging toggle, per-zone serialisation, cached wildcard reuse |

## 12. Decisions locked

All open questions are resolved. These are the defaults the implementation follows; every one is
operator-changeable in the GUI unless marked "fixed".

| # | Decision |
|---|---|
| D1 | DNS providers ship in this order: DuckDNS, Cloudflare, Route53, DigitalOcean, Hetzner, OVH, GoDaddy, RFC2136, manual. DuckDNS issues one wildcard certificate because of its single-TXT limitation. |
| D2 | GeoIP default is DB-IP Lite (no licence key required); MaxMind GeoLite2 is opt-in via key. Without any MMDB, country/ASN policy is reported **unavailable** in the GUI — never silently allowed. |
| D3 | The attack globe is on by default with a reduced-motion / no-WebGL fallback map. |
| D4 | Event retention: full audit for every blocked request; above 500 rps the *allowed* requests are sampled 1:10, with the sample rate stored per row so dashboards scale correctly. |
| D5 | Backups are a local encrypted download only. S3-compatible targets are post-1.0. |
| D6 | Ban escalation is the ladder in Phase 9; **3 failures never means a permanent ban**. Account lockout runs in parallel with IP bans. |
| D7 | Decoy-path hits (`/.env`, `/.git`, `/wp-login.php`, …) are an instant permanent ban — fixed behaviour, no legitimate traffic can trigger it. |
| D8 | ASN blocking defaults to **on with a curated hosting/VPS/cloud list**, since the target users are residential/mobile. Per-proxy override available. |
| D9 | Fingerprint mode defaults to `strict` on new proxies, with the header profile in §5.5. Cookie renaming and body rewriting stay opt-in. |
| D10 | The access gate is per-proxy and off by default; `accounts + TOTP` is the recommended mode shown first in the UI. |
| D11 | The admin GUI is LAN-only and exempt from all bans. `docker exec` unban is always available. |
| D12 | Phase 9 ships `1.0.0`. Anything after that follows the backlog, with PATCH bumps for fixes. |

## 13. Post-1.0 backlog

- Slack, Teams and WhatsApp channels (Twilio / WhatsApp Business API).
- Suricata sidecar as an optional IDS/IPS with its own resource profile.
- Multi-user with roles, OIDC/SSO (Authelia, Authentik, Pocket ID).
- eBPF per-flow telemetry replacing `/proc/net/nf_conntrack` parsing.
- HTTP/3 (QUIC), per-upstream circuit breakers, canary routing.
- HA pair with configuration replication, or config-as-code export/import.
- WASM/Lua plugin hooks for custom request logic.
- JA4/TLS-fingerprint blocklist for known scanner toolkits.
- Encrypted Client Hello once the DNS provider supports HTTPS records.
- Public status page and per-proxy analytics share links.
