# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

**Release convention**

- `MAJOR.MINOR.PATCH`, tracked in `VERSION` (single source of truth).
- Each completed plan phase bumps **MINOR**: `0.1.0` → `0.2.0` → … → `1.0.0`.
- Fixes and add-ons inside a shipped phase bump **PATCH**: `0.4.1`, `0.4.2`.
- Every push to `main` has a matching section here and an annotated tag `vX.Y.Z`.

## [1.1.1] — 2026-11-19

Fixes the decoy defaults that could ban real users, closes a round of security gaps, and
adds Plex forwarding as an add-on inside the 1.1 series.

### Added

- **Streaming forwarding** (`Streaming` page, `GET /api/streaming`,
  `PUT /api/streaming/{id}`): one transparent TCP relay per media application, with a section
  for **Plex** (`32400`) and **Jellyfin** (`8096`) and room for more through the catalog. Each
  relay binds its own WAN address and port on save, supports a source-CIDR allowlist and a
  concurrent-connection cap, and reports live counters plus the last error. Because TLS
  passes straight through, the server's own certificates keep working and it sees every
  client as the proxy's LAN address — the single entry its whitelist needs.
- `POST /api/system/restart` and a restart button on the Plex page. It exits the process so
  the container's restart policy rebuilds the listeners; host networking needs no port
  publishing, so saving the forwarder alone is normally enough.
- The Plex settings are mirrored into the compose env file (`PLEX_ENABLED`, `PLEX_PORT`,
  `PLEX_LISTEN_IP`, `PLEX_UPSTREAM`) when `WAFPROXY_ENV_FILE` or `deploy/.env` is visible.
  Merging preserves comments and unrelated keys, and a missing file is reported in the UI
  rather than failing the save.
- `urlguard` package: one place that validates outbound URLs (proxy upstreams, threat feeds,
  notification webhooks), refusing non-HTTP schemes and literal cloud metadata endpoints
  including the IPv6 and `0.0.0.0` spellings.
- `safepath` package: shared post-login redirect sanitiser used by both the access gate and
  the bot challenge, so the two cannot drift apart again.
- Docs: streaming firewall and per-application whitelist walkthrough (Plex, Jellyfin) in
  `docs/INSTALL.md`, decoy and streaming honesty notes in the README, `PLEX_*`/`JELLYFIN_*`
  and `WAFPROXY_ENV_FILE` documented in `.env.example`. The README was rewritten with a
  dashboard screenshot, a complete feature map and a quick start that matches the shipped
  compose file.
- The compose file now passes `WAFPROXY_LISTEN_GUI` and `WAFPROXY_LISTEN_WAN` from
  `deploy/.env` into the container. The README told first-boot users to set the GUI listener
  to a LAN address, but the compose file never forwarded the variable, so the instruction had
  no effect.
- Removed the unused `/api/dns/providers`, `/api/dns/credentials`, `GET /api/intel`,
  `GET /api/proxies/{id}` and `PUT /api/proxies/{id}/gate` endpoints; certificate providers
  come with `/api/certs`, feeds carry their own status, the proxies list already returns each
  site with its upstreams, routes and gate users, and gate changes go through the proxy
  update. `PUT /api/gate-users/{id}` is now used by the Access gate editor.

### Changed

- **The WAF is tunable from the console.** Policies has a **WAF profiles** tab listing every
  CRS profile with its mode, paranoia level, anomaly threshold, allowed methods, body limit
  and rule exceptions. The profile editor was previously API-only, so per-profile tuning
  described in the README had no user interface.
- **The audit log is visible.** Settings now shows the newest 20 administrator activities
  (sign-ins, settings and proxy changes, bans, restores) with source addresses, using the
  existing `/api/audit` endpoint instead of leaving it unreachable.
- **Gate accounts can be edited.** The Access gate page can reset a visitor's password and
  turn TOTP on or off. Turning it on for an account that has no secret returns the new
  authenticator secret once, so the account is not left behind a code nobody can produce; a
  password reset ends that account's existing gate sessions.
- **Gated sites can sign out their visitors.** The Proxies row for a site whose gate is on
  has a **Sign out visitors** action, which clears its gate sessions through
  `POST /api/proxies/{id}/gate/revoke`.
- **Streaming refusals are visible.** A ban that lands while a stream is open cuts that
  stream immediately, and both the cut and every later attempt from the banned address are
  written as `stream` events (stage `stream`, rule `stream-ban`) so they appear in Logs and on
  the attack globe next to the HTTP traffic. A retrying banned host is collapsed to one event
  a minute per application, with the number of attempts it folded in, so it cannot fill the
  event table. The page counts them as “Refused (active ban)” and “Streams cut by ban”.
- **Streaming is a byte relay, not an inspected proxy.** The WAF, ban engine and access gate do
  not see that traffic; only the source allowlist and the connection cap apply. This is
  documented on the page and in the README instead of being implied.
- Wildcard `EXPOSE` lines in the Dockerfile now declare all three listeners (`443`, `8080`,
  `8443`), matching the ports the binary actually binds.
- **Single-NIC hosts are covered.** The setup wizard, Settings and the Streaming page now say
  that both addresses must exist on the host and that one NIC uses the same IP for WAN and
  LAN; the streaming guide calls the listen address a host address instead of a second NIC.
  The shell also gets a navigation toggle below 720px, where the sidebar used to vanish.

### Fixed

- **Requesting a certificate without DNS credentials looked like a broken provider.** The
  DNS provider step accepted an empty credentials box, created the certificate and then
  failed in the background with `no DNS credentials configured for <provider>`, so picking a
  provider appeared not to work. The console now gets the list of providers that already
  have stored credentials (`configured` in `GET /api/certs`), refuses a request whose
  credentials are missing or not a JSON object with a message naming the expected shape, and
  reuses the stored credentials when the box is left empty. The list also refreshes every few
  seconds while a certificate is pending, so a request or renewal no longer sits on `pending`
  until the page is reloaded.
- **The setup wizard suggested an email Let's Encrypt rejects.** The ACME email placeholder
  was `you@example.com`, and `example.com` contacts are refused as `invalidContact`, failing
  every issuance; it now suggests a real-looking domain.
- **The Settings kernel badge printed a Go map.** The runtime card showed
  `map[active:false reason:...]`, which also widened the page into a horizontal scrollbar on
  a 1440 px window. The API now returns a readable status (`active` or the reason) and the
  card renders it as a badge.
- **Enabling TOTP on an existing gate account locked it out.** An account created without
  TOTP stored a sealed *empty* secret, so turning TOTP on later reused that value and every
  code was rejected. The API now treats a sealed empty value as “no secret”, generates a fresh
  one and returns it once so the account holder can enrol.
- **The dashboard is never blank on first paint.** It seeds the counters, charts and globe
  from `GET /api/metrics` and `GET /api/globe` instead of waiting for the first SSE frame, so
  an EventSource blocked by an extension or proxy no longer leaves the page empty.
- **The Logs stage filter was missing half the pipeline.** `whitelist`, `method`, `protocol`,
  `route` and `stream` events could not be selected, so banned streaming clients and whitelist
  decisions were invisible to the filter.
- **Decoy paths no longer ban real users by default.** The default list included
  `/wp-login.php`, `/wp-admin`, `/xmlrpc.php`, `/phpmyadmin` and `/actuator`, which real
  sites serve; a single visit from a legitimate visitor, crawler or uptime check caused a
  permanent ban. The defaults are now only paths no application serves (`.env`, `.git`,
  `.ssh`, backup and config files). Application-specific paths remain available per proxy
  under Policies → Decoy paths.
- **Open redirect after the access gate and bot challenge.** `next` values are pinned to a
  same-origin absolute path: protocol-relative (`//host`), backslash (`/\\host`), scheme
  (`https:`) and control-character forms all fall back to `/`.
- **Bot challenge bypass.** With bot protection off, a stale challenge cookie or a crafted
  request could skip the WAF stage for that request; the challenge result is now only
  honoured when the challenge actually ran.
- **Gate lockout foot-guns.** The passphrase attempt counter is reset on a correct passphrase
  and per-account lockouts always expire instead of accumulating across mode changes; an
  invalid gate mode is rejected at save time rather than silently weakening the proxy.
- **WAF panic failed open.** A Coraza panic during inspection returned the request to the
  upstream; it now fails closed with a 500 and an audit entry.
- **First-run setup race.** Two simultaneous setup requests could both create an
  administrator; user creation is now a single conditional insert that reports
  `ErrAlreadySetup`.
- **CSRF comparison** now uses `crypto/subtle` instead of `==`.
- **Cached responses dropped `Vary`.** Variants beyond `Accept-Encoding` (for example
  `Accept-Language`, cookies, auth headers) are no longer stored, because a cache hit would
  otherwise serve one variant to every client.
- **Restore path SSRF parity.** Backup restore now applies the same upstream rules as the
  editor, so a hand-edited export cannot install a metadata endpoint or a non-HTTP target.
- **TOTP codes are single-use.** The accepted time step is recorded (`users.totp_last_step`)
  and a replayed code, including one captured from the wire, is refused. Fresh installs get
  the column from the base schema; existing databases receive it through a new idempotent
  additive migration that records its version in `schema_meta`.
- **Invalid WAF modes on a protection profile** are refused instead of being stored and
  skipped at request time.
- **UI overflow**: long hostnames and rule IDs no longer stretch the layout; badge rows wrap
  and wide tables scroll inside their card.
- **API error handling**: a non-JSON error body (proxy or upstream HTML) now surfaces the
  HTTP status instead of a parse error.
- **A stale bind address no longer locks you out.** If the stored `wan_ip`/`lan_ip` is not
  configured on the host at boot (DHCP change, or the wizard was filled in before the
  interface came up), the listeners fall back to the first-boot `:8443` / `:8080` addresses
  and log which address was missing, instead of exiting into a restart loop with an
  unreachable GUI. When the GUI falls back to the wildcard `:8080`, the boot log warns that
  the admin login is bound to all interfaces until the stored address is fixed.
- **Dashboard interface auto-detection** uses the interface that carries the IPv4 default
  route and ignores container/bridge plumbing (`docker*`, `veth*`, `virbr*`, `dummy*`), so
  a Docker host charts its real WAN link instead of `docker0`. Settings now names the WAN and
  LAN interfaces the dashboard actually samples, says whether each came from auto-detection
  or from a configured field, and lists the names present on the host as a typed hint (and a
  browser suggestion list), so there is nothing to guess.
- Clearing an interface field in Settings now re-runs auto-detection for that field instead
  of leaving the dashboard sampling nothing until the next restart.
- **Ban actions outside the capped list.** Unban and “make permanent” looked the row up by
  scanning the 2000 newest bans, so an older record answered 404 and could not be lifted from
  the GUI. Both now load the row by id, promotion resolves the ban by CIDR, and an unknown id
  is a real 404.
- **Ban hit counting** is batched in memory and flushed by the sweeper, so a banned client
  sending thousands of requests per second no longer queues one SQLite write per rejection;
  a removed ban also drops its pending count.
- **Deleting a gate account** now removes its ACL rows and visitor sessions in one
  transaction, so a deleted account is not still signed in through the gate until its session
  expires; changing a gate password ends that account's sessions, and deleting an unknown id
  returns 404 instead of 200.
- **Kernel status in Settings** showed a stringified Go map, so the badge always read as a
  warning; it now reports `active` or the actual reason, matching the Policies page.
- **Feed deletion** reported a database error as “built-in feeds cannot be deleted”; a
  database failure is now a 500, a built-in or missing feed a 404, and the deletion is audited.
- **Audit coverage** now includes policy create/update/delete, protection-profile updates,
  feed create/update/delete, certificate renewal and deletion, gate-account
  create/update/delete, and revoking a proxy's gate sessions.
- **Streaming refusal counters** are incremented after the event is emitted, so the status
  number can no longer run ahead of the event that explains it; the per-source refusal table
  is capped at 4096 entries, so a spray of distinct banned addresses cannot grow it without
  limit.
- **Cloud metadata guard** also refuses the Alibaba (`100.100.100.200`) and AWS IPv6
  (`fd00:ec2::254`) instance-credential endpoints, which would otherwise pass as private
  addresses.
- **First-run wizard** no longer prefills another network's example addresses; blank fields
  with placeholders replace them, so setup cannot silently save a bind address this host does
  not own. Toast messages are announced to screen readers.

## [1.1.0] — 2026-11-19

Closes the remaining 1.0.0 feature gaps and adds executable pipeline coverage plus CI.

### Added

- **Administrator credential rotation** (`Account` page): password change requiring the
  current password and authenticator code, two-phase authenticator rotation that only
  commits after a new code is confirmed, fresh recovery codes, and “sign out everywhere”.
  Rotations revoke every other session while keeping the current one.
- **Decoy hostnames** configured in Settings. Requests for a listed name that is not an
  active proxy are logged as `decoy-host`, answered uniformly and permanently banned;
  names already used by a proxy are refused at save time.
- **Per-event notification routing**: independent toggles for temporary bans, permanent
  bans, access-gate lockouts and certificate expiry, including an explicit “none” state.
- **CrowdSec status** in the GUI and `GET /api/crowdsec/status`: configured state, LAPI
  endpoint (credentials redacted), last successful poll, applied decision count and the
  last error.
- **CSV export** of the filtered event log (`GET /api/events/export.csv`), capped at
  100,000 rows with spreadsheet-formula neutralisation.
- **Source IP explorer** (`Sources` page): prefix search over a selectable window with
  request/blocked counts, distinct hosts, first/last seen, ban state, per-IP request
  history and one-click 24 h ban/unban.
- **In-process pipeline tests**: real store, ban engine, policy pipeline, gate, bot guard,
  Coraza and ReverseProxy against an `httptest` upstream. Covers allow + logging, decoy
  path and decoy host bans, temporary bans, unknown-host blackholes, gate login, cache
  hits, spoofed forwarding headers, body limits and a CRS SQLi block. Account rotation and
  session revocation are covered by API tests.
- **GitHub Actions CI** (`.github/workflows/ci.yml`): gofmt, `go vet`, race tests, Go build,
  SPA typecheck/build, production dependency audit and a Docker image build.

### Changed

- Ban events are recorded with action `ban` instead of being flattened to `block`.
- Unknown-host drops are logged on HTTP/2 too, where hijacking is unavailable.
- Notification navigation now exposes the Account and Sources pages.

### Fixed

- **Recovery codes now work.** The code hashes are encrypted at rest like the TOTP secret,
  but they were compared against the ciphertext, so the documented way back in after a
  lost authenticator was always rejected. The compare and the rewrite now go through the
  crypto box, and a code is still spent on first use.
- Password and authenticator rotation accept a recovery code as the second factor, so an
  operator who signed in with one can restore a working authenticator. The Account page
  exposes the field on both forms.
- Unconfirmed authenticator rotations are discarded on password change, sign-out and
  sign-out-everywhere instead of lingering for five minutes.
- A request for a decoy hostname from an address already holding a temporary ban upgrades
  it to permanent; previously the escalation was skipped.
- CSV export streams rows instead of materialising up to 100,000 events in memory, and
  neutralises every attacker-influenced text column (`host`, `method`, `action`, `stage`,
  `rule_id`, `country`) against spreadsheet formula injection, not only path and UA.
- The Source IP explorer indexes active bans only.
- Manual ban deletions are recorded in the audit log.

## [1.0.0] — 2026-11-19

The ten planned phases were implemented together and shipped as the first release, so the
per-phase version numbers described in [PLAN.md](PLAN.md) did not exist as separate tags.
This section records what each phase contributes to `1.0.0`.

### Added — foundation (Phase 0)

- Go 1.27 backend and React 19 + TypeScript + Vite SPA, embedded into the binary.
- Docker Compose stack with host networking, non-root user (10001), read-only root
  filesystem and file capabilities for ports/nftables.
- SQLite (WAL) store with embedded schema, encrypted secret columns and settings KV.
- Four-step setup wizard: network bindings, base domain and DuckDNS token, administrator
  password + TOTP enrolment, review. Recovery codes are shown once and accepted at login.
- Session auth with argon2id, TOTP, CSRF tokens, HttpOnly/SameSite cookies, per-IP and
  per-account login limits, sliding idle expiry (12 h) with a 7 day absolute cap.
- Release tooling: `VERSION`, `CHANGELOG`, `Makefile`, `scripts/release.sh`, version
  compiled in via `-ldflags` and exposed at `/api/version` and `/api/health`.

### Added — proxy core (Phase 1)

- TLS 1.2/1.3 listener with HTTP/2, host and SNI routing, unknown-host blackhole, apex
  blackhole, WebSocket/upgrade passthrough and streamed responses.
- Weighted round-robin upstream pools with active health checks and recovery.
- Redirect and alias routes, path matching, gzip compression, and a conservative
  GET-only response cache for explicitly cacheable responses.
- Header hygiene: forwarding/override headers stripped inbound, stack headers stripped
  outbound (`Server`, `X-Powered-By`, `Via`, …), uniform rejection page.
- Request framing defences (CL+TE, duplicate lengths, absolute-URI targets, TRACE/TRACK),
  method allowlists, per-IP token-bucket rate limiting and body limits.
- Admin CRUD for proxies, upstreams, routes, profiles and access-gate mode.

### Added — TLS and ACME (Phase 2)

- lego v4 DNS-01 issuance with DuckDNS, Cloudflare, Route53, DigitalOcean, Hetzner, OVH,
  GoDaddy and RFC2136 providers; staging toggle; encrypted account key and credentials.
- Wildcard certificate support, per-proxy certificate assignment, automatic renewal at
  30 days, 12-hour renewal loop and expiry warnings.
- Serialised ACME orders, which is required for DuckDNS because it stores a single TXT
  record per domain.

### Added — policies, bans and GeoIP (Phase 3)

- Ordered pipeline: permanent ban → whitelist → country → ASN → decoy → threat feed →
  temporary ban → rate limit → TRACE/method checks.
- Temp and permanent bans with reason/source, hit counters, promotion, manual unban and
  per-CIDR upsert; GUI pages for temp and permanent lists.
- nftables `inet wafproxy` set with interval/auto-merge sets, IPv4 + IPv6, DROP policy,
  optional WAN ICMP echo drop, and graceful degradation to userspace when unavailable.
- Country block/allow, curated hosting/VPS/cloud ASN blocking (default on), decoy paths
  with instant permanent ban, IPv6 parity, proxy-scoped overrides.
- Optional WAN/LAN interface counters, conntrack session counts and hourly rollups.
- LAN-only admin GUI is exempt from bans; `docker exec wafproxy unban <ip>` emergency path.

### Added — WAF (Phase 4)

- Coraza v3 with embedded OWASP CRS, compiled per protection profile.
- Profiles: Generic Web, WordPress, API-only, Static/CDN, Admin panel (strict); editable
  paranoia, anomaly threshold, method allowlist, body limit and rule exceptions.
- Per-proxy mode `off / detect / block` with profile inheritance; detect mode logs without
  blocking. Rule exceptions compile into `SecRuleRemoveById` so the anomaly aggregator
  cannot re-block on a disabled rule.
- Attack labelling (sqli, xss, lfi, rce, php-injection, scanner, protocol-violation, …) in
  events, dashboard and globe.
- WAF body-limit and inspection errors fail closed.

### Added — threat intel (Phase 5)

- Feed manager with ETag/If-Modified-Since, gzip, 45 s timeout, size cap, CIDR aggregation
  and atomic in-memory swap; last-good list retained on failure.
- Nine built-in sources (FireHOL L1/L2, Spamhaus DROP/EDROP, Tor exits, Feodo Tracker,
  URLhaus, ET compromised, DShield) plus custom feeds with per-feed interval and action.
- Poisoning guardrail: a feed that grows more than 5× in one refresh is frozen and shown
  as `frozen` instead of being applied.
- Merged matcher with block > challenge > log precedence and per-feed status in the GUI.

### Added — CrowdSec and bot protection (Phase 6)

- LAPI stream bouncer (`WAFPROXY_CROWDSEC_URL`, `WAFPROXY_CROWDSEC_KEY`) that applies new
  decisions as bans (`source=crowdsec`) and lifts them when CrowdSec withdraws a decision.
- Optional CrowdSec sidecar with a stock nginx-parser acquisition over the proxy access log.
- Stateless JavaScript proof-of-work challenge with `off / light / standard / aggressive`
  levels, 24 h cookie bound to host + User-Agent, and automatic temporary ban after five
  failed solutions in ten minutes.

### Added — observability (Phase 7)

- Per-interface bps/pps sampling, conntrack state counts, per-proxy request/blocked/byte
  counters, 1 hour in-memory series and Server-Sent Events stream.
- Dashboard with live metrics, WAN/LAN split, top blocked sources and recent blocks.
- Canvas attack globe with arcs from source country to the configured home location,
  colour-coded by category and capped at 90 arcs.
- Event log with filters (IP, host, stage, action, blocked-only), 7 day retention
  (1–30 configurable), pagination and hourly flow rollups.
- Audit log for every administrative mutation.

### Added — notifications (Phase 8)

- Telegram bot, SMTP/Gmail and generic webhook channels; secrets encrypted and masked in
  the API.
- Five-minute digest for ordinary bans; immediate delivery for permanent bans, access-gate
  bans and certificate expiry warnings. Per-IP 24 h dedupe, five delivery attempts with
  retry, per-channel test button and delivery history.

### Added — access gate, backup and hardening (Phase 9)

- Per-proxy access gate: shared passphrase, accounts, or accounts + TOTP; per-proxy account
  allowlist; login page served on the proxy hostname with no external assets.
- Escalation ladder: 3 failures/10 min → 15 min ban; 10/24 h → 24 h ban; failures on 3
  days with 10 in 24 h → permanent. Account lockout after 5 failures/15 min runs in
  parallel. Decoy paths and confirmed feed/CrowdSec matches remain instant bans.
- Gate session TTL configurable (`gate_ttl_hours`), revocation per proxy, and gate modes
  reset to `off` on restore because secrets are never exported.
- Backup export/restore (settings, proxies, upstreams, routes, policies, feeds, bans);
  additive restore with per-item problems reported, and plaintext export that excludes
  secrets, private keys and password hashes.
- Hardening: CSP and security headers on the GUI, argon2id passwords, constant-time
  credential checks, uniform auth failures, dummy hash for unknown usernames, cloud
  metadata SSRF guard on upstreams, strict JSON decoding, bounded settings values,
  admin session idle/absolute expiry, and a resolution of several review findings
  (ACME self-deadlock, compressed-cache corruption, WAF fail-open, whitelist bypassing
  temporary bans, health checks cancelled by request contexts).

### Documentation

- `README.md` quick start and scope notes.
- `docs/INSTALL.md` deployment, Firewalla/DuckDNS walkthrough, first-run and upgrade.
- `docs/OPERATIONS.md` runbook, recovery, troubleshooting and capacity.
- `docs/BENCHMARKS.md` measured microbenchmarks with methodology and unmeasured items.

## [0.0.0] — 2026-11-19

Planning baseline. Full design in [PLAN.md](PLAN.md); no application code yet.
