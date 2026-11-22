# WAF-Proxy roadmap: 1.30 → 1.34

Release numbers below are provisional: each phase ships as the next minor version in
`VERSION` at the time, because the console work lands in parallel.

This roadmap turns the external review into five releases that stay inside the
current product shape: **one binary, one SQLite database, one node, home lab and
small edge deployments**. It fixes real defects first, then deepens the data
plane, then capacity and connections, then TLS, then operability and insight.

High availability, multi-node clustering, HTTP/3, shared caches and third-party
config importers are **out of scope** for these five releases. The last section
describes what a later HA product would require and which seams this roadmap
puts in place for it.

## How every phase is gated

Each phase is one release (`1.30.0` … `1.34.0`) and ships only when all of the
following are true:

- `go vet ./...` and `go test ./...` pass; new behaviour has table-driven tests.
- Additive schema migration only (`internal/store` `migrateAddColumns`, schema
  version bumped), with an upgrade test from a 1.28 database.
- Defaults preserve today's behaviour, except where a default is the defect
  being fixed. Every such change is called out in `CHANGELOG.md`.
- `docs/` is updated in the same change: the affected task page, the OpenAPI
  route list if a route changed, and `INSTALL.md`/`OPERATIONS.md` where an
  operator-visible knob appears.
- The web UI is only touched where a phase adds a setting. UI work is
  coordinated with the agent working on `web/`; backend fields land first and
  the UI follows, so neither side blocks the other.
- `make verify-release` passes.

---

## Phase 1 — Correctness of the forwarding substrate (1.30.0)

The reviewer found five defects. None need new architecture; they need the
existing counters and health state to be used, and configuration to expose the
choices operators already expect.

### Scope

1. **Use the balancing data that already exists.** `pick()` in
   `internal/proxy/upstream.go` records `inFlight` and `latency` and ignores
   both. Add a per-proxy policy: `weighted_rr` (current default),
   `least_conn`, `least_latency`, `ip_hash`, `sticky_cookie`. Least-conn reads
   `inFlight`; least-latency reads a decayed latency estimate (not just the last
   probe); `ip_hash` keys on the client IP already resolved by `clientip`;
   `sticky_cookie` sets a signed cookie that pins a client to one upstream.
   Per-upstream `max_conns` is enforced before selection, and a selection that
   cannot honour it falls through to the next candidate.
2. **Health checks that can fail.** Replace "any HTTP response is healthy" with
   a configurable probe: path, expected status (list or range), timeout,
   interval, healthy/unhealthy thresholds, and jitter. A `500` counts as a
   failure and ejects after the threshold. Add passive ejection: real upstream
   `502/503/504` responses feed the same failure counter, with a cooldown and a
   single half-open probe before returning the upstream to the pool.
3. **A capacity budget that is not box-wide.** `DefaultMaxInflight = 128`
   applies to the whole process. Keep a global ceiling as a backstop, but add
   per-site and per-client caps, a short bounded queue (for example 250 ms)
   before refusing, and expose per-host in-flight/queued counts. A single busy
   site can no longer starve every other site.
4. **Correct certificate selection.** `internal/acme/manager.go` chooses the
   "most specific" certificate with `len(domains[0])`, which is wrong as soon as
   a certificate covers several names. Score by the matched pattern
   (`*.example.com` vs `example.com` vs `a.example.com`), prefer an exact match,
   then the longest wildcard suffix, then the newest valid certificate. Make
   `Proxy.CertID` authoritative when set and fall back to SNI matching only when
   it is not.
5. **Stop honouring `HTTP_PROXY` for upstreams.** Remove
   `http.ProxyFromEnvironment` from the proxy transport and the header-audit
   client. A stray environment variable must not silently route customer
   traffic through a third party. Outbound proxying, if wanted later, becomes an
   explicit per-proxy setting.

Config surface added: upstream `max_conns`, probe settings and policy on the
proxy, sticky-cookie secret (generated, stored write-only), and the per-site /
per-client budget defaults. All optional; absent values keep current behaviour.

### Deliberately deferred

- Response-header/route-aware health checks ("healthy means this JSON body").
- Active checks other than HTTP GET (TCP connect, gRPC health).
- Circuit breakers per route (Phase 3 covers connection lifecycle, not
  per-route breakers).
- Any UI redesign beyond the fields the settings API needs.

### How it is tested

- `internal/proxy/upstream_test.go` (new): selection distribution over 10k picks
  for weighted and least-conn under synthetic in-flight load; `ip_hash`
  stability across picks and client IPs; sticky cookie round-trip and tamper
  rejection; `max_conns` exhaustion falls through and never exceeds the cap.
- Health loop tests with `httptest` upstreams: always-500 backend is ejected
  after N probes; a 200 returns it after half-open; passive 502s eject without
  waiting for the next probe; jitter stays within bounds; recovery requires one
  success, not a full threshold.
- Capacity tests extending `internal/proxy/budget_test.go`: two sites, one
  saturated, the other still served; per-client cap isolates one noisy client;
  queue drains and reports the queued count; refusal carries a distinguishable
  status/error.
- Certificate selection table test: overlapping SANs, wildcard plus apex,
  expired versus valid, `Proxy.CertID` override, unknown SNI falls back to the
  default certificate.
- Environment test: with `HTTP_PROXY` set to a dead listener, an upstream
  request still reaches a local `httptest` server.
- Upgrade test: open a 1.28 database, migrate, confirm defaults and that every
  existing upstream/proxy still resolves.

### Exit criteria

A backend returning 500 is out of rotation within one probe interval plus
threshold; no request is routed through `HTTP_PROXY`; one saturated site cannot
exhaust another's budget; and the balancing policy named in config is the policy
observed in the distribution tests.

---

## Phase 2 — Routing and response behaviour (1.31.0)

### Scope

- **Routing depth.** Keep the existing host → proxy → upstreams model and make
  routes first-class: match on method, header, query and regex path, with
  deterministic priority ordering and a per-rule upstream override. The current
  flat prefix match becomes one matcher kind, so existing configurations keep
  working unchanged.
- **Per-route timeouts, retries and error taxonomy.** Replace the single 60 s
  `ResponseHeaderTimeout` with per-route dial, response-header and total
  timeouts; distinguish `502` (upstream bad response), `504` (upstream timeout)
  and client cancellation (`499`, logged not sent). Retry only idempotent
  methods, only when zero request bytes were written, with a bounded attempt
  count and no retry after headers are sent.
- **Header and path rewriting, both directions.** Set/add/remove request and
  response headers, regex path rewrite, per-route HSTS and CSP, and redirect
  status choice (`301`/`307`/`308`) on redirect routes.
- **Conformance table.** Publish `docs/CONFORMANCE.md` with a status per case
  and drive it from tests: `Expect: 100-continue`, `HEAD`, `Range`,
  `Content-Length` + `Transfer-Encoding` rejection, duplicate/oversized headers,
  absolute-form request targets, and trailer handling. Cases that stay
  unsupported are named, not implied.

### Deliberately deferred

- HTTP/2 and HTTP/3 on the client side, pipelining, and full gRPC trailer
  semantics (documented as unsupported in the table).
- Rewrite rules that execute scripts or templates; only literal and regex
  replacement.
- Per-route WAF profile overrides — the policy pipeline already has profile
  selection at the site level, and changing it belongs with a policy review.

### How it is tested

- Matcher table tests: priority ties broken deterministically; regex compiled
  once; method/header/query combinations; a request matching nothing gets the
  documented fallback.
- `httptest` upstream that records what it received: header set/add/remove,
  path rewrite with capture groups, Host preserved or rewritten as configured.
- Retry tests: a flaky upstream that fails before reading the body succeeds on
  the second attempt; a POST with a body is never retried; a timeout maps to
  504 and a malformed response maps to 502.
- Redirect route tests for each status and for HSTS/CSP emission.
- Conformance tests in `internal/proxy/conformance_test.go` extended; the doc
  table is generated from the same case list so it cannot drift.

### Exit criteria

Every line in `docs/CONFORMANCE.md` has a test or an explicit "unsupported";
existing site configurations route exactly as before; timeouts and retries are
configurable per route with the documented error codes.

---

## Phase 3 — Capacity, connections, cache and stream routes (1.32.0)

### Scope

- **Per-upstream transports.** One `http.Transport` per upstream with sensible
  pool sizes, `MaxIdleConnsPerHost`, and `DisableCompression` where the pipeline
  already handles encoding. Reload keeps warm connections for unchanged
  upstreams instead of dropping everything; changed upstreams get a new
  transport and the old one drains.
- **DNS and address family.** Respect DNS TTL where the resolver exposes it,
  use Go's dual-stack dialing (Happy Eyeballs) explicitly, and cache resolved
  addresses briefly so a DNS outage does not take the site down.
- **Drain and readiness.** `/api/health?ready` reports draining; on shutdown the
  listener stops accepting, in-flight requests finish within a deadline, and
  keep-alive connections close gracefully.
- **Cache that cannot eat the box.** Replace the per-edge 32 MB × N arrangement
  with one global LRU with a total budget and a per-host quota, eviction by
  size, correct `Vary` handling, and no storage of `Set-Cookie` or
  `Cache-Control: private` responses. Add purge per host and purge-all from the
  console; report hit ratio and bytes per host.
- **Generic TCP/UDP stream routes.** A route kind that forwards an arbitrary
  listen port to `host:port`, with SNI passthrough for TLS, the existing ban and
  IP policy checks applied at connect time, connection caps per route and per
  client, and idle timeouts. This is the capability that currently forces people
  to keep HAProxy beside WAF-Proxy. The Plex/Jellyfin catalog stays as a preset
  on top of this primitive rather than a separate mechanism.

### Deliberately deferred

- Shared or tiered cache across nodes, cache warm-up, and request collapsing.
- QUIC/UDP-based application protocols beyond raw UDP forwarding (HTTP/3 is a
  separate protocol decision).
- Dynamic upstream discovery (DNS SRV, Consul, Docker labels).
- Connection multiplexing (HTTP/2 to upstreams).

### How it is tested

- Transport reuse test: a counter on the upstream's accepted connections shows
  reload does not create a new connection for an unchanged upstream.
- Drain test: start a slow request, signal shutdown, assert it completes and new
  connections are refused; readiness flips before the listener closes.
- Cache tests: `Vary` separates entries; `Set-Cookie` and `private` responses
  are not stored; a single host cannot exceed its quota; global budget holds
  under many hosts; purge removes only the target host.
- Stream tests: raw TCP echo through a route, TLS ClientHello with SNI passes
  through unmodified, banned client is refused at connect, connection cap
  refuses the N+1th connection and recovers after close, UDP datagrams round
  trip and respect the idle timeout.
- Load test in `perf/`: 200 concurrent clients against two sites with different
  budgets; assert per-site latency isolation and that global memory stays within
  the configured cache budget.

### Exit criteria

Reload preserves warm connections; the cache budget is global and enforced; a
TCP and a UDP route work with bans and caps; draining publishes readiness
before the port closes.

---

## Phase 4 — TLS and ACME (1.33.0)

### Scope

- **Certificates with a source.** Add `source` to `model.Cert`
  (`acme` | `uploaded` | `internal`) and an upload path for PEM certificate and
  key, with key/certificate match validation and chain ordering. `Proxy.CertID`
  is authoritative (Phase 1 already scores SNI).
- **Internal CA and domain-less mode.** Generate a local root, issue
  certificates for `*.home.arpa` and single-label hosts, expose the root as a
  downloadable trust anchor, and allow a site without `base_domain`. This is the
  most common first install, and today it is impossible.
- **HTTP-01 inside the listener.** Serve ACME HTTP-01 challenges from the
  existing :80 handler instead of letting lego start its own server, so the
  challenge goes through the same pipeline, logging and rate limits, and ports
  do not conflict.
- **Renewal reliability.** Jittered renewal windows, exponential backoff on
  failure, explicit handling of ACME 429/`badNonce` with retry-after, preferred
  chain selection, key type choice (ECDSA P-256 default, RSA optional), and
  post-issue validation (parse, match names, check expiry) before the
  certificate is activated. Failed renewals alert before expiry, not after.
- **Per-site TLS policy.** Minimum version, cipher suites, HSTS (with preload
  opt-in), and OCSP stapling toggle — stored per site, defaults unchanged.
- **Revocation and inventory.** A certificate inventory page/endpoint listing
  source, names, issuer, expiry, last renewal attempt and last error, plus
  revoke for ACME certificates.
- **HTTPS for the console.** Optional console TLS using the same manager, HSTS,
  and `Secure` cookies when enabled.

### Deliberately deferred

- Wildcard issuance via more DNS providers, EAB, and propagation dry-run: the
  existing DNS-01 provider set stays; adding providers is incremental work, not
  a design change.
- Client certificate authentication (mTLS) for sites.
- Multi-node certificate coordination (see HA section).

### How it is tested

- Cert selection and `CertID` override from Phase 1 extended with uploaded and
  internal certificates.
- Upload tests: mismatched key rejected, unordered chain accepted and
  reordered, expired certificate rejected with a clear error.
- Internal CA tests: root generated once, leaf chains verify against it,
  `*.home.arpa` issuance, trust anchor download byte-identical to the root.
- ACME tests against a local test ACME server (Pebble if available, otherwise a
  scripted responder): HTTP-01 solved through the proxy handler, 429 backs off
  and retries, bad nonce retried once, post-issue validation rejects a
  certificate with the wrong names, renewal happens inside the jittered window.
- Policy tests: a TLS 1.1 client is refused when the site minimum is 1.2; HSTS
  header appears only when enabled; OCSP staple present when enabled and
  available.

### Exit criteria

A fresh install without a public domain can issue an internal certificate and
serve HTTPS; an uploaded certificate is served for its names; renewals survive
429s and never activate an invalid certificate; every certificate in the store
is visible with its source and last error.

---

## Phase 5 — Operability and observability (1.34.0)

### Scope

- **Unattended setup.** `wafproxy setup --config file` plus `WAFPROXY_SETUP_*`
  environment variables, producing the same state as the wizard and printing the
  TOTP URI to stdout once. Idempotent: re-running against an initialized install
  reports and exits without changes.
- **Preflight before saving.** Check that ports are bindable, addresses exist on
  an interface, nftables/NET_ADMIN is available, DNS A/AAAA (and wildcard)
  match, CAA permits the CA, the clock is sane, and disk space is sufficient.
  Report each as pass/warn/fail with a one-line remedy.
- **Resumable wizard and post-install checklist.** Server-side draft state so a
  reload or a different browser does not lose progress; the checklist flips from
  real state (certificate issued, first site reachable, backup taken, alert
  channel tested).
- **Break-glass recovery.** `wafproxy recover --reset-password`,
  `--reset-totp`, `--rotate-master-key`, each requiring local access and printing
  what changed. Replaces "delete the database" as the documented answer.
- **CLI backup and retention.** `wafproxy backup` writes an encrypted archive
  (reusing the existing backup encryption), with nightly retention and a
  documented restore path.
- **Observability.**
  - JSON access logs with runtime-adjustable level and `X-Request-ID`
    propagated from client through WAF, gate and upstream, echoed in the
    response.
  - Per-stage latency: frame, screen, bot, body, gate, WAF, upstream TTFB,
    total, exported in logs and in the existing `/metrics` Prometheus output.
  - Queue depth, WAL size and database growth as first-class health signals with
    thresholds, not just gauges.
  - Alert rules with dedupe, quiet hours and a **Test** button that sends a real
    notification.
  - Redacted diagnostics bundle (config, versions, recent errors, health;
    secrets and client data removed) downloadable from the console.
  - 7/30-day rollups for request, error and ban counts with SLO-style panels
    computed from stored rollups, not live queries.
  - Certificate/ACME attempt and failure counters; upstream health timeline with
    flapping detection (N transitions in a window).
  - Synthetic canary: a scheduled request through a real site that exercises
    every stage and reports which stage failed.
- **Docs, continuously delivered.** Split the 739-line `INSTALL.md` into task
  pages (install, first site, certificates, gate/accounts, WAF tuning, backup and
  restore, upgrade, troubleshooting), generate the OpenAPI reference for every
  route and diff it against `server.go` in CI, add tested recipes (Nextcloud,
  Home Assistant, Proxmox, Cloudflare Tunnel), a CRS false-positive walkthrough,
  a symptom-first troubleshooting index, a pipeline/threat-model diagram
  generated from the stage list, and an upgrade matrix. README stays under 120
  lines and links into the docs.

### Deliberately deferred

- A separate docs site generator and hosted documentation.
- Importers for NPM/Traefik/Caddyfile/HAProxy (each is a parser plus a
  migration plan; they are a later, separate project).
- SSO/SAML, multi-tenant accounts, and per-operator audit export.
- Log shipping integrations beyond the existing webhook/agent-link delivery.

### How it is tested

- Setup tests: `setup --config` against a temp data dir produces a working
  install, second run is a no-op, TOTP URI is printed exactly once, missing or
  invalid keys fail with the field named.
- Preflight tests: a port already bound fails with the owning advice; a
  hostname with no A record warns; clock skew beyond tolerance fails.
- Recovery tests: reset password invalidates old sessions, reset TOTP clears the
  secret and prints a new enrollment URI, rotate master key re-wraps secrets and
  old ciphertexts no longer decrypt.
- Backup test: archive is encrypted, restore into an empty data dir reproduces
  sites, certs, users and settings (extending the existing YAML/JSON round-trip
  tests).
- Observability tests: a request with a client-supplied request ID keeps it end
  to end; a stage failure is attributed to the right stage; the canary reports
  the failing stage against a deliberately broken upstream; alert dedupe sends
  one notification for N identical events; the diagnostics bundle contains no
  secret values (asserted by scanning for known fixtures).
- Docs check: OpenAPI generation diffed in CI; every command in the install
  pages is executed in a container test where feasible.

### Exit criteria

A headless install completes from one config file and passes preflight; an
operator can recover a lost password and TOTP without deleting data; every
request is traceable by ID with stage timings; alerts fire once and can be
tested; the docs cover install through troubleshooting without a 700-line page.

---

## Deferred beyond 1.34

- **HA / multi-node**: shared configuration, distributed bans and rate limits,
  leader-elected ACME, shared cache, cluster health. See below.
- **HTTP/3 and QUIC.**
- **Config importers** (NPM, Traefik, Caddyfile, HAProxy).
- **Dynamic upstream discovery** and container-label routing.
- **Hosted docs site, SSO, mTLS.**

## What HA would look like later

The single-node releases are written so this is an extension, not a rewrite.
The rule to hold from Phase 1 onward: **node-local state is never the source of
truth**. Today that means keeping three kinds of state separable:

| Kind | Examples today | HA target |
| --- | --- | --- |
| Cluster configuration | sites, upstreams, routes, profiles, policies, users, settings | shared database (PostgreSQL) behind the existing `internal/store` interface, versioned and watched |
| Durable shared state | certificates, bans, audit/events, backups | shared DB plus object storage for PEMs and archives |
| Node-local state | connections, in-flight counters, cache, live rate-limit windows | stays local, with approximate global limits |

Concretely, an HA deployment would be:

1. **N stateless edge nodes** running the same binary in data-plane mode
   (`--role=edge`), behind an L4 VIP (keepalived/VRRP) or a cloud load balancer.
   No node holds unique state.
2. **A shared PostgreSQL** for configuration and durable records, replacing
   SQLite for clustered installs. The store interface and SQL are already
   centralized; the work is dialect, connection pooling and transactions, not
   call-site changes.
3. **Redis (or NATS) for ephemeral shared state**: ban lists, rate-limit
   counters, sticky-session table, cache purge bus. Enforcement stays local with
   a global budget derived from the shared counters, because per-request Redis
   round trips would dominate latency.
4. **One leader for certificate issuance**, elected through the shared store, so
   ACME rate limits are respected once per certificate rather than once per
   node. Certificates are written to shared storage and every node reloads on
   change. `Proxy.CertID` makes propagation unambiguous.
5. **Health checks per node, aggregated** for the console. An upstream is marked
   down when a quorum of nodes agree, preventing one node's broken network path
   from removing a healthy backend everywhere.
6. **Config as versions**: every write bumps a version; nodes long-poll or
   subscribe, apply atomically, and report the version they are serving. The
   console shows drift. Rolling upgrades drain one node at a time using the
   Phase 3 readiness endpoint.
7. **Cache stays per node** with a purge broadcast; a shared cache is a separate
   product decision because it changes failure modes (one cache outage becomes a
   site outage).
8. **Observability aggregates per node**: request IDs stay end to end, and the
   console merges per-node metrics; SLO rollups are written to the shared store.

What does not survive HA without change: SQLite write concurrency, in-process
ban and rate-limit maps, the box-wide in-flight ceiling, and per-node ACME
state. Phases 1–3 remove the last two as assumptions; Phase 4 isolates ACME
behind a manager; Phase 5 makes versioning and drain observable. The remaining
HA work is therefore a new storage backend, a coordinator, and deployment
packaging — a project in its own right, not a phase of this roadmap.

## Reviewer item traceability

Every item in the review maps to exactly one phase or to an explicit deferral.

### Proxy Core

| ID | Reviewer item | Where |
| --- | --- | --- |
| A1 | Real load balancing: least-conn, least-latency, ip_hash, sticky cookie, per-upstream max_conns | 1.30 (Phase 1) |
| A2 | Health checks: path, expected status, thresholds, passive 5xx ejection, jitter | 1.30 (Phase 1) |
| A3 | Per-route timeouts, retries, 502/504 taxonomy, retry only zero-byte idempotent requests | 1.31 (Phase 2) |
| A3b | Drop `http.ProxyFromEnvironment` on upstreams | 1.30 (Phase 1) |
| A4 | Routing depth: method/header/query/regex, priority ordering, per-rule upstream | 1.31 (Phase 2) |
| A5 | Header/path rewriting both ways, per-route HSTS/CSP, 301/307/308 | 1.31 (Phase 2) |
| A6 | Generic TCP/UDP stream routes with SNI passthrough, bans, connection caps | 1.32 (Phase 3) |
| A7 | Per-site and per-client concurrency caps, short bounded queue | 1.30 (Phase 1) |
| A7b | Per-host budget visible to operators | 1.34 (Phase 5) |
| A8 | Per-upstream transports and connection reuse across reload, DNS TTL, Happy Eyeballs, drain readiness | 1.32 (Phase 3) |
| A9 | Cache: one global LRU, per-host quota, Vary/Set-Cookie correctness, purge | 1.32 (Phase 3) |
| A10 | Protocol conformance: Expect/100-continue, HEAD, Range, framing, smuggling; published table | 1.31 (Phase 2), table extended through 1.32 |
| A10b | Pipelining, gRPC trailers, HTTP/3 | Deferred beyond 1.34 |

### Setup

| ID | Reviewer item | Where |
| --- | --- | --- |
| B1 | Unattended `setup --config` with `WAFPROXY_SETUP_*`, TOTP URI to stdout | 1.34 (Phase 5) |
| B2 | Preflight: ports, addresses, nft/NET_ADMIN, DNS, CAA, clock, disk | 1.34 (Phase 5) |
| B3 | Domain-less mode with internal CA and `*.home.arpa` | 1.33 (Phase 4) CA, 1.34 setup flow |
| B4 | Import from NPM/Traefik/Caddyfile/HAProxy | Deferred beyond 1.34 |
| B5 | Resumable wizard and post-install checklist | 1.34 (Phase 5) |
| B6 | Break-glass `recover --reset-password/--reset-totp/--rotate-master-key` | 1.34 (Phase 5) |
| B7 | Verify TLS and reachability during setup (staging issuance, DNS check inline) | 1.33 staging issuance, 1.34 setup checks |
| B8 | Encrypted `wafproxy backup` CLI with nightly retention | 1.34 (Phase 5); manual encrypted download already shipped in 1.28.1 |
| B9 | HTTPS for the console, HSTS, Secure cookies | 1.33 (Phase 4) |
| B10 | First-run security scorecard | 1.34 (Phase 5) |

### Docs

| ID | Reviewer item | Where |
| --- | --- | --- |
| C1 | Split the 739-line INSTALL into task pages; README under 120 lines | 1.34 (Phase 5), pages added as features land |
| C2 | Generated OpenAPI reference for every route, CI-diffed against `server.go` | 1.34 (Phase 5) |
| C3 | Tested recipes (Nextcloud, Home Assistant, Proxmox, Cloudflare Tunnel) | 1.34 (Phase 5) |
| C4 | CRS tuning guide with a false-positive walkthrough | 1.34 (Phase 5) |
| C5 | Symptom-first troubleshooting index | 1.34 (Phase 5) |
| C6 | Pipeline/threat-model diagram generated from the stage list | 1.34 (Phase 5) |
| C7 | Upgrade matrix, Keep-a-Changelog with a Security section | 1.34 (Phase 5); every release updates it |
| C8 | Accurate SECURITY.md | Done in 1.28.1; maintained every release |
| C9 | Contributor docs, refreshed screenshots/GIFs | Deferred beyond 1.34 (screenshots depend on the UI rebuild) |
| C10 | Hosted docs site | Deferred beyond 1.34 |

### Observability

| ID | Reviewer item | Where |
| --- | --- | --- |
| D1 | JSON access logs with runtime levels | 1.34 (Phase 5) |
| D2 | `X-Request-ID` propagated end to end, log-detail drawer | 1.34 (Phase 5) |
| D3 | Per-stage latency (frame/screen/bot/body/gate/WAF/upstream TTFB) | 1.34 (Phase 5) |
| D4 | Event-queue drops, WAL and DB growth as first-class health signals | 1.34 (Phase 5) |
| D5 | Threshold alerting with dedupe and a Test button | 1.34 (Phase 5) |
| D6 | Redacted diagnostics bundle | 1.34 (Phase 5) |
| D7 | 7/30-day SLO panels from rollups | 1.34 (Phase 5) |
| D8 | Certificate/ACME attempt and failure counters | 1.34 (Phase 5) |
| D9 | Upstream health timeline with flapping detection | 1.34 (Phase 5) |
| D10 | Synthetic canary exercising every stage | 1.34 (Phase 5) |

### TLS / ACME

| ID | Reviewer item | Where |
| --- | --- | --- |
| E1 | Certificate upload and `Cert.Source` field | 1.33 (Phase 4) |
| E2 | Internal CA, downloadable trust anchor, domain-less certificates | 1.33 (Phase 4) |
| E3 | HTTP-01 inside the existing listener | 1.33 (Phase 4) |
| E4 | More DNS providers, EAB, propagation dry-run | Deferred beyond 1.34 |
| E5 | Per-site min version, ciphers, HSTS, OCSP | 1.33 (Phase 4) |
| E6 | Wildcard certificate selection and `Proxy.CertID` authoritative | 1.30 (Phase 1) |
| E7 | Renewal jitter, backoff, 429 handling | 1.33 (Phase 4) |
| E8 | Preferred chain, key type, post-issue validation | 1.33 (Phase 4) |
| E9 | Revocation and certificate inventory | 1.33 (Phase 4) |
| E10 | Console TLS | 1.33 (Phase 4) |

### Deferred beyond 1.34 (whole features)

HA/multi-node clustering, HTTP/3, third-party config importers, dynamic upstream
discovery, shared cache, hosted docs site, SSO, site mTLS, contributor
screenshots. None of them are required by a single-node deployment.
