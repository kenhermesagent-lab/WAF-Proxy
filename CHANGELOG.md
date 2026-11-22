# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

**Release convention**

- `MAJOR.MINOR.PATCH`, tracked in `VERSION` (single source of truth).
- Each completed plan phase bumps **MINOR**: `0.1.0` → `0.2.0` → … → `1.0.0`.
- Fixes and add-ons inside a shipped phase bump **PATCH**: `0.4.1`, `0.4.2`.
- Every push to `main` has a matching section here and an annotated tag `vX.Y.Z`.

## [1.27.1] — 2026-11-22

### Added

- **Configuration transport in the console.** **Settings** now offers **Download YAML** and **Import
  YAML** beside the JSON backup, with the same success and problem reporting. The backup schedule's
  encryption checkbox and passphrase field are covered by component tests, as is the YAML import.

## [1.27.0] — 2026-11-22

### Changed

- **YAML proxies and policies reference profiles and hosts by name.** `waf_profile`,
  `protection_profile`, `access_profile` and a policy's `proxy` replace the numeric ids that only
  meant something on the exporting install. A file exported here imports into an empty install,
  resolves every reference, and re-exports identically — covered by a test that builds a full
  configuration, imports it into a fresh store and compares the two documents. A 1.26 file with
  numeric ids is refused; export it again from the install that wrote it.

### Fixed

- A configuration exported with empty settings no longer reports those empty values as invalid on
  import, and a proxy-scoped policy finds a host created earlier in the same file.

## [1.26.0] — 2026-11-22

### Added

- **Encrypted backups.** A backup schedule can be sealed with AES-256-GCM under a 16+ character
  passphrase; files gain `.enc`, and restoring one asks for the same passphrase. The passphrase is
  stored sealed like the transport password.
- **Profiles and lists in the YAML configuration.** `GET /api/config/export.yaml` now carries WAF
  profiles, protection profiles, access lists and access profiles (which name their lists and
  profiles), and no longer carries bans or feeds. `POST /api/config/import.yaml` adds the missing
  ones by name and resolves access-profile references, reporting an unknown list, profile or
  policy instead of guessing.

### Fixed

- **Agent tokens created in 1.24.0 keep their tools.** The old `read`, `ban` and `session` group
  names are expanded to the tools those groups covered, so an upgrade no longer leaves an agent
  with an empty catalog.

## [1.25.0] — 2026-11-22

### Added

- **YAML configuration export and import.** `GET /api/config/export.yaml` renders the JSON backup
  document as readable YAML, and `POST /api/config/import.yaml` applies one through the same
  additive restore path — existing hostnames are skipped, secrets stay excluded, and the response
  reports the imported counts and every problem. Profiles, access lists and settings outside the
  backup document are not covered yet.

### Changed

- **Agent token scopes are per tool.** The three groups from 1.24.0 are replaced by the gateway
  catalog itself: the console shows a checkbox per tool, the API rejects a name that is not a
  tool, and `tools/list`/`tools/call` enforce the token's exact set. Tokens created before this
  release, and the environment token, keep every tool.
- **The audit chain is anchored.** The newest hash is stored in settings, so removing rows from
  the end of the audit table is reported instead of verifying clean.

## [1.24.0] — 2026-11-22

### Added

- **Metrics scrape token.** `GET /metrics` now answers 401 unless the request carries
  `Authorization: Bearer $WAFPROXY_METRICS_TOKEN`, and 403 when that variable is unset, so an
  install with the console listener opened to the LAN does not publish its counters. The token
  must be at least 32 characters.
- **Audit hash chain.** Each new audit entry stores a SHA-256 over the previous entry's hash and
  its own fields. **Settings → Recent administrator activity → Verify chain**
  (`GET /api/audit/verify`) reports the first row that no longer matches; rows written before
  the chain is introduced are skipped. The chain catches edits to the database file, not an
  attacker who can rewrite every row.
- **Agent token scopes.** Tokens can be limited to `read`, `ban` or `session` tools. `tools/list`
  hides the rest and `tools/call` refuses them; the console shows each token's scopes. Tokens
  created before this release, and the environment token, keep access to every tool.

### Changed

- **Audit export covers the full table.** `GET /api/audit?format=csv` downloads every entry,
  oldest first, instead of the newest 200. The JSON view keeps its 200-row cap.

## [1.23.0] — 2026-11-22

### Added

- **Request simulator.** **Logs → Why?** replays a logged request through the ban, screening and WAF
  stages without reaching the upstream, spending a rate limit or writing a ban. It lists every rule
  that matched, names the upstream or route that would serve the request, and offers to except a
  blocking CRS rule after naming every other site that shares the profile. `POST /api/simulate`
  needs `policies.read`; nothing is audited or persisted.
- **Response inspection.** A WAF profile chooses `off`, `flag` or `block` for upstream responses.
  In `flag` and `block` the proxy buffers up to the profile body limit in `ModifyResponse` and runs
  the CRS response rules over the status, headers and body; a `block` match returns the uniform 502
  before the status line is written, so the upstream body never reaches the browser. `flag` records
  the rule and forwards the page. `text/event-stream`, WebSocket upgrades, range requests,
  compressed, bodyless and oversized responses are forwarded whole and logged as
  `response-skipped` with the reason as the rule. Off by default. Logs gains `response-waf` and
  `response-skipped` stage filters.
- **Metrics scrape endpoint.** `GET /metrics` serves the per-proxy request, block and byte counters in
  the Prometheus text format. It is public like `/api/health` and stays behind the console listener's
  private-network default.
- **Audit export.** `GET /api/audit?format=csv` downloads the 200 newest entries as CSV; without the
  parameter the JSON list is unchanged.
- **Bulk ban selection.** The Bans list has a select-all box, Ctrl/Cmd-click to add an address and
  press-and-drag over a range; an address stays draggable into the other box.
- **Release-check regression test.** `make test-release` (and CI) proves `deploy/check-version.sh`
  still refuses a `VERSION` that is not SemVer, a CHANGELOG mismatch, a stale `version.go` default
  and a release tag that disagrees with `VERSION`.

### Fixed

- A logged verdict keeps the stage that produced it (`waf`) instead of being relabelled `route` by
  the forward that follows the log.
- A WebSocket upgrade is logged with the 101 the client received instead of a 200, and the tunnel is
  untouched.
- The **Why?** modal reads the bare arrays `GET /api/proxies` and `GET /api/profiles` return, so a
  real event no longer claims no proxy is configured. A pasted query is re-encoded the way a
  browser sends it, a blocked result no longer claims there is no upstream, and the exception
  offer disappears once it has been saved.
- A clean request under a `block` profile no longer counts CRS setup actions as a match, which had
  logged every such request as a WAF event.

## [1.22.0] — 2026-11-22

### Added

- **Release checks.** `make verify-release` refuses a `VERSION` that is not SemVer or that disagrees
  with the newest `CHANGELOG.md` section; in GitHub Actions a `v*` tag must match `VERSION` too. CI
  runs it in a new release job.
- **SBOM.** `make sbom` writes CycloneDX 1.5 JSON for every module in the build graph and CI attaches
  it to the run. It reads `go list -m -json all`, so there is no extra build tool to install.
- **Upgrade test from the previous release.** `internal/store/testdata/db-v1.21.sqlite` is a database
  written by 1.21 and committed frozen; a test opens it through the current migrations and asserts
  the administrator, proxy, policy, list and setting survive. Regenerate deliberately with
  `WAFPROXY_WRITE_FIXTURE=1 go test -run TestWriteUpgradeFixture ./internal/store`.
- **Performance gate.** `internal/perf` builds the same 224 requests every run — benign pages, forms
  and API calls plus six attack classes, each checked against the rule set. `make perf` prints
  throughput and p50/p95/p99 for the hot path, while `make perf-gate` compares three benchmarks with
  `perf/baseline.json`: CI fails past a 25% rise in allocations, and past a 3× rise in time, which
  is as tight as a shared runner allows (identical runs there varied by 40% in wall time while
  allocations moved by under 0.5%). `make perf-record` re-records the baseline.
- **Request normalization.** Duplicate parameter names carrying different values, and values that
  change on a second decode (`%253Cscript%253E`), are reported by rule 900120/900121 before the rule
  set runs. A new **Request normalization** setting chooses off, flag (the default) or block.

### Fixed

- **A remote feed can no longer ban private space.** `127.0.0.0/8`, `10.0.0.0/8`, link-local,
  multicast, unspecified and IPv6 private or link-local prefixes are dropped when a feed is fetched,
  and the skipped count is logged. Locally uploaded lists keep them: blocking a private range on
  purpose is a legitimate choice for an operator's own list.

## [1.21.0] — 2026-11-22

### Added

- **Thirteen more application presets.** Vaultwarden, Gitea/Forgejo, Paperless-ngx, Grafana,
  Uptime Kuma, Mealie, Navidrome, PhotoPrism, Syncthing, n8n, BookStack, Cal.com and the *arr
  suite join the existing six. Each carries guidance notes (upload ceilings, streamed responses,
  WebSockets, admin areas, ports that are not proxied), now rendered in the **New proxy** dialog
  under the preset summary.
- **Eight keyless threat feeds.** Blocklist.de, GreenSnow, Binary Defense, CINS Army,
  BruteForceBlocker, IPSum level 3, Spamhaus DROP IPv6 and the ET firewall list are seeded
  disabled, so an upgrade never starts blocking new ranges on its own. Every non-local feed's
  **Action** column is now a selector (block, challenge, log only); local uploads keep their fixed
  block badge because the server already forces it.
- **Policies → Global Profile.** The old *Countries, IPs, ASN* tab now owns everything applied to
  every proxy. An IP policy is one **IP / Subnet** type with an Allow/Block action, so a single
  address or a whole CIDR can be allowed or blocked globally. Existing Whitelist and Blocklist
  profiles can be ticked to apply to every host, including hosts added later; a global whitelist
  is checked before the global blocklists, while a site's own access-profile lists remain narrower
  and still decide for that host. **ASN recommendations** adds a hosting/cloud or VPN network as an
  ordinary, editable ASN policy.
- **One Bans page.** Temporary and permanent bans share a single tab: the newest ten of each, a
  search across both lists, and a full-list popup with temporary and permanent side by side.
  Addresses can be dragged between them or ticked and moved, moved back to temporary (24 hours
  from the move), or lifted. Roll-up into the local threat list is unchanged.

### Changed

- **Moving a ban no longer needs the individual endpoints.** The bulk bans call accepts
  `action: "temp"` to demote a permanent ban back to a 24-hour temporary one, audited like the
  other movements.

### Fixed

- **A Global Profile list can no longer be deleted out from under itself.** Deleting a
  Whitelist/Blocklist still attached to Global Profile is refused with a 409 naming Global
  Profile, matching the existing refusal for access profiles and forwarders; detach it first.
- **The bot-challenge cookie is bound to the client network.** It was signed over host and user
  agent only, so one solved proof could be replayed from any address. IPv4 is bound exactly and
  IPv6 within its /64, so a rotating privacy address does not lose the cookie.
- **An upstream no longer defaults to disabled.** Creating or updating a proxy whose upstream
  omitted `enabled` stored it off, leaving the site on `502 no healthy upstream`; an omitted field
  now means enabled, and an explicit `false` still disables it.
- **`/api/setup/status` stops describing the host after setup.** The unauthenticated endpoint now
  returns only `needs_setup` and `version` once an administrator exists, instead of the base
  domain, listener addresses, interface names and kernel-ban state.

## [1.20.0] — 2026-11-22

### Added

- **Accounts and roles (RBAC).** **Account → Administrators and roles** adds more administrator accounts and
  assigns each one a role. Four built-in roles — Administrator, Operator, Read-only and Viewer — cannot be
  edited or deleted; custom roles grant view or change per area (dashboard, traffic, policies, proxies,
  streaming, certificates, sources, settings, accounts, system). A write grant implies read, the API refuses
  routes outside a role, and the console hides pages the role cannot see. A new account's authenticator secret
  and recovery codes are shown once. The last administrator cannot be demoted, deleted, or remove its own
  role.
- **Admin source allowlist.** **Settings → Network** accepts IPs/CIDRs that may open the sign-in form and call
  the admin API. The list is enforced at login and in the authenticated middleware, and a change that would
  exclude the caller's current address is refused instead of locking the operator out.
- **HTTP-01 and TLS-ALPN-01 certificates.** A certificate request now chooses DNS-01 (unchanged), HTTP-01 on
  port 80, or TLS-ALPN-01 answered by the existing HTTPS listener through the `acme-tls/1` ALPN protocol.
  Wildcards still require DNS-01, and non-DNS challenges need no provider credentials.
- **Bot filter.** **Policies → Bot filter** refuses known scraper user agents, or scrapers plus every declared
  bot and empty agent, before the proof-of-work challenge. Search engines, social previews and an editable
  allow list are exempt, and refusals are logged as a `bot-filter` stage naming the matched rule.
- **Backend header audit for protection profiles.** **Check a site** fetches a proxy's upstream as that
  hostname, compares its framing, HSTS, CSP, nosniff and referrer headers with the selected protection
  profile, and warns when `frame_options=off` would delete a strong application header, when SAMEORIGIN would
  replace a DENY the application already sends, or when neither side sets one.
- **Daily GeoIP refresh.** An installed DB-IP Lite database now updates itself once a day; the **Update
  database** button remains for manual refreshes, and the automatic timer can be switched off in Settings.

### Changed

- **Higher-traffic hosts.** The SQLite pool scales with the CPU count (2× CPUs, capped at 32, override with
  `WAFPROXY_DB_CONNS`) instead of staying at four connections, and the upstream transport keeps a larger idle
  pool so an 8 vCPU edge does not reopen backend connections between bursts. `docs/BENCHMARKS.md` now includes
  a capacity-planning section with projected limits and request-budget guidance for 4 vCPU/8 GB and
  8 vCPU/16–32 GB hosts, clearly separated from measured numbers.
- **Dashboard.** Requests and the request budget share one card: total requests on the left, in-flight/maximum
  and refusals on the right.

### Fixed

- **Two dead built-in threat feeds.** Spamhaus EDROP's file is now a header-only stub (merged into DROP)
  and URLhaus' public export answers `410 Gone` without an Auth-Key, so both rows are removed from new
  and existing databases. A custom feed that reuses either name is left alone.

## [1.19.0] — 2026-11-22

### Added

- **Streaming forwarders enforce the named blocklists and whitelists.** A Plex or Jellyfin
  section on the **Streaming** page now attaches any number of lists from **Policies → Blocklist
  profiles** / **Whitelist profiles**, with the same meaning they have for a proxied site: a
  blocklist refuses its addresses and countries first, a whitelist makes the port reachable only
  from what it holds plus the port's own allow list, and a blocklist wins when both name the same
  address. Country entries use the GeoIP database the HTTP pipeline already loads. Editing a list
  recompiles the live listeners in place, so a change never drops a running stream, and a list a
  forwarder still attaches cannot be deleted until it is detached. The selection is stored as
  `stream_<id>_lists`.

### Changed

- **Blocked and allowed events name the list that decided them.** A named blocklist refusal is
  filed under `list-block` and a whitelist refusal (or the allow it grants) under `list-allow`,
  and the verdict now carries the list name, so the Logs row and the event's reason say which
  list to edit instead of a generic profile stage.

### Fixed

- **Docker application updates failed with "lib missing".** `deploy/install-docker-updater.sh`
  installed `self-update` and `self-update-check` but not `wafproxy-update-lib.sh`, which the
  updater sources before it touches git, so every one-click update on a Docker host stopped at
  the guard. The library is now installed by every installer, and a test parses the updater's
  `source` lines and fails if any installer skips one of them.

## [1.18.0] — 2026-11-22

### Added

- **Named blocklists and whitelists.** **Policies → Blocklist profiles** and **Whitelist profiles** hold
  reusable lists: IPs and CIDRs pasted one per line, plus countries chosen from a searchable picker that
  moves them into the list. An **Access profile** attaches any number of them. A blocklist refuses its
  addresses and countries on every host that profile serves, and a whitelist makes those hosts reachable
  only from what it names; a blocklist attached to the same profile still wins. Entries are validated on
  save and stored canonically, the name and kind are fixed once created, and a list that a profile
  attaches cannot be deleted until it is detached. `GET/POST /api/lists` and `PUT/DELETE /api/lists/{id}`
  are the endpoints; the engine compiles each list once per reload, so a request merges prefixes instead
  of parsing them.
- **CI fails when the committed console bundle is stale.** The frontend job rebuilds `internal/webui/dist`
  and then fails on any difference from the checkout, so a release cannot ship an old console — which
  also stopped the updater from pulling cleanly.
- **A scripted test for the update restore step.** `deploy/test-self-update-restore.sh` builds a
  throwaway pair of repositories, dirties the checkout exactly the way `npm run build` does (an edited
  tracked bundle plus a new asset name), asserts `git pull --ff-only` refuses, then runs the updater's
  restore step and asserts the pull lands on the new release. The restore now lives in
  `deploy/wafproxy-update-lib.sh`, which both the updater and the test source, and a new CI job runs it.

### Changed

- `deploy/install.sh` and the updater install `wafproxy-update-lib.sh` next to the update scripts.

## [1.17.2] — 2026-11-22

### Fixed

- **The Update button and the documented upgrade commands failed on a checkout that had been
  built.** `npm run build` rewrites `internal/webui/dist`, which the repository commits, so
  `sudo git pull --ff-only` refused to run with "local changes to the following files would be
  overwritten", and the updater's restore of that directory left the built asset names behind:
  an untracked asset blocks the incoming commit exactly as an edited file does. The updater now
  puts the directory back before pulling (`git checkout` plus a scoped clean), and the README,
  `docs/INSTALL.md` and the console's fallback text give the sequence that works, ending in
  `deploy/wafproxy-self-update.sh` — the same script the button runs, which pulls, builds,
  installs and rolls back on failure.
- **An application update no longer needs a Node toolchain on the update user's `PATH`.** The
  updater ran `make all`, so a host where `npm` lives in an operator's shell (nvm), or one
  without npm registry access, failed at `npm ci` and the update aborted before any binary was
  installed. It now builds the console only when `npm` is reachable, and always runs `make
  build`, which embeds the console bundle the release already commits.

## [1.17.1] — 2026-11-22

### Added

- **A committed request-budget burst test.** `TestRequestBudgetShedsExactSplit` sets the budget to
  three, releases nine concurrent requests against an upstream that sleeps for 500 ms, and asserts
  the exact outcome: three `200`s, six `503`s that each carry a `Retry-After`, the upstream saw
  exactly three requests, and `Capacity()` reports 0 in flight, 3 allowed and 6 shed. It runs in
  about a second under `-race`, so a regression in shedding fails CI instead of needing a manual
  load run.
- **A WAF profile picker on the proxy form.** A preset attaches its profile to the site, but the
  form showed only the access profile, so the attached profile could not be seen or changed from
  the site it applied to. The form now lists the saved profiles (with "From the access profile" as
  the default) and shows the preset's profile when the site is edited.

### Fixed

- **The dashboard's request-budget card read `0 / 0`.** The event stream marshalled the collector
  snapshot directly, so the streamed payload lacked `inflight`, `max_inflight` and `shed` that
  `/api/metrics` filled in from the proxy. The card is fed by the stream, so it showed zeros from
  the first tick, and the budget counters appeared to be missing from the whole console. Both paths
  now go through one `metricsSnapshot()` helper, covered by `TestMetricsStreamCarriesTheRequestBudget`.

## [1.17.0] — 2026-11-22

### Added

- **A protocol conformance suite and fuzz corpora.** `internal/proxy/conformance_test.go` covers
  the request shapes that end in smuggling advisories: a duplicate `Content-Length`, a length
  together with `Transfer-Encoding`, empty or malformed header names, an absolute-form target, an
  `OPTIONS *` target, an `h2c` upgrade and an upgrade on a method other than `GET`. It also proves
  a `#` in a percent-encoded path survives forwarding, a dot-segment cannot reach a decoy path
  unseen, and a WebSocket `101` reaches the client with the tunnel usable. `conformance_fuzz_test.go`
  fuzzes `cleanPathSegments` (absolute, no dot segments, idempotent) and inbound header screening
  (no panic, no spoofable header survives). Fuzzing found three real parser bugs, fixed here: an
  empty or relative path was forwarded as-is instead of being rooted, `OPTIONS *` was treated as a
  site request, and an upgrade header was forwarded without being limited to a WebSocket `GET`.
- **A per-site response ceiling.** A WAF profile's `max_response` refuses an upstream response
  whose declared length exceeds it (502, with a `response-cap` event) and cuts a streamed response
  the moment it passes, discarding the partial cache entry. An upstream failure after the response
  started now logs and stops instead of appending an error page to a partial body.
- **Login-path throttling and an admin-path allowlist.** A profile can name the paths that take
  credentials (`login_paths`, `login_rps`, `login_burst`); each client gets its own bucket per path,
  so credential stuffing is throttled before it reaches an application that may have no limit of
  its own. `admin_paths` plus `admin_ips` restrict paths to the operator's own ranges; a malformed
  CIDR is refused at save time rather than silently leaving the path open.
- **Application presets.** `internal/preset` holds starting configurations for Nextcloud, Jellyfin,
  Plex, Home Assistant, Proxmox VE and a generic application: method allowlist, body and response
  ceilings, login paths and rate, admin paths and allowlist, and the CRS rule IDs each application
  is commonly a false positive for. Choosing one when a proxy is created writes an ordinary WAF
  profile named after the host (`GET /api/presets`, **Proxies → New proxy → Application preset**), so
  every value stays editable under **Policies → WAF profiles**. The console shows what a preset will
  set before it is applied and never re-applies it on edit.

### Fixed

- Saving a WAF profile no longer panics when the API runs without the policy engine (test servers);
  the reload is skipped instead.
- The proxy's WAF-profile columns gained the ceiling and the two path lists in schema version 14.

## [1.16.1] — 2026-11-22

### Added

- **A security policy.** [SECURITY.md](SECURITY.md) documents the supported versions, the private
  reporting route (GitHub security advisories), what a report should contain, the acknowledgement
  and fix targets, the disclosure deadline, what is in and out of scope, and the scope of the next
  review. The README links it from the documentation list and from the security section, and says
  plainly not to open a public issue for a vulnerability.
- **A fronting-proxy integration test.** `internal/proxy/fronting_proxy_test.go` puts a real HTTP
  proxy in front of the request pipeline with `WAFPROXY_TRUSTED_PROXIES` set through the actual
  configuration loader, and proves the address that proxy names is the one the access profile, the
  ban engine, the access log and the upstream see. It also proves a hop outside the allowlist is
  still overwritten: a ban on the header's value does not touch the sender, and a ban on the sender
  does.
- **A request-budget regression test.** `TestShedRequestGets503` covers the refusal path (status,
  `Retry-After`, counter). Under load with `WAFPROXY_MAX_INFLIGHT=8` and a two-second upstream, 40
  concurrent requests produced exactly 8 responses and 32 refusals, resident memory moved by
  204 kB, and `/api/metrics` reported `inflight 0`, `max_inflight 8`, `shed 32`.

## [1.16.0] — 2026-11-22

Findings from a security review of 1.14.0, fixed. None of them was a pre-authentication remote
compromise; each is a case where a safe default or an existing guarantee did not hold.

### Security

- **Agent webhooks go through the SSRF guard.** Saving an agent link now runs the endpoint
  through the same check as proxy upstreams, threat feeds and notification webhooks, so a
  link-local or cloud metadata address is refused instead of turning the console into the pivot
  the guard exists to prevent. A LAN or loopback collector is still accepted. The dispatcher
  uses its own client with a 5-second timeout that does **not** follow redirects, so a `302` to
  `169.254.169.254` cannot walk around the save-time check.
- **Session cookies are no longer stored in the clear.** `sessions.id` is an HMAC-SHA256 digest
  under the console key instead of the cookie value, so a copied database, backup, rsync or
  container volume holds no usable admin session. The digest is stable across restarts; sessions
  written by an earlier release cannot be converted and are cleared once, which signs everyone
  out after the upgrade.
- **`docker run` alone is safe.** The console now defaults to `127.0.0.1:8080` and
  `WAFPROXY_GUI_PRIVATE_ONLY=true` in the binary and the image, not only in compose and
  `install.sh`. The boot log warns when the console is bound off-host with the private-network
  check disabled. Nothing changes for an existing install: compose, `install.sh` and the
  wizard's stored listener all supply both values explicitly, and the stored listener still wins.
- **Real client addresses behind a trusted proxy.** New `WAFPROXY_TRUSTED_PROXIES` (empty by
  default) lists the CIDRs whose `X-Forwarded-For` may name the client. The right-most entry that
  is not itself a trusted proxy wins; an untrusted peer's header is still discarded, so spoofing
  remains impossible. The resolved address is used by the access gate, access profiles, rate
  limits, the ban engine, GeoIP, the access log, the upstream `X-Forwarded-For` and the
  console's private-network and Tailscale checks. Behind a tunnel, leaving it empty makes every
  client look like loopback — the LAN check then passes for traffic that is not on the LAN, and
  one decoy hit bans the tunnel itself.
- **The agent delivery queue is bounded.** At most 1000 pending rows per link: the oldest are
  dropped (and the drop is logged once per event) so a detector firing against a dead agent
  cannot fill an SD card. A link whose last delivery exhausted its attempts stops queueing new
  rows; the failed row stays visible for inspection.
- **Request memory is bounded.** New `WAFPROXY_MAX_INFLIGHT` (default 128) caps concurrent
  requests, each of which may buffer a body up to the profile limit. Requests past the budget
  are refused with `503` instead of growing the heap, and **Dashboard → Request budget** shows
  the current count and how many were refused.

### Fixed

- `TestDecoyMatchesCanonicalPaths` used one source address for every case while the decoy ban is
  recorded in a goroutine, so it could observe its own earlier ban and fail under `-race`. Each
  case now uses its own documentation address.
- `GET /api/bans` reported `limited: true` whenever the page was exactly full, even though
  nothing was hidden. It now means "there are more rows than shown"; the payload also carries
  `total`.
- A temporary ban longer than 24 hours was silently shortened. `POST /api/bans` now answers
  `400` and says so, instead of quietly applying a different ban than the one requested.
- README claimed features were "not included in 1.3.0" at version 1.15, and linked two headings
  that no longer existed.
- The README and `docs/INSTALL.md` still promised that the first-boot console fallback is a
  wildcard `:8080`, which stopped being true when the default moved to `127.0.0.1` in this
  release. Both now describe the loopback fallback and the wildcard warning that still exists for
  operators who configure one.

### Changed

- The repository no longer carries the internal planning document, the dated design specs or the
  security review that produced this release; the README, `docs/` and this changelog cover what
  ships.
- Example addresses in `.env.example`, the README and `docs/INSTALL.md` are neutral
  (`127.0.0.1`, `192.168.1.10`) instead of one specific home network, and the Plex/Jellyfin
  examples no longer name a real host.

## [1.15.0] — 2026-11-22

### Changed

- **The Update button prepares the install root itself.** `self-update` now creates
  `/var/lib/waf-proxy/{bin,lib,data}` with the owner and mode `install.sh` uses and moves state
  from `/var/lib/wafproxy` before installing. An update from 1.13 can no longer install the new
  unit, which expects `/var/lib/waf-proxy/data`, and leave the service dead with a missing
  database. The migration test is the database file rather than an empty directory, so the
  updater's own result record cannot make the move look unnecessary; `install.sh` uses the same
  test.
- **A failed update is rolled back, not left half-installed.** Before touching anything the
  updater keeps the binaries its current unit names, both unit files, the `/usr/local` symlinks
  and the pre-1.14 state path. If the install step, the restart or the first seconds of the new
  service fail, it puts every one of them back, restarts the previous build and reports that it
  did. A failed Update button therefore leaves WAF-Proxy running the version it ran before, and
  the message tells the operator to run `deploy/install.sh` if the console does not come back.
- **The outcome of the last update survives the restart.** The updater writes
  `data/last-app-update` and the Updates page shows it with an installed/failed badge, which is
  the only way the rollback message can reach the console: the update ends by replacing the very
  process that would have displayed it. Docker installs put the previous image tag back when the
  new container does not come up.
- Copying the helper scripts and binaries is now atomic (write, then rename), so a running script
  is never overwritten in place and an interrupted copy cannot leave a half-written binary.

### Fixed

- A failed application update reported `exit status 1` instead of the reason; the console now
  shows the updater's last output line, and the full output stays under **Last update output**.
- Removed the unused `joinIDList` store helper, and the snapshot fields that were produced but
  never read (`app_update_run_error`, `app_update_output`).
- Two README anchors (`#host-updates`, `docs/INSTALL.md#13-host-updates-on-systemd`) pointed at
  headings that no longer exist.

## [1.14.1] — 2026-11-22

### Fixed

- **The Access profiles tab no longer blanks the console.** A profile saved with no lists came
  back from the API as `rules: null`, which the page tried to map and crashed on, taking the
  whole interface with it; lists are now always a JSON array and the page also tolerates rows
  written by earlier builds. A page that still throws shows an error card instead of an empty
  console, and navigating away clears it.
- **Editing a profile no longer pretends its name is editable.** Both profile dialogs offered a
  name field that the server ignores once the profile exists; the field is now read-only for an
  existing profile. The lists, WAF profile and protection profile remain editable.
- **Updating a list over the API keeps fields the request leaves out.** `PUT /api/policies/{id}`
  reset `priority` to `0` and switched `enabled` off when the body omitted them, so a partial
  update silently disabled the list. Both fields now keep their stored value unless the request
  sets them.
- **The Policies tab bar wraps.** Seven tabs overflowed a 1440-wide console and forced the whole
  page to scroll sideways.

## [1.14.0] — 2026-11-22

### Changed

- **One install root: `/var/lib/waf-proxy`.** `bin/`, `lib/`, the update checkout (`src/`) and the
  state (`data/`) now live under the same directory, instead of `/usr/local/waf-proxy` for the
  program files and `/var/lib/wafproxy` for the database. `install.sh` moves both into the new
  root on upgrade and keeps the old state directory as `/var/lib/wafproxy.pre-1.14`.
  `exec`, `ProtectSystem` and the helper units were updated to the new paths; `/usr/local/bin` and
  `/usr/local/lib/wafproxy` remain symlinks for compatibility.
- **Application updates build from a managed checkout.** `install.sh` clones the checkout it ran
  from into `/var/lib/waf-proxy/src` (keeping the original `origin`) and records that as the
  update source, so the **Update application** button no longer rebuilds a directory under
  `/home` as its owner. A host where the clone cannot be created keeps recording the directory
  the installer was run from.
- **Build metadata uses the current repository name.** `AppRepo` and the Makefile default are
  `kenhermesagent-lab/WAF-Proxy`; a checkout whose origin still says `WAF-Proxy-Docker` is
  accepted as the same repository, and any other owner is still refused.

### Fixed

- **The Update button no longer refuses a normal checkout.** The pre-pull check ignored untracked
  files (build output, `data/`) and the console bundle the build itself regenerates, which made
  every update on an existing host fail. A rebuild now restores `internal/webui/dist` before
  pulling, the helper has a usable `PATH`, and the self-update script restarts
  `wafproxy.service` itself after installing, so the new binary is loaded.
- The Updates page waits up to 20 minutes for a rebuild instead of six, shows the helper's output
  while it runs, and reports a timeout with the log command to check instead of claiming success.

## [1.13.0] — 2026-11-22

### Added

- **MIT license** (`LICENSE`), linked from the README.

### Changed

- **Agent webhooks follow event routing.** Agent links now honour the same per-class switches as
  Telegram, email and the webhook channel, so muting a detector stops it reaching the agent too.
  Payloads are still queued before any network call and retried with the same backoff; a muted
  class is marked `suppressed` on the delivery row (pruned with delivered rows) instead of being
  posted, and an admin **Test** payload always goes through.
- **Recent deliveries shows the routing class.** Each row displays the class it routes under next
  to the kind it was stored with, and marks rows whose class is currently muted — so a legacy
  CrowdSec ban stored as `ban` no longer looks like an ordinary ban.

## [1.12.0] — 2026-11-22

### Changed

- **Permanent-ban roll-up is fail-safe.** The list is written, loaded and checked against the expected
  entry count before any ban row is deleted. If the list cannot load, the half-built feed is removed, the
  bans stay in force and the request fails with the reason instead of reporting a success that left
  addresses unblocked.
- **Rolled-up bans stay absolute.** The permanent-ban list is marked `always_block` and evaluated before
  the allow lists, so an address on a global IP whitelist is still refused while it is on that list — the
  same force it had as a ban row.
- **Docker keeps the console private by default.** Compose now binds the GUI to `127.0.0.1:8080` unless
  `WAFPROXY_LISTEN_GUI` is set, and passes `WAFPROXY_GUI_PRIVATE_ONLY=true`, so the unauthenticated setup
  wizard cannot be published on the WAN by starting the stack before `deploy/.env` is filled in.
  `deploy/.env` / `.env.example` document the LAN address and port to use.

### Fixed

- The temp-ban view's **Showing the newest 200** note now appears: the API's `limited` flag reflects the
  limit the store actually applied (including the default) instead of only an explicit one.

### Documentation

- The repository is **WAF-Proxy**; the build metadata default (`AppRepo`), quick-start clone URL and docs
  links follow the new name, and the README covers anomaly detection, AI Agent Access (agent webhooks and
  MCP tools), access profiles, the ban lifecycle, event routing and the Docker console binding.

## [1.11.1] — 2026-11-22

### Fixed

- **Muting an event class now stops what is already queued.** Routing was only checked when an alert was
  enqueued, so alerts that were pending when a class was muted — including CrowdSec bans stored as plain bans by
  an older build — were still delivered and retried. Routing is re-checked at delivery: an alert whose class is
  muted is marked `suppressed` instead of sent.
- CrowdSec ban classification moves into the notification package (`notify.BanClass`) and matches the source
  case-insensitively with any `crowdsec:`/`crowdsec/` suffix, so a decision cannot fall through to the
  temporary-ban class.

## [1.11.0] — 2026-11-22

### Added

- **Durable agent delivery.** An agent event is written to a queue before any network call, so a restart, a crash or
  a dead agent cannot lose it. Failed deliveries retry with exponential backoff (30s doubling, capped at an hour,
  eight attempts) and the link row now shows the last payload's state, attempt count and the error the agent
  returned, plus **Retry** and a **Test** that reports the real answer.
- **Access profiles bundle everything for a host.** A profile holds lists with a role — *allow only these* narrows
  the site to the addresses and countries it names, *block these* drops them — and carries its WAF and protection
  profiles. Creating a proxy host is now a single choice, and a host profile stacks on the global settings, so one
  site can be narrower than the global allow list.
- **Permanent bans roll up into a local threat list.** One button writes every permanent ban to
  `<data>/feeds/permanent-bans.txt`, loads it as a local feed so the addresses stay blocked, and clears the rows out
  of the ban table.

### Changed

- Temporary bans last at most 24 hours and are deleted when they expire, and the ban view caps at the newest 200, so
  the list only ever holds recent cool-downs.

## [1.10.0] — 2026-11-22

### Added

- **AI Agent Access.** **Agent access** is now **AI Agent Access** and gains *Agent links*: point one at the
  webhook your agent listens on and every new anomaly event is POSTed there as JSON, signed with
  `X-Wafproxy-Signature: sha256=HMAC(secret, body)` plus a timestamp so the agent can reject replays. The
  secret is sealed with the console key, links can be paused, and **Test** sends a synthetic event and
  reports what the agent answered. No model runs in the console; the agent does the thinking.
- **`list_anomalies` MCP tool** so an attached agent can read detections (kind, proxy, value, baseline)
  with the token it already holds.
- **IP / CIDR block list.** **Countries, IPs, ASN** can now create a block list next to the allow list, so an
  access profile can be a true whitelist or blacklist. An explicit IP block wins over an allow list entry
  for the same address — a compromised allowlisted host is still refused.

### Fixed

- An anomaly event reached a webhook without its stored id, so an agent could not refer to the event it
  was answering.

## [1.9.0] — 2026-11-22

### Added

- **Anomaly detection.** A new **Anomaly events** page evaluates the proxy counters once a minute and raises
  three detections, each with its own notification class so one can be muted without losing the others:
  *outbound traffic spike* (per-proxy response bytes above the floor and a multiple of that proxy's
  median over the last hour), *request-rate spike* (rps above the threshold and the baseline), and
  *authentication failure burst* (failed gate logins per proxy). A condition that lasts stays one open
  event, refreshed in place, instead of a new row every minute. Thresholds ship at the values in the
  design — 5 MB/min over 4×, 200 rps over 3×, 20 failures/min — and are editable on the page. Events can
  be acknowledged, and the list shows value against baseline so a false positive is easy to recognise.

## [1.8.1] — 2026-11-22

### Added

- **CrowdSec bans have their own notification routing.** **Notifications** gains a *CrowdSec ban* toggle,
  separate from *Temporary ban* and *Permanent ban*, so a busy blocklist feeding decisions into the bouncer
  no longer buries the bans this console decided on itself. Turn it off and CrowdSec decisions stay in the
  ban list and the logs; turn it on and they arrive like before. With no event list saved every class is
  still delivered, so nothing changes until you choose.
- **Address lookup on Threat intel.** A *Check an address* box answers whether a single IP is in a loaded
  feed (with the feed's action), whether it is currently banned (permanent or temporary, with the reason,
  source and expiry), or neither.

## [1.8.0] — 2026-11-22

### Added

- **Identity-provider access gate.** A proxy's access gate can now be handed to a provider you already run.
  **Policies → Identity providers** registers an Authelia, authentik or generic forward-auth endpoint with
  its verify URL, the portal unauthenticated visitors are sent to, an optional shared-secret header, and
  the product-specific URL hints for each. The proxy form's gate mode gains **Identity provider
  (forward-auth)** plus a provider picker. Every request is checked against the verify URL with the
  visitor's cookies and the usual `X-Forwarded-*`/`X-Original-URL` headers: a 2xx allows it, a 401 sends
  the visitor to the portal with `?rd=` back to the page, a provider redirect is followed by the browser
  rather than the proxy, and an unreachable provider refuses access instead of opening the site. Secrets
  are sealed with the console key and never returned; a provider a proxy still uses cannot be deleted.

## [1.7.0] — 2026-11-22

### Added

- **Protection profiles.** A named set of response headers (HSTS, CSP, frame options, referrer
  policy, permissions policy, cross-origin isolation) that the proxy applies to upstream responses.
  **Policies → Protection profiles** creates, edits and deletes them; each proxy picks one under
  **Protection profile**, and a new proxy preselects the built-in *Recommended hardening* profile.
  Choosing **None** leaves that site's headers untouched.
- **Access profiles.** A named bundle of existing WAF policies, so one site can be locked down
  without re-selecting rules per proxy. **Policies → Access profiles** edits the bundle; the proxy
  form's **Access profile** field applies it on top of the proxy's own policy. Disabled policies
  stay off even when a profile lists them.
- **HTTPS enforcement.** A proxy can now redirect plain HTTP to HTTPS before the WAF runs, so a
  policy that inspects the request body never sees the pre-redirect hit.
- **Scheduled backups.** **Settings → Backup schedule** writes the same JSON export the download
  button produces, on a daily or weekly schedule, to a local directory, a git working tree
  (optionally committed and pushed), SFTP, or FTP. Remote passwords are sealed with the console
  key; SFTP requires the destination's SHA256 host key fingerprint instead of trusting any key.
  FTP is offered but carries an **unencrypted** warning, because it sends the archive and its
  password in clear text. Local and git destinations keep the newest *N* files, and **Back up now**
  runs one immediately, reporting the target and any error on the card.
- **Automatic updates.** **Updates → Automatic updates** applies a newer build once a day at a set
  time, but only when the tracked branch actually has a newer build and the host reports update
  support; the outcome goes to the notification channels that route *Application update*.

## [1.6.3] — 2026-11-21

### Added

- **Bulk ban actions.** Temp bans has a checkbox per row and a select-all header. Ticking any rows
  reveals **Make permanently banned** and **Unban**, which apply to every selected row in one
  audited call (`POST /api/bans/bulk`). Already-permanent rows cannot be selected, so a select-all
  only ever acts on the temporary bans the admin is looking at.
- **Admins can create and delete their own CRS profiles.** **Policies → WAF profiles** has a
  **New profile** button; a new profile starts from safe values (block, paranoia 1, anomaly 5, the
  normal method list) and is tuned in the same editor. Custom profiles get a **Delete** action.
  Built-in profiles stay as reference points and cannot be deleted, and a profile a proxy still
  selects is refused with the reason (the column is `ON DELETE SET NULL`, so deleting it would
  silently drop that site to the default protection).

### Fixed

- Rule reporting now names the attack rule. The CRS setup action (900990) matches on every request
  with no severity, so it used to win the "most severe match" choice and every blocked request was
  logged as rule 900990 with an empty message.

## [1.6.2] — 2026-11-21

### Security

- **A checkout recorded from the Updates page must be this repository.** The root helper pulls that
  checkout and installs its build as root, so `app-configure` now compares the checkout's `origin`
  remote with the repository the running binary was compiled from (`owner/repository`, in any git
  remote spelling). Any other origin is refused, closing the path where a console admin points the
  root helper at a repository they control. A fork sets its own repository at build time with
  `make REPO=owner/repo` or the `REPO` build arg.
- **Path-style file-access probes are blocked.** `/etc/passwd` as a request path reached the backend
  while `/?file=/etc/passwd` was blocked, because the CRS local-file-inclusion rules inspect
  arguments only. The WAF now denies a canonical filename under `/etc` (`passwd`, `shadow`, `group`,
  `gshadow`, `sudoers`), `/proc/*/environ`, `/proc/*/cmdline` and `.ssh` private/authorised key
  paths, with a trailing boundary so ordinary names such as `/etc/passwd-docs` still pass.

### Fixed

- **The Update button works again on Docker Compose installs.** Support was decided by `stat`ing
  `/etc/wafproxy/self-update.conf` and `/usr/local/waf-proxy/lib` from inside the container, where
  those host paths never exist, so a correctly installed host updater still reported the button
  unavailable. The console now asks the helper for the recorded checkout, its existence and any
  missing scripts through a new `app-status` action, and names
  `install-docker-updater.sh` (rather than `install.sh`) as the remedy for a Docker install.
- `install-docker-updater.sh` already installed both `self-update` and `self-update-check`; the
  page now reports that state through the helper instead of guessing from container paths.

## [1.6.1] — 2026-11-21

### Security

- **app-configure records a path only.** The helper no longer copies the checkout's update scripts into the
  root-run lib directory: a console admin supplied only a directory, and copying code from it would let that
  admin execute arbitrary code as root. The installed scripts must come from `install.sh`; when they are
  missing the page says so and asks for `sudo ./deploy/install.sh`.
- The Update button is reported as supported only while the recorded checkout still exists and the installed
  updater scripts are present, instead of failing when an admin clicks it.
- **Dot-segment paths are canonicalised before inspection and forwarding.** `/x/../.env`, `%2e%2e` and
  backslash variants were matched against a decoy/WAF rule for the literal path while the backend resolved
  them to another one. The edge now resolves `.`/`..` and duplicate slashes first, so the console, the WAF
  and the upstream all see the same path; NUL bytes are rejected.

### Added

- API test for `POST /api/updates/app/config` covering the recorded path reaching the helper, an empty path
  returning 400, and a helper rejection returning 409.

## [1.6.0] — 2026-11-21

### Added

- **Updates: record a checkout installed in another directory.** When the root helper is running but no
  checkout is recorded (or the install lives outside the path `install.sh` saw), the application card now
  offers a **WAF-Proxy checkout directory** field. The helper validates the path (absolute, a git checkout
  with an `origin` remote and the `deploy/` update scripts),   records it in `/etc/wafproxy/self-update.conf` and enables the Update button. The recorded path is shown in
  `/api/updates` as `app_source_dir`.

### Changed

- The application card now says plainly when the Update button is unavailable on this host, why, and how
  to enable it (install the helper, or record the checkout). The manual `git pull` / `make all` /
  `install.sh` commands are labelled **Manual fallback** instead of reading like the expected path.

## [1.5.1] — 2026-11-21

### Fixed

- **Recent deliveries on Notifications were blank.** Alerts were serialized with Go field names
  (`Channel`, `CreatedAt`) while the page reads `channel` and `created_at`, so every queued Telegram or webhook
  delivery rendered as an empty row. `model.Alert` now carries the same lowercase JSON tags as the rest of the
  models, and a store test pins the keys.

## [1.5.0] — 2026-11-21

### Added

- **CrowdSec enrollment is part of the install.** The install card asks for the enrollment key first, explains where
  to get it (app.crowdsec.net → Security Engines → Add security engine), and passes it to the root installer, which
  runs `cscli console enroll` in the same run. The page then asks for the engine to be approved in the portal and
  offers **Restart CrowdSec**, which applies the accepted enrollment through the root helper. A second button installs
  without a Cloud link for operators without an account; the installer still creates and verifies the bouncer and
  enables it, so bouncer state, last poll and decisions applied are live immediately.
- **The Updates page covers the whole tool chain.** The managed package catalog now includes `curl`, `openssl`, `git`,
  `crowdsec` and `tailscale` alongside `ca-certificates`, `nftables` and `tzdata`, each with the role it plays. Host
  packages are checked once a day in the background, so the page has a current answer without pressing Check.

### Fixed

- **Statistics failed-login table fits a laptop screen.** The proxy moved under the address, the last attempt became a
  relative time, and the block action sits in the state cell, so the table no longer scrolls sideways and the button is
  always reachable.
- **Threat intel tables no longer stretch the page.** The Feeds table scrolls in its own container and long decision
  reasons wrap inside their column.

## [1.4.0] — 2026-11-21

### Added

- **Failed access-gate logins on Statistics.** Every rejected gate login is stored with the username that was
  tried, grouped by address, username and proxy, and shown with the attempt count, the last attempt and whether
  the address is already blocked. A **Block permanently** button creates a permanent ban from the row; the gate's
  own ladder (15 minutes, 24 hours) stays as it was.
- **Console-pushed blocklists on Threat intel.** A read-only card reports what the engine is enforcing from
  `cscli metrics show decisions`: subscribed blocklists (`lists`), the community blocklist (`CAPI`) and decisions
  pushed from the console (`console`). The console owns those subscriptions, so they cannot be edited here.
- **Plan and Decision management on the CrowdSec page.** The rows `cscli console status` prints (plan, Central
  API, decision management, PAPI subscriptions) are shown as read, with a plain statement of whether
  console-pushed decisions will reach this engine.

### Fixed

- **Console enrolment state is read before the credentials file.** `cscli console status` runs through the root
  helper first, so a host where the console service cannot stat `/etc/crowdsec` is no longer reported as
  "not linked"; a permission error now reads as unknown, and only a missing file reads as not linked.
- **The installer's key check cannot hang.** The verification `curl` is bounded with `--connect-timeout 3` and
  `--max-time 8`, so a Local API that accepts the connection but never answers fails the check instead of
  hanging the install.

## [1.3.5] — 2026-11-21

### Added

- **The CrowdSec page says whether the console accepted the engine.** It reads `cscli console status`
  and shows *pending acceptance* versus *accepted by console*, with the exact status row, instead of
  inferring enrolment from a credentials file. Enrollment is two-step, so this is the difference
  between "request sent" and "data is flowing".

### Fixed

- **An in-console application update restarts the privileged helper.** Without it a new helper
  action, such as reading the console status, stayed unavailable until a reboot or a reinstall.
- **The installer verifies the bouncer key before reporting success.** After creating the key it
  calls `/v1/decisions` with `X-Api-Key` and requires HTTP 200, retrying for a few seconds while the
  Local API settles. A key the engine rejects now fails the install instead of being saved and
  silently doing nothing.

## [1.3.4] — 2026-11-21

### Fixed

- **CrowdSec install no longer fails at the bouncer step.** The installer generates the key itself
  and passes it to `cscli bouncers add --key` instead of reading the key back from the command's
  output, which newer engines leave empty — the install used to abort with "cannot read the bouncer
  key from cscli" after the engine was already running. Releases without `--key` still fall back to
  parsing their output.

### Changed

- **Linking to CrowdSec Cloud is the only manual step, and it is documented in the page.** The
  installer already fills in the LAPI URL and bouncer key by itself; the CrowdSec page now walks
  through app.crowdsec.net → Security Engines → Add engine → enrol → accept →
  `systemctl restart crowdsec`, and keeps that guidance visible after enrolment.

## [1.3.3] — 2026-11-21

### Changed

- **WAN traffic is split by owner.** The proxy's TLS listeners count the wire bytes they move, so the
  dashboard now shows proxy inbound/outbound and server & other inbound/outbound separately, with
  each direction's rate, total, share of the interface and its own sparkline. Server & other covers
  SSH, the admin console, OS updates and the upstream legs of proxied requests; the note under the
  cards says so, and the one-hour history carries the same split.

## [1.3.2] — 2026-11-21

### Added

- **One-click application update.** The Updates page shows the version on the tracked branch and
  turns it into a single action: the root helper pulls the checkout, runs `make all`, installs the
  new binaries and helper scripts, and the console restarts onto the new build. Nothing is typed
  into the browser and the data directory is untouched.
- **Coastline-accurate globe.** The canvas globe now draws Natural Earth 1:110m land instead of a
  dozen hand-drawn shapes, folded onto the limb so shapes stay closed as the sphere rotates.
- **Single program directory.** Native installs keep binaries and helper scripts under
  `/usr/local/waf-proxy` (`bin/`, `lib/`); `/usr/local/bin/wafproxy` and
  `/usr/local/lib/wafproxy` remain symlinks, so units and older releases keep working.

### Fixed

- **Decoy honeypot bypass.** The decoy list was matched against the raw request path and was
  skipped entirely for whitelisted clients, so `/./secret-admin`, `//secret-admin` or
  `/x/../secret-admin` reached the upstream without a ban. Decoys now run for every client and
  compare a canonical path.

## [1.3.0] — 2026-11-21

### Added

- **Statistical analysis.** A new Statistics page aggregates a selected date range into total,
  successful and blocked requests, hourly traffic, per-proxy request and byte shares, visitor
  countries and request stages, with Today and Last 7 days shortcuts.
- **Uptime monitoring.** Enabled upstreams are probed with an HTTP HEAD every 30 seconds. The
  page shows aggregate proxy state, per-backend latency, status code, error and 24-hour uptime,
  and sends backend down/recovery transitions to the notification channels that enable the new
  **Backend up/down** event.
- **Per-proxy live traffic.** The dashboard ranks proxies by requests and shows live req/s plus
  inbound and outbound bps derived from the cumulative counters, alongside cumulative bytes and
  blocked requests.
- **Richer attack globe.** The globe now has 1 h / 6 h / 24 h history, a coarse world map,
  clickable WAF/DoS/ban/feed filters with counts, travelling arc pulses and a reduced-motion-safe
  matrix-style background.
- **Country picker.** Country allow/block policies use a complete ISO-3166 dropdown with flags
  and names, plus an explicit Allow or Block action instead of a free-text country code. A
  country allow list is now exclusive: countries not on it are blocked, while an explicit IP
  allow list still wins. With no GeoIP country the allow list fails closed.
- **Multiple streaming sources.** The Streaming allow list accepts one IP, a CIDR, or a
  comma-separated mix, with an empty list still meaning any source; matching remains
  any-of and the existing connection cap and ban engine apply.

## [1.2.0] — 2026-11-21

### Added

- **Application updates from the console.** The Updates page compares the running build with
  the repository checkout and offers an **Update application** button. Native installs rebuild and
  reinstall both binaries through the existing root helper, then restart under systemd. Docker
  Compose installs can add `deploy/install-docker-updater.sh`, which exposes the same fixed
  socket action and rebuilds/recreates the container while keeping the data volume. The
  browser never supplies a repository URL, branch or command; the install records the checkout
  and its owner and the helper runs one fixed check and one fixed update script. Rebuilds run in the background and the page
  reconnects after the service restarts.
- **Local threat-intel uploads.** Threat intel accepts `.txt` and `.csv` files up to 10 MB,
  stores them in the data directory, validates that they contain IPs/CIDRs and lists them as
  local feeds. Local lists are always global blocks and can be enabled, disabled, refreshed
  or deleted like any other feed. CSV files may put the address in any column.
- **GeoIP installation.** Settings → GeoIP database downloads the current DB-IP Lite city and
  ASN MMDB files, validates both before replacing either, reloads them and reports file dates.
  DB-IP Lite is CC BY 4.0 and attributed in the console.
- **Dedicated CrowdSec page.** The bouncer configuration is persisted in SQLite with the key
  encrypted, can be enabled, disabled and tested at runtime, and shows poll/error/applied
  status. The page documents the required Security Engine/LAPI, the Docker sidecar and native
  `cscli` setup. Environment variables remain first-boot defaults.

### Changed

- Feed source URLs are fixed at creation; updating a feed changes only its action, interval
  and enabled state, so a local upload cannot be redirected to a remote fetch.
- DB-IP files installed by the console take precedence over a manually supplied GeoLite2
  file; `GeoLite2-*` still works when no DB-IP file is present.

## [Unreleased]

### Added

- **Per-certificate automatic renewal policies.** The Certificates page now lets an admin
  choose monthly, every two months, every three months, or one month before expiry. The
  scheduler runs every 12 hours, shows the computed next-renewal date, caps late policies at
  seven days before expiry, and keeps the previous certificate serving when a renewal fails
  so the next check can retry.
- **Green shield branding and repository update guide.** The console sidebar and browser tab
  now use the same green shield mark. The README's **Updating from the repository** section
  documents backup, pull, rebuild and health-check steps separately for Docker Compose and
  native systemd, including how to return to a release tag.
- **MCP gateway for standalone security agents.** The console now exposes an authenticated
  Model Context Protocol endpoint at `/mcp` and an **Agent access** page for named tokens.
  A Hermes-style agent can review events, inspect one IP's byte/path history, block an IP or
  CIDR, block an access-gate username, list live gate sessions, kill one session by a
  non-secret ref, and revoke every session from an address. The gateway is a fixed tool
  catalog with no shell or filesystem access; mutations require a reason and are written to
  the audit log as `mcp:<token name>`. Tokens are stored as SHA-256 hashes and can be revoked
  from the console; a static `WAFPROXY_MCP_TOKEN` remains available for headless installs.
  See `docs/MCP.md` and the README's **Agent access** section.
- Go tests for MCP authentication, protocol negotiation, tool discovery, log review, IP and
  username blocking, session revocation by ref/IP, over-broad CIDR refusal, audit attribution
  and token revocation; Vitest coverage for the Agent access page, token creation and
  one-time display.

- **Host updates on the native install.** A new **Updates** page inventories the fixed host
  package allowlist (`ca-certificates`, `nftables`, `tzdata`), refreshes the apt index, and
  shows available versions plus high/critical OSV advisories. Updates run through a separate
  root-owned `wafproxy-updated` Unix-socket helper with a compiled package allowlist; the
  console service keeps `NoNewPrivileges=yes`. Docker shows the page read-only because host
  packages belong to the image. See `docs/INSTALL.md` §13.
- Go tests for apt policy parsing, CVSS ranking, inventory snapshots and the helper allowlist;
  Vitest coverage for unsupported Docker/container and high/critical update states.
- **Native VM sizing guidance and `deploy/uninstall.sh`.** The README now recommends Ubuntu
  Server 24.04 LTS minimal with 4 vCPU, 8 GB RAM, 50 GB local NVMe and two NICs for the
  systemd deployment, with the 2 vCPU / 4 GB / 30 GB floor. The uninstall script stops and
  removes the native units, binaries, config, data, logs, app-owned nftables table and
  `wafproxy` user/group after confirmation; `--keep-data` preserves the database and config
  for a reinstall.

- **Native Tailscale access.** The console now has a **Tailscale** page with two default-off
  listeners. **Admin console over Tailscale** adds a `tailscale0` listener on the GUI port and
  accepts only `100.64.0.0/10` clients while keeping the LAN console unchanged. **Proxy app
  traffic over Tailscale** adds a second TLS/SNI listener on the WAN port, preserving the
  existing certificates, Host header and WAF pipeline. A small authoritative DNS responder can
  answer split DNS for configured proxy hostnames on the tailnet address; it is non-recursive
  and does not resolve arbitrary names. The native installer detects an existing Tailscale
  interface but deliberately leaves installation and `tailscale up` to the operator. See
  `docs/INSTALL.md` §12.
- Go tests for Tailscale address selection, the tailnet-only admin source check, DNS answers,
  API validation, and Vitest coverage for the new console page's unavailable, active, DNS-error
  and restart states.

## [1.1.1] — 2026-11-19

Fixes the decoy defaults that could ban real users, closes a round of security gaps, and
adds Plex forwarding as an add-on inside the 1.1 series.

### Added

- **Native systemd install.** The same binary now runs without Docker on a two-NIC Linux host:
  `make build && sudo ./deploy/install.sh` installs `deploy/wafproxy.service`, creates the
  `wafproxy` user and `/var/lib/wafproxy`, and grants only `CAP_NET_BIND_SERVICE` and
  `CAP_NET_ADMIN` through systemd ambient capabilities, so 443 and nftables work as a
  non-root service. The installer lists the host interfaces and asks which is WAN and which is
  LAN, then binds the proxy to the WAN address and the admin GUI to the LAN address only. It
  also enables an RFC1918-only client check on the admin listener (loopback is kept for an SSH
  tunnel) and prefills the wizard with the same addresses, so finishing setup cannot silently
  move the GUI back to another interface. `deploy/wafproxy.env.example` keeps the manual-install
  fallback on loopback. Docker Compose is unchanged and remains the reference deployment; both
  paths share the wizard, database and console.
- **Console regression test for the certificate dialog.** Vitest and Testing Library now cover
  the failed-`/api/certs` and empty-provider states, including the disabled select and
  **Request** button, and keep the normal provider path enabled.
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

- **A failed certificate load left an unusable provider dropdown.** If `GET /api/certs`
  failed or returned no providers, the certificate dialog still opened with an empty select
  and its Request button submitted the form anyway. The dialog now shows the load error, or a
  “no providers available” message, keeps the select disabled and disables **Request** until a
  provider list exists; the API also rejects an empty or unknown provider with a 400 instead of
  queueing a background issuance that cannot work.
- **`POST /api/bans` used Go field names.** The create handler returned the ban engine's
  `Record` (no JSON tags), so a caller saw `CIDR`/`Permanent`/`CreatedAt` while `GET /api/bans`
  returned the lowercase `model.Ban` shape. It now returns the stored row, including its id,
  with the same keys as the list.
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
per-phase version numbers described in the project plan did not exist as separate tags.
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

Planning baseline. Full design in the project plan; no application code yet.
