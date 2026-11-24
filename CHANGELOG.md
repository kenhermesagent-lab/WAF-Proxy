# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

**Release convention**

- `MAJOR.MINOR.PATCH`, tracked in `VERSION` (single source of truth).
- Each completed plan phase bumps **MINOR**: `0.1.0` → `0.2.0` → … → `1.0.0`.
- Fixes and add-ons inside a shipped phase bump **PATCH**: `0.4.1`, `0.4.2`.
- Every push to `main` has a matching section here; a release is published with an annotated
  `vX.Y.Z` tag on the commit that carries its section.

## [1.65.0] — 2026-11-24

### Added

- **Each streaming service has its own tab.** A strip under the Proxies tabs lists every
  forwarder in the catalog, and the page shows only the card, status and connecting guide of the
  one selected, so Jellyfin's settings no longer sit under Plex's. A dot marks the forwarders that
  are on, the strip scrolls sideways, and the page opens on the first enabled service.
- **Enabling a forwarder opens the port on the host firewall.** firewalld gets
  `--permanent --add-port` for the listen range and a reload, ufw gets `allow <range>/<proto>`. The
  ports a save opened are recorded beside the settings, so moving a card to another port or
  switching it off closes exactly what this console opened and leaves hand-written rules alone. A
  container with host networking shares those rules, and when neither tool is reachable the save
  still succeeds and the page says which range to open by hand.
- **The release-tag rules cannot drift from the runbook.** `deploy/check-tags-docs_test.sh` maps
  every refusal `deploy/check-tags.sh` and `scripts/release.sh` can print to the sentence
  `docs/OPERATIONS.md` uses for it, and runs in `make verify-release` and first in the `release` job,
  so it still runs while tags on origin are behind. A rule that lands without a runbook line fails
  the gate instead of being found later.
- **A release tag publishes the container image too.** The `image` job builds `wafproxy:<version>`,
  boots it and asks `/api/health` for its own version before it pushes
  `ghcr.io/<owner>/wafproxy:<version>`, so a tag delivers the binaries and the image that matches
  them. Dispatching the workflow for a tag that already exists builds and publishes its image the
  same way, so a release cut before this rule can still get one.
- **The release image is published for amd64 and arm64, and `latest` follows the newest tag.** One
  buildx build publishes both platforms under the documented package name, and the job reads the
  index back, so a manifest that lost an architecture fails the release instead of one host's pull.
  It then pulls the tag back from the registry and boots that copy, catching a truncated upload that
  would otherwise look green. `ghcr.io/<owner>/wafproxy:latest` moves only when the tag is the
  newest on `origin`, so dispatching an older tag republishes its own version and leaves the alias
  where it is.
- **The tag step says why it failed.** An unreadable remote is now reported as an Actions error
  annotation instead of a bare git exit code, and the wider token goes in as an authorization header
  with the checkout's own credential stripped from the remote first, because one request carries one
  credential and sending both is what made the first attempt die on a `git ls-remote`.
- **A wider token lets the job push every tag.** `TAG_PUSH_TOKEN`, when the repository sets it, is
  preferred over the App's token for the tag push and the API calls, so a tag whose range touches
  `.github/workflows/` — the case the App refuses — lands without anyone pushing it by hand. Its push
  also raises the event `Release` listens for, so the dispatch is kept only for the App's path.
- **The tags now publish their own releases.** A ref the tag job creates with `GITHUB_TOKEN` raises
  no push event, so `Release` never started for `v1.61.0` through `v1.65.0`: they had tags but no
  release, no binaries, and the Latest badge still pointed at `v1.60.0`. The job now dispatches
  `Release` for every dated tag that has no release, and does so even when one tag was refused.
- **Release tags fill themselves when a version lands.** `release-tags.yml` now also runs on a push
  to `main` that touches `CHANGELOG.md` or `VERSION`, so the dated section a release adds gets its
  annotated tag without anyone dispatching the workflow; it is idempotent (tags origin already has
  are skipped) and a push that changes neither file never starts it.
- **A tag names a commit a token may push.** When several commits carry the same `VERSION`, the tag
  now prefers one that did not change a file under `.github/workflows/`, because a GitHub App token
  cannot push the others — `v1.62.3` sat on a dependency refresh that edited two workflows and had to
  be placed on the newest commit of the same release that left them alone.
- **The tag helper gets past the workflow-file refusal.** A tag whose commit changed
  `.github/workflows/` cannot be pushed by the runner's token, and the tag run stopped on the first
  one — `v1.62.3` points at a merge that touched `ci.yml`. The helper now creates that tag through the
  API (tag object plus ref, no commits travelling) and carries on past a refusal, failing at the end
  with the versions it could not create instead of hiding the rest.
- **A release tag lands on the release that actually shipped.** `deploy/create-release-tags.sh` tagged
  the oldest commit that stamped `VERSION`, so a run would publish the notes and the binaries of a
  first draft and leave out every fix added before the version was cut. The version still in `VERSION`
  is now tagged at the newest commit that carries it; a version that has since been succeeded keeps
  the commit that cut it, because a later merge can briefly stamp the old number again. The walk also
  skips commits older than `VERSION` instead of ending on them.
- **The newest release keeps the GitHub "Latest" badge.** The releases API marks every newly
  published release latest unless it is told not to, so nine runs for a tag backlog would leave
  whichever finished last on the badge. The `assets` job now asks for `--latest` only when the tag is
  the highest version on `origin` and passes `--latest=false` otherwise, which also demotes an old
  release when its tag is dispatched again; `docs/OPERATIONS.md` gives the one-line
  `gh release edit <tag> --latest` for the backlog those tag-push runs already created.
- **The tags a dated section is missing can be cut from a runner.** The **Create release tags**
  `workflow_dispatch` job runs `deploy/create-release-tags.sh`, which tags each version at the
  commit that stamped `VERSION` to it and carries its section, pushes what origin lacks and then
  runs the remote gate. It defaults to a dry run, skips tags origin already has, and fails rather
  than tagging a commit whose `VERSION` names something else.

### Fixed

- **A stopped forwarder could start a handler after its shutdown.** A connection accepted as the
  service was rebinding or closing could register its relay after the shutdown had finished
  waiting, leaking the stream; the handler now registers under a lock that the shutdown closes
  first.
- **The example env file names the release it ships with.** `VERSION` in `.env.example` still read
  `1.20.0`, so a fresh `deploy/.env` tagged the image and the compose service after a release from
  months ago.
- **A tag backlog no longer hides the rest of the release job.** The tag check still turns red, but the
  job carries on through the pin checks, the SBOM and its upload and fails at the end, so the rest of
  the release metadata is still produced and attached while the tags are behind.
- **A streaming card that fails to bind no longer opens its port.** The firewall step runs after
  the listener, and a bind failure now leaves the rules untouched instead of punching a hole for a
  service that never started. A card that was already on closes the range the console opened for
  its previous port before the save fails, so a rebind onto a busy port cannot leave the old port
  open in front of no listener.
- **A stopped firewalld is not read as running.** Detection compared the state output for the word
  "running", which the tool's own "not running" answer also contains; it now has to be exactly
  that word, and a failing command reports the tool's message instead of "exit status 1".
- **The Backup card stops repeating the daily file.** Each tier reports its own last run, so a
  recent daily copy no longer appears as both the last run and the last daily copy; leaving the
  daily tier on adds its own last and next rows instead.

### Documentation

- The streaming install guide and the configuration reference describe the per-service tabs and
  say which firewall the console opens and which range to open when it cannot.
- The Settings help explains the two backup counts: the schedule keeps its own number of files,
  the optional daily tier keeps a second count, and each prunes independently.
- **The Docker install page shows how to run the published image.** It gives the `docker pull`
  line for `ghcr.io/kenhermesagent-lab/wafproxy:<version>`, read from `VERSION` in `deploy/.env`
  so the pull and the container cannot disagree, the name to tag it under so compose starts it
  without a build, and the reminder that the package starts private and needs a `read:packages`
  token until it is made public. The upgrades page gains the matching pull-and-restart path.

## [1.64.0] — 2026-11-24

### Added

- **Optional HTTP/3 over QUIC.** `WAFPROXY_HTTP3=1` makes the WAN port serve QUIC on UDP beside
  the TCP listener, through the same handler, so the WAF, gate, bans, cache and access log apply
  without a second implementation. TLS 1.3 with the existing certificate resolver and the `h3`
  ALPN, 0-RTT refused because a replayed request would skip the address check, at most 100
  incoming streams per connection, and at most ten handshakes a second from one source until its
  address is verified.
- **Backups keep two retention tiers.** The Backup schedule gains a daily copy beside its weekly or
  daily run: each tier writes its own file names (`wafproxy-daily-*` and `wafproxy-backup-*`) and
  prunes by its own count, so a weekly schedule with 52 copies holds a year while the last seven
  daily copies age out independently. Every file is still a complete export, and retention now
  applies to SFTP and FTP destinations too, which previously kept everything forever. When both
  tiers fall due in the same minute, the scheduler queues the second one behind the first and
  retries a run that fails, so a copy is never skipped for the whole period. A destination that
  refuses the prune's listing or delete now leaves the copy reported as written instead of failing
  the run.
- **Alt-Svc is advertised only where it can be used.** HTTP/1.1 and HTTP/2 answers over TLS carry
  `h3=":<port>"; ma=86400` while the QUIC socket is bound; the plain-HTTP redirector, an answer
  that already came over h3, and a node whose h3 bind failed advertise nothing.
- Over h3 the pipeline behaves as it does over HTTP/2: a GET, HEAD and POST reach the upstream, a
  policy block answers `403` without touching it, and a cacheable response is served from the
  cache. A demotion releases the UDP socket with the TCP listener.
- **The agent gateway reaches the console's newer surfaces.** `/mcp` adds read tools for the
  tenant list (`list_sites`), one host's full posture (`get_proxy`), certificate expiry
  (`list_certificates`), WAF profiles (`list_waf_profiles`), the media relay's live state
  (`get_stream_status`) and the administrator audit log (`query_audit`), plus one containment
  action, `cut_stream_ip`, which ends every relay stream from an address and audits the cut.
  `GET /api/mcp` now returns the catalog in `tools`, and the console's AI Agent Access page
  renders it from there instead of a hardcoded list.
- **Agent tokens are issued per site.** The token dialog picks the site a token acts on, and the
  gateway resolves each bearer token to that site before running a tool, so a tenant's agent
  reads and writes only that tenant's logs, proxies, bans, gate sessions and settings. `list_sites`
  still names every tenant, the host console mints and revokes tokens for all of them, and the
  environment token keeps acting on the default site.
- **A release tag that disagrees with `VERSION` fails the build.** The `assets` job compares
  `$TAG` with the version at the tagged commit before anything is compiled, attested or signed,
  so a `v1.62.4` tag on a commit holding 1.64.0 fails instead of uploading 1.64.0 binaries to a
  1.62.4 release; a `workflow_dispatch` run against an existing tag is checked the same way.

### Changed

- **A released section must carry its annotated tag on origin, and on main.** `deploy/check-tags.sh`
  requires a `vX.Y.Z` tag for every dated CHANGELOG section from 1.61.0 up, refuses a lightweight
  tag or one on a commit that does not carry the section, and the `release` job runs it on origin
  with `--remote`, so a release cannot ship untagged and the backlog cannot build up again. It also
  refuses a tag whose commit is not on `main`, so a tag on an unmerged branch — a release nobody
  receives — is caught in both modes. A section still marked `unreleased` needs no tag yet. The rule
  is enforced on `main` only, so a release branch can write its section before the tag exists;
  `--branch main` forces it from anywhere.
- **A tag has to name a version the CHANGELOG ships, and to have been cut in order.** A `vX.Y.Z`
  tag with no dated section fails — a `v1.62.4` tag on a commit that reached `main`, say — as does a
  release whose commit was cut after a newer one shipped, so an out-of-order release is caught even when its commit
  is merged. The date that counts is the release commit's, so re-cutting an older tag onto the
  right commit — the fix for a tag that landed on the wrong one — is not a late release. Tags below
  1.61.0 predate the rule and are left alone.
- **The tag check reads `VERSION` at the tagged commit too.** A `vX.Y.Z` tag whose commit carries
  another version fails as surely as a missing tag — in the clone, and on origin where the remote
  run fetches the tag a shallow checkout does not have — so a tag can never name a version the
  commit does not hold.
- **`scripts/release.sh` cuts the tag itself.** It commits the `VERSION` stamp and the rebuilt
  console bundle, creates the annotated tag on that commit, and runs the tag check before printing
  the push commands, so a release made through the script cannot ship untagged. It refuses a
  version older than the newest tag, and removes its own tag again when that check fails.
- **A UDP forwarder on the WAN port is a startup error.** The relay binds before the listener
  serves, so the boot names the card that holds the port and says to move it or unset
  `WAFPROXY_HTTP3`, instead of failing later with a bare "address already in use". A port held by
  something outside this process leaves HTTPS serving, logs the failure and stops advertising h3.
- **The uptime monitor is always on Statistics.** Its card moved above the date range, so backend
  probes stay on screen on Overview, Traffic and Access gate logins alike, and the separate
  Uptime tab is gone.
- **The topbar site chip names the console host, not the site's label.** The switcher, the
  single-site chip and the account menu's site list read `acme.example.com` instead of `Acme`, so
  the site a page answers for is visible at a glance. A site with no console host still shows its
  name. `GET /api/me` now carries `site_host` for the current site.

### Fixed

- **The agent gateway stayed on one site.** It was built on an unscoped store, so one token
  could read every tenant's events, gate sessions and gate users, and its audit rows were
  written without a site and stayed invisible in the console. The gateway now uses the default
  site's store, the same rows the console that mints tokens shows; `list_sites` still names
  every tenant.
- **The AI Agent Access page wraps instead of running off the card.** Every tool's description and
  the token scope list wrap inside their cells, so the 21-tool catalog reads in full at 1440 px
  without a sideways scroll.
- **A fresh single-node install serves again.** With high availability off the boot normalises a
  leftover standby to `standalone`, but a data directory that never held a role file has no node id
  and the save was refused. The node stayed a standby, bound the WAN address and never accepted a
  connection, so a new host answered the console and nothing else. The normalisation now mints the
  id, and the first request after the wizard is proxied.

### Security

- HTTP/3 refuses 0-RTT, bounds handshakes per unverified source, caps a connection at 100 streams
  and reuses the existing certificate resolver, so a QUIC client meets the same WAF, gate and ban
  policy as an HTTP/2 one.
- An answer advertises h3 only while the QUIC socket is bound: a client is never pointed at an
  alternative that is not listening.

### Documentation

- `docs/screenshots/agent.png` is retaken on a 1.64.0 build, now showing the tool catalog the
  page reads from `GET /api/mcp`, and the screenshot index says which capture is newer than the
  v1.62.2 set.
- `docs/CONFORMANCE.md` moves HTTP/3 from unsupported to supported with the cases that prove it,
  the configuration reference lists `WAFPROXY_HTTP3`, the install guides open the UDP port, and
  the Cloudflare Tunnel page states that the connector reaches the origin over HTTP/2, so h3 is a
  direct-path feature.

## [1.63.0] — 2026-11-24

### Added

- **A game server is now a first-class service.** A streaming service can forward UDP, with one
  session per client source and a connected upstream socket per session, so replies are
  demultiplexed by the kernel rather than by parsing the game's protocol. Sessions are capped in
  total and per source address, and an idle session is reclaimed after 60 seconds by default
  while media keeps its 30-minute window. No schema change and no new outbox row.
- **Port ranges.** `port_count` maps a listen range 1:1 onto the upstream — 2456–2458 forwards to
  2456–2458 — so a Valheim or ARK server is one card instead of three. A range that would run past
  65535 on either side is refused with the offending port named.
- **A ban cuts a live UDP session.** The ban map is checked on every datagram, not only when a
  session opens, so a source banned mid-session stops within one datagram; the cut is counted and
  logged once per throttle window instead of once per packet.
- Relay events now carry the protocol and the exact listen port that was hit, so a UDP range names
  the port a refusal came from in Logs as well as in the counters.
- **TCP+UDP pairing.** `protocol=both` binds a TCP listener and a UDP socket on the same number,
  which is what FiveM and Factorio need, and reports one status: bound only when both sockets are,
  with the failing protocol named otherwise. TCP services gained port ranges too, so a game that
  opens several TCP ports is one card.
- **The relay reports what it moves.** Each service now returns bytes and packets in both
  directions, refusals, oversize drops, live sessions per protocol and the fifty busiest sessions.
- **Game server presets.** The catalog seeds Minecraft (Java and Bedrock), Source, Valheim,
  Palworld, FiveM, Factorio, ARK, Rust and 7 Days to Die with a default protocol, port range and
  a one-line note; ARK's query port and Rust's RCON are separate cards. Every value stays
  editable, and a test compares the install guide's table with the catalog so the two cannot drift.
- **The Streaming page groups the catalog and shows it live.** Media, game and custom sections each get
  a card with its protocol, port range, upstream and — for UDP — the per-source and idle limits; a UDP
  card with no allow list says plainly that it answers any source. The status side shows what is
  bound, bytes each way, refusals, oversize drops and the busiest source.
- **Sessions carry a last-seen time, and the page refreshes itself.** The status list keeps the fifty
  newest sessions with bytes, packets, start and last activity, ranked by traffic, and the page polls
  every three seconds — only while the tab is visible.
- **Prometheus covers the forwarders.** `wafproxy_stream_sessions`, `_stream_bytes_total`,
  `_stream_packets_total`, `_stream_refused_total{reason}` and `_stream_cap_hits_total` report per
  service on the existing authenticated `/metrics` endpoint, for listening services only, and
  `_stream_events_dropped_total` reports rows the event writer had to drop.

### Changed

- **Streaming settings are stored per key and stay backward compatible.** `protocol`, `port_count`,
  `upstream_port`, `max_per_source`, `idle_seconds` and `max_datagram` join the existing keys, and a
  configuration saved by 1.60 loads unchanged as one TCP port. Port-conflict checks now compare the
  protocol as well: a TCP and a UDP listener may share a number, two on the same protocol may not.
- **Relay rows are written in batches.** A refused game client retries in a loop, so events go through
  a 1,024-row buffer that inserts once per 250 ms or 256 rows through the same `InsertEvents`
  transaction the HTTP pipeline uses; a full buffer drops rows and counts them instead of stalling a
  stream.
- A UDP port below `1024` names the switch that unlocks it: the error says
  **Refuse sources that are not on an allow list**, which is the control on the card.
- **An HA move binds the forwarders the store holds now.** Every promotion reads the streaming
  settings again, so a card saved while this node was active — or replicated from the peer while it
  was a standby — is what binds, instead of the map read at boot. A demotion closes the UDP sessions
  and releases the game ports before the HTTP listener's drain budget is spent, so the node taking
  over binds immediately. A failover still drops live game sessions, which [docs/HA.md](docs/HA.md)
  now states in the failover checklist.
- **The service unit raises `LimitNOFILE` to 8192.** A UDP session owns a descriptor and the default
  1024 is below the 256-session cap on a few cards at once; the install script copies the unit, so a
  fresh install and an upgrade both get it.

### Security

- An oversized datagram is dropped and counted, never truncated and forwarded. `max_datagram`
  bounds the buffer in both directions; the default is 1500 bytes.
- **A UDP port cannot become a reflector.** The amplification ports (DNS `53`, NTP `123`, SNMP
  `161`, CLDAP `389`, SSDP `1900`, mDNS `5353`, memcached `11211`) refuse UDP outright, and a UDP
  port below `1024` needs the allow requirement plus at least one allowed source. One address may
  start at most ten new sessions a second, with a burst of thirty, so a reconnect loop cannot walk
  the port range. Turning on **Refuse sources that are not on an allow list** refuses every session
  when no list is attached, which is the safer default for a friends-only server.

### Documentation

- **The relay is documented as one feature.** The install guide now carries the protocol and port
  table for media and game cards, the router rule per protocol (a `both` card is two rules), the
  descriptor cost of UDP sessions with the `LimitNOFILE` check, and the failover session-loss note.
  The configuration reference lists every new field with its default and bounds, and the operations
  runbook gains a "a game server does not connect" checklist that starts at the protocol, not the
  log. The README's limits say plainly what the relay does not do: no protocol parsing, no player
  counts, no game panel, and a spoofable UDP source.
## [1.62.3] — 2026-11-24

### Changed

- **The console toolchain moved to Vite 8, Vitest 5, jsdom 31, TypeScript 7 and
  `@vitejs/plugin-react` 6.** They land together because their peer requirements overlap:
  plugin-react 6 needs Vite 8, and jsdom 31 needs Node 22.22.2 or newer. The production build,
  the typecheck and all 112 component tests pass under the new toolchain, and the embedded
  console was rebuilt with it.
- **Go dependencies refreshed.** `kin-openapi` 0.133 → 0.153 (the generated OpenAPI document is
  unchanged) and `miekg/dns` 1.1.72 → 1.1.73.
- **Actions and base images.** `actions/setup-go` 7.1.0, `actions/setup-node` 7.1.0 and
  `actions/upload-artifact` 7.0.2, still pinned by commit; Alpine 3.24 and Node 26 in the image
  build, still pinned by digest. CI now runs the console job on Node 26, the version that builds
  the shipped bundle.
- **The console declares Node 26 as its floor.** `web/package.json` pins `engines.node` to
  `>=26` and `web/.npmrc` sets `engine-strict`, so `npm ci` in `web/` stops with an `EBADENGINE`
  message on an older runtime instead of installing a tree jsdom 31 and Vite 8 cannot run. The
  lockfile's root package entry carries the same range, so `npm ci` stays in sync with it.

### Fixed

- **Dependabot's console majors could not pass one at a time.** The five open PRs were
  interdependent — `@vitejs/plugin-react` 6 requires Vite 8, so on Vite 6 it failed the peer
  check — and each branch was dozens of commits behind. `dependabot.yml` now groups those majors
  into one PR, and this release applies them as one reviewed upgrade.

### Documentation

- **The console gallery is recaptured on a 1.62.2 demo install.** `docs/screenshots/` now shows
  the current sidebar and pages, and **Sites** and **High availability** are pictured for the
  first time. The demo data behind the captures covers two tenant sites, nine proxies,
  certificates, bans, threat feeds and a week of traffic shaped by a daily curve, so the trend,
  stage and source views show something realistic.

## [1.62.2] — 2026-11-24

### Added

- **An HA startup failure now has a recovery path in the console.** When the stored switch is on
  but the loops did not come up, the HA page shows a recovery panel with the start failure,
  **Retry startup** and **Copy diagnostics**. `GET /api/ha` carries `runtime_error`, and the new
  `POST /api/ha/retry` re-authenticates and runs the same runtime start the boot path uses.

### Fixed

- **A tenant console no longer offers host-wide pages.** Bundles, CrowdSec and High availability are
  hidden from a tenant's navigation and tabs, and a deep link to a host-only tab opens the first tab
  that console may read. `#/ha` renders the HA page only on the default site; Settings drops its HA
  section and the readiness checklist drops its CrowdSec row there, so neither points at a hidden page.

### Documentation

- **The guides now describe the released console.** README carries a screenshot tour of every
  captured page, the configuration reference documents the **Sites** and **High availability**
  pages and the Settings switch, and the screenshot index names the build its captures came from.
  The roadmap, HA build record and HA guide are marked delivered, the broken relative links in
  the two scale plans point at the roadmap again, and the README's "not included" list no longer
  contradicts the custom roles it already documents.

## [1.62.1] — 2026-11-24

### Fixed

- **A failed HA activation no longer leaves the data plane serving.** If the active role file
  cannot be written after listeners have accepted, the node now drains the plane and its loops,
  records standby, and resumes the peer's write gate and replication instead of serving under a
  promoting role.
- **A control socket that cannot be bound no longer reports HA as running.** The socket is bound
  before replication, audit capture or the witness lease starts, so a live socket owned by another
  process fails the start and leaves the runtime stopped; only a refused connection is treated as
  stale, cleanup only unlinks the socket this process created, and stopping closes the listener so
  an immediate re-enable does not collide with the old one.
- **A boot-time HA start failure is visible in the console.** The status carries the startup reason,
  moves include it in their refusal, and the HA page shows it instead of only the role file.
- **The restart banner sits beside the HA switch** and leaves after the toast confirms reconnection.
- **Tenant consoles can no longer read the host-wide bundle or CrowdSec pages.** Their listing,
  hit, install and blocklist routes now require the host console, matching their mutating routes.

## [1.62.0] — 2026-11-24

### Fixed

- **A cached DNS answer no longer stalls a connection on a dead family.** The resolver cache had
  replaced `net.Dialer`'s own fallback, so an answer whose first address was IPv6 on a host with no
  IPv6 route burned the whole five-second dial timeout before IPv4 was tried. Both families are now
  dialled at once and the first success wins, while addresses inside a family stay in order.

- **A route that fails to build gives its upstream pool back.** A reload that failed after the
  connection pool was acquired held a reference forever, so the pool could never close its idle
  connections.

- **The lockfile names the release it belongs to.** `web/package-lock.json` still said 1.60.1 while
  `package.json` moved on, which is what `npm ci` and a release audit read; it is updated, and
  `deploy/check-version.sh` now fails when the two disagree.

### Changed

- **Capacity is visible instead of guessed.** `GET /api/capacity` reports what the node is holding
  and what it refused: requests in flight against the cap, the queue, buffered bytes, refusals split
  by reason (`bytes`, `queue`, `site`, `client`), the cache's bytes, hits and misses per site, the
  number of upstream pools, and heap and GC counters. `/metrics` exports the same numbers as
  `wafproxy_inflight_requests`, `wafproxy_queued_requests`, `wafproxy_buffer_bytes`,
  `wafproxy_shed_total{reason}`, `wafproxy_cache_{bytes,hits_total,misses_total}{site}`,
  `wafproxy_heap_bytes` and `wafproxy_gc_cycles_total`. The dashboard gains a Capacity card with the
  in-flight meter, the queue, the cache hit rate and a link to the setting to raise when anything was
  shed. A tenant console sees its own routes only; the budget itself is process-wide. Refusals already
  logged `stage=capacity`, and the report is the aggregate of them.

- **A burst is absorbed, not refused.** Admission now bounds request bytes as well as the request
  count (`WAFPROXY_MAX_BUFFERED_BYTES`, default 512 MiB, and a `WAFPROXY_MAX_INFLIGHT` default of
  256), and a request that cannot be admitted waits `WAFPROXY_QUEUE_MS` (default 250 ms, per-site
  `queue_ms`, `0` for the old behaviour) for a slot before it receives a 503. On the test host,
  200 clients against a 128-request budget refused 162,630 of 345,571 requests with no queue and
  none with it, while completing 17 % more of them. `WAFPROXY_MEMORY_LIMIT` sets the soft heap
  limit and boot refuses a buffer budget that cannot fit under it.

- **A cached response is compressed once, for every client.** The cache key is now the URL alone:
  one identity copy per entry, with `br` or `gzip` built on the first hit that asks for it and kept
  inside the entry. Clients whose `Accept-Encoding` differed only in order or weights used to keep
  duplicate entries and none of them received a compressed cached body. Negotiation honours
  q-values (`br` wins a tie), a client that refuses every encoding gets a 406, and a body the
  upstream already encoded is no longer stored as if it were plain. A cacheable request is now
  forwarded with `Accept-Encoding: identity` so an origin that compresses for its clients still
  fills the cache; an origin that encodes regardless is passed through uncached. Variant bytes are
  charged to the host's quota as well as the total. On the test host a hit on a
  64 KiB asset served 39,817 rps against 3,667 rps for the same request through the pipeline, with
  6,366 bytes on the wire instead of 65,536. Brotli is quality 4, chosen from the table in
  `docs/BENCHMARKS.md`.

- **Upstream connections survive a reload.** Each upstream address keeps its own connection pool
  (default 64 idle connections, 256 in total, per-site `upstream_idle_conns`), so a busy backend no
  longer competes with another site's for slots. A reload reuses the pool of an unchanged upstream
  instead of rebuilding it, and a removed or changed upstream closes its idle connections while the
  requests already in flight finish. Dialling now resolves through a 30-second cache with one lookup
  per host at a time, and keeps dialling the last good address for five minutes while the resolver
  is failing, so a DNS blip does not take every backend down with it. Health probes keep their own
  short-timeout, no-keep-alive transport. A test drives two reloads of an unchanged upstream and
  records zero new upstream connections.

- **A slow client cannot hold a request slot.** A request body now has its own deadline
  (`WAFPROXY_BODY_TIMEOUT`, default 30 s, per-site `body_timeout_s`, `0` disables it) that is cleared
  before the forward: a trickled upload is cut with a 408 and logged as `body-timeout`, while an
  upstream response streaming past the deadline is untouched. The listener's blanket 60-second
  request read timeout is gone; the per-site deadline is now the one bound on a body.

### Added

- **A cached hit can be answered before the WAF, per site.** With `cache_pre_waf=1` a cacheable GET
  that has a fresh entry is served after screening but before the CRS: bans, the allow-list, the
  rate limit and the bot filter still apply, while the CRS request rules, per-IP WAF rules, bot
  challenge and access gate do not see it. Off by default; the API refuses the setting on a site
  with an access gate or a WAF mode other than block/detect, so it cannot quietly disable a
  control the operator asked for. On the test host a cached 1 KiB asset served 38,459 rps against
  8,720 rps when every hit was inspected.

- **Sizing and the shedding answer are written down.** `docs/OPERATIONS.md` pairs
  `WAFPROXY_MAX_BUFFERED_BYTES` with a sizing table and a checklist that maps each refusal counter to
  the setting to change, `docs/CONFIGURATION.md` lists the per-site capacity settings (`queue_ms`,
  `body_timeout_s`, `cache_pre_waf`, `upstream_idle_conns`), and the README no longer lists brotli as
  missing or implies relay-class throughput for inspected requests.

- **A capacity number instead of a guess.** `cmd/perftool -proxy` runs the real proxy — TLS
  listener, routing, cache and event writer — against stub upstreams with a keep-alive client
  fan-out, and records requests, rps, p50/p95/p99, shed count and peak RSS per mode in
  `perf/proxy-*.json`. The first recorded runs are in `docs/BENCHMARKS.md`: on this sandbox the
  uncached path served 6,080 rps, a cache hit 54,776 rps, and the same hit with the WAF on
  10,574 rps. `-cache` and `-encoding` choose what the run asks for, including a compressed 64 KiB
  asset for measuring the cache's encoded variants.

- `github.com/andybalholm/brotli` (pure Go, no cgo) for cached response variants.

## [1.61.2] — 2026-11-23

### Fixed

- **A tenant administrator can no longer reach the host console.** The site switcher is only
  honoured for a session on the host's own console, host-wide areas (sites, system and HA) stay
  closed to tenant sessions even when their role carries the wildcard permission, and role
  definitions, backup scheduling, signature bundles, CrowdSec, streaming forwarders, agent links
  and MCP tokens are host-console only, and the uptime panel reports only the caller's backends.
- **A rejected new password no longer consumes a password-reset link.** The password is validated
  before the single-use token is spent, so a policy error leaves the link usable.
- **A bundle rule set to block no longer overrides a profile in detect-only mode** when the site
  inherits its WAF mode from that profile.
- **The policy rate limiter now prunes strike timestamps**, so a bucket that ever denied a request
  can be cleaned up instead of staying in memory forever.
- **Encrypted backup files are pruned** along with plain ones, so scheduled encrypted backups no
  longer grow the destination without bound.
- **Ban management is site-scoped.** A manual ban is recorded against the console that created it,
  and editing a ban by id cannot reach another site's row.
- **First-boot setup runs only on the host console**, because it writes host-wide settings.

## [1.61.1] — 2026-11-23

### Added

- **A Check for updates button on the WAF-Proxy application card**, so the console can refresh
  its own repository check from the section that shows the application version, not only the
  host package check below it.

### Fixed

- **Enabling high availability from Settings now reports the restart and reconnects.** The save
  answers whether the service must restart, the console shows that it is restarting instead of
  sending failing requests at the stopping process, and it reloads the switch and the nav once
  the service answers again.
- **A peer's outbox acknowledgement is clamped to this node's stream head**, so a stale or
  malformed acknowledgement cannot prune changes the peer never received.
- **The HA join attempt limiter drops expired buckets**, so repeated guesses from many addresses
  no longer leave one empty entry per address behind.

## [1.61.0] — 2026-11-23

### Changed

- **The High availability switch is the only switch.** `WAFPROXY_HA_ENABLE` is gone. Turning
  on **Settings → High availability** enables the runtime, starts the HA loops and allows
  pairing; the first enable asks the service supervisor for one restart, which binds the HA
  link and management listeners and settles the floating service address. Later enables and
  disables are live. An upgrading operator can delete the variable; it is ignored.

### Fixed

- **Joining a pair now makes the joining node the standby**, so the pair cannot end up with two
  writers and a failover has a standby to promote. The node that issues the pairing code is
  recorded as the active.
- **A sync on the active is refused from the console as well as the CLI**, so a mirror pass
  cannot overwrite the serving node with its peer's copy.
- **A witness that was never reachable no longer leaves an active writing.** The lease keeper
  reports a loss after one TTL even when it never obtained a lease, and unpairing stops the
  keeper instead of letting it demote the node later.
- **`wafproxy ha status` reads the stored switch** instead of the removed boot variable, and a
  paired standby is reported out of service when HA is off.
- **HA metrics follow the switch**, and an empty `WAFPROXY_HA_MGMT_LISTEN` no longer attempts a
  wildcard management listener.

## [1.60.1] — 2026-11-23

### Fixed

- **Every page offers its help.** The Dashboard kept a hand-written header, so it had no `?` button
  or shortcut even though its help exists; it now uses the shared page header like every other page.
  A hostname in its proxy table opens that hostname's filtered log.
- **No control is a link wrapped around a button.** The log's CSV export and the two Cloudflare
  dashboard links are now anchors styled as controls, so a press cannot fire two navigation
  targets. The Settings section nav is a set of buttons rather than `#section` anchors, so it
  cannot be opened in a new tab as a hash the router rewrites.
- **“Skip to content” no longer leaves the page.** The link focuses the main region instead of
  changing the hash, which the router treated as a page change.
- **Two dashboard surfaces fit a 320px screen.** The attack globe derived a 304px width from its
  minimum height and pushed the page sideways, and an info popover centred on its icon opened past
  the screen edge; the globe now takes its width from the card and the popover becomes a bottom
  sheet on a phone.
- **Readiness badges line up on a phone.** Below 560px, a row's status badges sit at its right edge
  whatever the label's length, so the long-label rows no longer leave a ragged badge column; the
  fix link still moves below the text.
- **The HA-off card's “Open Settings” is a real control.** It used a `button` class the stylesheet
  does not define, so the link rendered unstyled; it now uses the console's in-card link style.
- **The documentation link names this repository.** It pointed at the pre-rename
  `WAF-Proxy-Docker` repository, and the CrowdSec instructions still used the old checkout path.
- **Help topics describe controls that exist.** Logs names the real `blocked=1` filter, Agent
  describes the audit trail instead of a delivery log, Tailscale describes its native listeners
  rather than `tailscale serve`, and Dashboard, Access and Statistics now point at the place each
  action actually lives.

## [1.60.0] — 2026-11-23

> **High availability, off by default.** The two-node hardware lab gates in
> [docs/HA.md](docs/HA.md) and the P8 chaos/soak gate have not been run, so HA ships
> dark: nothing changes until an operator sets `WAFPROXY_HA_ENABLE=1` and turns it on in
> Settings. Run that checklist before relying on a pair in production.

### Added

- **Optional two-node high availability.** A pair of nodes can share one virtual service address,
  with one active and one standby. HA is off by default: `WAFPROXY_HA_ENABLE=1` allows it and the
  **Settings → High availability** switch turns it on, so a single-node install behaves exactly as
  before. The role lives in a file beside the database (`standalone`/`active`/`standby` plus the
  move state), so a restored database cannot silently change who serves. Pairing writes a
  26-character code valid for ten minutes; the joining node proves the fingerprint and receives the
  master key over the pinned TLS link.
- **Moves without a restart.** `wafproxy ha failover|failback` (and the console buttons) drain
  configuration writes, stop background loops on the old active, bounce keepalived through
  `ha notify`, wait for the address, register sessions with `conntrack`, and only then serve. A
  heartbeat with a higher epoch parks an active in `split-brain-risk` instead of letting both
  nodes answer.
- **Witness lease and fencing.** With a witness, the active renews a three-second lease and
  self-demotes when it cannot; automatic failover needs the witness, a fence command and a healthy
  peer, renews the lease before serving, and parks the node after four moves in an hour.
- **Replication of configuration, sessions, bans, audit and alerts.** A snapshot after pairing and
  every 30 minutes, streamed changes through an outbox with per-record acknowledgements, a 100 MiB
  outbox cap and a 64 MiB snapshot cap. A standby follows the stream and is read-only until it is
  promoted.
- **Console page, API and CLI.** `GET /api/ha` plus events, diagnostics, config, pair/join/sync,
  failover/failback, unpair and notify, behind `ha.read`/`ha.write` with fresh re-authentication
  and a typed cluster id for the destructive actions. It is dark by default and the two-node
  hardware lab gates have not been run, so production use needs that run first. The
  **High availability** page shows the
  four states, the peer, replication, the console's action history and the guarded actions; the
  Settings switch starts and stops the HA loops in the running process. `wafproxy ha` exposes the
  same operations on a node whose console is unreachable, and `wafproxy ha upgrade --check`
  compares the two nodes' release, schema and protocol before an upgrade starts, exiting non-zero
  when a move would be refused. An unreadable role or pair record is never read as permission: a
  settings save that cannot re-check it is refused, and at boot a corrupt pair record counts as
  paired while HA is on, so a standby cannot start serving alone.
- **Tests.** A partition simulator that runs the real state machine, heartbeat, witness, fence and
  flap guard on a fake clock (the partition matrix plus 200 randomized partitions, asserting at
  most one live active per tick and an unexpired lease for every promotion), handler and route
  tests for every HA action, and page/toggle/nav tests for the console.

### Changed

- Turning HA off on a **paired** node requires its cluster id (`X-HA-Cluster-ID`, typed in
  Settings) and is always refused on a paired standby; a refused save writes no key and no audit
  row. A paired standby is never rewritten to standalone while HA is off: it stays out of service
  and `GET /api/ha` says why.

### Documentation

- [README.md](README.md#high-availability) describes the pair in one page and links the runbook.
- [docs/OPERATIONS.md](docs/OPERATIONS.md#upgrading-a-high-availability-pair) adds the
  standby-first upgrade path and an HA row to the daily checks.
- [docs/HA.md](docs/HA.md) carries the design, the state machine, the console specification and
  the lab checklist; [docs/openapi.yaml](docs/openapi.yaml) was regenerated (no route changes).

## [1.59.0] — 2026-11-23

### Added

- **Apps tab: publish a site's hostnames through the tunnel.** The Cloudflare page now has Admin
  and Apps tabs. Apps lists the site's proxies with a publish switch, saves the list per site, and
  shows the exact Public Hostname values to paste into the Cloudflare dashboard: the loopback
  service on the WAN port, the hostname as origin server name, and no-TLS-verify on. Each published
  row can be checked, and "Check published" runs them all; results cover DNS, a direct-origin
  record, the edge `CF-Ray` and whether Access prompts before the app loads.
- **Cloudflare edge certificates.** A published hostname gets its TLS from Cloudflare's edge, so
  the console refuses HTTP-01 and TLS-ALPN-01 certificate orders for it with a clear message and
  stops renewing such existing certificates; DNS-01 still works. The apps row says which
  certificate is in use.

### Changed

- The Cloudflare tunnel connector is host-wide: a tenant console can publish its own hostnames but
  cannot change the shared token, install or run the connector.

### Fixed

- **Cloudflare settings are read where they are stored.** The connector token, tunnel id and
  strict-origin switch live in the host settings, so a console opened on a tenant site no longer
  shows an unconfigured tunnel. Published hostnames are the per-site part of the same page.

## [1.58.0] — 2026-11-23

### Added

- **Cloudflare Tunnel, managed from the console.** The Cloudflare page installs `cloudflared` from
  Cloudflare's package repository through the root helper, seals the tunnel token in the database
  and runs the connector itself, so publishing the console needs no port forward, public IP or
  certificate on the GUI listener. The page walks through the dashboard steps (create the tunnel,
  paste the token, add the public hostname, put Access in front) and runs eight checks: binary,
  token, connector registration, DNS answers, direct-origin record, edge `CF-Ray`, the origin
  marker and the Access redirect.
- **Cloudflare client addresses.** With the tunnel enabled and the strict-origin switch on, the WAF
  trusts `CF-Connecting-IP` from the connector for policies, logs and bans, and strips the header
  before a request reaches an upstream.
- **`cloudflared` in the host package catalog.** Updates notices a connector that is older than
  the installed package; restarting it stays a click rather than an interruption mid-traffic.
- [Cloudflare Tunnel and Access guide](docs/install/07-cloudflare-tunnel.md) and the
  [design](docs/superpowers/specs/2026-11-23-cloudflare-tunnel-design.md) behind it.

### Changed

- `deploy/install.sh` installs `deploy/cloudflared-install.sh` next to the CrowdSec installer, and
  the Upgrades page documents the new package.
- **Printable help keeps its print rules to itself.** The printable route marks the document and
  every help-specific print rule is scoped to that marker, so printing another console page is
  unchanged and `styles.css` carries one print block again.

### Notes

- This release is the Admin tab in token mode on a native install. App hostnames, API mode
  (creating tunnels and DNS records from the console) and a Docker sidecar are later slices; a
  container console stays read-only and points at the host install.

## [1.57.2] — 2026-11-23

### Fixed

- **The printable help cannot restyle another page's print.** The route sets a `help-doc` class on the
  body, and the print rules that hide the action bar and flatten the help card are scoped to it, so a
  dashboard, log or report still prints with the console's existing print block. The two print blocks in
  `styles.css` are now one.

## [1.57.1] — 2026-11-23

### Added

- **Every page explains itself in place.** A `?` beside the page title, or the `?` key, opens a side panel
  with what the page is for, the concepts behind it and what to do first. The text is Markdown under
  `web/src/help/`, compiled into the bundle, so it matches the running version and needs no internet; a
  test fails when a page has no help or a help file outlives its page.
- **Readiness starts with the first hour.** The page opens with a **Getting started** checklist driven by
  real state — a hostname, a certificate, traffic, an alert target, a second factor, a second admin —
  and switches to the hardening score once those settle. Completed rows fold away per administrator
  (stored server-side in `admin_prefs`), and the empty Proxies, Logs and Notifications states now say
  what would fill them.

### Fixed

- **Invitations and password-reset mail use the console site's own SMTP server.** Both paths read
  the default site's notification channels, so an invitation sent from a tenant console went out
  through the default site's account, and was refused with "email notifications are not
  configured" when only the tenant had SMTP. The request's site now supplies the channels and the
  configuration check.
- **An invitation created for another site links to that site's console.** The account is created
  on the site the invitation belongs to, but the emailed link named the console the administrator
  was browsing, so the recipient opened it on the wrong site and was told the invitation was
  invalid or expired. The link now uses the target site's console host with the request's scheme
  and port.
- **A site's Settings page names and saves the site it is editing.** After switching sites in the
  topbar the page still labelled itself with the console's own site and kept the host-wide network
  and update controls enabled, so its save posted those keys and failed. The settings response now
  carries the request's `site_slug` and `site_name`; the page shows that site, leaves the
  host-wide keys out of its save and disables their controls. A tenant console writing auto-update
  gets the same `403` as the other host-wide settings instead of a `500`.
- **Unset bot filtering and normalization no longer block a Settings save.** A site with no rows
  yet, and an install created by `wafproxy setup`, read those two settings back empty and the API
  refused the whole form. Empty is accepted as "never set"; the engines already default it to off
  and flag.

### Changed

- **The container job also proxies a real request.** After the console answers, the smoke test
  creates the first admin, signs in with a recovery code, issues a certificate from the internal CA,
  points `app.smoke.test` at a loopback upstream and fetches it through the WAN listener. A console
  that serves its own pages but cannot route traffic now fails the build.
- **The CI actions run on Node 24.** `actions/checkout`, `docker/setup-buildx-action` and
  `docker/build-push-action` moved to their current majors (`v7.0.1`, `v4.4.1`, `v7.4.0`), re-pinned
  by commit with version comments, which clears the runner's Node 20 deprecation warning.

## [1.57.0] — 2026-11-23

### Added

- **Administrators can be invited by email.** The Team page has an **Invite by email** action that
  asks only for an email address, first and last name, and a role. The recipient gets a single-use
  link, valid for seven days, back to this console's own address (the internal IP and port it was
  reached on). There they choose their own username and password and are shown a new authenticator
  secret and recovery codes; the account exists only once that link is opened, so nobody has to
  hand over a password.
- **Alert routing is per event and per channel.** Notifications now show one row per event with a
  checkbox for Telegram, one for email and one for the Slack/Teams/webhook channel. Every event
  reaches all three by default; untick a box to drop that channel for the event, or all three to
  suppress it everywhere. The choice is stored as `notify_routes`; the older `notify_events` list
  and its `none` mute still apply to installs that have not saved the new grid.
- **Console mail is a branded HTML message.** Alerts, the channel test, password-reset links and
  invitations are sent as `multipart/alternative`: the console's header and an action button for
  HTML readers, and the same text with the link written out for clients that do not render HTML.
  The logo is drawn in the message itself, so no mail client has to fetch anything from the
  internal console.
- **Release artifacts are signed and attested.** The release workflow signs each binary and
  `SHA256SUMS` keyless with cosign, attaching a `.sigstore.json` bundle, and publishes build
  provenance with `actions/attest-build-provenance`. A download can be checked against the
  workflow identity instead of a stored key; the commands are in
  [docs/OPERATIONS.md](docs/OPERATIONS.md#verifying-a-download). Its actions are pinned to commit
  SHAs, so a moved tag cannot change what a verified run executed.
- **Base images are pinned by digest.** The `Dockerfile` names `node:22-alpine`, `golang:1.27-alpine`
  and `alpine:3.21` by their multi-arch index digests, so a moved tag cannot change what a reviewed
  image build compiles against while arm64 hosts keep working. `deploy/check-image-pins.sh` fails CI
  when a `FROM` carries a tag without a full digest.
- **CI starts the image and checks the console.** The container job now runs the built image on host
  networking, waits for `/api/health`, fetches `/` and the bundle asset the shell names, and compares
  the reported version with the build arg. An empty `internal/webui/dist` or a console that never
  binds fails the run instead of shipping.
- **Workflow actions cannot drift back to tags.** `deploy/check-workflow-pins.sh` fails CI when any
  workflow references an action by tag, branch or abbreviated commit; a local `./action` and a
  `docker://image@sha256:` digest still pass. `make verify-release` and `make test-release` run it
  with its regression test.

### Fixed

- **The container image built without its console.** The `ui` stage copied `web/` flat into `/src`, so
  the Vite `outDir` of `../internal/webui/dist` resolved to `/internal/webui/dist`; the Go stage
  then copied an empty `/src/internal/webui/dist` and `//go:embed dist` stopped the build with
  `pattern dist: cannot embed directory dist: contains no embeddable files`. The package now sits at
  `/src/web`, which is what the relative output path expects.
- **A non-default site's Settings page could not be saved.** The form posted the read-only
  host-wide keys (`wan_ip`, `max_body`, and the rest) that the API deliberately refuses for a
  tenant, so every save returned `403` even when only per-site fields changed. The server now
  returns the host-wide key list with the settings and the form leaves those keys out of its save;
  the API still refuses them if anything else posts them.
- **A line break in a configured address could add mail headers.** SMTP From and recipient values
  containing CR/LF are refused before the message is built.

## [1.56.0] — 2026-11-23

### Added

- **Every administrator can carry an email address.** The Team page shows an email column, the
  invitation and edit forms accept one, and the Account page has a card for the signed-in
  administrator. Alerts and password-reset links go to these addresses; the warning beside the
  field says that an account without one cannot reset a forgotten password by email.
- **Remembered browsers are listed and revocable.** The Account page shows each trusted device
  with its browser, address, age and a **Current** marker, and a **Revoke** button per row. Trusting
  a browser is no longer a one-way decision until the next password or authenticator change.
- **Saved site isolation tests cover the rest of the console.** The API-level test now also proves
  that feeds, access lists, WAF and protection profiles, certificates and saved log views written
  on one site are invisible from another site's console.

### Changed

- **Email setup is the system sender only.** Notifications no longer ask for From and To: the
  sender is the SMTP username and the recipients are the administrators' profile addresses, so a
  Gmail or other SMTP account is all the setup needs. Existing installs keep working; the stored
  From/To values are simply no longer read or shown.
- **Which settings are per site is stated plainly.** `dos_rps`, `dos_burst`,
  `sample_above_rps`, `retention_days`, normalization, protection switches, decoy hosts, WAF and
  access profiles, notification channels, anomaly thresholds, canary and ACME email/staging are
  read and applied per site by that site's own engines. `max_body` is one process-wide buffer
  read from the default site, so its field is disabled with a note on any other site's console and
  the API refuses a per-site write of it with the same `403` as the other host-wide keys. The
  host-wide sections (network, admin source allowlist, CrowdSec, GeoIP, updates) stay read-only
  there too. The README lists both groups.

### Fixed

- **A crash during the per-site migration left the host unable to restart or recover.** If the
  process died after the `log_views` rebuild created its staging table, every later start and
  `wafproxy recover` stopped on `table log_views_sites already exists`, so the host stayed down
  until the database was edited by hand. The rebuild now runs in one transaction, creates and
  drops its table idempotently and ignores rows it has already copied, so an interrupted
  migration resumes on the next start.
- **`wafproxy recover` now finishes the job for any site.** It reads without a site scope instead
  of only the default site, and clears sessions, remembered browsers and outstanding reset links
  so a recovered host has no stale sign-in left behind.

## [1.55.2] — 2026-11-23

### Fixed

- **A rolled-back install kept failing to start with `adopt bans rows`.** After an update to 1.55.1
  was rolled back, CrowdSec and feed syncs in the older binary wrote bans that name no site. When
  one repeated an address the default site already bans, the next start stopped at
  `adopt bans rows: constraint failed: UNIQUE constraint failed: bans.site_id, bans.cidr`, the
  updater rolled back again, and every restart left more unowned rows. The per-site migration now
  keeps the stronger of the two bans (permanent first, then the later expiry), adopts it and drops
  the duplicate, so the install boots again without a manual cleanup.
- **The same rollback could stop on `adopt log_views rows`.** A saved view the older binary
  rewrites is only unique per site, so a name the default site also has failed the adoption with
  `UNIQUE constraint failed: log_views.site_id, log_views.name`. The migration now keeps the most
  recently updated definition of a duplicated name and adopts it.

## [1.55.1] — 2026-11-23

### Fixed

- **An install that banned one address on two sites failed to start.** The base schema still
  created the pre-sites unique index on `bans.cidr` while the per-site migration replaces it with
  one on `(site_id, cidr)`. Once a second site held the same address, every start stopped at
  `apply schema: constraint failed: UNIQUE constraint failed: bans.cidr`, and a self-update
  rollback could not help because the older binary reads the same database. The base schema no
  longer creates the global index; the per-site migration drops any leftover one and enforces the
  pair, so a database already in the restart loop boots again without manual repair.

## [1.55.0] — 2026-11-23

### Added

- **Statistics is four tabs.** **Overview** holds the request totals and the outcome stages;
  **Traffic** holds per-site requests and visitors by country; **Uptime** is the live probe view;
  **Access gate logins** is the failed-sign-in table with its **Block** action. The date range and
  the trend chart sit above the tabs so switching views keeps the same period, and the range strip
  is hidden on Uptime, which ignores it.
- **Remember this device.** A checkbox on the login form trusts that browser for 30 days, so the
  authenticator code is skipped there. Only a hash of the cookie is stored, and changing the
  password, rotating the authenticator or resetting the password from an email link forgets every
  trusted browser.
- **Recovery codes moved behind an explicit link.** The login form no longer shows a recovery field;
  **Don't have your authenticator code?** reveals it, and a sign-in that spends one offers a
  replacement authenticator and fresh recovery codes before the console opens.
- **Forgot password by email.** When the email channel is configured, the login form offers a
  single-use 30-minute reset link to the alert mailbox; it is hidden otherwise. The link works once,
  sets a password of 12+ characters, and signs out every session and remembered device.

- **Policy, notifications, anomaly detection, the canary and ACME are per site.** A new
  `internal/siteres` registry builds one instance of each per site from a store handle scoped to
  that site, and every console endpoint, the proxy's request path, the manual canary probe, the
  certificate listener, the expiry warning and the ban/gate alerts use the active site's
  instance. The five configuration surfaces no longer share one global copy: one site's
  `max_body`, notification channels, anomaly thresholds, canary target or ACME account cannot
  reach another site's.
- **The proxy decides every request with the site's own policy engine**, selected by the
  hostname's site (and by the proxy row's site for response inspection and WAF profiles). A
  second site's WAF profiles and policies are compiled instead of being ignored, which a
  single shared engine read from the default site only.
- **The certificate listener multiplexes every site's certificates**, and the plain-HTTP
  ACME-01 handler and TLS-ALPN-01 store answer from the site that started the issuance.

### Changed

- **A manual `POST /api/canary` uses the site's monitor**, so it dials the way the scheduled
  probe does instead of constructing a bare prober.
- **`docs/OPERATIONS.md` describes the per-site instances**, their host-wide exceptions and the
  upgrade fallback.

## [1.53.1] — 2026-11-23

### Changed

- A bundle provider whose last check failed now shows an amber **check failed** badge instead of the
  green **signed** one. Its already-downloaded packs stay listed, and the badge returns to `signed`
  with the next successful check.

### Fixed

- The admin menu left-aligns its entries — the shared `button` rule was centring them — and is a
  little narrower.
- The administrator activity and managed host package tables in Settings no longer scroll sideways
  at 360px and 768px: the audit detail is capped and wraps on a phone, the user and source columns
  drop below 900px, and the package rows wrap their advisory text.

### Fixed

- **An SMTP relay that needs no authentication now receives mail.** The notifier always offered
  credentials, so a relay that does not advertise `AUTH` rejected every message. Credentials are
  only offered when a username or password is configured.

## [1.53.0] — 2026-11-23

### Added

- **Sites page and site switcher.** The console lists every site with its console host, hostnames,
  retention and admin count, and creates, edits and removes them, reporting the server's own
  message for a duplicate slug, an invalid console host or a refused delete. The topbar switcher
  scopes every API call to the chosen site (`X-WAF-Site`), remembers it in `localStorage`, and
  remounts the views on a switch so the previous site's data never stays on screen.
- **`host_admin` built-in role** for a tenant administrator: hostnames, policies, certificates,
  feeds, settings and accounts of its own site, but not the `sites` area. The console hides the
  Sites page, the switcher and the host-level Tailscale and MCP pages from it, and the API ignores
  a site header from a session that may not read sites.
- **`sites` permission area** (`sites.read`/`sites.write`) in the role editor, with
  `GET/POST /api/sites` and `PUT/DELETE /api/sites/{slug}`.

### Changed

- **Settings carry the site they apply to**, and the host-wide sections (network, updates, GeoIP)
  are disabled with an explanation on a non-default site's console instead of failing on save.
- **The Proxies page's "Sites" tab is now "Hostnames"**, which is what it lists.
- **`console_host` is validated** on create and update, so a pasted URL or a path is refused with a
  message rather than stored as a site nobody can reach.

## [1.52.0] — 2026-11-23

### Added

- **Known good signature bundles.** Three packs now ship inside the binary — `secret-probes`,
  `exploit-payloads` and `scanner-tools` — validated and compiled at startup, listed under
  **Threat intel → Bundles** with an **Enable**/**Disable** button each. They start switched off, so
  a release never begins logging new signatures without a decision.
- **Bundle providers can be managed from the console.** The new **Bundle providers** card adds a
  channel by name, manifest URL and ed25519 publisher key, replaces one by saving the same name, and
  removes one with **Remove**. The list is stored in the database and applied without a restart;
  `WAFPROXY_BUNDLE_PROVIDERS` and the single-channel pair keep working until the first provider is
  saved here.
- **Every installed pack can be switched off globally.** A disabled pack keeps its files and version
  (so re-enabling needs no download) and contributes no rules to any profile; the per-profile
  off/log/block mode still applies to the packs that are enabled.

### Fixed

- **Bundle rules that used a regex escape never matched.** `\.` in an operator was doubled on the way
  into the Coraza directive, which turned it into a literal backslash, so a downloaded pack's
  path-anchored rules silently stopped matching. Operators now reach the engine as written.
- **Bundle hits missed every rule that only logged.** The query required the event's final stage to be
  `waf`, but a log-only match lets the request continue, so its event was named after the later stage
  even though it carried the bundle rule ID. Hits now count the reserved bundle ID range regardless
  of stage.

## [1.51.1] — 2026-11-23

### Fixed

- **The console's wide tables fit their cards at 360px and 768px.** The WAF profile table, the
  protection profiles, the ASN recommendations, the activity log, the dashboard's recent blocks and
  Sources scrolled sideways below 1100px. They now use the same tiers as the bundle and Feeds
  tables: the long identifier or message is capped first, then the secondary counts and timestamps
  drop, and at phone width the value that must not disappear moves into the cell that stays — the
  profile's bundle modes under its name, the event's status under the request, the clock under the
  source — while the row buttons stack. Bundles also no longer show an empty `Version` column on a
  phone, and a hit's provider/version line stays inside its cell.

## [1.51.0] — 2026-11-23

### Added

- **Per-site backups and restores.** Settings → **Download JSON** now exports the calling
  site only and names the file after it (`wafproxy-<slug>-backup.json`). The new
  `wafproxy backup --site <slug>` writes the same document for one site, and
  `wafproxy backup --all` writes one encrypted file per site plus a `sites.json` manifest
  naming each slug, console host and file. Restoring a document writes only into the site
  whose console posted it.
- **Scheduled backups cover the whole install.** The nightly job was building its document
  from the default site's handle, so every other site was silently missing from the file.

### Changed

- **A runtime ban belongs to the site that observed it.** A ban raised by the decoy trap or
  the rate limiter is recorded against the hostname's site, so that site's console lists
  it, while the kernel set it feeds stays the union of every site's bans and keeps dropping
  the address for all of them.
- **Retention is per site.** The hourly loop reads each site's own `retention_days`, so one
  site shortening its history can no longer delete another site's events.
- **`docs/OPERATIONS.md` has a Sites section** covering console hosts, the host/tenant
  settings split, host-wide kernel bans, per-site retention and restore boundaries.

## [1.50.0] — 2026-11-23

### Added

- **One console per site.** A site's `console_host` is now served by the same process as every
  other console. The console resolves the request's `Host` to its site, and every handler receives
  a store bound to that site, so it lists and changes only that site's proxies, certificates,
  bans, policies, feeds, lists, gate accounts and sessions, admins and sessions, events,
  analytics, audit trail and saved log views. Settings written on a site's console stay on that
  site. A session issued on one console cannot authenticate on another, and the login form of one
  console rejects another console's administrators.
- **A certificate per console host.** The console listener keeps resolving its certificate on each
  handshake, now over every site's certificates, so two consoles on one process each present the
  certificate issued for their own hostname. A single-site install keeps presenting the
  `base_domain` certificate exactly as before.

### Changed

- **Host-wide settings are refused per site.** `wan_ip`, `lan_ip`, `gui_port`, `admin_allow_cidrs`,
  the CrowdSec endpoint and the auto-update schedule stay process-wide. Any console reads them;
  saving one from a site other than `default` now answers `403` instead of making it look saved.
- **The proxy side runs unscoped.** Bans, feeds, certificates, the policy engine, the gate and the
  anomaly monitor load every site's rows, because they serve every hostname; the console is the
  only place a site narrows what is visible.
- **Bans are keyed by site and address.** The same CIDR can be banned on one site and allowed on
  another, and a duplicate ban is only a duplicate inside its own site.
- **A saved log view's name is unique inside its site**, so two sites can both keep a view called
  "errors" (the table is rebuilt on upgrade).

### Fixed

- **Deleting a row that belongs to another site answers `404`**, not a silent success or a `500`.
- **Events recorded before a proxy was matched** belong to the default site instead of vanishing
  from the console.
## [1.49.5] — 2026-11-23

### Changed

- **Settings is one scrolling page again**, with the former **Updates** and **Readiness** tabs folded
  into its vertical section list: Network · Updates · Protection · Retention & ACME · Backup ·
  Runtime status · GeoIP database · Administrator activity · Readiness · About. `#/settings/updates`
  and `#/readiness` land on Settings.
- **CrowdSec console blocklists** moved from Threat intel → Feeds to **Threat intel → CrowdSec**,
  between the engine/bouncer summary and the automatic install card, so the decisions the engine is
  enforcing sit next to the engine that enforces them.
- The Threat intel tab row keeps all five tabs on one line at 390px by tightening tab padding at
  phone widths instead of wrapping CrowdSec onto a second row.

### Fixed

- A role without a page's permission now sees the "Your role does not include this page." card with
  a button to the first page it can open. It previously redirected to that page before the card
  could render.
- The Settings section list highlights the section nearest the top of the viewport, so the last
  short sections no longer leave an earlier one highlighted when the page cannot scroll further.

## [1.49.4] — 2026-11-23

### Changed

- **Related pages now share one entry with tabs** instead of sitting apart in the sidebar. The
  route is `#/<page>/<tab>`: bare `#/proxies` opens Sites, bare `#/settings` opens General, and an
  unknown tab falls back to that page's default. Old page hashes are rewritten in place, so a
  bookmark to `#/certs`, `#/sources`, `#/crowdsec`, `#/streaming`, `#/updates`, `#/readiness` or
  `#/intel` still lands on the right view. The sidebar drops from 20 entries to 16, grouped as
  Overview · Traffic · Threat · Access · System.
- **Proxies** holds **Sites**, **Certificates** and **Streaming**; the restart card stays on the
  Streaming tab for now.
- **Policies** holds **Bans**, **Profiles** (global profile, WAF profiles, protection profiles),
  **Access profiles**, **Lists** and **Bot filter**. Access profiles moved here from the access
  gate because a profile is config for a proxy, not an account.
- **Threat intel** holds **Feeds**, **Lookup**, **Sources**, **Bundles** and **CrowdSec**.
- **Access gate** holds **Accounts** and **Identity providers**.
- **Settings** holds **General**, **Updates** and **Readiness**; the two former sidebar pages are
  now tabs of Settings and their old hashes redirect there.
- The page header carries the description once, above the tab row; an absorbed page no longer
  repeats its own header inside the tab.

### Fixed

- **Threat intel's "Set bundle mode" button** now opens **Policies → Profiles**; it previously
  pointed at a Policies query parameter that no longer selected the tab.
- **A long kernel status reason no longer widens Settings at phone width.** The runtime row uses
  the same wrapping badge as Policies, so the page keeps its 390px width.
- **Copy that named the old pages points at the new tabs**: access-profile hints name Profiles and
  Lists, Streaming points at Policies → Lists, and Settings names Threat intel → CrowdSec.

## [1.49.3] — 2026-11-23

### Fixed

- **The Feeds table no longer scrolls sideways.** It was 855px wide in a 285px card at 360px and
  wider than its card on a 768px tablet, because the feed URL, the last error and a long feed name
  sized their cells freely. It now follows the bundle tables: `Entries` drops at ≤1100, `Last
  refresh` at ≤900, the URL/name/error caps step down, and at phone width the state badge moves
  under the feed name while the row buttons stack, so Feed, Action and the controls fit without a
  hidden column and without horizontal scroll.

## [1.49.2] — 2026-11-23

### Added

- **Several signed bundle providers.** `WAFPROXY_BUNDLE_PROVIDERS` takes a JSON list of
  `{name, url, public_key}`; each provider keeps its own manifest URL, publisher key, anti-rollback
  sequence and last error, and is checked and downloaded on its own, so an unreachable publisher
  cannot hold up the others. The console lists every provider with its own **Check** button next to
  **Check all**, each installed bundle shows the provider that delivered it, and bundle hits name
  the provider too. The original `WAFPROXY_BUNDLE_URL`/`WAFPROXY_BUNDLE_PUBKEY` pair still works as
  the provider `default`. A bundle name belongs to one provider, because profiles switch a bundle
  by name: a second publisher advertising the same name is refused with an error naming the owner.

### Changed

- **The bundle card, hit table and profile switch fit a phone and a tablet.** Bundle names, rule IDs
  and versions no longer break mid-word at 360px; the hit table drops counts and timestamps before
  it can push the Outcome column off the card at 768px; and the profile dialog's per-bundle switch
  aligns the same way on every row.
- **`bundles.test.ts` was never running.** `vitest.config.ts` only includes `src/**/*.test.tsx`, so
  the existing bundle tests were silently skipped. The file is now `bundles.test.tsx` and runs, with
  new cases for the blocked/logged outcome badges and the "every match was served" banner.

## [1.49.1] — 2026-11-23

### Documentation

- **The release convention no longer claims a tag per push.** The header here said every push to
  `main` carries an annotated `vX.Y.Z` tag, which the repository does not do; it now says what
  `docs/OPERATIONS.md` says — every push has a section, and a release is published by tagging the
  commit that carries it.
- **`docs/MCP.md` matches the gateway.** The page is **AI Agent Access**, the read-tool table was
  missing `list_anomalies` (1–200, default 50), and `block_ip`'s `ttl_seconds` is 0–31536000 with
  `0` meaning 24 hours unless `permanent` is set, not 60–31536000.
- **`docs/BENCHMARKS.md`** no longer calls 8 MiB the *default* body ceiling: 8 MiB is the hard
  ceiling on a profile's inspected body and the shipped profiles default to 128 KiB.
- **`docs/ROADMAP.md` delivery status** was self-contradictory — its Phase 4 bullet said console
  TLS and revocation were both missing and shipped in 1.40.0, and its Phase 5 bullet listed
  diagnostics, the canary, the OpenAPI check and the INSTALL split as undelivered while also
  naming them as done. It now lists what shipped per phase and what is still outstanding
  (`setup --config` with `WAFPROXY_SETUP_*`, `recover --rotate-master-key`, install-time
  preflight, per-stage latency metrics, certificate/ACME counters, flap detection, SLO rollups,
  recipe pages), and the screenshot item is marked delivered.
- **`docs/openapi.yaml` regenerated** so the route reference and its `info.version` match the
  build again; `go run ./tools/openapi -check` passes.

## [1.49.0] — 2026-11-23

### Added

- **Sites, the foundation for multi-domain hosting.** Every configurable row now carries a site,
  and a `site_settings` overlay lets a site override its own behaviour while host-wide keys (bind
  addresses, update schedule, CrowdSec, Tailscale) stay fixed for the process. An existing install
  is adopted by a single `default` site whose console host is the `base_domain` it already
  advertised, so nothing has to be reconfigured and no console behaviour changes. `wafproxy sites
  list|add|rename|remove` manages sites, and a slug, console host or site row is validated and
  unique before it is written.

## [1.48.8] — 2026-11-23

### Documentation

- **Every console page is pictured.** `docs/screenshots/` holds a capture of the dashboard,
  statistics, proxies, streaming, policies, sources, threat intel, logs, anomaly events,
  activity, access gate, certificates, agent access, notifications, settings, readiness and
  updates, taken from a demo install with sample sites, bans, events and a certificate. The
  [screenshot index](docs/screenshots/README.md) says which page each image shows, and the
  README, the configuration reference, the installation pages, the runbook and this release's
  security policy embed the ones they describe.
- **Corrections after checking the guides against a running console.** The runbook's renewal
  line now states the real policy (checked every 12 hours; a month before expiry by default,
  with `Every 3 months` capped at seven days before expiry), the lost-password section starts
  with `wafproxy recover --user … --password … --reset-totp` instead of jumping to deleting the
  database, and the release-tag section describes the tagging convention rather than claiming
  every changelog section already has a tag.
- **The README states the sampling rule exactly** (`sample_above_rps`, 500 requests per second
  by default) instead of saying allowed requests are never logged.
- **SECURITY.md**: removed a duplicated "Reporting a vulnerability" heading, put the delivered
  fixes back in newest-first order, and replaced the claim that `govulncheck` runs in CI with
  what CI actually runs (`go vet`, the race suite, `npm audit --omit=dev`).

## [1.48.7] — 2026-11-23

### Fixed

- **Bundle hits report what happened, not what the profiles would allow.** The outcome badge came
  from the installed profile modes, so a rule that only ever matched on a log-only site still read
  "blocked" because some other profile allows blocking it. The query now returns blocked and logged
  counts from the recorded event action, a rule that saw both shows both badges, the column is
  labelled Outcome, and the "these requests were served" banner follows the same counts.
- **The profile dialog said "1 rules"** for a single-rule pack; the count is pluralised.

## [1.48.6] — 2026-11-23

### Added

- **An end-to-end bundle channel test.** It serves a real signed manifest over `httptest`, then
  covers the first install, a `304` on the next check, a version bump that replaces the pack, and a
  profile switched to `block` refusing a matching request with a 403 — the whole path from
  publisher to verdict in one test instead of a unit test per step.

### Fixed

- **The previous bundle version survives an install.** `prune` counted the installed version against
  its own budget, so the first install after a bump deleted the pack it is supposed to keep,
  leaving nothing to roll back to. It now keeps the installed pack plus the one before it, which
  the new end-to-end test asserts.

## [1.48.5] — 2026-11-23

### Fixed

- **The configuration reference matches the code.** Corrected health probes (HTTP `GET` every 10
  seconds, not `HEAD` every 30), body-limit behaviour (413 at the global limit and WAF rule 200004
  at the profile limit, never truncation), the admin session lifetime (12-hour idle, 7-day
  absolute), gate sessions (site- and account-bound, not client-network-bound), the temporary-ban
  cap, notification batching, and the scope of event retention and of the protection switch.
- **Missing defaults and ranges are documented**: per-site advanced fields, WAF profile limits,
  anomaly thresholds, streaming connection caps, the seeded feeds that start enabled and the ban
  list caps. Host package updates are marked as native-install-only.

## [1.48.4] — 2026-11-23

### Changed

- **Badge colour now means status, never category.** A plain badge is an intentional off state
  (Tailscale listeners, a disabled stream, an unconfigured notification channel), amber is
  "enabled but not working", red is a failure, green is healthy. Audit action names and Logs stage
  labels no longer change colour by what kind of event they are; the Logs table says in one line
  that its stage colour follows the outcome.
- **One absolute time format.** `fmtTime` prints `2026-11-23 20:03` regardless of browser locale;
  relative timestamps keep the relative label and carry the absolute time on hover. Raw
  `toLocaleString`/`toLocaleDateString` calls in Updates and the quick-action ban list use it too.
- **Two save patterns instead of four.** Settings, Notifications and Tailscale share the sticky
  footer (`SaveBar`), which states what will change and stays hidden until it is needed; a form
  that lives inside one card (CrowdSec bouncer, Streaming service, Anomalies detection,
  Auto-update) saves from that card's header. Labels are "Save settings" or "Save" — no more
  "Save and apply" in one place and a button at the bottom in another.
- **Every page has a description.** Logs, Sources, Threat intel, CrowdSec, Certificates,
  Notifications, Updates, Tailscale, Agent access, Account, Anomalies and Streaming gained the same
  one-line page header subtitle the rest of the console already had.

## [1.48.3] — 2026-11-23

### Fixed

- **The fallback WAF engine is read under the set lock.** `For` returned `s.fallback` directly for a
  site without a profile, while `SetBundles` replaces that engine on every install, so a request
  could read it while the refresh path wrote it. `SetBundles` also compiled the fallback inside the
  write lock, stalling every request for the length of a CRS compile; it now compiles first and
  swaps under the lock.
- Added race tests for the three concurrent paths: a pack install against live inspection, the
  manager's refresh loop against console reads (including a cancelled `Start`), and a WAF reload
  against per-profile bundle-mode lookups. `go test -race ./...` is clean.

## [1.48.2] — 2026-11-23

### Added

- **An admin configuration reference**, `docs/CONFIGURATION.md`. It documents every console page,
  tab, field, option and default, the settings that exist only in the API or YAML, the signature
  bundle channel, every environment variable, the data directory and the headless commands, and
  it is linked from the README and the documentation index.

### Fixed

- **The published version now matches `VERSION`.** The README introduction said 1.28.0 and the
  supported-versions table in `SECURITY.md` listed 1.28.x, so both now read 1.48.x.

## [1.48.1] — 2026-11-23

### Fixed

- **Each page heading is printed once.** The top bar already names the page, so Access gate,
  Activity, Proxies, Policies, Readiness, Settings and Statistics no longer repeat that name as a
  second heading, and Certificates no longer repeats it in its card title. Dashboard and
  Statistics also drop their alternate titles ("Operations overview", "Traffic analytics").
- **The Settings save bar appears only while something is unsaved**, so it no longer sits over the
  form's fields while browsing.
- **The Dashboard throughput card shows an empty state** instead of an axis of repeated "1 B/s"
  labels until a proxy actually moves traffic.
- **Kernel and repository failures read in plain language.** Policies shows "Kernel bans off" with
  the technical reason on hover, and Updates says the latest version could not be checked instead
  of printing the raw error.

## [1.48.0] — 2026-11-23

### Added

- **Signed signature bundles.** `internal/bundle` follows an ed25519-signed manifest on an hourly
  schedule, verifies the signature, SHA-256, advertised size and a throwaway compile, then installs
  a pack atomically and keeps the previous version as the last known good copy. A manifest whose
  `sequence` does not increase is refused, so a mirror cannot roll the channel back. Packs carry
  rules only, never addresses.
- **Per-profile bundle modes.** WAF profiles gained `bundle_modes` (`off`, `log`, `block`; unset
  means log), and a bundle mode is resolved per profile, never globally. `waf.Match` reports the
  rule's origin and pack, and the policy layer decides CRS and bundle rules separately. A site
  pinned to WAF mode `detect` keeps logging even when its profile allows a bundle to block.
- **Threat intel → Signature bundles** shows the channel, publisher key, installed versions and the
  modes across profiles, with a manual check. **Bundle hits** groups the rules that matched in the
  last 24 hours from the existing `events.rule_id` column, so no new write path was added.
- **Policies → WAF profiles** gained a read-only Bundles column and a per-bundle switch in the
  profile dialog, next to paranoia and rule exceptions.
- `GET /api/bundles`, `POST /api/bundles/check` and `GET /api/bundles/hits`, all under the
  `sources.*` permission area.
- `cmd/bundletool keygen|sign` publishes a channel and validates every rule before signing it.
- `WAFPROXY_BUNDLE_URL`, `WAFPROXY_BUNDLE_PUBKEY` and `WAFPROXY_BUNDLE_INTERVAL` configure the
  channel; without the first two it stays off and only installed packs are served.

### Changed

- `waf.Set` compiles installed packs into each profile engine and exposes `SetBundles`, so an
  install recompiles the same way a profile edit already did.
- `README`, `.env.example` and `docs/openapi.yaml` document the channel, the rule format and the
  new endpoints.

## [1.47.21] — 2026-11-23

### Added

- **"Buy me a coffee" in four places**, so a tip is one click from wherever an operator
  already is: an icon beside the signed-in user and version at the foot of the sidebar, a
  card at the bottom of Readiness, an About section at the end of Settings, and the sign-in
  page footer next to Documentation. The addresses now live in `web/src/links.ts` rather than
  being repeated per page.
## [1.47.20] — 2026-11-23

### Changed

- **A release tag now costs one CI run, not the whole suite.** A tag push runs only the
  `release` job, so publishing a backlog of tags no longer rebuilds the backend, console,
  updater, benchmarks and container image once per tag; branch pushes still run every job.

## [1.47.19] — 2026-11-23

### Added

- **Tag pushes run CI.** A `v*` tag now triggers the workflow, so the `release` job validates
  the tagged commit and fails when the tag name disagrees with `VERSION` (the check already
  covered the newest `CHANGELOG.md` section and the `version.go` default). `docs/OPERATIONS.md`
  gained a short section on pushing and verifying release tags.

## [1.47.18] — 2026-11-23

### Added

- **Signed-in administrators** in the account menu lists every live console session with the
  source address, browser, sign-in time and idle expiry, and marks the browser you are using.
  It needs read access to Settings and never exposes a session identifier.
- A "Buy me a coffee" link in the account menu for operators who want to tip the project.

## [1.47.17] — 2026-11-23

### Added

- A store test covers `EventTotals` directly: a host filter checks the total, blocked count and
  distinct sources and hosts, a blocked-only filter checks that challenges and bans count as
  blocked, and an unmatched filter returns zeroes instead of a missing row.

## [1.47.16] — 2026-11-23

### Added

- **Any investigation can be archived as a Markdown report.** `GET /api/events/incident.md`
  takes the Logs page filters (`ip`, `host`, `country`, `stage`, `action`, `blocked`) and a
  window, and answers the same write-up a runbook gets for a single source: summary, verdict
  counts, the newest 50 events and the audit actions mentioning the subject. An empty window
  says so. Both report routes now come from one renderer, documented in the API reference and
  in `docs/OPERATIONS.md`.

### Changed

- **The console fetches its incident report instead of building one.** The Logs report and the
  source drawer's report are rendered by the server, so the drawer, a cron job and a runbook
  cannot drift apart; the preview, copy, download and print controls are unchanged.

### Fixed

- **A palette verb or search aimed at the page already open applies its filter.** Navigating to
  the log with the query already in the address bar changed no hash, so nothing happened; the
  page now re-reads the query on every navigation.

## [1.47.15] — 2026-11-23

### Added

- Regression tests for the notification 500 on a failed recent-alert query and for the
  canary reporting an empty DNS answer as a `dns` stage instead of panicking; the prober's
  resolver is now injectable for the test.
- A canary test ages the delivered outage row past 24 hours and asserts the dedupe lets a
  fresh alert through, covering the window in both directions.

### Fixed

- **Readiness showed "Notification target configured — missing" for Telegram users.**
  It counted MCP agent links from `/api/agents`; it now counts the enabled channels
  `/api/notifications` reports.

### Changed

- Readiness moved to the bottom of the System group, directly above Settings.

## [1.47.14] — 2026-11-23

### Fixed

- **Printing a report printed the console behind it.** The print stylesheet hid the sidebar, top
  bar and the drawer's buttons, but left the page the drawer was opened over — filters, the event
  table, Save view / Copy link / Delete view — and the download filename in the output. A printed
  report is now the report alone (title plus Markdown), checked through Chromium's real print
  pipeline for both the Logs report and a source drawer's report.

## [1.47.13] — 2026-11-23

### Added

- A focused test feeds a deliberately broken document (missing `$ref` and a duplicate
  `operationId`) to the OpenAPI validation guard, so the guard itself is covered.
- A canary test restarts the notifier and checks that an already delivered outage is
  still deduplicated from stored alert rows, not process memory.

## [1.47.12] — 2026-11-23

### Fixed

- Changing `canary_host` carried the previous site's outage state over: the new site's
  first failure sent no alert and its consecutive count started above one. The monitor
  now resets the outage state when the probed host changes.

## [1.47.11] — 2026-11-23

### Fixed

- `GET /api/notifications` ignored a database error from the recent-alert query and
  returned an empty list as success; it now answers 500 like the settings read.
- The canary probe indexed the first resolved address without checking that the
  resolver returned one, so an empty answer panicked the health handler.
- A misplaced comment left the OpenAPI `Generate` function undocumented and described
  `operationID` as `Generate`.

## [1.47.10] — 2026-11-23

### Added

- A regression test drives a canary outage and recovery through the real
  `notify.Manager` queue and a webhook, proving the recovery is delivered even though
  the outage is still inside the 24 hour dedupe window.

## [1.47.9] — 2026-11-23

### Added

- `internal/openapi` now validates the committed document with kin-openapi: YAML structure,
  schema references and duplicate operations fail `go test ./...`, not just the
  byte-for-byte regeneration check.

### Fixed

- Generated operation IDs were the handler name, so every guarded route was `authed`; they
  are now derived from method and path (`getApiProxies`, `deleteApiProxiesId`).

## [1.47.8] — 2026-11-23

### Fixed

- The API reference now matches the two routes it got wrong: the internal CA root is
  documented as an `application/x-pem-file` download, and `GET /api/notifications`
  describes its real `settings` / `channels` / `recent` / `event_kinds` wrapper with
  `Alert` rows, instead of loose objects and a typed settings object.

## [1.47.7] — 2026-11-23

### Fixed

- **Read-only roles no longer get dead Save view / Delete view buttons.** The Logs page now takes
  `traffic.write` (the permission the shared-view API checks, not `policies.write`) and disables
  those two controls without it, so a reader can still pick and copy a shared view but cannot
  trigger a save that would fail or a delete that would only reappear on reload.

## [1.47.6] — 2026-11-23

### Added

- **Incident reports are fetchable without a browser.** `GET /api/ips/{ip}/incident.md?hours=24`
  renders the same Markdown as the console's Incident report drawer — summary, verdict counts,
  newest-first timeline and the audit actions that mention the address — with a
  `text/markdown` body and an `incident-<ip>-<stamp>.md` download name. It sits under the
  `traffic` read permission, so a cron job or on-call runbook can store write-ups with the
  same access it already needs for the log export. Timestamps are UTC and counts are grouped;
  country names, which the console resolves through the browser's `Intl`, appear as ISO codes.

## [1.47.5] — 2026-11-23

### Added

- **Saved log views are shared with the team.** Named views now live on the server behind
  `GET /api/log-views` and `PUT`/`DELETE /api/log-views/{name}`, guarded by the `traffic` area:
  any role that can read logs sees every view, and only a role that can write traffic may save
  or delete one. The browser's `localStorage` copy is still read first and kept up to date, so a
  node that cannot reach the API keeps its last known views and a refused save falls back to a
  browser-only view with an explicit notice.

### Fixed

- The API reference typed every path parameter as an integer; `{name}` and `{ip}` are strings now.

## [1.47.4] — 2026-11-23

### Fixed

- **Navigating away closes an open drawer.** A source drawer opened from the log stayed on screen, with
  its backdrop dimming whatever page you moved to; navigation now closes the drawer and any command
  dialog.
- **The palette's empty preflight names the subject** — "No requests in the last 24h came from
  AS64500." rather than "match asn (number) 64500".
- **The Readiness kernel row reads as one sentence**: "Bans apply in user space only — <reason>".

## [1.47.3] — 2026-11-23

### Fixed

- The API reference described `GET /api/notifications` as bare settings and the internal
  CA root as JSON; it now documents the settings/channels/recent wrapper and a
  `text/plain` PEM response.
- The canary monitor carried an unused logger and notification marker; both were
  removed rather than left as future placeholders.

## [1.47.2] — 2026-11-23

### Fixed

- A canary recovery used the outage dedupe key, so the notice was dropped as a duplicate
  for 24 hours; recovery now has its own key.
- `wafproxy recover --reset-totp` cleared the second factor but left existing sessions
  alive and claimed they were invalidated; both credential resets now delete sessions.

## [1.47.1] — 2026-11-23

### Changed

- `make test` runs `go run ./tools/openapi -check` first, and CI has the same step, so a
  route change without a regenerated `docs/openapi.yaml` fails the build instead of
  waiting for someone to read the diff.

## [1.47.0] — 2026-11-23

### Added

- The generated OpenAPI reference now carries request and response schemas for the main
  groups — sites/proxies, bans, certificates, notifications and anomaly — including the
  upload, internal-certificate, test and settings bodies plus 400/401 responses.

## [1.46.0] — 2026-11-23

### Added

- **TLS is its own canary stage.** The probe dials, then handshakes with SNI and checks
  the presented certificate, so an expired certificate, a wrong-host certificate and a
  plain connect failure are reported separately. The leaf expiry is returned as
  `cert_expires_at`, including in the scheduled canary's health snapshot.

## [1.45.1] — 2026-11-23

### Changed

- The OpenAPI generator lives in `internal/openapi`, and its test renders the document
  from `internal/api/server.go` and fails when `docs/openapi.yaml` is stale, so the
  reference cannot drift silently.

## [1.45.0] — 2026-11-23

### Added

- **Scheduled canary.** A timer probes one site through the proxy, retries failures,
  reports whether it answered (`POST /api/canary`), and exposes the last result under
  `canary` in `GET /api/health` with latency, failing stage and consecutive failures.
  Failures notify once per outage after retries and recovery notifies once.
- Settings `canary_enabled`, `canary_host`, `canary_interval_s` and `canary_retries`.

## [1.44.0] — 2026-11-23

### Added

- **Diagnostics bundle download.** `GET /api/diagnostics/bundle` returns a zip with
  version, redacted settings, listener and certificate status, recent errors
  (certificates, failed alerts, anomalies, 5xx) and a sanitized access-log tail.

## [1.43.4] — 2026-11-23

### Fixed

- **Proxy 360 no longer rounds a bad day up to 100% uptime**, and a proxy with no blocked
  requests shows "0.0% of requests" instead of a dash.
- **Activity stops reporting upstream ids as a change.** Saving a proxy rewrites its upstream and
  route rows, so their ids differ in every snapshot; the diff compares the configuration only, and
  a real change still shows.
- **A long kernel-status badge no longer widens the Policies page on a phone.** The badge wraps
  instead, and the tab strip wraps with it.
## [1.43.3] — 2026-11-23

### Fixed

- `POST /api/notifications/test` returns `400` for a missing or unknown channel instead
  of reporting it as a provider failure with `502`.

## [1.43.2] — 2026-11-23

### Fixed

- The console HTTPS docs showed `WAFPROXY_LISTEN_GUI` with a URL scheme although the
  setting is a `host:port` listen address; the TLS and host variables are now annotated
  with what `config.Load` accepts.

## [1.43.1] — 2026-11-23

### Fixed

- **The console kept serving the certificate it saw at startup.** The TLS listener
  captured one certificate and returned it for the console host forever, so a renewal
  or a replacement upload needed a restart. The handshake callback now resolves through
  the certificate manager every time; the fail-fast check at boot remains.

## [1.43.0] — 2026-11-23

### Added

- **Private ACME directory.** `WAFPROXY_ACME_DIRECTORY` and `WAFPROXY_ACME_CA_FILE`
  point issuance and revocation at an on-prem ACME server, and the plain-HTTP
  challenge/redirect handler is exported so integration tests exercise the listener
  itself.
- **Pebble end-to-end test.** `TestPebbleHTTP01` issues a real certificate through the
  listener against Pebble, checks that an unresolvable name fails and is stored as an
  error, and verifies the HTTPS redirect.

## [1.42.0] — 2026-11-23

### Changed

- `docs/INSTALL.md` is now a hub of task pages under `docs/install/`, and
  `docs/README.md` indexes the install, operations and project docs.
- **API reference.** `docs/openapi.yaml` is generated from the routes registered in
  `internal/api/server.go` (`go generate ./internal/api`), with `-check` to catch a stale
  file.

## [1.41.0] — 2026-11-23

### Added

- **Diagnostics bundle.** `GET /api/diagnostics` returns versions, listeners,
  configuration counts, certificate metadata and settings with secrets, URL credentials
  and query strings redacted.
- **Synthetic canary.** `POST /api/canary` resolves, connects and requests a benign path
  through the gateway, reporting every stage and naming the first failure (`waf`,
  `route` or `upstream`).

## [1.40.1] — 2026-11-23

### Changed

- Threshold alerting and the notification **Test** action are now documented in
  `docs/OPERATIONS.md`: the three anomaly kinds, their settings and defaults, the
  24-hour dedupe key, and the `200`/`502` behaviour of `POST /api/notifications/test`.

### Fixed

- Regression tests now cover the parts that had none: a webhook test message reaching a
  real HTTP endpoint, unknown channels failing, deduplication by alert key, and the API
  endpoint returning `200` only after the provider accepted the message.

## [1.40.0] — 2026-11-23

### Added

- **HTTPS for the admin console.** Set `WAFPROXY_LISTEN_GUI_TLS=1` and
  `WAFPROXY_GUI_HOST` and the console serves the certificate the certificate manager
  already holds for that name; other names still resolve through SNI, and a missing
  certificate stops the listener instead of falling back to plain HTTP.
- **Certificate revocation.** `POST /api/certs/{id}/revoke` asks the ACME CA to revoke
  issued certificates before removing them, and removes uploaded and internal
  certificates locally. A CA refusal leaves the certificate in place and reports why.

## [1.39.1] — 2026-11-23

### Fixed

- **Readiness renders again.** `/api/certs` answers `{certs: […]}`; the page read it as a bare array
  and the section failed with "f.some is not a function". The CrowdSec row is also no longer labelled
  optional twice, and the kernel row reads as a sentence.
- **The palette's "Release a ban" verb opens again.** `/api/bans` answers `{bans: […]}`; the unban
  dialog read that object as an array, which blanked the console.
- **The palette's preflight verb sends real policy kinds** (`ip_blacklist`, `country_blacklist`,
  `asn_block`) instead of values the endpoint rejects, so it no longer fails with "unknown policy kind".
- **Ban dialogs and toasts no longer promise a duration the server may not set.** A stricter existing
  permanent ban stays in force, so the messages say "banned" and the source drawer says an existing
  longer ban stays.
- **Incident reports write an em dash instead of a blank cell** for an event with no rule message, and
  preflight summaries use grammatical singulars ("1 request from 1 address matches").
## [1.39.0] — 2026-11-23

### Added

- **`wafproxy backup`.** Writes the same configuration document the console exports,
  encrypted with a passphrase (or `WAFPROXY_BACKUP_PASSPHRASE`), to
  `<data>/backups/wafproxy-backup-<time>.json.enc` with `0600` permissions, and `--keep N`
  prunes older backups so a nightly cron entry is one command.

## [1.38.0] — 2026-11-23

### Added

- **Incident report.** A **Report** button on the source drawer and on the event log builds a
  self-contained Markdown write-up of the window: summary, verdicts by stage, the newest events as a
  timeline, and every administrator action that mentions the subject. Copy it, download it as `.md`,
  or print it — a print stylesheet leaves only the report on the page. A window with no events says
  so instead of inventing content.
- **Command actions.** The palette takes verbs, not just destinations: ban an address, release a ban,
  disable a proxy, or preflight a rule against recorded traffic. Each asks for confirmation and does
  what the page-level control does. A role without the permission never sees the verb, and the dialog
  still refuses the action if the role lacks it.
- **Readiness checklist.** A scored page — base domain, TLS certificate, GeoIP databases, kernel
  enforcement, backup schedule, notification target, second factor and the audit chain, with CrowdSec
  as an unscored optional row — where every unmet row links to the control that fixes it. A source
  that fails to load marks its row unknown, never ready.

### Changed

- The palette lists the verbs under **Actions** beside pages and search results.
- Phone layout: 44 px navigation and drawer targets, wrapping action rows and table cells that wrap
  instead of clipping long paths or IPv6 addresses. `--faint` was lightened to clear AA contrast on
  the elevated surface.
- The live log tail announces each new event to screen readers through a polite live region.

## [1.37.0] — 2026-11-22

### Added

- **Activity page.** The audit log as a page: filter by actor, area and window, then expand any entry
  that changed a proxy, policy, WAF profile, protection profile, access profile or access list to see
  the field-by-field difference between the state before and after. **Roll back** restores the earlier
  values, is recorded as its own `*.rollback` entry and leaves the hash chain verifying. A role
  without that entity's write permission sees the diff but no rollback button. Deletions show the
  removed state and say to recreate them: rollback restores edits.
- **Saved log views.** Name the log's current filters, recall them from the dropdown, copy a
  shareable `#/logs?...` link, or delete a view. Views are stored per browser and a corrupt stored
  value is ignored.
- **Bulk actions on the log.** Tick sources — the whole page at once or one by one — and ban them for
  24 hours, copy the addresses, or clear the selection. Selection is per page, clears on a new search
  and reports a partial failure by count instead of claiming success.

### Changed

- Audited mutations store the state they changed in `audit_snapshots`, captured before and after the
  write. Snapshot writes are best-effort and never block the change they describe.
- `GET /api/audit/{id}` returns an entry with its stored state; `POST /api/audit/{id}/rollback`
  restores an edit after checking the entity's own write permission rather than the route's area.

## [1.37.1] — 2026-11-23

### Added

- **Internal CA and domain-less certificates.** `POST /api/certs/internal` signs a certificate
  from a local root for names like `nextcloud.home.arpa`, and
  `GET /api/certs/internal/root` serves the trust anchor clients install. The root persists in
  the data directory with a 0600 key, so trust survives restarts.
- **HTTP-01 inside the gateway.** A plain-HTTP listener (`WAFPROXY_LISTEN_HTTP`, off by default)
  serves ACME challenge tokens from the gateway's own handler and redirects every other request
  to HTTPS; lego no longer binds port 80 by itself.
- **Per-site minimum TLS version.** A site can require TLS 1.3 while every other host keeps 1.2.
- **Unattended setup and break-glass recovery.** `wafproxy setup --password …` creates the first
  administrator without a browser, and `wafproxy recover --password … --reset-totp` resets a
  locked-out account and invalidates its sessions.

### Changed

- Failed renewals now back off (30 minutes doubling to six hours, with jitter) instead of retrying
  every renewal tick.

## [1.36.1] — 2026-11-23

### Fixed

- **Bot challenge on IPv6 sites.** The challenge cookie is signed over the site's host name, and the
  port was stripped at the first colon, so a `Host` header such as `[2001:db8::1]:443` was reduced to
  `[2001`. Every host name starting with those characters shared one binding, and a challenge solved
  on one site was accepted by another from the same client network. The port is now split with the
  standard host/port parser, and a regression test keeps two IPv6 sites apart.

## [1.36.0] — 2026-11-22

### Added

- **Request-ID propagation.** `X-Request-Id` is accepted from a client or load balancer when it is
  a plain token (at most 64 characters), generated otherwise, echoed on the response and carried
  on the access-log event.
- **JSON access logs.** `WAFPROXY_ACCESS_LOG_FORMAT=json` writes one JSON object per request with
  the request ID, host, status, bytes, latency, stage, rule and action. The nginx combined format
  remains the default.

## [1.35.0] — 2026-11-22

### Added

- **Certificate upload.** `POST /api/certs/upload` accepts a PEM certificate and key, checks that
  they match and parse, reads the names and validity from the certificate itself, rejects expired
  certificates, and activates the result immediately.
- **Certificate source in the inventory.** Every certificate now records whether it came from
  ACME, an upload or the internal CA, and the field is part of the certificate list.

## [1.34.0] — 2026-11-22

### Added

- **Routing depth.** Routes now match method, a request header (`Name: value`), a query
  fragment, or a regex path with capture-group rewrites, in priority order, and can name their
  own upstream, timeout and redirect status (`301`/`307`/`308`).
- **Custom TCP forwarder.** The streaming catalog gains a Custom TCP service, so an arbitrary
  listen port can be forwarded to an arbitrary target with the existing allow lists, connection
  caps and bans instead of keeping a second proxy for it.
- **Published conformance table.** `docs/CONFORMANCE.md` lists the supported and deliberately
  unsupported protocol behaviours with the test that covers each supported row.

## [1.33.0] — 2026-11-22

### Added

- **Proxy 360.** A **360** button on every proxy opens one panel with that site's measured traffic
  (requests, block share, bytes in and out), upstream health and 24-hour availability, the assigned
  protection profile and certificate, the gate mode, every upstream with its weight and state, and
  the redirects and aliases. It links straight to the hostname's log and to the editor.
- **Policy preflight.** Before adding a country, IP/subnet, ASN or decoy policy, **Preflight** replays
  it against the last 24 hours of logged requests using the server's own matchers: how many requests
  and addresses it would affect, how many of those are served today (or refused, for an allow rule),
  and samples. Rate limits are explained rather than guessed. Nothing is saved and no state changes.

### Changed

- The preview is `POST /api/policies/preflight`, needs `policies.write` and only reads events.

## [1.32.0] — 2026-11-22

### Added

- **Shared response cache with quotas.** One 128 MiB process-wide cache replaces the 32 MiB
  per-site budgets, with a 32 MiB per-hostname quota and oldest-entry eviction, so one site can no
  longer crowd out every other site. `POST /api/cache/purge` drops one host or the whole cache.
- **Drain readiness.** `GET /api/health?ready=1` answers `503` while the listener is shutting down,
  and the readiness flag flips before the port closes.

### Changed

- A configuration reload keeps warm upstream connections instead of closing every pooled
  connection on the box.

## [1.31.0] — 2026-11-22

### Added

- **Per-site upstream timeout.** `upstream_timeout` bounds a whole request to the backend in
  seconds; zero keeps the transport default. A timeout now answers `504` instead of flattening
  every forwarding failure into `502`.
- **Bounded retries.** `retries` replays only idempotent requests (GET, HEAD, OPTIONS, PUT, DELETE)
  whose body can be replayed, and only before any response byte is read; upstream `502/503/504`
  answers are retried within the same limit.
- **Header rewriting.** Ordered `request_headers` and `response_headers` rules (`set`, `add`,
  `remove`), applied to the request before forwarding and to the response before inspection.
  Framing and hop-by-hop headers are refused at save time.

## [1.30.0] — 2026-11-22

### Added

- **Per-site balancing policies.** `weighted_rr` (default), `least_conn`, `least_latency`,
  `ip_hash` and `sticky_cookie`; the in-flight and latency counters the old picker recorded are
  now used. An upstream's `max_conns` removes it from selection while it is saturated.
- **Configurable health probes per site.** Path, accepted status codes (default `200-399`),
  interval and failure threshold; upstreams inherit the site's settings. A real 5xx now feeds the
  same failure counter, so a backend that keeps returning errors is ejected instead of staying
  "healthy" forever.
- **Per-site and per-client request budgets** alongside the process-wide ceiling, with `503` for a
  saturated site and `429` for a client that spends its own share.

### Fixed

- **Certificate selection ranked by `domains[0]`.** A multi-name certificate could win for a host
  it did not cover best; selection now compares the matched pattern, and a site's `cert_id` is
  authoritative over SNI matching.
- **`HTTP_PROXY` hijacked upstream traffic.** The forwarding transport and the header audit no
  longer use `http.ProxyFromEnvironment`, so an environment proxy cannot silently carry customer
  traffic.

### Changed

- `docs/ROADMAP.md` maps every item from the external review to a release or an explicit deferral.

## [1.29.0] — 2026-11-22

### Added

- **Investigate source drawer.** A source address now opens the same drawer from the log, the
  dashboard's top blocked sources and recent blocked requests, the attack map's event list, the
  source explorer and a source result in ⌘K search: request and block totals for 1h/24h/7d/30d,
  distinct hosts, first and last seen, threat-intel matches, the recent requests from that address
  and its ban state. An administrator holding `policies.write` can ban it for 24 hours with a typed
  reason, or release an existing ban, after confirmation; every other role gets the read-only view.
- **Live tail on the log.** The event log follows new requests every two seconds, stops polling
  while the tab is hidden, catches up on return, and does not fight a search the operator is
  waiting on.
- **Needs attention queue on the dashboard.** One list of what is actually broken or pending:
  backends down, failed and soon-expiring certificates, threat feeds in error or frozen,
  unexplained anomalies from the last day, pending security package updates and an available
  console update. Each item links to the page that fixes it and leaves the list when its cause
  clears; there is nothing to dismiss.

### Changed

- The source explorer's inline detail panel and its `prompt()` ban are gone. Its rows open the
  shared drawer, and every ban now has a typed reason and a confirmation step.
- The dashboard's backends-down banner is part of the attention queue instead of a separate
  message, so one outage is reported once.

## [1.28.1] — 2026-11-22

### Fixed

- **Encrypted imports read the file as text.** Both **Import backup** and **Import YAML** decoded the
  selected file with `File.text()`, which replaces every invalid UTF-8 byte of ciphertext, so a
  sealed file downloaded from the console could not be restored at all. Both paths now read bytes
  and post a Blob; verified in a browser against a throwaway data directory.

### Changed

- README rewritten around 1.28 (RBAC, challenge types, encryption, transport), SECURITY.md names
  the supported 1.28 line and lists the fixes delivered since the last review, example domains and
  LAN addresses replace the reference deployment's, and unreferenced screenshots and design notes
  are removed.

## [1.28.0] — 2026-11-22

### Added

- **The manual downloads can be encrypted.** Fill the passphrase field beside **Download JSON** or
  **Download YAML** and the file is sealed with the same AES-256-GCM format as the scheduled backup;
  **Import YAML** opens an encrypted file with that passphrase. A passphrase under 16 characters is
  refused.

### Changed

- The backup encryption option is a labelled switch with its passphrase field directly beneath it,
  and the console's request helpers share one response parser.

## [1.27.2] — 2026-11-22

### Added

- **Attack map country drill-down.** The dashboard globe opens into a full map with a five-group
  legend, country labels and drag-to-rotate. Clicking a country isolates it, filters the event list
  to that source, and labels the selected region; country hit-testing also works at 2× device scale.

### Changed

- **Console rail and mark.** The navigation rail is narrower and left-aligned, and the old shield
  glyph is replaced by the WAF-Proxy shield mark, which is also the browser favicon, on the sidebar
  and sign-in screen.

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
