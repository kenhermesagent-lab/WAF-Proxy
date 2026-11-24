# Plan C — Game-server streaming (and HTTP/3 as the follow-on)

Status: **approved 2026-11-23.** Owned by the second agent, which starts at C1.
Owner: a second agent, on its own branch, in parallel with Plan A. Window: **three
weeks** for the relay (14.5 task-days), then one review-and-merge pass; HTTP/3 is
the next slice. Releases: **1.63.0**, **1.64.0**. Build loop: the roadmap's
[Post-1.60 scale track](../../ROADMAP.md).
Companion plan: [Plan A — fat node](2026-11-23-scale-plan-a-fat-node.md).

## Why this plan exists

The customer is a person hosting a handful of game servers for friends, not a
game company. They already have the hard parts solved: the game panel installs
and updates servers (Pterodactyl and friends), and the router forwards ports.
What they do not have is a single front door with the same source policy,
ban list, visibility and TLS story as their web sites. Today that means a second
reverse proxy (usually HAProxy) beside WAF-Proxy, or nothing at all.

The recommendation taken in the review, and confirmed here, is **relay-grade,
not gateway-grade**:

- **In scope:** an L4 TCP **and UDP** relay with port ranges, TCP+UDP pairing,
  game presets, the same bans/lists/countries, per-source limits, live
  visibility, and one console.
- **Out of scope:** protocol parsing (no Steam A2S, no RCON, no player counts),
  a game panel, mod management, anti-cheat, UDP health checks, and any promise
  of DDoS scrubbing beyond what the kernel and existing L3/L4 bans do.

That boundary is what makes three weeks enough. It also matches what the existing
relay already is: a transparent byte pipe that deliberately does not terminate
TLS, because Plex clients validate `*.plex.direct` names.

## Current state, verified

| Fact | Evidence |
| --- | --- |
| TCP only, one listen port per service | `internal/streaming/streaming.go` (`net.Listen("tcp", …)`, single `Port`) |
| Catalog is Plex, Jellyfin, Custom TCP | `streaming.go` `Catalog` |
| Per-port source policy, bans, countries, caps already work at accept | `sourcePolicy.verdict`, `Manager.accept` |
| Idle timeout is 30 min for media; caps default 256 | `streaming.go` consts |
| Events are written one row per refusal, synchronously | `cmd/wafproxy/main.go` `SetEventSink` → `InsertEvents([]model.Event{row})` |
| Forwarders start with the data plane, only on the active node, and rebind on promotion | `cmd/wafproxy/plane.go` `Serve`, `main.go` "a standby must not hold a media port" |
| No metrics, no byte counters, no per-session view | `Status` only has counts |
| No UDP, HTTP/3 or QUIC anywhere | confirmed by grep; `docs/CONFORMANCE.md` says HTTP/3 unsupported |

## Goals (measurable)

| ID | Goal | Measure |
| --- | --- | --- |
| C-G1 | A game server behind WAF-Proxy is a first-class service | UDP and TCP+UDP presets bind, pass traffic, and survive a 100-packet loss-free echo test |
| C-G2 | Ranges work | Valheim 2456–2458 and ARK 7777–7778 map to the same range on the upstream |
| C-G3 | The same policy applies | a banned source stops within one datagram; an allow list refuses a new session; per-source session and rate caps hold |
| C-G4 | Operators can see it | sessions, bytes in/out, packets, refused, and top sources per service, live |
| C-G5 | UDP is not a reflector | privileged/amplification ports refused, datagram size capped, per-source new-session rate limited, a warning when a UDP port is open to the world |
| C-G6 | HA stays correct | a standby holds no game ports; demotion closes sessions and releases ports; promotion rebinds |
| C-G7 | No migration | no schema change; settings only, already `ClassReplicated` |
| C-G8 | HTTP/3 lands afterwards without rework | the same handler serves h3; conformance table updated; TCP path unchanged |

## Non-goals

- Player counts, server names, map info: those need protocol parsing.
- Game panel functions (install, update, mods, backups) — Pterodactyl owns them.
- Anti-cheat, packet inspection, DPI.
- A second WAF for game traffic. Games are not HTTP; the relay's policy is
  source-based, and the plan says so in the UI rather than implying more.
- Changes to `internal/proxy` — Plan A owns that tree. This plan touches
  `internal/streaming`, `internal/api/streaming.go`, the console Streaming page
  and docs.
- N-node HA. The pair is the target.

## Decisions taken

| Decision | Choice | Why |
| --- | --- | --- |
| UDP model | one shared listen socket, one **connected** upstream socket per client session | replies must be demultiplexed by client; a connected socket also drops unsolicited replies from other hosts |
| Session identity | client IP:port + listen port | NAT rebinding creates a new session; the old one expires |
| UDP idle timeout | 60 s default (10–3600), configurable | games keepalive; media stays at 30 min |
| Port model | base port + count, mapped 1:1 to upstream base + count | covers Valheim/ARK/FiveM/Factorio without a rules engine |
| Protocol | `tcp`, `udp`, `both` | FiveM and Factorio share a number |
| Presets | editable seed values, never enforced | game port docs change; the operator must be able to override |
| Refusal events | throttled per source per service (existing throttle), batched in the writer | a UDP scan must not become a write storm |
| HA | sessions are node-local and are not replicated; the active node alone binds | matches the existing forwarder lifecycle |
| HTTP/3 | own release (1.64.0), after the relay | it is a separate protocol, with its own socket, cert and conformance work |

## Data model (no migration)

All new state is settings, which the HA snapshot already replicates, plus live
in-memory counters.

| Key | Scope | Meaning |
| --- | --- | --- |
| `stream_<id>_enabled` | host | unchanged |
| `stream_<id>_protocol` | host | `tcp` \| `udp` \| `both`, default `tcp` |
| `stream_<id>_port` | host | base listen port |
| `stream_<id>_port_count` | host | 1–16, default 1 |
| `stream_<id>_upstream` | host | host or host:port; base upstream |
| `stream_<id>_upstream_port` | host | base upstream port when it differs from listen |
| `stream_<id>_max_conns` | host | TCP connections **or** UDP sessions, default 256 |
| `stream_<id>_max_per_source` | host | UDP sessions per source address, default 8 |
| `stream_<id>_idle_seconds` | host | UDP session idle, default 60; TCP keeps 30 min |
| `stream_<id>_max_datagram` | host | default 1500, max 8192 |
| `stream_<id>_allow` / `_lists` | host | unchanged |
| `stream_<id>_require_allow` | host | UDP only; refuses everything not on an allow list |

`streaming.Config` grows the fields; `ConfigFromSettings` keeps reading the old
`plex_*` keys. `Normalize` validates: port range within 1–65535 and not
crossing it, count 1–16, protocol valid, upstream port arithmetic valid,
privileged listen ports (< 1024) refused unless `require_allow` is on and the
service is not in the amplification denylist.

New catalog shape:

```go
type Service struct {
    ID          string
    Label       string
    Group       string // "media" | "game" | "custom"
    Protocol    string // default protocol
    DefaultPort int
    PortCount   int
    Notes       string // shown under the card
}
```

## Task C1 — UDP relay core (4 days)

New file `internal/streaming/udp.go`, owned by the same `Manager` so policy,
status and shutdown stay in one place.

```go
type udpRuntime struct {
    def    Service
    cfg    Config
    pc     *net.UDPConn          // shared listen socket
    done   chan struct{}
    wg     sync.WaitGroup
    mu     sync.Mutex
    sess   map[sessionKey]*udpSession
    active atomic.Int64
    // counters: total, blocked, banned, dropped, pktsIn/Out, bytesIn/Out
}

type udpSession struct {
    key      sessionKey          // client addr + listen port
    client   *net.UDPAddr
    upstream *net.UDPConn        // connected socket to upstream
    lastSeen atomic.Int64        // unix nanos
    bytesIn, bytesOut, pktsIn, pktsOut atomic.Uint64
    started  time.Time
}
```

Read loop:

1. `ReadFromUDPAddrPort` into a pooled buffer of `maxDatagram` bytes.
2. Look up the session by `(client, listen port)`. On miss: enforce
   `max_per_source`, the new-session rate limit, source policy, ban list and
   `require_allow`; then `net.DialUDP` to `upstream + offset`. A refusal emits
   the existing throttled event with `Protocol: "udp"`.
3. Every datagram checks the ban map (86 ns at 100k prefixes, allocation-free —
   `internal/netmatch`), so a ban cuts live traffic immediately, not only new
   sessions.
4. `WriteToUDP` to the upstream; count packets and bytes.
5. A per-session reader goroutine (`upstream.Read`) writes replies back to the
   client, refreshes `lastSeen`, counts bytes, and exits on error or close.
6. A janitor ticker (every 5 s) closes sessions idle beyond `idle_seconds` and
   removes them.

Shutdown and demotion: `Close()` and `Apply` close every session socket before
closing the listener, so the port is free for the other node on promotion.

FD budget: one listen socket + one socket per session (default cap 256). The
docs page must state `LimitNOFILE` guidance and the `ulimit -n` check; the
service unit ships `LimitNOFILE=8192`.

Tests (`internal/streaming/udp_test.go`):

- echo: client sends 20 datagrams, all return byte-identical, counters match.
- range: a service on 2456–2458 with upstream base 2456 maps port N to
  upstream N; assert each port's replies arrive on the right client port.
- connected-socket property: a third socket sends to the session's upstream port
  and its datagram is never delivered to the client.
- per-source cap: 9th session from one address is refused, the 8th still works,
  closing one allows a new one.
- idle expiry with a fake clock: session disappears, socket closed (assert
  `Read` returns `net.ErrClosed`).
- ban: add a ban while a session is active; the next datagram is dropped and the
  session is closed; the event is emitted once per throttle window.
- max datagram: an oversized datagram is dropped and counted, not truncated.
- shutdown: `Close()` releases the port (immediate rebind succeeds).

## Task C2 — Config, port ranges, TCP+UDP pairing (2 days)

- `Config` fields as above; `Normalize` rules; `ConfigFromSettings` defaults and
  backward compatibility (`protocol` empty means `tcp`; `port_count` empty means
  1; `upstream_port` empty means same as listen, preserving today's behaviour).
- `Manager.Apply` gains a `udp` branch; for `both`, one TCP listener and one UDP
  socket are created and their statuses merged in `Status` (`Bound` only when
  every requested protocol is bound; `LastError` names the failed one).
- `Status` grows `Protocol`, `PortCount`, `ActiveSessions` (UDP), `Sessions`
  (top talkers, capped at 50), `BytesIn/Out`, `PacketsIn/Out`, `Refused`,
  `UpstreamBase`, and keeps the existing TCP fields.
- Port conflict detection in `internal/api/streaming.go` must compare protocol
  too: TCP and UDP on the same number are legal; two services on the same
  protocol and address are not; the WAN `:443/udp` reservation is checked once
  HTTP/3 exists.

Tests: settings round-trip for every new key, legacy key fallback, `Normalize`
table (bad range, count 0, port 70000, count crossing 65535, upstream base
mismatch, privileged port without allow list), `both` binds two sockets and
reports one status, TCP-only configs behave exactly as 1.60

## Task C3 — Game presets (1 day)

Add to `Catalog` (all editable; this is a seed, not a contract):

| Game | Protocol | Ports | Notes |
| --- | --- | --- | --- |
| Minecraft Java | TCP | 25565 | no UDP |
| Minecraft Bedrock | UDP | 19132 | IPv6 uses 19133 |
| Source engine (TF2, CS, Garry's Mod) | both | 27015 | TCP is used by some tools |
| Rust | both | 28015 (game), 28016 (RCON TCP) | two services, or a count-2 range if the operator accepts the mapping |
| Valheim | UDP | 2456–2458 | count 3 |
| Palworld | UDP | 8211 | |
| FiveM | both | 30120 | same number on both protocols |
| Factorio | both | 34197 | |
| ARK: Survival Evolved | UDP | 7777–7778 | query port 27015 is separate |
| 7 Days to Die | both | 26900–26903 | count 4 |

Each preset carries `Notes` and, where a query port is separate, a second card
the operator can enable or delete. The page says "ports change; check the game's
current documentation" in one line, and the Custom TCP entry becomes Custom
TCP/UDP with the protocol select.

Tests: catalog invariants (IDs unique, ports in range, protocol valid), settings
defaults prefill from the preset, docs table matches the catalog (a Go test reads
the Markdown table and compares IDs and ports, so the two cannot drift).

## Task C4 — Console: one Streaming page, grouped (2.5 days)

`web/src/pages/Streaming.tsx` (423 lines today) becomes:

- Three groups with headings: **Media** (Plex, Jellyfin), **Game servers**
  (presets), **Custom** (TCP/UDP forwarder).
- Each card: enable switch, protocol select, listen IP, port + count (count
  hidden when 1), upstream host/port, allow list, named lists, max sessions,
  max per source (UDP only), idle seconds (UDP only), Save.
- Live strip per card: state badge (bound / error + reason), sessions or
  connections, In/Out (human bytes), refused, and the top source address.
- UDP cards show the reflection warning when `require_allow` is off and the
  allow list is empty: "this port answers anyone; add an allow list or tick
  'require allow list'". Not a blocker for friends-only servers behind NAT, but
  it must be visible.
- The DNS/Steam query-port note appears as helper text, not as a second feature.

`web/src/types.ts`: extend `StreamingService`; `web/src/pages/Streaming.test.tsx`
covers grouping, protocol switching (UDP-only fields appear), count > 1 payload,
warning banner conditions, and legacy services rendering unchanged.

## Task C5 — UDP safety controls (1 day)

- Amplification denylist, refused at `Normalize` with the reason:
  `53` (DNS), `123` (NTP), `1900` (SSDP), `5353` (mDNS), `11211` (memcached),
  `389` (CLDAP), `161` (SNMP). A game will never need these; allowing them turns
  the box into a reflector.
- Privileged ports (< 1024) require `require_allow` plus a non-empty allow list,
  and are refused for `both`/`udp` otherwise.
- `max_datagram` (default 1500) caps the read buffer; larger datagrams are
  dropped and counted, never truncated and forwarded.
- New-session rate limit per source: 10/s with a burst of 30, implemented with
  the existing `throttle` table pattern (bounded, pruned).
- `require_allow`: when on, a UDP service with no allow list and no whitelist
  refuses every new session with a clear event.
- Docs: a short "UDP is spoofable" paragraph — allow lists are weaker on UDP
  because the source address can be forged; the caps and denylist are what
  protect the box, not attribution.

Tests: each denied port, privileged-port rule, oversized datagram, rate limiter
allows the burst and then refuses, `require_allow` refuses with the reason in the
event detail.

## Task C6 — Visibility, metrics, event batching (2 days)

- `Manager.Statuses()` exposes per-service counters and the 50 newest sessions
  (bytes, packets, duration, last seen). Sorted by bytes, so the page can show
  top talkers without a second call.
- Prometheus (`internal/metrics`): `wafproxy_stream_sessions{service}`,
  `_stream_bytes_total{service,direction}`, `_stream_packets_total`,
  `_stream_refused_total{service,reason}`, `_stream_cap_hits_total`.
- Event writer: `main.go`'s stream sink currently inserts one row per event
  synchronously. Replace with a buffered channel (1,024) and a ticker (250 ms)
  that calls `InsertEvents` in batches, dropping with a counter when full —
  the same shape the proxy's `eventWriter` already uses. Method field carries
  `UDP` or `TCP`; path carries `:port` and, for ranges, the actual port.
- Console page polls `GET /api/streaming` every 3 s while visible (existing
  page already polls? if it does, reuse the interval; if it does not, a 3 s
  poll only while the tab is visible).

Tests: counters move on traffic; event batching inserts N rows in one
transaction (store spy), drops are counted, method/port are correct for UDP;
metrics names appear after one session.

## Task C7 — HA lifecycle (1 day)

The relay must remain "active node only":

- `dataPlane.Serve` applies forwarders after promotion (already true); add UDP
  to `ApplyAll` and assert the standby has no bound UDP port (`ss`-free test:
  `ApplyAll` not called ⟹ no socket).
- On `Close`/demotion, UDP sessions are closed and the port is released before
  the HTTP listener stops; a test binds the same port immediately after.
- Add a `sim`-style test in `internal/ha` (the package already has `sim_test.go`)
  that drives promote → traffic → demote → promote and asserts one active
  listener at a time.
- Document: a failover drops game sessions. That is inherent to a two-node pair
  without connection replication, and it is better than a split-brain port.

## Task C8 — HTTP/3 and QUIC (next release, 5 days)

Deliberately not in the three-week window. It is the second reason a self-hoster
keeps another proxy around, and it is a protocol project, not a relay tweak.

- Dependency: `github.com/quic-go/quic-go` (pin; no cgo). `http3.Server` wraps
  the **existing** `proxy.Server` handler, so WAF, gate, bans, cache and logs are
  identical by construction.
- `:443/udp` listener, enabled by `WAFPROXY_HTTP3=1`; binds beside the TCP
  listener. If a UDP stream service already holds 443, startup fails with the
  service name (port conflict check must include this).
- TLS: reuse the existing certificate manager through `GetCertificate`; ALPN
  `h3`; **0-RTT disabled** (replay risk), connection migration left at the
  library default, `MaxIncomingStreams` bounded (default 100).
- `Alt-Svc: h3=":443"; ma=86400` added to HTTP/1.1 and HTTP/2 responses only
  when h3 is enabled and the request arrived over TLS. Not added on the plain
  HTTP redirector.
- QUIC handshake floods are bounded by a connection-attempt rate limit; the
  existing per-client caps apply per stream as usual.
- Cloudflare Tunnel: the connector speaks HTTP/2 to the origin, so h3 is not
  offered through a tunnel. Document that; do not pretend otherwise.
- `docs/CONFORMANCE.md`: HTTP/3 row moves from "Not implemented / Unsupported"
  to supported with the tested cases (GET, POST with body, HEAD, WAF block,
  cache hit, 0-RTT refused).
- Tests: quic-go client negotiates h3; WAF blocks an attack identically;
  cache hit over h3; TCP unaffected when the flag is off; alt-svc absent when
  off; a UDP stream on 443 conflicts with a clear error.

## Task C9 — Docs and release (1 day)

- `docs/install/04-crowdsec-and-streaming.md`: media and games in one page,
  with the port table, `LimitNOFILE`, router guidance (forward TCP and UDP for
  `both`; some routers need separate rules), and the HA session-loss note.
- `docs/CONFIGURATION.md`: new settings and their defaults.
- `docs/OPERATIONS.md`: "a game server does not connect" checklist (protocol
  mismatch, port range mapping, allow list, upstream firewall, NAT loopback).
- `README.md` feature list and Limits; `CHANGELOG.md` for 1.63.0 (and 1.64.0
  when h3 lands).
- `VERSION` **1.63.0**; version files, compose pins, `SECURITY.md`, rebuilt
  bundle, `bash deploy/check-version.sh`, `make verify-release`.

## Verification

```bash
go build ./...
go test ./internal/streaming/... ./internal/api/... ./internal/ha/... ./internal/metrics/...
cd web && npx tsc --noEmit && npx vitest run && npm run build
bash deploy/check-version.sh
```

Manual matrix on a host with a real game server (or a UDP echo server for the
mechanics): Minecraft Java (TCP), Valheim (3-port UDP range), FiveM-style TCP+UDP
on one port, a banned source cut mid-session, a demotion releasing the port, and
one hour of idle traffic to confirm no sessions leak (`ss -u` count flat).

The manual matrix is required for release: the sandbox has no real NIC and no
game server, so the tests prove mechanics, not a specific game.

## Risks and their answers

| Risk | Answer |
| --- | --- |
| UDP relay used as a reflector | amplification denylist, privileged-port rule, `max_datagram`, per-source caps, `require_allow` and a visible warning; documented spoofing limit |
| FD exhaustion at 256 sessions | cap enforced before dial, `LimitNOFILE=8192` in the unit, docs check, `ss` guidance |
| Session table growth under spoofed sources | per-source cap + janitor + bounded throttle table (4,096, already in the package) |
| Port ranges confuse users | count field with a live "listens on 2456, 2457, 2458 → forwards to …" preview and `Normalize` errors naming the exact port |
| HA failover drops games | documented as expected for a two-node pair; the alternative (both nodes bound) is worse |
| HTTP/3 scope creep into the relay release | h3 is a separate release with its own gate; 1.63.0 ships without it |
| Plan A touches the same settings loader | this plan adds keys only; no change to `internal/proxy`, `internal/waf`, `internal/config`, `internal/store` schema or classification |

## Order, weeks and commits

| Week | Tasks | Ends with |
| --- | --- | --- |
| 1–2 | C1 → C5 (10.5 days) | — |
| 3 | C6, C7, C9 (4 days) | **1.63.0** committed on the branch |
| 4 | deslop pass, reviews, one merge to `main` | 1.63.0 on `main`; C8 is next |

C1 → C2 → C3 → C4 → C5 → C6 → C7 → C9 (1.63.0), then C8 → C9 (1.64.0). One
commit per task. The 14.5 task-days are the build, with half a day of slack in
weeks 1–2; the week-4 pass is the review and merge the roadmap's build loop
requires. Rebase on `main` after Plan A's releases land; the only shared
files are `VERSION`, `CHANGELOG.md`, `docs/ROADMAP.md` and `internal/api/server.go`
(one route block), and each is a one-line conflict by construction.
