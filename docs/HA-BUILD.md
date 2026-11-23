# HA build: execution plan

> **Status: proposed.** Nothing in this document exists in 1.55.2. Read it beside
> [HA.md](HA.md), which explains what each phase must make true and why; this file turns
> that into ordered tasks that can be picked up, reviewed and reverted one at a time.

**Build status.** Last checked against 1.57.0 on 2026-11-23. A task is *landed* only when
its test exists and `go test ./...` passes; everything else is untouched.

| Task | Status | Evidence |
|---|---|---|
| P0-00 lab | not started | VIP mode needs two VMs |
| P0-01 role file | landed | `internal/ha/role_test.go` |
| P0-02 listener lifecycle | landed | `internal/proxy/listen_test.go`, 100 bind/close cycles |
| P0-03 loop gate | landed | `internal/ha/gate_test.go`; backup and auto-update managers moved into the restartable active supervisor in `cmd/wafproxy/plane.go` |
| P0-04 `IP_FREEBIND` | landed | `internal/netbind` |
| P0-05 management listener | landed | config validation plus a second console listener |
| P0-06 `ReloadAll` | landed | `api.ReloadAll` reloads every site's policy and the proxy routes; the promotion calls it |
| P0-07 sealed certificate keys | landed, schema 23 | `internal/store/cert_seal_test.go` |
| P0-08 hashed gate tokens | landed, schema 24 | `internal/store/gate_hash_test.go` |
| P0-09 table classification | landed | `internal/store/classification_test.go` |
| P0-10 `recover --rotate-master-key` | not started | |
| P1-01 state machine | landed | `internal/ha/state_test.go` |
| P1-02 control socket | landed | `internal/ha/control.go`, 0600 socket inside a 0700 directory, `internal/ha/failover_test.go` |
| P1-03 `ha status` | landed | `cmd/wafproxy/ha_test.go` |
| P1-04 readiness and health | landed | `internal/api` handler tests |
| P1-05 read-only standby | landed | `internal/api/standby_test.go` |
| P1-06 console banner | not started | |
| P2-01 cluster identity | partial | self-signed key per node pinned by fingerprint, not a cluster CA; `internal/ha/identity_test.go` |
| P2-02 pairing code | landed | 128-bit code, hash at rest, 10-minute single use: `internal/ha/pair.go` |
| P2-03 join handshake | landed | pinned TLS, cluster secret, master key sealed under it and written 0600: `internal/ha/link_test.go`, `internal/ha/pair_master_test.go` |
| P2-04 unpair and rekey | partial | `ha unpair` removes pair and code, keeps role and key; no automatic rekey of the peer |
| P2-05 pairing CLI | partial | `ha pair`, `ha join`, `ha unpair`; no persistent audit trail beyond log lines |
| P3 snapshot replication | landed | sealed whole-database snapshot over the pinned link, transactional restore, `ha sync`: `internal/store/snapshot_test.go`, `internal/ha/snapshot_test.go` |
| P4-01 outbox schema | landed, schema 25 | `ha_outbox`, `ha_peer_ack`, `ha_applied`, all classified local: `internal/store/outbox_test.go` |
| P4-02 enqueue API | landed | `upsertChanged`/`deleteCaptured` commit the change and its outbox row together |
| P4-03 session write paths | landed | sessions, trusted devices, password resets and the TOTP replay step |
| P4-04 bans and gates | landed | bans, username bans, gate sessions and gate failures |
| P4-05 audit and alerts | landed | audit rows with their chain head, pending and delivered alert state |
| P4-06 pull protocol | landed | one page per second, contiguous apply, `(origin, seq)` dedupe, ack watermark, prune |
| P4-07 overflow | landed | 100 MiB ceiling returns 409, the standby takes a snapshot, the ack resets the stream |
| P4-08 diagnostics | landed | `ha status --json`, `/api/ha/diagnostics`, `wafproxy_ha_outbox_depth` |
| P5-01 preflight | landed | `internal/ha/preflight.go`, one failure test per check; `ha failover --dry-run --json` |
| P5-02 quiesce, drain, epoch | landed | `internal/ha/failover.go`, `role.go`; a crash after persisting the epoch restarts as `promoting` |
| P5-03 promotion sequence | landed | ordered hooks in `Promote`; `api.ReloadAll`, `ban.Reconcile`, `proxy.ListenWith` |
| P5-04 control socket, keepalived | code landed, lab pending | `cmd/wafproxy/ha_move.go`, `deploy/ha/keepalived.conf`, `deploy/ha/notify.sh` |
| P5-05 drain and rejoin | code landed, lab pending | standby pre-binds with `IP_FREEBIND` and serves nothing; `dataPlane.Drain` closes listeners and forwarders |
| P5-06 failback | landed | `Demote`, `ha failback`; an abort is refused once the data plane serves |
| P6-01 heartbeat | landed | `/ha/ping` on the pinned link, `internal/ha/heartbeat.go`; two lost beats change nothing, the third trips, recovery resets |
| P6-02 witness and lease | landed | `internal/ha/witness.go`, `wafproxy ha witness --listen`; the active renews every 3 s and self-demotes after the 10 s TTL |
| P6-03 fencing hook | landed | `internal/ha/fence.go`; `{peer}` is shell-quoted, a timeout kills the whole process group, exit 0 means down |
| P6-04 automatic gate | landed, lab pending | `internal/ha/auto.go`; heartbeat + witness + fence evidence, the automatic sequence skips a dead peer and renews the lease before Serve; `WAFPROXY_HA_AUTO_FAILOVER` requires both witness and fence |
| P6-05 higher-epoch demotion | landed, lab pending | a heartbeat with a higher epoch makes the active stop serving into `split-brain-risk`; it follows the peer again only after `Reconcile` adopts the peer's epoch |
| P6-06 guards and flap control | landed | `internal/ha/flap.go`; the fourth automatic move in an hour parks the node with a reason `ha status` shows, and only a manual move clears it |
| P6-07 partition simulator | landed | `internal/ha/sim_test.go`: the partition matrix plus 200 randomized partitions on a fake clock; every tick asserts at most one live active and every promotion carried an unexpired lease for its own epoch |
| P7-02 `ha_enabled` backend | landed, loops boot-time | `ha_enabled` is host-wide (`publicSettingKeys`, `hostSettingKeys`), accepts only `0`/`1`, is audited as `ha.enable`/`ha.disable`, and the effective value is read per request for `/api/me` and `/api/ha`; the runtime still starts at boot, so turning HA on starts its loops at the next restart |
| P7-01 HA API | landed | `internal/api/ha.go`: `GET /api/ha`, `GET /api/ha/events`, `GET /api/ha/diagnostics`, `PUT /api/ha/config`, `POST /api/ha/{pair,join,sync,failover,failback,unpair,notify}`; `ha.read`/`ha.write`, fresh re-authentication, cluster id on failover and unpair, 409 while disabled; the events list is process-local |

**Replication boundary.** Configuration still travels as a whole snapshot, once
immediately after pairing and every 30 s after that (P3-04's debounce replaces the
cadence): it changes rarely and a snapshot is easier to verify. A downloaded snapshot
older than the stream this node has already applied is discarded rather than restored.
The streamed class (sessions, trusted
devices, password resets, bans, gate sessions and failures, audit, alerts) is captured
row by row. Every capture happens in the transaction that made the change, so a write
cannot be acknowledged without its outbox row. The standby pulls one page a second,
applies it in order and acknowledges the highest contiguous sequence; the active prunes
at or below that sequence. A page that does not start where the reader left off, or a
stream over 100 MiB, falls back to a sealed snapshot and resets the watermark. A restore
clears every table before inserting any, because deleting `users` cascades into
`sessions`. A standby writes no audit rows of its own, so the chain it receives from the
active still verifies after promotion.

The 30-second snapshot check is gated by a configuration digest: the standby asks
`/ha/config` for the active's canonical hash of the replicated tables and restores a
snapshot only when it differs, so an idle pair does not rewrite every table twice a
minute. A gap, an overflow or an apply error still forces a restore.

**Not covered yet.** Only the active captures, so a returning old active still needs a
snapshot (P5-05/P5-06 land the sequence, not the lab run). Applied rows are not forwarded
to a third node. The P4 gate was exercised with two stores and the real pinned TLS
listener on loopback, not on two VMs with a VIP: 10,000 logins with a `kill -9` failover,
the 200 ms ban-before-crash check and the `fill-disk` overflow fixture remain lab work for
P5/P8. The P5 gate itself — ten planned and ten unplanned moves across two VMs, WebSocket
close codes, RTO and `tcpdump vrrp` — has not been run; there is no VIP, keepalived or
root nftables in the build environment.

Gaps inside the landed slice: the role gate wraps the loops started in `run()`, but the
backup and auto-update managers start inside `internal/api` and still run on a standby until
P1 hands them the gate; `ha status` reports the role file rather than a live machine, so it
is accurate but not yet a subscription; `/api/ha/diagnostics` reports the outbox, but the
HA settings toggle and the console page are P7, so nothing in the UI can enable or show HA.

**How to use it.** Each task is one branch and normally one pull request. Tasks are ordered:
the serial path is P0 → P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8, with P7 able to start once P5
merges and P8 overlapping the last two weeks of P6 and P7. A task's **Done** line is the
check the reviewer runs, not a description of intent. If a gate fails, revert the phase, not
the plan.

## 1. Rules every task follows

- **Dark by default.** `WAFPROXY_HA_ENABLE` is `0` unless the lab sets it. A merged task must
  leave a single-node binary behaving exactly as 1.55.2.
- **One concern per PR.** A migration PR contains the migration and its test, no feature code
  that depends on it. A console PR contains the page and its test, no API changes.
- **No new dependency.** Standard library plus what `go.mod` already has. The metrics
  endpoint stays the hand-rolled collector in `internal/api/handlers.go`.
- **Every task lands with a test.** A seam gets a unit test; a write path gets a test that
  fails without the change; a console rule gets a vitest.
- **Forward-only migrations.** Three this build: schema `23` sealed certificate keys, `24`
  hashed gate tokens, `25` outbox and peer ack (1.57.0 already carries `22`). `schemaVersion`
  in `internal/store/store.go` goes up once per migration, never per phase.
- **Evidence per phase.** `deploy/ha-lab/logs/<phase>/` holds the client CSV, both nodes'
  `ha status --json`, the transition rows and the journal excerpt. That directory is the
  attachment on the phase PR.

Gate commands, used in the tasks below:

| Command | Proves |
|---|---|
| `go build ./...` | everything compiles with HA off and on |
| `go test ./internal/... ./cmd/...` | unit and handler tests, no lab needed |
| `make vet` | static checks |
| `make test` | full suite plus `docs-check` (OpenAPI drift) |
| `cd web && npm test` | vitest for the console |
| `cd web && npm run build` | TypeScript check and production bundle |
| `make perf-gate` | the request path did not regress |
| `deploy/ha-lab/ha-lab.sh <verb>` | the failure under test is reproducible |

Branch naming: `ha/p0-01-role-file`, `ha/p3-03-transactional-apply`. One task, one branch,
one merge commit series that can be reverted with `git revert`.

## 2. Order, effort and tracks

| Phase | Tasks | Ideal days | Track | Can start when |
|---|---|---|---|---|
| Lab (`P0-00`) | 1 | 5 | infra | now |
| P0 Seams | 10 | 15–17 | data plane | lab is up |
| P1 Role machine | 6 | 10 | control plane | P0 merged |
| P2 Pairing and trust | 5 | 10 | trust | P1 merged |
| P3 Configuration replication | 7 | 15 | data plane | P2 merged |
| P4 Sessions, bans, audit | 8 | 15 | data plane | P3 merged |
| P5 Manual failover | 6 | 15 | both | P4 merged |
| P6 Automatic failover | 7 | 15 | both | P5 merged |
| P7 API, settings, console | 7 | 10 | console | P5 merged |
| P8 Chaos, soak, release | 6 | 10 | both | P6 and P7 merged |

Solo this is 20–24 weeks; two engineers run P0/P3/P4 (data) in parallel with P1/P2/P7
(control and console) after the lab, and join for P5, P6 and P8. The per-task days are ideal
engineering days and do not include review or CI waits.

## 3. Before P0: the two-node lab (P0-00)

**P0-00 The lab** — L, 5 days.

- Files: `deploy/ha-lab/{docker-compose.yml,ha.env,ha-lab.sh,client.sh,README.md}`,
  `Makefile` targets `ha-lab-up`, `ha-lab-test`, `.gitignore` entry for `logs/`.
- Change: two nodes from the working tree on fixed `ha`/`wan` addresses, a witness running
  `wafproxy ha witness --listen :9444`, a client loop at 10 ms writing status/latency CSV, and
  the verbs in HA.md 13.2 (`up`, `down`, `reset`, `break-link`, `heal-link`, `kill-active`,
  `pause-active`, `slow-peer`, `fill-disk`, `corrupt-snapshot`, `skew-clock`, `freeze-witness`).
  Document in the README that VIP mode needs two VMs or macvlan, not plain compose.
- Verify: `make ha-lab-up` gives two healthy nodes and a non-empty client CSV; `break-link`
  makes the peer unreachable and `heal-link` restores it; `reset` wipes the volumes.
- Done: a reviewer can break and heal the pair with two commands, and the CSV is the RTO
  measurement for every later phase.

## 4. P0: seams and prerequisites (3 weeks)

**Goal.** The process can change role at runtime, stop and rebind its listeners, and no longer
broadcasts plaintext secrets. No HA behaviour ships.

**Entry:** lab merged. **Exit:** the gate at the end of this section.

### P0-01 Role file and node identity — M, 3 days

- Files: `internal/ha/role.go`, `internal/ha/role_test.go`, `cmd/wafproxy/main.go` (create or
  read at boot).
- Change: `data/ha/node.json` with `{node_id, role, epoch, peer, updated_at}`, written `0600`
  via temp file + `fsync` + `rename` + directory `fsync`. Read at boot; missing, unreadable or
  unparsable means `standby`, never `active`. No role is stored in SQLite.
- Verify: `go test ./internal/ha -run Role`.
- Done: truncated JSON, wrong mode, symlink and empty file all resolve to `standby`, and a
  valid file round-trips byte-identically apart from `updated_at`.

### P0-02 Listener lifecycle — M, 3 days

- Files: `internal/proxy/server.go` (`Run` at line 417, `RunHTTP`), `internal/proxy/run_test.go`.
- Change: extract `Listen(ctx) (*Listeners, error)`, `(*Listeners) Drain(ctx)` and
  `(*Listeners) Close()`. `Run` and `RunHTTP` stay as wrappers, so no caller changes. Closing
  and rebinding the same address must work, because failback does exactly that.
- Verify: `go test ./internal/proxy -run Listen -race`.
- Done: bind, serve, drain with a request in flight, close, rebind the same address, one
  hundred cycles, file-descriptor count flat.

### P0-03 Background loop gate — M, 4 days

- Files: `cmd/wafproxy/main.go` (`run()`), `internal/ha/gate.go`, `internal/siteres/siteres.go`
  (`Start` 184, `RenewLoop` 221).
- Change: one gate answering `Active()` from the role file, wrapping every goroutine started in
  `run()`: retention (decide explicitly whether the prune half still runs), GeoIP update,
  certificate watch, feeds, bundles, bans, CrowdSec, gate, bots, uptime, backups, auto-update,
  agent links, the MCP gateway, and `siteres.Set.Start`, which is what starts the per-site ACME
  `RenewLoop`.
- Verify: `go test ./cmd/wafproxy -run LoopGate` with a table of `{role, loop, wantStarted}`.
- Done: a new loop that forgets the gate fails the table, and a standby runs no ACME order,
  no feed refresh and no backup schedule.

### P0-04 `IP_FREEBIND` — S, 1 day

- Files: `internal/netbind/freebind_linux.go`, `freebind_other.go`, tests.
- Change: `SetsockoptInt(fd, SOL_IP, IP_FREEBIND, 1)` before `bind`, `ErrUnsupported` on
  non-Linux. Applied to the WAN and HTTP-01 listeners only, and only in VIP mode.
- Verify: bind an address that is not on the interface; succeeds with the option, fails with
  `EADDRNOTAVAIL` without it.
- Done: the test runs in the lab (privileged) and is skipped where the option is unavailable.

### P0-05 Management listener — S, 1 day

- Files: `cmd/wafproxy/main.go`, `internal/config/config.go` (address resolution).
- Change: `WAFPROXY_HA_MGMT_LISTEN` is required in HA mode; no silent fallback to loopback or
  to `0.0.0.0` (correction 4). The console keeps working on the node's own address while the
  WAN listener is not bound.
- Verify: start with HA on and the variable unset; the process refuses with a clear error
  naming the variable.
- Done: the lab's standby is reachable on its management address while nothing listens on 443.

### P0-06 `ReloadAll` — M, 2 days

- Files: `internal/api/server.go` beside `reloadEngines` (line 515), `internal/api/reload_test.go`.
- Change: ordered reload — certificates → per-site resources (`siteres.Set.Each` and `Reload`)
  → bundles → feeds → policies → `proxy.Reload` → streaming `ApplyAll` (role-gated) →
  notifications. Returns one error per subsystem, never aborts the rest, names the failing
  subsystem in the log.
- Verify: `go test ./internal/api -run ReloadAll`.
- Done: one subsystem returning an error leaves the others applied and the error identifies it.

### P0-07 Seal certificate private keys — M, 2 days (migration 23)

- Files: `internal/store/proxies.go` (`SaveCert` 453 and the read path), `internal/store/store.go`
  (`schemaVersion`, `migrateAddColumns`), tests.
- Change: seal `key_pem` with `crypto.Box` under the master key, mark the row so the loader
     knows the format, dual-read during the rollover, re-seal in one pass. `schemaVersion` to `23`.
- Verify: migrate a fixture database, then `sqlite3` shows no plaintext key; every certificate
  still loads in the proxy test suite.
- Done: a fresh install and a migrated install both serve the same certificates, and the
  column contains no `BEGIN PRIVATE KEY`.

### P0-08 Hash gate session tokens — M, 2 days (migration 24)

- Files: `internal/gate/gate.go` (176), `internal/store/policies.go` (589), tests.
- Change: store `HMAC-SHA256(master key, "wafproxy-gate\x00" + token)` as `gate_sessions.id`,
  mirroring `store.sessionID` with its own separator. `schemaVersion` to `24`. The migration
  invalidates existing visitor sessions once; that is a release note.
- Verify: `go test ./internal/gate ./internal/store -run Gate`.
- Done: no raw gate token appears in the database, the login flow still round-trips, and an
  old cookie is rejected exactly once.

### P0-09 Table classification — S, 1 day

- Files: `internal/ha/classes.go`, `internal/store/classify_test.go`.
- Change: `replicated`, `streamed`, `local` sets and a test that walks `sqlite_master` and
  fails on any unclassified table. The P3 encoder imports the same sets.
- Verify: add a dummy table in the test fixture and watch it fail.
- Done: the test fails on an unknown table with the table name in the message.

### P0-10 `recover --rotate-master-key` — M, 2 days

- Files: `cmd/wafproxy/main.go` (`recoverCLI` 287), tests.
- Change: unwrap with the old password, re-seal every sealed secret, re-key the session HMAC
  (all admin sessions die), print a fresh recovery code.
- Verify: end-to-end test with a fixture database.
- Done: old cookies are rejected, sealed certificate keys still load, gate sessions are
  invalid, and the new recovery code authenticates.

**P0 gate.** `make test`, `make vet`, `cd web && npm test`, `make perf-gate`, and the lab in
both modes: one node with HA off behaves identically to one node with `WAFPROXY_HA_ENABLE=1`
and role `active`; 100 listener cycles; a migrated `sqlite3` dump has no plaintext gate token
and no plaintext `key_pem`. **Rollback:** revert the phase branch; migrations 22 and 23 have
already shipped separately and are not reverted with it.

## 5. P1: role machine and control plane (2 weeks)

**Goal.** A node can say what it is, the unsafe answer is never the default, and a standby is
provably read-only.

**Entry:** P0 merged. **Exit:** P1 gate.

### P1-01 State machine — M, 2 days

- Files: `internal/ha/state.go`, `internal/ha/state_test.go`.
- Change: `State` (`standalone`, `active`, `standby`, `ready-standby`, `draining`, `promoting`,
  `demoting`, `fenced`, `split-brain-risk`), `Event`, pure `Next(state, event) (State, []Action)`.
- Verify: table test over the full matrix.
- Done: illegal transitions (`active` + `promote`) return an error and no action, and every
  legal transition has one row.

### P1-02 Control socket — M, 2 days

- Files: `internal/ha/control.go`, tests.
- Change: Unix socket at `WAFPROXY_HA_CONTROL_SOCKET`, `SO_PEERCRED` check (uid 0 or the
  `wafproxy` gid), `0600` token file in the same directory, one-line request/response JSON, 2 s
  deadline.
- Verify: `go test ./internal/ha -run Control` plus a call as the wrong uid.
- Done: wrong uid, wrong token, oversized line and slow client are each refused and counted.

### P1-03 CLI status and notify — M, 1 day

- Files: `cmd/wafproxy/ha.go`, `cmd/wafproxy/main.go` (dispatch before `run()`).
- Change: `status`, `status --watch`, `status --json`, `notify master|backup|fault`. Unknown
  subcommand prints usage and exits 2.
- Verify: `go test ./cmd/wafproxy -run HACLI`.
- Done: `ha status --json` parses as one JSON object on stdout with logs on stderr only.

### P1-04 Readiness and health — S, 1 day

- Files: `internal/api/server.go` (`health` 619, `routes` 194).
- Change: `ready = proxy.Ready() && role.Serving()`; the body gains `ha.enabled/role/state/
  peer/epoch/config_version/lag_s/last_sync/vip/last_error`; `last_sync` older than
  `2 × failover_after_s` is unready; plain `/api/health` stays 200.
- Verify: handler test for each state.
- Done: `?ready=1` returns 503 for `draining`, `standby`, `syncing` and `split-brain-risk`, and
  200 with a current `last_sync` when active.

### P1-05 Read-only standby and `ha` permissions — M, 2 days

- Files: `internal/api/server.go` (`authed` 539), `internal/api/rbac.go`, `internal/rbac/rbac.go`,
  tests.
- Change: after session lookup, reject every non-GET with `409 standby`, except `/api/ha/*`,
  `/api/login`, `/api/logout`, `/api/me`, `/api/account/*`. Add the `ha` area to `Areas` and the
  `permissionFor` switch (`ha.read` for GET, `ha.write` otherwise).
- Verify: `go test ./internal/api -run Standby`.
- Done: every mutating route in `routes()` is covered by a table test, so a new route is 409 on
  a standby unless it is explicitly allowlisted.

### P1-06 Console banner and readiness row — S, 1 day

- Files: `web/src/App.tsx`, `web/src/pages/Readiness.tsx`, tests.
- Change: poll `/api/ha` once a minute; render `STANDBY — READ ONLY` above `.content` on every
  page; add one Readiness row that links to the HA page built in P7. No HA page in this phase.
- Verify: `cd web && npm test`.
- Done: with a standby response the banner appears on Dashboard and Settings, and it disappears
  when the role becomes active.

**P1 gate.** Lab node B in standby: nothing bound on 443, nothing bound to the VIP, console
reachable on its management address, every write `409 standby`, `?ready=1` 503, and
`ha status --json` stable for an hour with RSS and thread count flat. **Rollback:** revert P1;
the role file and gated loops from P0 remain inert with HA off.

## 6. P2: pairing and trust (2 weeks)

**Goal.** Two nodes share a trust root and a master key, and pairing is the only way to get
either. Everything later assumes an authenticated peer.

**Entry:** P1 merged. **Exit:** P2 gate.

### P2-01 Cluster PKI — M, 3 days

- Files: `internal/ha/pki.go`, tests.
- Change: cluster CA (ECDSA P-256, 10 years) and node certificates (1 year, SANs = node id plus
  both addresses) on `crypto/x509`. Node keys at `data/ha/node.key`, `0600`, deliberately not
  sealed: they are needed before the master key exists.
- Verify: CA and leaf round-trip, expiry boundaries, SAN checks.
- Done: a certificate from another CA fails verification with a distinguishable error.

### P2-02 Pairing code store — M, 2 days

- Files: `internal/store/ha_pairing.go`, migration step in the same schema version as P0's
  `ha` tables (no separate bump), tests.
- Change: 26 base32 characters (128 bits) grouped as `WAF-XXXX-…`, stored only as
  `HMAC-SHA256(code)`, with `expires_at` and `used_at`, constant-time compare, 5 attempts per
  10 minutes per source.
- Verify: wrong, expired, reused and sixth attempt.
- Done: the plaintext code is never written to disk, logs or the audit row.

### P2-03 Join handshake — L, 3 days

- Files: `internal/ha/join.go`, `internal/ha/join_test.go`.
- Change: TLS 1.3 with SPKI pinning against the fingerprint in the code; transcript hash;
  master key wrapped in AES-256-GCM under `HKDF(pairing secret, transcript)`; node certificate
  issued. Pairing establishes trust only — P3 moves data.
- Verify: table test for wrong code, wrong pin, foreign cluster certificate, replayed join,
  plaintext client rejected.
- Done: a recorder wrapping the transport finds no master-key bytes in either direction on a
  failed join, and node B keeps an empty data directory.

### P2-04 Unpair and rekey — S, 1 day

- Files: `internal/ha/join.go`, `cmd/wafproxy/ha.go`.
- Change: `ha unpair [--force]`, `ha rekey --node <id>`; unpair stops replication, rotates the
  cluster secret and leaves the local copy intact but unpaired.
- Verify: pair, unpair, pair again; rekey invalidates the old peer certificate.
- Done: peer certificates from before a rekey are refused with `401 unknown node`.

### P2-05 Pairing audit and CLI — S, 1 day

- Files: `internal/ha/join.go`, `internal/api/ha.go` (stub routes), `cmd/wafproxy/ha.go`.
- Change: audit every attempt on both sides with outcome and source address, failures included;
  CLI `ha init` and `ha join` print the code, the expiry and the peer fingerprint once.
- Verify: an audit row for each attempt row in the table test.
- Done: a failed join leaves a row on both nodes, and the code is absent from it.

**P2 gate.** Pair and unpair 20 times with no manual file copying; a failed join leaves node B
empty and `standby`; the sixth attempt in 10 minutes is refused. **Rollback:** revert P2; the
P1 role file and control socket stay usable for manual moves.

## 7. P3: configuration replication (3 weeks)

**Goal.** A change on the active reaches the standby within a second and every engine on the
standby is rebuilt from it.

**Entry:** P2 merged. **Exit:** P3 gate.

### P3-01 Canonical encoder and header — L, 3 days

- Files: `internal/ha/snapshot.go`, `internal/ha/snapshot_test.go`, golden fixture.
- Change: fixed structures or sorted keys, never a raw map dump; header
  `{cluster_id, epoch, version, schema_version, hash}` with SHA-256 over the uncompressed
  canonical bytes; encode only the `replicated` set from P0-09.
- Verify: encode the same fixture twice and compare bytes; encode on two databases with the
  same logical content and compare hashes.
- Done: two encodes of one database are byte-identical, and adding a map iteration order
  permutation cannot change the hash (property test).

### P3-02 Sealed snapshot envelope and limits — M, 2 days

- Files: `internal/ha/snapshot.go`, tests.
- Change: gzip then AES-256-GCM under `HKDF(master key, "snapshot" || epoch)`; reject unknown
  tables and columns, cap decompressed size at 64 MiB and rows per table; corrupt ciphertext
  fails closed.
- Verify: unknown table, unknown column, oversize, truncated and bit-flipped inputs.
- Done: every rejected document leaves the live database byte-identical.

### P3-03 Transactional apply — L, 3 days

- Files: `internal/ha/apply.go`, tests.
- Change: one transaction with `PRAGMA foreign_keys=OFF` scoped to it, delete then insert per
  table in dependency order, reset `sqlite_sequence` to `MAX(id)` (hygiene, correction 1),
  write local `config_version`, commit, then `ReloadAll`. Nothing touches live tables outside
  the transaction.
- Verify: `kill -9` mid-apply, restart, previous state intact; re-apply is idempotent.
- Done: a crash at any statement leaves either the old version or the new one, never a mix, and
  `sqlite_sequence` equals `MAX(id)` afterwards.

### P3-04 Config version, debounce and acknowledgement — M, 2 days

- Files: `internal/store` (touch hook), `internal/api/server.go` (`reloadEngines`), `internal/ha/sync.go`.
- Change: `store.TouchConfig()` on the write paths that already reload, plus `PRAGMA
  data_version` polling on the second connection; 500 ms debounce; send and wait for the
  standby to acknowledge the exact `(epoch, version, hash)`.
- Verify: one write per configuration class arrives inside the debounce.
- Done: p95 under one second on the lab, and an unacknowledged version is retried rather than
  assumed delivered.

### P3-05 Reconcile and per-table diff — M, 2 days

- Files: `internal/ha/sync.go`, tests.
- Change: five-minute hash comparison; on mismatch send a full snapshot and log row count plus
  hash per table.
- Verify: mutate one row out of band on the standby and watch reconcile repair it.
- Done: the log names the differing table on the first mismatch, before the snapshot is applied.

### P3-06 Version and epoch floor — S, 1 day

- Files: `internal/ha/apply.go`.
- Change: refuse a snapshot below the applied version or below the local epoch.
- Verify: replay an older snapshot after a newer one.
- Done: a rolled-back node cannot resurrect an old admin or lift a ban; the error names both
  versions.

### P3-07 Sync CLI and diagnostics — S, 1 day

- Files: `cmd/wafproxy/ha.go`, `internal/api/ha.go`.
- Change: `ha sync`, `ha sync --dump <file>`, `ha status --json` gains `config_version`,
  `config_hash`, `last_sync`, `last_error`.
- Verify: dump a snapshot, decode it with the test helper, compare the hash.
- Done: the dump is the only way to inspect a snapshot outside the lab without sending it.

**P3 gate.** One thousand changes across every configuration class: p95 under one second, no
reload error in 24 hours, schema mismatch refuses to sync and names the table and column,
`break-link` and `slow-peer` both recover without a restart. **Rollback:** revert P3; the
standby returns to a read-only copy of its own database.

## 8. P4: sessions, bans and audit (3 weeks)

**Goal.** People stay signed in and bans stay enforced across a move. This is the phase that
touches existing write paths, and it is the most expensive one.

**Entry:** P3 merged. **Exit:** P4 gate.

### P4-01 Outbox schema — S, 1 day (migration 25)

- Files: `internal/store/store.go` (migration step), `internal/store/ha_outbox.go`, tests.
- Change: `ha_outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT, kind TEXT, op TEXT,
  row_id TEXT, payload BLOB, created_at TEXT)` and `ha_peer_ack(peer TEXT PRIMARY KEY,
  acked_seq INTEGER, updated_at TEXT)`; `schemaVersion` to `25`. Both tables are `local` in
  P0-09's classification, or explicitly excluded from the snapshot.
- Verify: fresh and migrated databases have both tables and the same index names.
- Done: the classification test still passes with the new tables.

### P4-02 Transaction-scoped enqueue API — M, 2 days

- Files: `internal/store` transaction helper, tests.
- Change: `Enqueue(tx, kind, op, rowID, payload)` and a variant of each affected write that
  accepts an existing transaction, so the state change and its outbox row commit together.
- Verify: a rolled-back transaction leaves no outbox row; a committed one leaves exactly one.
- Done: no write path can enqueue outside the transaction that made the change.

### P4-03 Session write paths — M, 3 days

- Files: `internal/store/sessions.go`, `internal/api` login/logout paths, tests.
- Change: enqueue in the same transaction for `CreateSession`, `DeleteSession`, trusted devices,
  password resets and `ClaimTOTPStep`. Expiry touches stay asynchronous (they only refresh when
  less than half the idle window remains).
- Verify: ten thousand logins/logouts with a failover in the middle; every cookie minted before
  the move resolves after it.
- Done: no acknowledged session write is missing on the new active while the peer was healthy.

### P4-04 Bans, gate sessions and lockouts — M, 2 days

- Files: `internal/store/policies.go`, `internal/gate/gate.go`, tests.
- Change: enqueue bans, username bans, gate session create/delete and gate failures, each in
  its transaction. Kernel reconcile stays a promotion step (P5).
- Verify: a ban issued 200 ms before `kill -9` is enforced on the new active, userspace and
  `nft list set inet wafproxy block4`.
- Done: the userspace and kernel views agree within one second of the new active serving.

### P4-05 Audit and pending alerts — M, 2 days

- Files: `internal/store/audit.go`, notifications delivery path, tests.
- Change: enqueue audit rows with their head, and pending alert deliveries; dedupe on
  `(origin, seq)` so a replay cannot double-send.
- Verify: audit head consistent after a failover; a replayed alert batch sends once.
- Done: `GET /api/audit/verify` passes on the new active.

### P4-06 Pull protocol, gaps and watermark — L, 3 days

- Files: `internal/ha/outbox.go`, tests.
- Change: standby asks for `seq > acked_seq`, applies in order, dedupes on `(origin, seq)`,
  returns the highest contiguous sequence; both sides prune below the watermark.
- Verify: out-of-order delivery, duplicate delivery, a gap at sequence 5 (nothing past it
  applies), crash between two applies.
- Done: a gap stalls rather than skips, and the ack never advances past a missing sequence.

### P4-07 Overflow and pruning — M, 1 day

- Files: `internal/ha/outbox.go`, tests.
- Change: outbox above 100 MiB stops streaming, raises `outbox_overflow`, sends a full snapshot
  and resets the outbox at the watermark; log and alert.
- Verify: an overflow fixture in the test, plus `fill-disk` in the lab.
- Done: a session created during an overflow still authenticates after the snapshot.

### P4-08 Per-kind diagnostics — S, 1 day

- Files: `internal/api/ha.go`, `internal/metrics` collector.
- Change: `outbox_depth`, `acked_seq`, `lag_s` and per-kind pending counters in
  `ha status --json` and `/api/ha/diagnostics`; add `wafproxy_ha_outbox_depth`.
- Verify: handler test and one scrape.
- Done: a single kind with growing depth is visible without opening SQLite, which is how the
  debugging playbook identifies a transaction bug in one write path.

**P4 gate.** Ten thousand logins/logouts with a failover in the middle, every pre-move cookie
still valid; a ban 200 ms before `kill -9` enforced on the new active; audit head consistent;
overflow path exercised. **Rollback:** revert P4; schema 24 stays, empty and inert.

## 9. P5: manual failover and failback (3 weeks)

**Goal.** An operator can move traffic deliberately, and the move is measured rather than
hoped for.

**Build note (dark, on `ha/full-build`).** The sequence, the preflight, the control
socket and the keepalived hook are built and unit-tested with injected hooks. A standby
now pre-binds the service address with `IP_FREEBIND`, serves nothing, follows the stream
until a move, and on demotion drains its listeners and forwarders while the process stays
up. Promotion stops the follower, quiesces and drains the peer, re-runs preflight at the
head of the stream, persists the next epoch with `fsync`, reloads every site's policy,
reconciles bans into the kernel, serves, and only then writes the active role. Every step
before `serve` rolls back to standby; an abort after `serve` is refused with the reason.
The pieces that need two VMs are not verified here: the VIP actually moving, keepalived's
notify exit codes, WebSocket/SSE close codes, and the RTO measurements.

**Entry:** P4 merged. **Exit:** P5 gate on two VMs.

### P5-01 Preflight as data — M, 3 days

- Files: `internal/ha/preflight.go`, tests.
- Change: `[]Check{name, ok, detail}`, returned by `ha failover --dry-run --json` and gating the
  real run. Checks: peer reachable; same cluster, schema and protocol; no higher epoch; hash
  matches; lag under 5 s; certificates loaded for every enabled hostname; database writable and
  `PRAGMA quick_check` clean; disk above 5%; skew under 5 s; no configuration write in flight.
- Verify: one test that fails each check in turn.
- Done: `--dry-run` changes nothing and names the first failing check and its fix.

### P5-02 Quiesce, drain and epoch persist — L, 3 days

- Files: `internal/ha/failover.go`, `internal/ha/role.go`.
- Change: quiesce writes → drain the outbox → snapshot and acknowledge `(epoch, version,
  hash)` → persist `epoch + 1` with `fsync` before any listener accepts.
- Verify: crash between persist and serve; restart comes back as `promoting`, never `active`
  with the old epoch.
- Done: no listener accepts on the new epoch until it is on disk.

### P5-03 Promotion sequence — L, 3 days

- Files: `internal/ha/failover.go`, `internal/api/server.go` (`ReloadAll`), `internal/ban`.
- Change: pre-bind on the standby with `IP_FREEBIND` → `ReloadAll` → reconcile bans into
  nftables → serve. One function per step, each with its own verification.
- Verify: lab `kill-active`, then four user-visible checks from HA.md 8.3.
- Done: the new active serves 443 with the current configuration and kernel bans without a
  restart.

### P5-04 VIP move and keepalived exit codes — M, 2 days

- Files: `deploy/ha/keepalived.conf`, `deploy/ha/notify.sh`, `cmd/wafproxy/ha.go`.
- Change: the notify script calls the control socket; a refused transition exits non-zero so
  `notify_fault` is visible. Config and script are as in HA.md section 6.
- Verify: two VMs, `tcpdump -ni eth1 vrrp` and `ip -4 addr show eth1`.
- Done: a deliberate refusal shows as `FAULT` in keepalived and the VIP does not move.

### P5-05 Old active drain and rejoin — M, 2 days

- Files: `internal/ha/failover.go`, `internal/proxy/server.go`.
- Change: `http.Server.Shutdown`, streaming stop, WebSocket/SSE close with 1001, role becomes
  `standby`, then replay the outbox from the new active.
- Verify: an open WebSocket during the move closes with 1001 and reconnects.
- Done: no `EADDRINUSE` on failback, and the old active has the new epoch within one heartbeat.

### P5-06 Failback — M, 2 days

- Files: `internal/ha/failover.go`, `cmd/wafproxy/ha.go`.
- Change: the P5-02/P5-03 sequence in reverse, plus `ha.healthy_for_s` and a full resync; a
  repaired node never trusts its own database.
- Verify: change configuration on B while A is repaired, then fail back; the change survives.
- Done: no re-login, no manual repair, and `--abort` is refused after the move with the reason.

**P5 gate.** Ten planned and ten unplanned failovers, alternating, on two VMs: zero 5xx on a
planned move, RTO p99 under one second planned and under five seconds unplanned, no
acknowledged session lost, no manual repair, no re-login. **Rollback:** revert P5; P4
replication stays, the operator returns to manual stop/start.

## 10. P6: automatic failover, witness and fencing (3 weeks)

**Goal.** Unattended failover, with a hard guarantee that it cannot produce two active writers.

**Entry:** P5 merged. **Exit:** P6 gate.

**Build note (started, dark).** P6-01 to P6-04 are built. `/ha/ping` feeds a monitor
where the third lost beat is the decision; the witness grants one 10 s lease, renewed
every 3 s, and an active that cannot renew demotes itself after the TTL. Fencing runs the
operator's command with the peer quoted and kills its process group on timeout. The
automatic gate needs the peer down, a live baseline heartbeat, this node's lease for the
next epoch, a successful fence, matching last-known schema and protocol, and the local
database, disk, certificate and in-flight-write checks; the move then skips quiesce and
drain and renews the lease once more before Serve. It is enabled only by
`WAFPROXY_HA_AUTO_FAILOVER`, which refuses to load without both the witness and the fence
command. P6-05 and P6-06 are built too: the watcher runs on both roles, an active that
hears a higher epoch stands down into `split-brain-risk` and reconciles only when the
peer answers again, and more than three automatic moves in an hour parks the pair with
the reason in `ha status`. P6-07 is built: `internal/ha/sim_test.go` runs the link,
process, witness, fence, disk and skew failures through the real state machine, heartbeat,
witness and flap guard on a fake clock, including a 200-partition random run, and asserts
that no tick leaves two live actives and no promotion runs on an expired or foreign lease.
The two-VM partition and fencing run is still the gate.

### P6-01 Heartbeat — M, 2 days

- Files: `internal/ha/heartbeat.go`, tests.
- Change: `/ha/ping` on the existing mTLS channel, 1 s period, three consecutive failures to
  act. VRRP decides the VIP; the application decides the role, deliberately from a different
  signal.
- Verify: fake clock, loss of 2 and 3 beats.
- Done: two lost beats change nothing; the third starts the gate, and recovery resets the count.

### P6-02 Witness — L, 3 days

- Files: `internal/ha/witness.go`, `cmd/wafproxy/ha.go` (`witness` subcommand), tests.
- Change: `POST /ha/lease {cluster_id, epoch, holder}` → `{granted, expires_at}`, 10 s TTL,
  renew at 3 s, monotonic epoch, witness stores only that tuple and refuses a lower epoch.
  The active self-demotes when it cannot renew.
- Verify: two actives claiming the same epoch, renew after freeze, lower epoch refused.
- Done: `wafproxy ha witness --listen :9444` from the same binary, and the lab's witness is a
  second implementation of the client.

### P6-03 Fencing hook — S, 1 day

- Files: `internal/ha/fence.go`, `deploy/ha/fence-ipmi.sh`, tests.
- Change: `ha.fence_command` with `{peer}` substituted and a 30 s timeout; exit 0 means the
  peer is down, anything else means do not promote.
- Verify: command exits 0, 1 and times out.
- Done: a non-zero fence blocks promotion with the exit status in the transition reason.

### P6-04 Automatic promotion gate — M, 2 days

- Files: `internal/ha/preflight.go`, `internal/ha/failover.go`.
- Change: P5 preflight minus operator-only checks, plus lease and fence. `--force` is the only
  way past a failure and prints what is at risk first.
- Verify: each blocked check in the simulator.
- Done: automatic promotion never runs with an expired lease or a failed fence.

### P6-05 Self-demotion on a higher epoch — M, 2 days

- Files: `internal/ha/role.go`, `internal/ha/failover.go`.
- Change: observing a higher epoch closes listeners, refuses writes and stays `split-brain-risk`
  until the peer is reachable and epochs reconcile.
- Verify: two-node lab with `break-link`, then heal.
- Done: an operator-visible state, not a silent retry loop.

### P6-06 Guards and flap control — S, 2 days

- Files: `internal/ha/failover.go`.
- Change: `max_failovers_per_hour`, `failback_after`, flap counter that parks the pair in a
  state requiring an operator.
- Verify: simulator with a flapping peer.
- Done: the fourth failover in an hour parks rather than promotes, and the status says why.

### P6-07 Partition simulator — M, 3 days

- Files: `internal/ha/sim_test.go`.
- Change: drive `Next()` and the gate through the partition matrix on a fake clock — link down
  with both healthy, active dead, standby dead, both dead, witness down, witness split, skew
  ±30 s, disk full, active killed mid-failover.
- Verify: `go test ./internal/ha -run Sim -count=200`.
- Done: every scenario asserts at most one active node, and 200 randomized partitions never
  violate it.

**P6 gate.** Two hundred randomized partitions in the simulator: never two actives, never a
promotion with an expired lease, never a promotion past a failed fence; two real-time
end-to-end cases on the VMs. **Rollback:** revert P6; P5 manual failover remains.

## 11. P7: API, settings, console, docs (2 weeks)

**Goal.** Operable by someone who did not build it, invisible to everyone who has not enabled it.

**Entry:** P5 merged. **Exit:** P7 gate.

### P7-01 HA API — M, 3 days — built

- Built: `internal/api/ha.go`, `cmd/wafproxy/ha_control.go`. The console uses the same move
  manager, role files and join functions as the CLI. `ha.read` reads, `ha.write` mutates; every
  mutation re-checks the signed-in user's password and, when enrolled, a live authenticator
  code; failover and unpair require the cluster id; a disabled host answers 409 on mutations
  and still answers `GET /api/ha` so the page can explain itself. `GET /api/ha/events` is the
  last 20 console actions in this process, not a durable transitions table.

- Files: `internal/api/ha.go`, `internal/api/server.go` (`routes` 194), `internal/api/rbac.go`.
- Change: `GET /api/ha`, `GET /api/ha/events`, `GET /api/ha/diagnostics`, `PUT /api/ha/config`,
  `POST /api/ha/{pair,join,sync,failover,failback,unpair,notify}`; CSRF, admin allowlist and
  fresh re-authentication on mutations; failover and unpair require the cluster id.
- Verify: handler tests per route and per role.
- Done: a `viewer` gets 403 on every route, `ha.read` can read and cannot post, and HA disabled
  returns 409 with the reason.

### P7-02 Settings key and enablement backend — S, 1 day — built

- Built: missing `ha_enabled` means off; `0`/`1` only; host-wide for tenants and audited
  separately. `Enabled` is the boot master switch AND the stored setting, computed from the
  live setting on every `/api/me`, `/api/ha` and health call, so the console flips without a
  restart. The runtime itself boots only when both are on, because the HA listener, replay and
  watcher are started in `run()`; starting them from `reloadEngines` is not wired yet, so an
  operator who turns HA on starts it with the next restart, as Appendix B.3 describes.
- Not built: the Settings switch (P7-03) and the nav rule (P7-04).

- Files: `internal/api/server.go` (`publicSettingKeys`, `putSettings`, `/api/me`),
  `internal/store/sites.go` (`hostSettingKeys`), `internal/ha/manager.go`.
- Change: `ha_enabled` host-wide, `0`/`1` validation, effective value in `/api/me.ha_enabled`
  and `/api/ha.enabled`, manager starts/stops loops from `reloadEngines`. `WAFPROXY_HA_ENABLE=0`
  keeps routes and loops absent and reports why.
- Verify: save as default site, save as tenant (403), `/api/me` before and after.
- Done: toggling changes the effective value without a restart, and a tenant cannot set it.

### P7-03 Settings toggle UI — S, 1 day

- Files: `web/src/pages/Settings.tsx`, `web/src/pages/Settings.test.tsx`.
- Change: section `ha` between `retention` and `backup`, one `Switch` bound to
  `s.ha_enabled`, existing `SaveBar` as the save button, state-dependent help text, link to
  `#/ha`, disabled for tenant and `host_admin`.
- Verify: `cd web && npm test`.
- Done: the switch appears directly above Backup, saves with the page, and its help text
  reflects paired/unpaired/env-locked.

### P7-04 Nav rule, fallback card and banner wiring — S, 1 day

- Files: `web/src/nav.ts`, `web/src/App.tsx`, `web/src/nav.test.tsx`, `web/src/types.ts`.
- Change: `requires?: "ha_enabled"` on `NavItem`, `allowed()` check, System item, reason-aware
  fallback card for `#/ha`, `onMeChanged` refetch from Settings, keep the standby banner.
- Verify: `npm test`.
- Done: the item is absent while disabled, appears after enabling without a reload, and a deep
  link explains why it is unavailable.

### P7-05 The HA page — L, 3 days

- Files: `web/src/pages/HA.tsx`.
- Change: the cards and four states in HA.md Appendix B.4 — role/state, peer, VIP/network,
  replication, sessions, bans, witness, transitions, diagnostics, maintenance.
- Verify: `npm run build` and manual review against the four states.
- Done: every card renders from `/api/ha*` alone, and no action is offered that the role or
  state cannot perform.

### P7-06 Page tests — M, 2 days

- Files: `web/src/pages/HA.test.tsx`, `web/src/pages/Settings.test.tsx`, `web/src/nav.test.tsx`.
- Change: four page states, toggle PUT, nav visibility, disabled-action reasons.
- Verify: `npm test`.
- Done: removing the `requires` check or the disable rule makes a test fail.

### P7-07 OpenAPI, docs and upgrade path — S, 1 day

- Files: `docs/openapi.yaml` (generated), `docs/OPERATIONS.md`, `CHANGELOG.md`, `README.md`,
  `docs/HA.md` status block.
- Change: `go generate ./internal/api`; `ha upgrade --check`; standby-first upgrade documented;
  status block flipped only when P8 passes.
- Verify: `make docs-check`.
- Done: `make test` is green with the regenerated spec, and no doc claims HA ships before P8.

**P7 gate.** `make test`, `make vet`, `cd web && npm test`, `cd web && npm run build`. RBAC:
`viewer` sees nothing, `ha.read` reads and cannot post. Disabled: no nav entry, `#/ha` explains
it, `POST /api/ha/pair` 409. Enabled and unpaired: setup card and `ha status` = `unpaired`.
**Rollback:** revert P7; the API and page disappear, the P6 machine keeps working from the CLI.

## 12. P8: chaos, soak and release (2 weeks)

**Goal.** Proof under the failures that actually happen, then stop changing it.

**Entry:** P6 and P7 merged. **Exit:** P8 gate and the release checklist.

### P8-01 Chaos harness — M, 3 days

- Files: `internal/ha/lab_test.go` (`//go:build ha_lab`), `deploy/ha-lab/scenarios/`.
- Change: Go tests driven by `ha-lab.sh` verbs, behind a build tag so `go test ./...` never
  needs privileged networking.
- Verify: `go test -tags ha_lab ./internal/ha -run Lab`.
- Done: each scenario has a name, a timeout and a machine-readable verdict.

### P8-02 Scenario suite — L, 3 days

- Files: same as P8-01.
- Change: one scenario per row of the debugging playbook: standby restart mid-snapshot, active
  restart mid-outbox, overflow, corrupted snapshot, schema mismatch, wrong/expired/reused code,
  foreign certificate, replayed sequence, clock skew, disk full, master key mismatch, VIP move
  with an open WebSocket, failover during ACME, failover during backup, standby upgrade while
  the active writes.
- Verify: `make ha-lab-test`.
- Done: every row of HA.md 13.12 has a reproducing scenario, and each fails when its protection
  is removed.

### P8-03 Soak — M, 2 days plus 72 hours unattended

- Files: `deploy/ha-lab/soak.sh`, results in `logs/soak/`.
- Change: production request rate for 72 hours with one planned failover per day; watch RSS,
  file descriptors, goroutines, table growth and outbox depth.
- Verify: the soak log and a flat RSS/FD/goroutine graph.
- Done: no growth beyond the recorded baseline and no unrepaired transition.

### P8-04 Performance gate — M, 2 days

- Files: `Makefile`, `docs/PERFORMANCE.md` if the project keeps records there.
- Change: `WAFPROXY_HA_ENABLE=1, role: active`, ban and session paths, record before and after.
- Verify: `make perf-gate`.
- Done: the delta is in the PR and accepted explicitly; `make perf-record` only after that.

### P8-05 Security review tests — M, 2 days

- Files: `internal/ha/security_test.go`.
- Change: the two tests from HA.md 12.7 — snapshot scan for secret fixtures, and the schema
  classification test — plus break-each-property checks for pinning, replay, rate limit and
  epoch monotonicity.
- Verify: deliberately break each property and watch the test fail.
- Done: no test in this file has never failed.

### P8-06 Release checklist — S, 1 day

- Files: `docs/HA.md` status block, `docs/OPERATIONS.md`, `CHANGELOG.md`, `README.md`,
  `docs/HA-BUILD.md` (this file, marked built).
- Change: the definition of done in HA.md 13.14, three migrations named, one-time gate re-login
  called out, `ha_enabled` absent on fresh installs, no new module in `go.mod`, upgrade
  exercised both directions on real hosts.
- Verify: a fresh install, an upgrade from 1.55.2, and a downgrade to HA off.
- Done: the checklist is signed off in the PR, and the release notes name the three migrations.

**P8 gate.** Everything in HA.md 13.13 green on the lab and on two real hosts with the release
binary, HA off by default, every HA table empty until pairing. **Rollback:** the release can be
reverted to a build with `WAFPROXY_HA_ENABLE=0`; migrations stay, which is why they shipped
separately.

## 13. What blocks what

These are HA.md section 14's open decisions. Each one blocks the task named, not the whole
build, so settle it before that task starts:

| Decision | Blocks | Default if nobody decides |
|---|---|---|
| Networking: VIP first, LB and DNS-DR documented later | P5-04, P6-01 | VIP + keepalived |
| Automatic failover off unless a witness or fence exists | P6-04 | Refuse automatic promotion without one |
| Is a third witness host acceptable | P6-02 | Ship the witness, document the requirement |
| Event history replication | P3-01 | Async on, explicit gap report when off |
| Approve the two P0 migrations | P0-07, P0-08 | Ship both, separately |
| Master key transfer in-band during pairing | P2-03 | In-band, out-of-band option documented |
| Pairing code length | P2-02 | 128-bit, 26 base32 characters, 10 minutes |
| Standby-first upgrade | P7-07 | Required, refuse automatic failover on mismatch |
| `ha.write` default holder | P7-01 | Administrator only |
| Tenant visibility | P7-04 | Default console only |

## 14. The first five pull requests

If the plan is approved, this is the order work starts in, and each one is reviewable on its own:

1. **P0-00** lab, compose file and `ha-lab.sh` skeleton with `up`, `down`, `reset`,
   `kill-active`, `break-link`, `heal-link`. This is first because every later review uses it.
2. **P0-01** role file, with the fail-safe tests.
3. **P0-02** listener lifecycle, with the 100-cycle rebind test.
4. **P0-03** loop gate and the `{role, loop, wantStarted}` table.
5. **P0-04** and **P0-05** together: `IP_FREEBIND` and the required management listener.

After those, P0-06 `ReloadAll`, then the two migrations, which are the first changes that touch
stored data and therefore get their own release notes.
