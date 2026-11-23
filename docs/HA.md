# High availability: an active/standby pair

> **Status: partly implemented on `ha/full-build`, dark by default.** P0-P5 of
> `docs/HA-BUILD.md` are built: role file, pairing and join with a pinned
> certificate, sealed master-key transfer, whole-database snapshot replication
> gated by a configuration digest, a row-level outbox for sessions, trusted
> devices, password resets, bans, gate sessions and failures, audit and alerts, and
> manual failover and failback through a local control socket with a keepalived
> notify hook. P6-01 to P6-04 are built: `/ha/ping` with a three-beat heartbeat
> monitor, a witness that grants one 10 s lease (the active renews and demotes
> itself when it cannot), a fence hook, and an automatic promotion gate that needs
> all three plus the local preflight. An active that hears a higher epoch stands
> down into `split-brain-risk`, and more than three automatic moves in an hour
> parks the pair until an operator moves by hand. Automatic failover is opt-in
> through `WAFPROXY_HA_AUTO_FAILOVER`, which refuses to start without a witness
> and a fence command. Everything is gated by `WAFPROXY_HA_ENABLE` (off by
> default), so a single-node install behaves as it did before. The partition
> simulator (P6-07) and the guarded HA API (P7-01, including `GET /api/ha`) are
> built; the console page and its Settings toggle (P7-02 to P7-06) and the two-VM
> lab gates are not, so sections that describe them state the intended end state.
> `docs/HA-BUILD.md`
> carries the per-task status and the known gaps.
>
> The document is written so an operator can read the runbooks as the intended
> end state and an implementer can build against them. Each section that asserts
> something about today's code names the file and function it was checked
> against.

**Scope:** two nodes, one active and one warm standby, one floating service VIP.

**Non-goals:** active/active, horizontal scale, a shared response cache, a
per-tenant VIP, cross-site automatic failover.

---

## Contents

- [1. What the pair gives you](#1-what-the-pair-gives-you)
- [2. Blockers verified against 1.55.2](#2-blockers-verified-against-1552)
- [3. Topology and the two supported network modes](#3-topology-and-the-two-supported-network-modes)
- [4. Prerequisites](#4-prerequisites)
- [5. Pairing runbook](#5-pairing-runbook)
- [6. keepalived and the VIP](#6-keepalived-and-the-vip)
- [7. Configuration and session sync](#7-configuration-and-session-sync)
- [8. Failover procedure](#8-failover-procedure)
- [9. Failback procedure](#9-failback-procedure)
- [10. What should and should not trigger a failover](#10-what-should-and-should-not-trigger-a-failover)
- [11. Split-brain, witness and fencing](#11-split-brain-witness-and-fencing)
- [12. Security prerequisites](#12-security-prerequisites)
- [13. Build plan: phases, gates and debugging](#13-build-plan-phases-gates-and-debugging)
  - [13.1 Sequencing and the rules every phase follows](#131-sequencing-and-the-rules-every-phase-follows)
  - [13.2 The two-node lab (build this first)](#132-the-two-node-lab-build-this-first)
  - [13.3 P0: Seams and prerequisites](#133-p0-seams-and-prerequisites)
  - [13.4 P1: Role machine and control plane](#134-p1-role-machine-and-control-plane)
  - [13.5 P2: Pairing and trust](#135-p2-pairing-and-trust)
  - [13.6 P3: Configuration replication](#136-p3-configuration-replication)
  - [13.7 P4: Session, ban and audit replication](#137-p4-session-ban-and-audit-replication)
  - [13.8 P5: Manual failover and failback](#138-p5-manual-failover-and-failback)
  - [13.9 P6: Automatic failover, witness and fencing](#139-p6-automatic-failover-witness-and-fencing)
  - [13.10 P7: API, console, docs and upgrades](#1310-p7-api-console-docs-and-upgrades)
  - [13.11 P8: Chaos, soak and release gate](#1311-p8-chaos-soak-and-release-gate)
  - [13.12 Debugging playbook](#1312-debugging-playbook)
  - [13.13 Acceptance criteria](#1313-acceptance-criteria)
  - [13.14 Definition of done](#1314-definition-of-done)
- [14. Decisions to settle before coding](#14-decisions-to-settle-before-coding)
- [Appendix A: proposed configuration surface](#appendix-a-proposed-configuration-surface)
- [Appendix B: health, metrics and console](#appendix-b-health-metrics-and-console)
  - [B.1 Health](#b1-health)
  - [B.2 Metrics](#b2-metrics)
  - [B.3 The Settings toggle](#b3-the-settings-toggle)
  - [B.4 The High availability page](#b4-the-high-availability-page)
- [Appendix C: data classes](#appendix-c-data-classes)

---

## 1. What the pair gives you

A second node holds a continuously updated copy of the configuration, certificates,
bans and sessions. When the first node stops, the second one takes the service VIP
and serves the same hostnames with the same certificates, and nobody signs in again.

| Target | Value | What dominates it |
|---|---|---|
| RTO, planned move | under 1 s | 30 s drain for existing connections, new traffic moves immediately |
| RTO, unplanned loss | 2–5 s | VRRP advert timeout plus the promotion gate |
| RPO, acknowledged session writes | 0 while the peer is healthy | peer acknowledgement before the HTTP response; the degraded case is in 13.7 |
| RPO, configuration | up to the 500 ms snapshot debounce | coalesced full snapshots |
| RPO, bans | under 1 s | outbox stream |
| RPO, event history | the configured lag, or an accepted gap | optional async batch |

Beyond failure cover, the pair is what makes maintenance cheap: upgrade the
standby, fail over, upgrade the old active. Same for a kernel update, a host
migration or a certificate experiment. That is usually worth more day to day than
the failover itself.

The design is a deliberate deviation from the HA sketch in `docs/ROADMAP.md`,
which targets PostgreSQL plus Redis and N stateless edge nodes. That is the right
answer for horizontal scale. It is also a rewrite of the storage layer. A
two-node pair can be built on the SQLite database that already holds everything,
with logical replication on top, and that is what this plan does.

---

## 2. Blockers verified against 1.55.2

These are the conditions that decide whether HA is a feature or a rewrite. Each
was checked in the current tree rather than assumed.

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| B1 | Data-plane listeners bind once and never rebind | **Confirmed** | `internal/proxy/server.go` `Run` (line 417) binds every address, then blocks on `Serve` until the context is cancelled. `RunHTTP` calls `ListenAndServe` directly. The GUI listeners in `cmd/wafproxy/main.go` are `net.Listen` + `Serve` goroutines. There is no handle to stop or start them independently. |
| B2 | A standby would bind `:8443` on every interface | **Confirmed** | `cmd/wafproxy/main.go:435`: when `config.IsLocalAddress(cfg.ListenWAN)` is false, the stored address is replaced by the first-boot fallback, whose default is `:8443` (`internal/config/config.go:75`, wildcard bind). A standby that does not own the VIP therefore opens the proxy on all interfaces instead of not at all. |
| B3 | Background loops run unconditionally | **Confirmed** | `cmd/wafproxy/main.go` starts retention, GeoIP, cert watch, feeds, bundles, bans, CrowdSec, gate, bots, uptime, backups, auto-update, agent links, the MCP gateway and `siteres.Set.Start`. The last one starts a per-site ACME `RenewLoop` (`internal/siteres/siteres.go:184`, renew at line 221). Two live nodes would place duplicate ACME orders, send duplicate alerts and write duplicate backups. |
| B4 | There is no full reload path | **Confirmed** | `internal/api/server.go:515` `reloadEngines` calls only `reloadPolicies()` and `proxy.Reload()`. A replicated snapshot would leave certificates, feeds, bundles, notification channels, streaming config and per-site resources serving stale state until restart. |
| B5 | Certificate keys and gate tokens are plaintext at rest | **Confirmed** | `internal/store/proxies.go:453` `SaveCert` writes `cert_pem` and `key_pem` as raw BLOBs. `internal/gate/gate.go:176` mints a random token and stores it as the cookie value itself; `internal/store/policies.go:589` `CreateGateSession` inserts that raw token as `gate_sessions.id`. Admin sessions are already hashed (`store.sessionID`, HMAC-SHA256 with the master key), so this is an inconsistency, not a design decision. |
| B6 | Applying a snapshot must reset `sqlite_sequence` or inserts collide | **Partly wrong — corrected below** | The tables are `AUTOINCREMENT` (about 25 of them in `internal/store/store.go`), but a collision is not what happens. |

### Correction 1: the `sqlite_sequence` argument

The plan said that without a reset, the first post-promotion insert "can collide
with an ID from the snapshot". That is not how SQLite behaves. It was checked
directly:

```
sqlite> INSERT INTO t(v) VALUES('a');      -- id 1
sqlite> DELETE FROM t;
sqlite> INSERT INTO t(id,v) VALUES(1,'x');
seq after explicit lower id: 1
sqlite> INSERT INTO t(v) VALUES('b');      -- id 2, no collision
sqlite> DELETE FROM t;
sqlite> INSERT INTO t(id,v) VALUES(50,'x');
seq after explicit higher id: 50
sqlite> INSERT INTO t(v) VALUES('c');      -- id 51
```

`sqlite_sequence` only ever moves forward: an explicit id above the current value
raises it, an explicit id below it leaves it alone. After a delete-and-insert of a
snapshot, the sequence is therefore at or above `MAX(id)` either way, and the next
automatic id cannot collide with a replicated row.

The reset is still worth doing, for a different reason: **rollback**. The standby
keeps the previous snapshot for one generation, and IDs in that older snapshot can
be lower than the ones just written. Restoring it leaves `sqlite_sequence` ahead of
the data, which is harmless for uniqueness but produces unexplained id gaps that
look like data loss during an incident. Reset to `MAX(id)` after every apply so the
tables read consistently, and treat it as hygiene, not as the fix for a uniqueness
bug. Do not write a test that asserts a collision without the reset; it will pass
for the wrong reason.

### Correction 2: `ReloadAll` is orchestration, not new machinery

The primitives mostly exist: `acme.Manager.Load`, `bundle.Manager.Load`,
`siteres.Set.Reload(siteID)` and `siteres.Set.Each`, plus `proxy.Reload`,
`policy.Reload` and `streaming.Manager.ApplyAll`. What is missing is one entry
point that calls them in a defined order and reports which subsystem failed. Build
`ReloadAll(ctx)` as a thin, idempotent function with a per-subsystem error list —
not as a second reload mechanism.

### Correction 3: "listeners bind once" is true for the data plane, not for streaming

`streaming.Manager.Apply` (`internal/streaming/streaming.go:540`) stops and rebinds
a forwarder listener on demand, and `ApplyAll` walks the whole catalog. A standby
must therefore be prevented from applying enabled streaming configs, rather than
being unable to. Put the role in that call site explicitly; do not rely on the
listener abstraction.

### Correction 4: the console fallback is worse than the WAN fallback

For the console, `cmd/wafproxy/main.go:440` falls back to `WAFPROXY_LISTEN_GUI`,
whose default is `127.0.0.1:8080`. A standby whose stored `lan_ip` is stale does not
merely bind too widely: it loses its management console entirely, because loopback
is not reachable from the operator's workstation. HA mode needs an explicit
management address (`WAFPROXY_HA_MGMT_LISTEN`), and it must never fall back to
loopback silently.

### Correction 5: `/api/health?ready=1` already exists

`internal/api/server.go:619` already returns `503` with `ready: false` when
`proxy.Ready()` is false, and `?ready=1` is the documented readiness probe. HA does
not add that mechanism; it widens the predicate so `standby`, `syncing`,
`split-brain-risk` and a stale configuration also count as not ready, and adds the
`ha` block to the body. Keep the plain `GET /api/health` at 200 so the management
console can still render the state.

### Correction 6: `recover --rotate-master-key` does not exist yet

Revoking a compromised standby (section 12) depends on rotating the master key.
`cmd/wafproxy/main.go` implements `unban`, `setup`, `recover`, `backup` and `sites`;
`recover` accepts `--password` and `--reset-totp` only. `docs/ROADMAP.md` lists
`recover --rotate-master-key` as a Phase 5 item that was not delivered. Either build
it as part of this plan's P0 (13.3), or state plainly that a compromised standby means rebuilding
both nodes. Do not document a command that does not exist.

---

## 3. Topology and the two supported network modes

```
                    DNS: *.example.com -> 203.0.113.10
                                  |
                         [ service VIP ]
                          203.0.113.10
                        /               \
             +------------------+   +------------------+
             | Node A (active)  |   | Node B (standby) |
             | WAN  443, 80     |   | mgmt console only|
             | console on LAN   |   | HA link :9443    |
             | nftables bans    |   | bans warm (user) |
             +---------+--------+   +---------+--------+
                       |   HA link: mTLS only      |
                       +---------------------------+
                       |                           |
                 keepalived VRRP             keepalived VRRP
                 priority 150                priority 100, nopreempt
```

**VIP mode (recommended, same L2 segment).** keepalived moves the address; WAF-Proxy
follows through a local control socket. The HA link is a dedicated VLAN, a direct
cable, WireGuard or Tailscale, and is never reachable from the WAN.

**External L4 load balancer.** Use the same role machine and skip VRRP. The load
balancer must health-check the **public WAN listener over TCP**, because
`/api/health` is mounted on the GUI listener (`cmd/wafproxy/main.go` mounts
`apiServer.Handler()` on the GUI mux), not on the proxy listener, and the console is
private by design. A standby keeps the WAN port unbound, so the check fails and the
balancer sends traffic to the active; after promotion the port is bound and the check
passes. TLS terminates on WAF-Proxy, so the balancer must be TCP passthrough, and
`WAFPROXY_TRUSTED_PROXIES` should list the balancer CIDRs if it forwards client
addresses.

**DNS failover** is a DR mode, not a primary one: resolver caching and TTLs make the
outage minutes long. It reuses replication with manual promotion.

| Plane | Active | Standby |
|---|---|---|
| WAN TLS listener | bound | not bound |
| HTTP-01 listener | bound | not bound |
| Streaming forwarders | bound | not applied (role-checked in `ApplyAll`) |
| Console | on the node's management address | same, read-only |
| HA listener `:9443` | bound to the HA interface | bound |
| Configuration writes | allowed | `409 standby` |
| ACME, backups, notifications, canary, uptime, anomaly | running | stopped |
| Ban enforcement | kernel + userspace | userspace only; kernel set rebuilt on promotion |
| Response cache, rate-limit buckets, in-flight counters | warm | cold |

Why not active/active: the rate-limit buckets, gate lockout ladder, response cache
and in-flight budget are per-process. Two active nodes would double an attacker's
allowance, halve the cache hit rate and still need a shared store on the hot path.

---

## 4. Prerequisites

Before touching either node:

- Two hosts, each sized to carry **the whole** load alone. A half-size standby is a
  liability at the moment it is needed. The WAF is the expensive stage, so measure at
  production request rate rather than trusting a small synthetic test.
- The same WAF-Proxy version on both nodes, and NTP with skew under 5 s.
- A private HA link, `9443/tcp` between the two nodes only (plus the witness, if
  used). Never expose it to the WAN.
- A service VIP that is **not** also the node's primary address, and a router/DNS
  change pointing hostnames at the VIP.
- keepalived on both hosts if using VIP mode. In Docker, keepalived runs on the
  **host**, not in the container: the container has `NET_ADMIN` and host networking,
  but VIP ownership and VRRP belong to the host network namespace.
- The systemd unit needs a writable runtime directory for the control socket.
  `deploy/wafproxy.service` sets `ProtectSystem=strict` and only allows writes under
  the data directory and `/run/wafproxy-updates`. Add:

  ```ini
  RuntimeDirectory=wafproxy-ha
  RuntimeDirectoryMode=0750
  ```

  and put the socket at `/run/wafproxy-ha/ha.sock`, so the directory name and the
  socket path agree. (The plan previously paired `RuntimeDirectory=wafproxy-ha` with
  `/run/wafproxy/ha.sock`; with `ProtectSystem=strict` the socket could not be
  created.)

- Node B starts with an **empty data directory**. Joining must refuse a directory
  that already holds a different `master.key` unless the operator explicitly resets
  it.
- Certificates, and therefore the master key, must already be in place on node A.

---

## 5. Pairing runbook

Pairing establishes three things once: who the peer is, a shared trust root for the
replication channel, and the same master key so both nodes decrypt the same secrets
and accept the same session cookies.

> The pairing code is 26 base32 characters: 128 bits, single use, valid for ten
> minutes. Only its SHA-256 hash is stored on disk.

### 5.1 On node A (the active)

Both nodes need `WAFPROXY_HA_ENABLE=1` and `WAFPROXY_HA_MGMT_LISTEN`. Pairing also
needs `WAFPROXY_HA_LINK_LISTEN` (for example `10.0.0.10:9443`), which must be
reachable only on the private network between the two nodes.

```bash
sudo systemctl restart wafproxy   # after setting the variables
sudo wafproxy ha pair
```

Expected output:

```
fingerprint: 3f9c...c21a
code:        WAF-7K3M-9Q2X-4B8N-6T1R-A1B2-C3D4
On the other node run:
  wafproxy ha join --active 10.0.0.10:9443 --fingerprint 3f9c...c21a --code WAF-...
```

`ha pair` creates `data/ha/node.json` (standby on first use) and a self-signed
`data/ha/tls.{crt,key}`, prints the public-key fingerprint an operator compares out
of band, writes only the hash of the code to `data/ha/pairing.json` (mode `0600`,
ten minutes, single use), and prints the exact join command. The daemon must be
running for the join to succeed.

Implemented scope: the pair shares a 256-bit cluster secret and each side pins the
other's public key. The master key is **not** transferred in-band yet, so a standby
that has to decrypt replicated secrets needs it provisioned out of band (P2-03 gap).

### 5.2 On node B (the standby)

```bash
sudo wafproxy ha join \
  --active 10.0.0.10:9443 \
  --fingerprint 3f9c...c21a \
  --code WAF-7K3M-9Q2X-4B8N-6T1R-A1B2-C3D4
sudo systemctl restart wafproxy
sudo wafproxy ha status --watch
```

The join verifies the pinned fingerprint before it sends anything; a wrong pin,
a wrong or expired code, or a missing link listener exits non-zero and leaves no
pair record. On success both nodes store `data/ha/pair.json` (mode `0600`) with the
same cluster id and secret. Restart the service so it reads the new pair.

### 5.3 Verify the pair

```bash
# On either node: role, peer, epoch, versions, lag.
sudo wafproxy ha status

# The HA API route and console page are not implemented yet (P7); use
# `wafproxy ha status --json` on the node itself.

# Readiness must say standby, not ready to serve traffic.
curl -s -o /dev/null -w '%{http_code}\n' 'http://10.0.0.11:8080/api/health?ready=1'   # 503
```

Checks that must all be true before going further:

1. Both nodes report the same `cluster_id`, and node B reports `epoch` equal to node
   A's with `config_version` and `config_hash` matching.
2. Node B has **no** listener on 443 and nothing bound to the VIP.
3. Node B's console shows the `STANDBY — READ ONLY` banner, and a mutating request
   returns `409 standby`.
4. A configuration change on A (rename a proxy, toggle a setting) appears on B within
   one second, and the proxy on B rebuilds its routes.
5. Issue a test ban on A; it is present in B's ban list without a restart.

If any check fails, stop here. `ha unpair --force` on both nodes returns them to
standalone; node A keeps serving, node B keeps a copy of the last state it applied.

---

## 6. keepalived and the VIP

keepalived owns the address; WAF-Proxy owns the application role. They meet at the
local Unix socket `/run/wafproxy-ha/ha.sock`, reachable only by root or the
`wafproxy` group, with a `0600` token file in the same directory. The socket is never
exposed over the network.

### 6.1 Notify script

`/usr/local/bin/wafproxy-ha-notify`:

```sh
#!/bin/sh
# keepalived -> WAF-Proxy role notification. Runs as root, drops to wafproxy.
set -eu
case "${1:-}" in
  MASTER|BACKUP|FAULT) ;;
  *) echo "usage: $0 MASTER|BACKUP|FAULT" >&2; exit 2 ;;
esac
exec sudo -u wafproxy /usr/local/bin/wafproxy ha notify "$1"
```

Make it executable and readable only by root and the service group:
`chown root:wafproxy`, `chmod 0750`. Both files ship in `deploy/ha/`; they talk to
`/run/wafproxy-ha/ha.sock` by default (override with
`WAFPROXY_HA_CONTROL_SOCKET`).

### 6.2 Minimal unicast VRRP instance

`/etc/keepalived/keepalived.conf` on node A. On node B, change `priority` to 100 and
`unicast_src_ip` to `10.0.0.11`; the peer lists swap.

```conf
global_defs {
  router_id wafproxy-a
  enable_script_security
  script_user root
}

vrrp_instance wafproxy {
  state BACKUP                 # both nodes start as BACKUP; priority decides
  interface eth1               # the HA link, not the WAN interface
  virtual_router_id 51
  priority 150                 # 150 on A, 100 on B
  advert_int 1
  nopreempt                    # a returning node must not take the VIP back
  unicast_src_ip 10.0.0.10
  unicast_peer {
    10.0.0.11
  }
  virtual_ipaddress {
    203.0.113.10/24 dev eth1
  }
  notify_master "/usr/local/bin/wafproxy-ha-notify MASTER"
  notify_backup "/usr/local/bin/wafproxy-ha-notify BACKUP"
  notify_fault  "/usr/local/bin/wafproxy-ha-notify FAULT"
}
```

Notes that matter in practice:

- `nopreempt` only takes effect with `state BACKUP`, which is why both nodes start
  as BACKUP. This is the setting that stops a rebooted former active from stealing
  the VIP back in the middle of a maintenance window.
- keepalived appends its own arguments when it expands a notify string, which is why
  the script reads `$1` as the literal action the config passed. Keep the literal in
  the config and keep the `case` check in the script.
- VRRP authentication is weak. Use unicast peers on a trusted segment, and prefer
  WireGuard or a dedicated VLAN between sites. Do not rely on VRRP auth as a security
  control.
- Add `arp_ignore=1`, `arp_announce=2` and `arp_filter=1` on the VIP interface so a
  node does not answer for the address while it does not own it.
- If the WAN interface is also the HA interface, a link failure takes both away at
  once. Prefer a separate link, or accept that a cable cut is a site outage.

### 6.3 The boot rule

A standby must never follow the stored `wan_ip`. In HA mode, before any listener is
bound:

```
if node.role == standby:
    do not bind WAN, HTTP or streaming
    do not use the wildcard WAN fallback (:8443)
    bind only: HA listener + management console (WAFPROXY_HA_MGMT_LISTEN)
```

This is a small change in `cmd/wafproxy/main.go` around the existing
`config.IsLocalAddress` fallbacks, and it is the difference between a dormant standby
and a second proxy quietly answering on every interface.

---

## 7. Configuration and session sync

The active is the **only** configuration writer. The standby accepts reads on its
management console and rejects every mutation with `409 standby`, except the HA
control routes and the console's own login/logout/account paths, which keep the
read-only console usable. The guard belongs next to the existing mutating-request
check in `internal/api/server.go` `authed`, where the CSRF test already runs.

Two channels:

1. **Configuration snapshot** — full, canonical, versioned, debounced 500 ms, plus a
   5-minute reconciliation. Carries sites, settings, users, profiles, proxies,
   certificates and keys, gate accounts, feeds and bundles metadata, audit rows and
   head. Excludes `events`, `flows`, rollups, GeoIP files, access logs and
   `data/ha/`.
2. **Ordered outbox** — `(seq, kind, op, row_id, payload, created_at)` for admin
   sessions, trusted devices, password resets, gate sessions, username bans, bans,
   TOTP step claims, audit and pending alerts. Applied in order, acknowledged by the
   highest contiguous sequence, pruned when acknowledged.

Every state carries `(cluster_id, epoch, version, schema_version, content_hash)`.
`epoch` increments on promotion; `version` increments on every configuration write;
a standby refuses a snapshot older than what it already applied. That is what stops a
rolled-back node or a mirror from resurrecting an old admin or a lifted ban.

Session continuity is the visible benefit:

| Session | Storage today | Move rule |
|---|---|---|
| Admin cookie `__wfp_sid` | `sessions.id` = HMAC(master key, token) | create/delete strict-acked before the HTTP response |
| CSRF token | `sessions.csrf` | with the row |
| Trusted device, password reset | `trusted_devices`, `password_resets` (hashed) | streamed |
| TOTP replay guard | `users.totp_last_step` | strict, before acknowledging the login |
| Gate cookie `__wfp_gate` | `gate_sessions.id` (raw token today) | strict create/delete; hashing is a prerequisite |
| Username ban, gate lockout rows | `username_bans`, `gate_failures` | streamed |

Expiry touches are asynchronous: `authed` only refreshes a session when less than
half of the 12-hour idle window remains, so at most one write every six hours. Losing
a touch shortens an idle lifetime; it does not sign anyone out mid-request.

> Implemented today: a standby pulls the active's whole replicated and streamed
> state every 30 seconds and restores it in one transaction (`wafproxy ha sync`
> performs one pull by hand). Admin and gate session rows therefore move, but a
> failover can still lose the writes made since the last pull. The per-write
> outbox in P4 is what narrows that to the acknowledgement contract above.

What cannot move: established TCP/TLS sockets, WebSocket and SSE streams, streaming
forwarder connections, in-flight requests, the response cache, and the in-memory
rate-limit and lockout windows. Planned failover drains the first group; the rest
reconnect or start cold. Document the in-flight POST risk rather than pretending a
VIP move is transparent to a non-idempotent request.

---

## 8. Failover procedure

### 8.1 Planned failover (the one to rehearse)

Triggered from the console, `wafproxy ha failover`, or a maintenance window. Every
step is reversible until the VIP moves.

```bash
# 1. Preflight only: no traffic moves.
sudo wafproxy ha failover --to b --dry-run
```

The preflight checks: both nodes healthy; standby in sync with the same schema and
protocol; peer reachable; no higher epoch observed; applied snapshot hash verified;
session/ban lag under 5 s; certificates loaded for every enabled hostname; database
writable and `PRAGMA quick_check` clean; disk free above 5%; clock skew under 5 s.

```bash
# 2. Real move, with a 30 s drain for existing connections.
sudo wafproxy ha failover --to b --drain 30s
```

Sequence, and what to watch:

1. Configuration writes are quiesced; in-flight writes finish.
2. The outbox drains and a fresh snapshot is sent. The standby must acknowledge the
   exact `(epoch, version, hash)` before anything moves.
3. Node B opens its listeners on the VIP with `IP_FREEBIND`, so the sockets exist
   before the address arrives. This is the step that gets the move under a second;
   without it there is a bind race after the address appears.
4. keepalived releases the VIP on A and B claims it.
5. B increments the epoch, starts accepting, reconciles bans into nftables, reloads
   certificates and runs `ReloadAll`.
6. A drains: `http.Server.Shutdown` with the drain deadline, keep-alives close,
   streaming forwarders stop, WebSocket/SSE get a close frame where possible.
7. A writes `role: standby` and returns to `ready-standby` after replaying anything
   written during the handover.

Success looks like: `ha status` on both nodes agrees on epoch; the VIP is on B;
`/api/health?ready=1` returns 200 on B and 503 on A; no 5xx attributable to the move;
admin and gate sessions still work.

**Abort**: before step 4, `Ctrl-C` or `ha failover --abort` returns A to active with
no traffic impact. After the VIP moves, the only safe "abort" is to let the failover
finish and then run a failback.

### 8.2 Unplanned failover

1. Node A loses power, panics, is OOM-killed, or its process dies.
2. keepalived misses adverts; B becomes MASTER after about 3 s and the VIP moves.
3. B was `ready-standby`, sees the peer gone, passes the promotion gate, bumps the
   epoch, activates pre-bound sockets.
4. Clients reconnect. Admin and gate cookies are still valid. Certificates and bans
   are already warm. The cache is cold.
5. In-flight requests are lost; a POST may already have reached the upstream.

If automatic failover is off (the default without a witness), the on-call operator
runs:

```bash
sudo wafproxy ha status                 # confirm peer unreachable, lag acceptable
sudo wafproxy ha failover --to b --force   # explicit data-loss acknowledgement
```

`--force` is required when the lag exceeds the gate, and it prints what is at risk
before it proceeds. Automatic failover is deliberately opt-in (section 11).

### 8.3 After either failover

```bash
curl -fsS http://10.0.0.11:8080/api/ha
sudo wafproxy ha status --watch
# Bans present in the kernel, not just the table:
sudo nft list set inet wafproxy block4
sudo nft list set inet wafproxy block6
```

Then confirm the four things that actually matter to users: a hostname answers over
TLS with the expected certificate, an admin session opened before the move still
works, a gate visitor is not asked to sign in again, and a ban issued before the move
still blocks.

---

## 9. Failback procedure

Failback is manual by default. Automatic failback flaps, duplicates notifications
and ACME work, and causes a second outage for no user benefit.

1. **Repair the old node.** Bring it up as a standby. It may be hours behind, so it
   applies a full snapshot rather than trusting its local database.
2. **Replay everything.** Sessions, gate sessions, bans, certificates and
   configuration written while the peer was active must arrive before failback is
   offered. This is what stops a failback from signing people out — the earlier draft
   left this implicit and it is the single most likely user-visible regression.
3. **Hold the health window.** The node must stay healthy and in sync for
   `ha.healthy_for_s` (default 600 s) before the console enables **Fail back**.
4. **Run the same planned sequence in reverse**, with the same preflight and drain.

```bash
sudo wafproxy ha status                      # peer healthy, in sync, epoch equal
sudo wafproxy ha failback --to a --dry-run
sudo wafproxy ha failback --to a --drain 30s
```

`nopreempt` means a rebooted node never takes the VIP back on its own; the operator
or a scheduled window does. Optional modes: `manual` (default), `scheduled` (for
example 03:00 in a maintenance window), `auto` (only with a witness and only after
the health window). A `max_failovers_per_hour` guard and a `failback_after` delay
stop oscillation.

Verification after failback is the same four checks as after failover, in reverse.

---

## 10. What should and should not trigger a failover

| Cause | Default action | Why |
|---|---|---|
| Active host down, panic, power loss | automatic (if enabled) | the only real node failure |
| Active process crash loop, listener dead | automatic after `failover_after` | health and listener checks fail |
| Database I/O error, WAL corruption, read-only filesystem | automatic after `quick_check` fails | cannot persist bans, sessions, audit |
| Disk below 1% | automatic | cannot write logs, events, sessions |
| WAN link down while the peer is healthy | automatic | no path to clients |
| Operator command or maintenance window | planned | deliberate handover |
| HA link partition with both nodes healthy | **no**, unless a witness grants the lease | split-brain case |
| Upstream 5xx, one backend down | no | failover cannot fix a broken backend; alert instead |
| Canary failing for N cycles | no by default | DNS or upstream trouble is not a node failure |
| Certificate renewal failure | no | the standby holds the same certificate; alert before expiry |
| High CPU, memory pressure, attack traffic | no | failover doubles the problem |
| Single missed heartbeat | no | hysteresis prevents flapping |
| Admin logout, configuration error | no | not availability events |

---

## 11. Split-brain, witness and fencing

Two nodes cannot form a quorum by themselves. If the HA link partitions while both
can still reach the LAN, both may believe they should be master, and the VIP alone
does not settle it because VRRP adverts travel over the same broken link.

Layered defence, cheapest first:

1. **VIP ownership** with `nopreempt`, `arp_ignore` and unicast peers. Stops the
   common duplicate-ARP race, not a determined partition.
2. **Epoch check.** A node that sees a higher epoch than its own demotes immediately,
   closes its listeners and refuses writes, even if it still holds the VIP briefly.
3. **Standby write refusal.** Even a mistaken promotion cannot corrupt configuration:
   the damage is duplicate traffic and duplicate notifications, not divergent state.
4. **Witness lease.** A tiny `wafproxy witness` on a third host (router, Raspberry Pi,
   small VM) grants one ten-second lease at a time and stores only
   `{cluster_id, epoch, holder, expires_at}` over the same mTLS identity. If the
   active cannot renew, it self-demotes. This is the recommended production setup.
5. **STONITH.** Power off the peer through IPMI, a PDU or a cloud API before claiming
   the VIP. If fencing fails, do not promote.
6. **Manual mode.** For a home lab without a witness, leave automatic failover off.
   A short manual outage is better than two active writers.

On heal, the lower-epoch node demotes, drains and resyncs; there is no merge.

---

## 12. Security prerequisites

These are not optional polish. Each one is a precondition for shipping HA, because
replication turns "a database file on one host" into "two hosts and a network stream
carrying the whole security state".

### 12.1 Encrypt certificate private keys at rest

Today `SaveCert` writes `cert_pem` and `key_pem` as plain BLOBs
(`internal/store/proxies.go:453`). A snapshot, a backup, or a stolen standby therefore
hands over the private key for every hosted name.

- Seal the key with the existing `crypto.Box` (master key). Use a distinguishable
  prefix or a new column so a migration can re-encrypt existing rows in one pass and
  the loader can read both forms during the rollover.
- Acceptance: a database file plus no master key yields no usable certificate key; a
  restored backup with the master key serves TLS; the certificate inventory still
  lists expiry and source.

### 12.2 Hash gate session tokens

`internal/gate/gate.go:176` creates the token and stores it as `gate_sessions.id`;
`internal/store/policies.go:589` inserts the raw value. The cookie is a bearer
credential sitting in the database and in every snapshot.

- Store `HMAC-SHA256(master key, "wafproxy-gate\0" + token)` the way admin sessions
  already do (`store.sessionID`), with its own domain separator.
- A migration invalidates existing visitor sessions once. Say so in the release notes;
  it is a one-time re-login for gate visitors, and it is the right trade.
- Acceptance: a snapshot containing gate sessions cannot be replayed as a cookie;
  `LookupGateSession` still resolves a live cookie and still honours username bans.

### 12.3 Protect the snapshot and the pairing exchange

- Encrypt the snapshot envelope with AES-256-GCM under a key derived from the master
  key and the epoch, in addition to mTLS. That protects temporary files on disk and
  makes a captured stream useless without the master key.
- Compress before encrypting, bound the decompressed size (64 MiB), reject unknown
  tables and columns, and cap row counts. A peer is authenticated, not trusted to send
  a safe document.
- Bootstrap TLS uses SPKI pinning against the fingerprint in the pairing code; there
  is no `InsecureSkipVerify` mode in production.

### 12.4 Keep node identity out of the replicated data

`data/ha/node.json` (role, epoch, peer, node id) is node-local, `0600`, fsynced on
every change, and never part of a snapshot. Missing or corrupt means `standby` — the
fail-safe default. Exclude `data/ha/` from backups and snapshots: restoring a node
identity would clone a node.

### 12.5 Master key handling

- Same key on both nodes, `0600`, backed up separately; without it neither node can
  decrypt secrets or accept sessions.
- Transfer it only inside `HKDF(pairing secret, transcript)` AEAD, or out of band with
  `--master-key-file`. Never log it, never paste it into a ticket.
- A compromised standby means the key is compromised. The response is: unpair, rotate
  the master key, re-seal secrets, reissue certificates, re-pair. **`recover
  --rotate-master-key` does not exist in 1.55.2** (section 2, correction 6), so build
  it in P0 or document "rebuild both nodes" honestly.

### 12.6 Transport and authorization

- Mutual TLS with cluster-CA certificates, TLS 1.3 (1.2 minimum), session tickets
  disabled on the HA listener, per-message length limits and read deadlines.
- Bind `:9443` to the HA interface only, never `0.0.0.0`. Firewall to the peer `/32`
  and the witness.
- Monotonic sequence numbers, epoch checks and nonces; reject and count replays.
- `ha.read` / `ha.write` permissions; Administrator holds `ha.write` by default, the
  built-in read-only roles hold `ha.read`, and a dedicated HA role can be granted both;
  `host_admin` never. The HA page and its Settings toggle exist on the `default` console
  only, and the page is hidden until HA is enabled (Appendix B.3-B.4).
- Mutating HA actions require CSRF, the admin source allowlist, and fresh
  re-authentication: pair, join, failover, failback, unpair, rekey, force sync.
  Failover and unpair require typing the cluster name.
- Rate-limit the join endpoint (5 attempts per 10 minutes per source), compare the code
  hash in constant time, and audit every pairing, join, rekey, unpair and transition
  on both nodes.

### 12.7 Two tests that keep this honest

- A schema-classification test that fails when a new table is neither replicated,
  streamed nor explicitly node-local.
- A snapshot round-trip test that scans the encoded document for known secret fixtures
  (private key material, raw gate token) and fails if either appears unencrypted or
  unreduced to a digest.

---

## 13. Build plan: phases, gates and debugging

The four stages this section used to list were release milestones, not work packages: "Phase 1 —
pair, sync, manual failover" is about three months of work and six independently testable
subsystems. This version cuts the same scope into nine phases that can each be merged, tested and
reverted on their own, and adds the part that decides whether HA is real — how to build the
failure you are debugging, and what to look at when it happens.

Mapping from the old outline, so nothing is lost: Phase 0 → P0; Phase 1 → P1–P5 plus P7;
Phase 2 → P6; Phase 3 → P8. The work is ordered so that every phase produces something testable,
and so that the two data migrations land before any replication code can depend on them.

The task-level view — PR-sized work items in execution order, with files, verification
commands and per-task done criteria — is [HA-BUILD.md](HA-BUILD.md). This section stays the
authority on what each phase must make true and why; that file is the checklist used to build it.

### 13.1 Sequencing and the rules every phase follows

| Phase | What it makes true | Depends on | Size | Risk |
|---|---|---|---|---|
| P0 | Seams: role file, stoppable listeners, gated loops, `ReloadAll`, sealed certificate keys, hashed gate tokens, `recover --rotate-master-key` | — | 3 wk | low |
| P1 | A node knows what it is: role machine, control socket, widened readiness, read-only standby | P0 | 2 wk | low |
| P2 | Two nodes trust each other: cluster CA, pairing code, join, unpair | P1 | 2 wk | medium |
| P3 | The standby holds the same configuration, live, and rebuilds every engine on apply | P2 | 3 wk | high |
| P4 | Sessions, bans and audit survive a move | P3 | 3 wk | high |
| P5 | Planned and unplanned failover with keepalived, and failback | P4 | 3 wk | high |
| P6 | Unattended failover that cannot produce two writers | P5 | 3 wk | high |
| P7 | The surface: `wafproxy ha` CLI, `/api/ha`, console page, OpenAPI, docs, upgrade path | P5 | 2 wk | low |
| P8 | Proof: chaos suite, 72-hour soak, performance gate, release gate | P7 | 2 wk | — |

About 20–24 weeks for one engineer, 12–14 for two. The estimate assumes the lab in 13.2 exists in
week one. Without it, add half again to every phase from P4 on, because every one of those phases
is debugged by breaking a pair.

Rules that apply to every phase:

1. **Every phase merges dark.** `WAFPROXY_HA_ENABLE` (Appendix A) defaults to `0`, and with it off
   the binary behaves exactly as 1.55.2, with every new path unreachable. Turn it on in the lab
   from P1, and keep it the only difference between a passing and a failing test.
2. **A phase ends with a revertible commit series and a gate.** If the gate fails, revert the
   phase, not the plan.
3. **No second mechanism where one exists.** `ReloadAll` wraps the existing reload primitives;
   readiness widens `proxy.Ready()`; replication reuses `Store`, not a parallel data layer; the
   metrics endpoint stays the hand-rolled one in `internal/api/handlers.go:1910`. No new
   dependency is added for this feature.
4. **A phase adds its own failure injection to the lab script.** If you cannot reproduce a failure
   on demand, you cannot debug it during an incident. That is the point of the lab, not a nicety.
5. **The two P0 data migrations ship first, separately.** Sealing certificate keys and hashing
   gate tokens are independently good changes. Shipping them inside the HA release makes a
   rollback ambiguous: HA code can be reverted, a migration cannot.

### 13.2 The two-node lab (build this first)

Nothing from P4 onward is debuggable without a pair you can break repeatedly. Build
`deploy/ha-lab/` before the first line of `internal/ha`.

```
deploy/ha-lab/
  docker-compose.yml   # node-a, node-b, witness, client, two user networks
  ha.env               # fixed addresses, ports, master-key mount
  ha-lab.sh            # up, down, reset, break-link, heal-link, kill-active, ...
  client.sh            # 10 ms request loop against the VIP; writes status + latency CSV
  keepalived/          # used by the VM flavour only, see below
  logs/                # gitignored; the artifact attached to every failover bug
```

- `node-a` and `node-b` run the same image built from the working tree with
  `WAFPROXY_HA_ENABLE=1`, their own data volume, `cap_add: [NET_ADMIN, NET_RAW]`, and fixed
  addresses on `ha` (`10.77.0.0/24`) and `wan` (`10.78.0.0/24`).
- `witness` runs the same binary as `wafproxy ha witness --listen :9444`, so the lease protocol
  has two implementations from P6 instead of one.
- `client` runs `client.sh` on `wan`: one request every 10 ms, recording status, latency and
  which node answered. That file is the RTO measurement; do not benchmark separately.
- **VIP mode cannot be tested in plain compose.** VRRP needs a real interface and the kernel must
  move the address. Use two VMs, or `macvlan` off a promiscuous parent, for the P5 keepalived
  tests, and keep compose for everything else. Write that in the lab README rather than
  discovering it when `nopreempt` quietly does nothing across a bridge.

`ha-lab.sh` verbs, one per row of the failure matrix in 13.12:

| Verb | What it does | Used by |
|---|---|---|
| `up`, `down`, `reset` | start, stop, wipe the volumes | all |
| `break-link` | `iptables -I INPUT -s <peer> -j DROP` on both nodes, HA network only | P3–P6 |
| `heal-link` | reverse it | P3–P6 |
| `kill-active` | `kill -9` the process; the container stays up | P4, P5 |
| `pause-active` | `docker pause`, so the socket is open and nothing answers | P5, P6 |
| `slow-peer` | `tc qdisc add dev eth0 root netem delay 2s` | P3, P4 |
| `fill-disk` | a 90%-full file in the standby's data volume | P3, P4 |
| `corrupt-snapshot` | flip one byte in the last snapshot the standby received | P3 |
| `skew-clock` | move one container's clock by 30 s | P5, P6 |
| `freeze-witness` | `SIGSTOP` the witness | P6 |

Add `make ha-lab-up` and `make ha-lab-test` next to `perf` in the `Makefile`. The test target runs
the scripted scenarios and belongs in a nightly job, not in `go test ./...`.

**Debug.** Every container writes its data directory and logs under `deploy/ha-lab/logs/`. The
client writes CSV, so an RTO is `awk` over a file rather than a stopwatch, and every failover
report can carry the same evidence.

### 13.3 P0: Seams and prerequisites

**Goal.** Make the process able to change role at runtime without a restart, and close the two
holes that replication would otherwise broadcast. No HA behaviour ships.

1. **Role file and identity** — new `internal/ha/role.go`. `data/ha/node.json` holds
   `{node_id, role, epoch, peer, updated_at}`, written `0600` through temp file + `fsync` +
   `rename`, then `fsync` on the directory. Read at boot; a missing, unreadable or unparsable
   file means `standby`, never `active`. Test: truncated JSON, wrong mode, symlink, empty file.
2. **Stoppable data plane** — `internal/proxy/server.go`. Extract the body of `Run` (line 417)
   into `Listen(ctx) (*Listeners, error)` plus `(*Listeners) Drain(ctx)` and `Close()`. `Run`
   stays as a wrapper so no existing caller changes; `RunHTTP` gets the same treatment. Closing
   and re-binding the same port must work, because failback does exactly that. Test in
   `internal/proxy/run_test.go`: bind, serve, drain with a request in flight, close, rebind the
   same address, one hundred cycles, file-descriptor count flat.
3. **Loop gating** — `cmd/wafproxy/main.go`. Wrap every goroutine started in `run()` in a gate
   that answers `Active()` from the role file. Must not start on a standby: retention (decide
   once whether its prune half still runs), GeoIP update, certificate watch, feeds, bundles,
   bans, CrowdSec, gate, bots, uptime, backups, auto-update, agent links, the MCP gateway, and
   `siteres.Set.Start`, which is what starts the per-site ACME `RenewLoop`
   (`internal/siteres/siteres.go:221`). Test: a table of `{role, loop, wantStarted}`, so a new
   loop that forgets the gate fails the suite.
4. **`ReloadAll`** — `internal/api/server.go`, beside `reloadEngines` (line 515). Ordered:
   certificates → per-site resources (`siteres.Set.Each` and `Reload`) → bundles → feeds →
   policies → `proxy.Reload` → streaming `ApplyAll` (role-gated) → notifications. Returns one
   error per subsystem and never aborts the rest; the failing subsystem is named in the log.
   Test: one subsystem failing leaves the others applied.
5. **`IP_FREEBIND`** — `internal/netbind/freebind_linux.go`, `SetsockoptInt(fd, SOL_IP,
   IP_FREEBIND, 1)` before `bind`, with a `!linux` stub returning `ErrUnsupported`. Applied to
   the WAN and HTTP-01 listeners only, and only in VIP mode. Test: binding an address that is not
   on the interface succeeds with the option and fails with `EADDRNOTAVAIL` without it.
6. **Sealed certificate keys** — `internal/store/proxies.go` `SaveCert` (line 453) and its read
   path. Seal the key with `crypto.Box` under the master key, mark the row so the loader knows
   the format, dual-read during the rollover, and re-seal in one pass. Bumps `schemaVersion` to
   `23` (1.57.0 already carries `22`) with a matching entry in the `migrateAddColumns` step list
   (`internal/store/store.go`).
7. **Hashed gate tokens** — `internal/gate/gate.go:176` and
   `internal/store/policies.go:589`. Store `HMAC-SHA256(master key, "wafproxy-gate\x00" + token)`
   as `gate_sessions.id`, mirroring `store.sessionID` with its own domain separator. Bumps
   `schemaVersion` to `24`, after the certificate migration's `23`, because the two ship
   separately. The migration invalidates existing visitor sessions once; release-note it as a
   one-time re-login.
8. **Schema classification** — `internal/ha/classes.go` plus `internal/store/classify_test.go`.
   Three sets (`replicated`, `streamed`, `local`) and a test that walks `sqlite_master` and fails
   on any unclassified table. The P3 encoder imports the same sets, so the test and the wire
   format cannot drift.
9. **`recover --rotate-master-key`** — `cmd/wafproxy/main.go` `recoverCLI` (line 287). Unwrap with
   the old password, re-seal every sealed secret, re-key the session HMAC (all sessions die),
   print a fresh recovery code. Test: old cookies rejected, sealed certificate keys still load,
   gate sessions invalid.
10. **Management listener** — `WAFPROXY_HA_MGMT_LISTEN`, required in HA mode, and never a silent
    fallback to loopback (correction 4).

**Gate.** `go test ./...` and `make perf-gate` pass on one node. A container built from the tree
serves identically with HA off and with `WAFPROXY_HA_ENABLE=1, role: active`. Dropping and
re-binding the data plane works 100 times. `sqlite3` on a migrated database shows no plaintext
gate token and no plaintext `key_pem`.

### 13.4 P1: Role machine and control plane

**Goal.** A node can say what it is, and the safe answer is always the default. This is the phase
that makes a standby harmless, and it is worth shipping on its own: a second copy that is
provably read-only is already useful as a warm spare for manual moves.

1. `internal/ha/state.go`: a `State` enum (`standalone`, `active`, `standby`, `ready-standby`,
   `draining`, `promoting`, `demoting`, `fenced`, `split-brain-risk`), an `Event` enum, and a
   pure `Next(state, event) (State, []Action)`. Table-test the full matrix, including illegal
   transitions (`active` + `promote` must return an error and no action).
2. `internal/ha/control.go`: the Unix socket at `WAFPROXY_HA_CONTROL_SOCKET`, `SO_PEERCRED` check
   (uid 0 or the `wafproxy` gid), a `0600` token file in the same directory, one-line
   request/response JSON, a 2 s deadline. This is what the keepalived notify script talks to.
3. `cmd/wafproxy/ha.go`: `status`, `status --watch`, `status --json`, `notify
   master|backup|fault`, dispatched from `main()` before `run()`. Unknown subcommand prints usage
   and exits 2.
4. Readiness: `internal/api/server.go:619` becomes `ready = proxy.Ready() && role.Serving()`, the
   body gains the `ha` block, and a `last_sync` older than `2 × failover_after_s` also counts as
   unready. Plain `GET /api/health` stays 200 so the console can render a node that is
   deliberately not serving.
5. Read-only standby: a guard inside `authed` (line 539) after the session lookup and before the
   handler, rejecting every non-`GET` with `409 standby` except an allowlist — `/api/ha/*`,
   `/api/login`, `/api/logout`, `/api/me`, `/api/account/*`. Add the `ha` area to
   `permissionFor` in `internal/api/rbac.go` and to `internal/rbac`, so `ha.read` and `ha.write`
   are real permissions rather than strings in a doc.
6. Console: `web/src/App.tsx` polls `/api/ha` once a minute and renders `STANDBY — READ ONLY` on
   every page. Do not build a status page here: the role, epoch, peer and lag belong on the
   High availability page built in P7 (Appendix B.4), and the Readiness checklist gets one HA
   row that links to it.

**Gate.** With the lab up and node B set to standby: nothing bound on 443, nothing bound to the
VIP, the console reachable on its management address, every write `409 standby`,
`/api/health?ready=1` returning 503, and `ha status --json` stable for an hour with RSS and
thread count flat.

### 13.5 P2: Pairing and trust

**Goal.** Two nodes share a trust root and a master key, and pairing is the only way to get
either. Everything after this phase assumes an authenticated peer.

1. `internal/ha/pki.go`: cluster CA (ECDSA P-256, 10 years) and node certificates (1 year, SANs =
   node id plus both addresses), built on `crypto/x509`. Node keys live at `data/ha/node.key`,
   `0600`, deliberately not sealed — they are needed before the master key exists.
2. Pairing code: 26 base32 characters (128 bits) grouped as `WAF-XXXX-…`, stored only as
   `HMAC-SHA256(code)` with `expires_at` and `used_at`, compared in constant time, 5 attempts per
   10 minutes per source. This settles open decision 7 in the direction the CLI can print.
3. Join handshake over TLS 1.3 with SPKI pinning against the fingerprint in the code. Client
   hello → transcript hash → master key wrapped in AES-256-GCM under
   `HKDF(pairing secret, transcript)` → node certificate issued. The first snapshot is not part
   of this phase; pairing establishes trust, P3 moves data.
4. `ha unpair [--force]` and `ha rekey --node <id>`.
5. Audit every attempt on both sides with the outcome and source address, failures included.

**Tests.** Wrong code, expired code, reused code, wrong pinned fingerprint, a peer presenting a
certificate from another cluster, a plaintext client rejected when 1.3-only is chosen, a replayed
join, and the sixth attempt in ten minutes being refused. Each asserts that no master key left
the process: wrap the transport in a recorder and search the bytes.

**Debug.** `ha status` prints the peer fingerprint; `openssl s_client -connect … -cert … -key …`
reproduces a handshake failure outside the Go client. Log the transcript hash at debug level on
both sides — that is the value that differs when the key unwrap fails.

**Gate.** Pair and unpair 20 times in a row with no manual file copying, and a failed join leaves
node B with an empty data directory and role `standby`.

### 13.6 P3: Configuration replication

**Goal.** A change on the active is on the standby within a second and every engine on the standby
is rebuilt from it. This is the phase where "the standby is a real copy" becomes true.

1. `internal/ha/snapshot.go`: canonical encoding (fixed structures or sorted keys, never a raw
   `map[string]any` dump), gzip, then AES-256-GCM under `HKDF(master key, "snapshot" || epoch)`.
   Header `{cluster_id, epoch, version, schema_version, hash}` where `hash` is SHA-256 over the
   uncompressed canonical bytes.
2. Encode only the tables in the `replicated` set from P0. On decode, reject unknown tables and
   columns, cap decompressed size at 64 MiB and rows per table. The peer is authenticated, not
   trusted to send a safe document.
3. Apply inside one transaction with `PRAGMA foreign_keys=OFF` scoped to it: delete then insert
   per table in dependency order, reset `sqlite_sequence` to `MAX(id)` (hygiene, correction 1),
   write the local `config_version`, commit, then `ReloadAll`. A crash mid-apply must leave the
   previous state intact, so nothing touches the live tables outside that transaction.
4. Trigger: `store.TouchConfig()` on the write paths that already call `reloadEngines`, plus
   `PRAGMA data_version` polling for the second connection. Debounce 500 ms, send, wait for the
   standby to acknowledge the exact `(epoch, version, hash)`.
5. Reconcile every five minutes by comparing hashes. On mismatch send a full snapshot and log the
   per-table diff — row count and hash per table. That diff is the artifact for every "the nodes
   disagree" report.
6. Version floor: the standby refuses a snapshot whose `version` is below what it already applied,
   or whose `epoch` is below its own. This is what stops a rolled-back node resurrecting an old
   admin or a lifted ban.

**Tests.** A golden snapshot file; hash stability across two encodes of the same database (this
catches map ordering immediately); unknown table and oversize rejected; corrupted ciphertext
rejected with no partial apply; `kill -9` mid-apply then resume; idempotent re-apply;
`sqlite_sequence` equal to `MAX(id)` afterwards; one change per configuration class arriving
within the debounce.

**Debug.** `ha status --json` prints `config_version` and `config_hash` on both nodes. Equal
versions with different hashes means the encoder is not canonical — diff the two snapshot files
byte-wise. `ha sync --dump` writes the current snapshot to a file without sending it, which is
the only way to inspect it safely outside the lab.

**Gate.** One thousand changes across every configuration class: p95 under one second, no reload
error in 24 hours, and a schema mismatch refuses to sync while naming the table and column.

### 13.7 P4: Session, ban and audit replication

**Goal.** People stay signed in and bans stay enforced across a move. This is the phase users
notice, and it is the one that costs the most because it touches write paths rather than adding a
new package.

1. Schema: `ha_outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT, kind TEXT, op TEXT,
   row_id TEXT, payload BLOB, created_at TEXT)` and `ha_peer_ack(peer TEXT PRIMARY KEY,
   acked_seq INTEGER, updated_at TEXT)`. `schemaVersion` to `25`, after P0's `23` and `24`.
2. Enqueue in the same transaction as the state change. The paths that matter: `CreateSession` and
   `DeleteSession`, `CreateGateSession` and its delete, trusted devices, password resets,
   `ClaimTOTPStep`, bans and username bans, gate failures, audit rows, pending alert deliveries.
   Each needs a transaction-scoped variant. The honest cost of this phase is touching those
   functions, not writing the replicator.
3. Ship by pull: the standby asks for `seq > acked_seq`, applies in order, dedupes on
   `(origin, seq)`, and returns the highest contiguous sequence. Both sides prune below the
   watermark.
4. **The acknowledgement budget, stated plainly.** The HTTP response waits for local commit and
   enqueue, not for the peer. Waiting for the peer would make the active's writes fail whenever
   the standby is down, which is a worse trade for a WAF than a short window of un-replicated
   state. What the pair guarantees is the other direction: *if the peer acknowledged, it has the
   record*. The 250 ms `session_ack` budget is when the peer is declared `lagging`, and a
   `lagging` peer is not promotable — that is what turns "maybe lost a session" into "refused to
   promote". The RPO row in section 1 says "0 while the pair is healthy" for exactly this reason;
   an unconditional 0 would only be true if writes failed whenever the peer was unreachable.
5. Overflow: an outbox above 100 MiB stops streaming, raises `outbox_overflow`, sends a full
   snapshot, and resets the outbox at the watermark. Log it as an event and alert on it; silently
   dropping is the one failure mode that loses a ban.

**Tests.** Out-of-order delivery; duplicate delivery; a gap at sequence 5 (nothing past it
applies); watermark semantics under a crash; `kill -9` between two row applies then resume; the
overflow path; a session created during an overflow that still authenticates after the snapshot;
the audit head staying consistent.

**Debug.** `ha status --json` gives `outbox_depth`, `acked_seq` and `lag_s`;
`sqlite3 data/wafproxy.db 'select seq, kind, op from ha_outbox order by seq desc limit 20'` shows
what is stuck; `/api/ha/diagnostics` carries the per-kind counters. A single kind with a growing
depth is a transaction bug in that one write path, not a transport problem.

**Gate.** Ten thousand logins and logouts with a failover in the middle: every cookie minted
before the move still resolves after it. A ban issued 200 ms before `kill -9` is enforced on the
new active, in userspace and in nftables.

### 13.8 P5: Manual failover and failback

**Goal.** The operational feature: an operator can move traffic deliberately, and the move is
measured rather than hoped for.

1. Preflight as data: a `checks` slice of `{name, ok, detail}` returned by
   `ha failover --dry-run --json`, and the same structure gating the real run. Checks: peer
   reachable; same `cluster_id`, `schema_version` and protocol; no higher epoch observed; hash
   matches; lag under 5 s; certificates loaded for every enabled hostname; database writable and
   `PRAGMA quick_check` clean; disk above 5%; skew under 5 s; no configuration write in flight.
2. The planned sequence, one function per step, each returning its own verification: quiesce
   writes → drain the outbox → snapshot and acknowledge `(epoch, version, hash)` → pre-bind on the
   standby with `IP_FREEBIND` → keepalived releases and the standby claims → persist `epoch + 1`
   with `fsync` before any listener accepts → `ReloadAll` → reconcile bans into nftables → serve →
   the old active drains (`http.Server.Shutdown`, streaming stop, WebSocket/SSE close with 1001)
   → old active becomes `standby` and replays.
3. Abort: any failure before the VIP move restores the preflight state and names the failing step.
   After the move there is no abort, and the CLI refuses `--abort` with the reason instead of
   pretending.
4. keepalived: the config and notify script are in section 6. This phase's job is the script's
   **exit code** — keepalived logs nothing useful when a notify script fails, so a refused
   transition must exit non-zero to make `notify_fault` visible.
5. Failback reuses the sequence in reverse, plus the `healthy_for_s` hold and a full resync: a
   repaired node must not trust its own database, because it may be hours behind.

**Tests (VMs, not compose).** A planned move under `client.sh` load with zero 5xx and RTO p99
under one second; `kill -9` giving RTO under five seconds with no acknowledged session lost;
`docker pause` exercising the VRRP timeout path; `break-link` with both nodes healthy producing
no promotion without a witness. After each, the four user-visible checks from section 8.3.

**Debug.** Start every "it did not fail over" report with `ha failover --dry-run --json`, which
names the failing check. Then separate the three layers, in this order: `tcpdump -ni eth1 vrrp`
(are adverts flowing), `ip -4 addr show eth1` (who holds the VIP), `nft list set inet wafproxy
block4` (is the kernel state there). One command per layer; do not debug them together.

**Gate.** Ten planned and ten unplanned failovers, alternating, with no manual repair and no
re-login between them.

### 13.9 P6: Automatic failover, witness and fencing

**Goal.** Unattended failover, and a hard guarantee that it cannot produce two active writers.

1. Heartbeat over the HA link (`/ha/ping` on the existing mTLS channel), 1 s period, three
   consecutive failures to act. VRRP decides the VIP; the application decides the role, and they
   deliberately do not use the same signal.
2. The promotion gate is P5's preflight minus the operator-only checks. `--force` is the only way
   past a failed gate, and it prints what is at risk first.
3. Witness lease: `POST /ha/lease {cluster_id, epoch, holder}` → `{granted, expires_at}`, 10 s
   TTL, renew at 3 s, monotonic epoch, and a witness that stores nothing but that tuple and
   refuses a lower epoch. The active self-demotes when it cannot renew. Implement it as
   `wafproxy ha witness --listen :9444`, in the same binary, so deployments carry no extra
   artifact.
4. Fencing hook: `ha.fence_command` with `{peer}` substituted and a 30 s timeout; exit 0 means
   the peer is down, anything else means do not promote. Put the reference IPMI implementation in
   `deploy/ha/` — it is three lines and saves every operator from inventing it.
5. Self-demotion on observing a higher epoch, even while holding the VIP: close listeners, refuse
   writes, and stay `split-brain-risk` until the peer is reachable and the epoch reconciles.
6. `max_failovers_per_hour` and `failback_after` guards, plus a flap counter that parks the pair
   in a state that needs an operator.

**Tests.** Deterministic first: `internal/ha/sim_test.go` drives `Next()` and the gate through the
partition matrix on a fake clock — link down with both healthy, active dead, standby dead, both
dead, witness down, witness split, clock skew ±30 s, disk full on the standby, active killed
mid-failover. One table row per scenario, each asserting the number of active nodes is at most
one. Real time only for the two end-to-end cases.

**Debug.** Every transition writes an audit row `{from, to, event, epoch, reason}`; reconstruct an
incident from that table, not from logs. `ha status --json` carries `witness.lease_expires_in_s`
and `last_transition`. Use `CLOCK_MONOTONIC` for local timers and wall clock only for
certificates — a clock step is the most common cause of a lease that expires early.

**Gate.** Two hundred randomized partitions in the simulator: never two active, never a promotion
with an expired lease, never a promotion past a failed fence.

### 13.10 P7: API, console, docs and upgrades

**Goal.** The feature becomes operable by someone who did not build it, and invisible to
everyone who has not turned it on.

1. `internal/api/ha.go`: `GET /api/ha`, `GET /api/ha/events`, `GET /api/ha/diagnostics`,
   `PUT /api/ha/config`, `POST /api/ha/{pair,join,sync,failover,failback,unpair,notify}`.
   Register in `routes()`, add the `ha` case to `permissionFor` (`ha.read` for GET,
   `ha.write` for everything that changes state), then regenerate with
   `go generate ./internal/api` and commit `docs/openapi.yaml`. `make docs-check` runs
   `tools/openapi -check` and fails on drift, so this is not optional.
2. Enablement is two layers, and both must be honest in the UI. `WAFPROXY_HA_ENABLE` is the
   boot-time master switch: `0` registers no routes and no loops, and the console must say
   why the switch is disabled. The day-to-day switch is the stored host-wide setting
   `ha_enabled`; add it to `publicSettingKeys` and its `0`/`1` validation in `putSettings`
   (`internal/api/server.go`), and to `hostSettingKeys` in `internal/store/sites.go` so a
   tenant console cannot set it. Missing means off. The HA manager starts and stops its
   loops on the setting change from `PUT /api/settings`, so no restart is needed.
   `GET /api/me` gains the effective `ha_enabled` (and `ha_role`) so the sidebar can hide
   the page without a second request.
3. Settings: insert `{ id: "ha", label: "High availability" }` into `SECTIONS` in
   `web/src/pages/Settings.tsx` immediately before `backup`, and render `<section id="ha">`
   between `#retention` and `#backup`. One `Switch` bound to `s.ha_enabled === "1"` through
   the page's existing `set()` helper; the existing `SaveBar` is the save button, and no
   second one is added. Copy, disable rules and the unpair-before-disable confirmation are
   in B.3.
4. `web/src/pages/HA.tsx` + `web/src/pages/HA.test.tsx`: the page specified in B.4, fed
   only by `/api/ha*` so it works on a standby's management console. Wire it into
   `web/src/nav.ts` (System group, `permission: "ha.read"`, `requires: "ha_enabled"`,
   `hideFor: ["host_admin"]`), add the `requires` check to `allowed()` and the reason-aware
   fallback card in `web/src/App.tsx`, and add the types to `web/src/types.ts`. Extend
   `web/src/nav.test.tsx` for the visibility rule, `web/src/pages/Settings.test.tsx` for the
   switch and the PUT, and `web/src/pages/HA.test.tsx` for the four page states (unpaired,
   paired-active, paired-standby, disabled deep link).
5. CSRF, the admin source allowlist and fresh re-authentication on every mutating route;
   failover and unpair require typing the cluster id.
6. Docs: flip the status block in this file, add the HA row to the health section of
   `docs/OPERATIONS.md`, write the `CHANGELOG.md` entry, and only then add the feature line to
   `README.md`.
7. Upgrade path: standby first, schema and protocol checked before a join, automatic failover
   refused on a mismatch, and `ha upgrade --check` to say so before the operator starts. An
   upgrade leaves `ha_enabled` exactly as the operator set it.

**Gate.** `make test` (which includes `docs-check`), `make vet`, the web tests, and
`go test ./internal/openapi`. RBAC: a `viewer` cannot see the page or read `/api/ha`;
`ha.read` alone reads status and cannot post a failover. With `ha_enabled=0` the System nav
has no HA entry, `#/ha` opens the "turned off" card, and `POST /api/ha/pair` answers 409.
With it on and no pair, the page shows the setup card and `ha status` says `unpaired`.

### 13.11 P8: Chaos, soak and release gate

**Goal.** Prove it under the failures that actually happen, then stop changing it.

1. The chaos suite as a Go test behind `//go:build ha_lab`, driven by `ha-lab.sh`, so it never
   slows `go test ./...` and never needs privileged networking in CI.
2. One test per unglamorous case: standby restart mid-snapshot; active restart mid-outbox;
   outbox overflow; corrupted snapshot; schema mismatch; wrong, expired and reused pairing code;
   foreign cluster certificate; replayed sequence; clock skew; disk full on the standby; master
   key mismatch; a VIP move with an open WebSocket; failover during an ACME renewal; failover
   during a backup; upgrading the standby while the active writes.
3. A 72-hour soak at production request rate with one planned failover per day, watching RSS,
   file descriptors, goroutine count and table growth.
4. Performance: `make perf-gate` with `WAFPROXY_HA_ENABLE=1, role: active`. The ban and session
   paths are the hot ones; record before and after, put the delta in the PR, and only re-record
   with `make perf-record` after a reviewed decision that the cost is acceptable.
5. Security review against section 12, including the two tests in 12.7. Break each property
   deliberately and confirm the test fails: a test that has never failed is unverified.

**Gate.** Everything in 13.13 green on the lab and on two real hosts, using the release binary,
with HA off by default and every HA table empty until pairing.

### 13.12 Debugging playbook

The symptom table. Every row assumes `ha status --json` and `/api/ha/diagnostics` have already
been captured, because they answer half the questions below.

| Symptom | First check | Usual cause |
|---|---|---|
| Standby never reaches `ready-standby` | `ha status --json` → `sync.last_error` | hash mismatch from a non-canonical encoder; schema version differs; outbox gap; clock skew |
| VIP flips back and forth | `tcpdump -ni eth1 vrrp`; `ip -4 addr show eth1` | both nodes MASTER: `nopreempt` without `state BACKUP`, missing `arp_ignore`, or a notify script exiting non-zero |
| Promoted node answers `409` to every write | `cat data/ha/node.json`; `ha status` | role file never flipped, or an epoch check demoted it and the operator missed the transition |
| Administrators signed out after failover | compare `sha256sum data/master.key` on both nodes (never print the key) | master key differs, or the `sessionID` HMAC domain separator changed in the release |
| Gate visitors signed out, once | compare `schemaVersion` on both nodes | the P0 gate-hashing migration has not been applied on one side |
| Ban issued before the move is not enforced | `nft list set inet wafproxy block4`; outbox tail | userspace-only ban, or the nftables reconcile step was skipped on promotion |
| `EADDRNOTAVAIL` after promotion | check `IP_FREEBIND` on the WAN listener | option missing, or applied to the wrong listener, or VIP mode is off |
| `EADDRINUSE` on failback | `ss -ltnp '( sport = :443 )'`; goroutine dump | the drained listener was never closed; `Close()` not called on the drain path |
| Snapshot apply is slow or OOMs | row counts per table; applied size | 64 MiB cap hit, or indexes rebuilt per apply instead of once at the end |
| Duplicate ACME orders or duplicate alerts | the P0 loop table; `siteres.Set.Start` | a background loop without a role gate |
| Repeated split-brain alerts | `witness.lease_expires_in_s`; clock source | lease TTL shorter than the renew interval, wall clock used for timers, epoch not `fsync`ed before accept |
| Replication lag climbing | `outbox_depth`; `slow-peer` in the lab | one blocked write transaction holding the apply, or a transport that reconnects but never resubscribes |

A bug report for this feature carries five artifacts: `ha status --json` from both nodes, the last
50 transitions from the audit table, the client CSV covering the window, the relevant journal
excerpt, and the failing `--dry-run --json` output. Without them the report is a guess.

### 13.13 Acceptance criteria

1. Two fresh nodes pair in under five minutes with one code and no manual file copying (unless
   the operator chooses out-of-band key transfer).
2. A configuration change on the active is served by the standby within one second (p95),
   verified by an automated test.
3. An administrator signed in through the VIP stays signed in across a planned failover and
   across `kill -9` of the active.
4. A gate visitor stays signed in across the same two events.
5. A ban issued on the active blocks the address on the new active, in userspace and nftables.
6. A certificate issued on the active is served by the new active with no new ACME order.
7. Planned failover under load produces no 5xx attributable to the move; long-lived streams close
   with a clear reason.
8. Unplanned failover under load restores service in under five seconds and is at most one
   debounce behind on configuration. Acknowledged session writes are not lost while the pair was
   healthy; the degraded case is documented rather than denied.
9. Failback repeats the result in reverse with no re-login, including changes made while the peer
   was active.
10. With a witness, a partition leaves at most one active node; without one, automatic failover is
    refused.
11. `/api/ha`, `/api/health`, `/metrics` and the console show role, peer, epoch, versions and lag;
    lag above threshold alerts.
12. The standby refuses every configuration write and says why.
13. HA is off by default, and every HA table is empty until a pair is created.
14. Every row of the 13.12 table has a test that reproduces it.
15. The two tests in section 12.7 fail when their property is deliberately broken.
16. The HA page is absent from the sidebar and the command palette until HA is enabled, and
    `#/ha` then explains that it is off. Enabling in Settings makes the page appear with no
    reload; disabling with a live pair requires the cluster id and unpairs first.
17. The page answers every question in B.4 in all four states (unpaired, paired-active,
    paired-standby, disabled), and its **Copy diagnostics** output contains all five
    artifacts 13.12 asks for.
18. With `WAFPROXY_HA_ENABLE=0` no HA route or loop exists, the Settings switch is disabled
    with the reason, and every HA table is still empty.

### 13.14 Definition of done

The release that turns this document from a plan into a feature ships when: the status block at
the top of this file is rewritten to describe what exists rather than what is proposed;
`docs/OPERATIONS.md` documents the pair as an operational mode; `CHANGELOG.md` names the three
data migrations (`23` sealed certificate keys, `24` hashed gate tokens, `25` outbox) and the
one-time gate re-login; `README.md` lists HA without a "planned" qualifier;
`WAFPROXY_HA_ENABLE` defaults to off with an explicit note that a single node is still the
supported default; `ha_enabled` is absent on a fresh install, so the console has no HA page
and no HA nav entry until an operator turns it on; no new module appears in `go.mod`; and the upgrade path has been exercised in
both directions, standby first and then back, on real hosts rather than only in the lab.

---

## 14. Decisions to settle before coding

1. **Networking:** floating VIP with keepalived first, external LB and DNS-DR
   documented as later modes? (Recommended.)
2. **Automatic failover default:** off unless a witness or fencing hook is configured?
   (Recommended; manual failover is still one command.)
3. **Witness:** is a third tiny host acceptable? If not, automatic failover stays
   manual-only and that should be stated in the release notes, not discovered later.
4. **Event history:** replicate asynchronously with a lag cap, or accept a gap after
   failover? (Recommended: async on, explicit gap report when off.)
5. **Security prerequisites:** approve the certificate-key encryption and gate-token
   hashing migrations before HA ships? (Strongly recommended; both are independently
   good changes.)
6. **Master key:** transfer inside the authenticated pairing channel by default, with
   an out-of-band option? (Recommended.)
7. **Pairing code strength:** 80-bit 16-character code with a 10-minute single-use
   window, or a longer 128-bit code? Pick one and make the document and the CLI agree.
8. **Upgrade policy:** require the standby to be upgraded first and refuse automatic
   failover on a schema or protocol mismatch? (Recommended.)
9. **Who may fail over:** `ha.write` on Administrator only by default, or on Operator too?
   (Recommended: Administrator only; grant it to a dedicated HA role instead of widening
   the everyday operator.)
10. **Tenant visibility:** should a tenant console ever see pair status read-only, or is HA
    strictly a default-console capability? (Recommended: default console only, as in B.4.)

---

## Appendix A: proposed configuration surface

Boot-only environment. None of these are read by 1.55.2.

```ini
WAFPROXY_HA_ENABLE=0                    # boot master switch; 0 registers no HA routes or loops
WAFPROXY_HA_MGMT_LISTEN=10.0.0.11:8080  # management console on this node's own address
WAFPROXY_HA_CONTROL_SOCKET=/run/wafproxy-ha/ha.sock
WAFPROXY_HA_LINK_IFACE=eth1
WAFPROXY_HA_WITNESS=https://10.0.0.5:9444
WAFPROXY_HA_AUTO_FAILOVER=0             # only on with a witness or fencing hook
```

Runtime, host-wide, default site only, replicated:

```
ha.peer                    10.0.0.11:9443
ha.vip                     203.0.113.10
ha.failover_after_s        3
ha.drain_s                 30
ha.failback_mode           manual | scheduled | auto
ha.healthy_for_s           600
ha.max_failovers_per_hour  3
ha.sync_events             1
ha.durability              normal | full
```

No role is stored in the database. `wafproxy ha status` reads `data/ha/node.json` for
the local role and the replicated `ha_config` for topology.

CLI, proposed:

```bash
wafproxy ha status [--watch]
wafproxy ha init  --peer <addr> --ha-listen <addr> --mgmt <ip> --vip <ip> --iface <if>
wafproxy ha join  --active <addr> --code <code> --mgmt <ip> --ha-listen <addr> --iface <if>
wafproxy ha sync
wafproxy ha failover --to <a|b> [--dry-run] [--drain 30s] [--force]
wafproxy ha failback --to <a|b> [--dry-run] [--drain 30s]
wafproxy ha notify master|backup|fault      # local socket only
wafproxy ha witness --listen :9444          # the third host; no data plane
wafproxy ha unpair --force
wafproxy ha rekey --node <id>
```

API, proposed: `GET /api/ha`, `GET /api/ha/events`, `PUT /api/ha/config`,
`POST /api/ha/{pair,join,sync,failover,failback,unpair}`, with `ha.read` / `ha.write`
and OpenAPI regeneration via `go generate ./internal/api`.

## Appendix B: health, metrics and console

### B.1 Health

`GET /api/health` stays public and 200, and gains:

```json
{
  "status": "ok",
  "ready": false,
  "ha": {
    "enabled": true,
    "role": "standby",
    "state": "ready-standby",
    "peer": "10.0.0.10:9443",
    "epoch": 7,
    "config_version": 184,
    "lag_s": 0.2,
    "last_sync": "2026-11-23T10:31:02Z",
    "vip": "203.0.113.10",
    "last_error": ""
  }
}
```

`?ready=1` answers 503 while `draining`, `standby`, `syncing` or
`split-brain-risk`. The console keeps using the plain endpoint so it can render the
state of a node that is deliberately not serving. When HA is off the `ha` block reports
`enabled: false` with role `standalone`, and readiness is unaffected.

### B.2 Metrics

Prometheus: `wafproxy_ha_role`, `wafproxy_ha_peer_up`, `wafproxy_ha_epoch`,
`wafproxy_ha_config_version`, `wafproxy_ha_replication_lag_seconds`,
`wafproxy_ha_failovers_total{result}`, `wafproxy_ha_outbox_depth`. The series are absent,
not zero, while HA is off, so a dashboard can tell "not configured" from "not healthy".

### B.3 The Settings toggle

HA is turned on in **Settings → High availability**, immediately above **Backup**. That is
`{ id: "ha", label: "High availability" }` in `SECTIONS` and a `<section id="ha">`
between `#retention` and `#backup` in `web/src/pages/Settings.tsx`; nothing else on the
page moves. The section holds one `Switch` ("Enable high availability") bound to
`s.ha_enabled === "1"` through the page's existing `set()` helper, so the existing
`SaveBar` at the bottom is the save button. There is no second save control and no
auto-save: an operator can change the switch, change other settings, and save once.

Help text, which changes with state:

| State | Text under the switch |
|---|---|
| Off, unpaired | Off. This node serves on its own, exactly as it does today. |
| On, unpaired | On, not paired yet. Open High availability under System to create or join a pair. |
| On, paired | On, paired with `<peer>` (`active`/`standby`, last sync `<age>`). |
| Boot switch off | Disabled: this host booted with `WAFPROXY_HA_ENABLE=0`. |

While the switch is on, a `link-button` **Open High availability** navigates to `#/ha`.
The paired and unpaired lines come from `GET /api/ha` and are omitted for a role without
`ha.read`; the switch itself needs `settings.write`, which the settings route already
requires.

Rules:

- `ha_enabled` is a stored **host-wide** setting (`"0"`/`"1"`). Add it to
  `publicSettingKeys` and accept only `0`/`1` in `putSettings`; add it to
  `hostSettingKeys` in `internal/store/sites.go` so a non-default site gets the existing
  `ErrHostWideSetting`/403 instead of a silent no-op. Missing means off, so fresh and
  upgraded installs stay single-node (13.14).
- On a tenant console the section renders read-only with the existing `hostWide` note. For
  `host_admin` it is disabled with "Host-wide capability: the default console administers
  it." The API enforces both; the UI just does not offer a control that will fail.
- Precedence: `WAFPROXY_HA_ENABLE` is the boot master switch. `0` means no HA routes and
  no loops exist and the switch is disabled with that reason; `1` or unset lets the stored
  setting decide. `GET /api/me.ha_enabled` and `GET /api/ha.enabled` report the
  **effective** value, so the console never links to a page that would 404.
- Enabling does nothing else. No listener, no replication, no keepalived change. It makes
  `POST /api/ha/pair` and `/api/ha/join` legal, shows the nav entry and page, and lets the
  role machine initialise at the next boot. The confirmation toast says exactly that and
  links to the page.
- Disabling stops the HA manager, closes the HA listener and returns the node to the
  single-node state. With a live pair it is refused until the operator types the cluster
  id, because the peer keeps its copy and its keepalived instance. The confirmation lists
  the manual steps — remove the VIP or stop keepalived on the peer, expect the peer to keep
  serving a frozen copy, then unpair or wipe it — and the console calls
  `POST /api/ha/unpair` before saving `ha_enabled=0`.
- Audit: `settings.update` already records changed keys; add explicit `ha.enable` and
  `ha.disable` rows with the acting administrator and source IP, because this switch
  changes who can move the service address.
- Timing: live, through the existing `reloadEngines` path. A node whose `WAFPROXY_HA_ENABLE`
  is `0` still needs a restart, which is what a boot-time master switch means.

### B.4 The High availability page

**Where it lives.** `NAV_GROUPS` → `System`, last, with the other node-level pages:
Agent access, Notifications, Tailscale, Sites, High availability.

```ts
{
  id: "ha", label: "High availability", icon: "server",
  permission: "ha.read", requires: "ha_enabled", hideFor: ["host_admin"],
  hint: "Role, peer, replication and failover",
}
```

**When it is visible.** Five conditions, all evaluated in `App.tsx`'s `allowed()`:

1. `ha.read` — add the `ha` area to `internal/rbac/rbac.go` ("High availability: role,
   peer and replication"). Built-in roles are re-seeded on every boot (`seedRoles` upserts
   them), so Read-only and Operator pick up `ha.read` without a migration; only
   Administrator holds `ha.write` by default.
2. `me.ha_enabled` — `NavItem` grows `requires?: "ha_enabled"`, checked as
   `!n.requires || (n.requires === "ha_enabled" && me?.ha_enabled)`. It stays plain data,
   so `nav.test.tsx` covers it without a DOM.
3. not `host_admin` — HA is a host capability, not a tenant one.
4. the default-site console.
5. the effective value after `WAFPROXY_HA_ENABLE` (folded into `me.ha_enabled`).

`CommandPalette` receives `visibleNav`, so the same rule applies there. `NAV` keeps the
item, so `routeFromHash` still parses `#/ha`: the URL is not the security boundary.

**When it is hidden but linked.** A bookmark, a tab opened before the switch was turned
off, or a role change can land on `#/ha` while the page is not visible. `App.tsx` already
renders a fallback card when `pageAllowed` is false; give it a reason:

| Case | Card |
|---|---|
| HA disabled | High availability is turned off. Enable it in Settings → High availability. Button opens that section. |
| Role lacks `ha.read` | Your role does not include this page. (existing copy) |
| `host_admin` or tenant console | High availability is administered from the default console. |

Turning the switch off while the page is open must not wait for a reload. The Settings
page gets an `onMeChanged` callback (App refetches `/api/me`), `me.ha_enabled` goes false,
and the existing effect that normalises an invisible page navigates to the Dashboard.

**What the page shows.** Header: cluster name and id (copyable), a role badge (`ACTIVE`,
`STANDBY`, `DRAINING`, `SPLIT-BRAIN RISK`, `UNPAIRED`), the state from the role machine,
time in role, app and schema version, last transition. Header actions: **Sync now** and
**Copy diagnostics**. Cards, in this order:

| Card | What it answers | Content |
|---|---|---|
| Role and state | What is this node doing right now? | role, state, epoch, config version, uptime in role, last transition reason, whether it is serving 443 and holding the VIP |
| Peer | Is the other node alive and current? | address, node id/name, app and schema version, heartbeat age, RTT, clock skew, TLS pin match, replication lag, outbox depth, last error; **Test connection** |
| VIP and network | Who owns the address clients use? | VIP and owner, interface, last keepalived notify state (`MASTER`/`BACKUP`/`FAULT`/unknown), HA link address, network mode (VIP / external LB / DNS DR), and a red flag when the VIP is here but the role is standby, or the reverse |
| Replication | What has not arrived yet? | per-class rows from Appendix C: config (version, hash, last apply, pending), sessions, security decisions, audit, alerts, events (last acked seq, pending, lag, last error); outbox depth against 100 MiB, snapshot size against 64 MiB, last reconcile |
| Sessions | Will anyone be signed out? | counts only — admin sessions, trusted devices, gate sessions, pending resets — split replicated/node-local, with the age of the last session transaction; amber when a session class is behind |
| Bans | Is enforcement in step? | userspace bans, `block4`/`block6` counts, last ban sequence applied, kernel reconcile time; **Reconcile now** on the active |
| Witness | Can this pair fail over on its own? | witness address, lease TTL, lease held/expires in, last contact, verdict; explicit "automatic failover is manual-only" when none is configured |
| Transitions | What happened, and who did it? | last 20 transitions: time, from → to, initiator (operator, automatic, keepalived, CLI), reason, duration, epoch |
| Diagnostics | Why is it not working? | the runnable checks (master key match, schema match, clock skew, disk headroom, port conflicts, certificate expiry, pin match, settings parity) with ok/warn/fail and the fix; **Copy JSON** of `GET /api/ha/diagnostics` |
| Maintenance | What can I do about it? | **Test failover** (dry run), **Fail over**, **Fail back**, **Unpair** — `ha.write`, fresh re-authentication, cluster id typed |

Sessions and bans deliberately show counts and ages, never tokens or hashes: the page is
readable by `ha.read`, which is wider than `policies.write`.

**The four states the page must render** (and the four tests in `HA.test.tsx`):

1. **Enabled, not paired** — a setup card replaces the operational cards: **Create a
   pair** (26-character base32 code shown once, 10-minute expiry, copy button) or **Join a
   pair** (code plus expected peer address), a prerequisites checklist (certificates,
   master key transfer, HA address, firewall, clock sync, keepalived), and a link to the
   pairing runbook in section 5. Every other action is disabled with "Pair this node
   first."
2. **Paired, active** — all cards live, maintenance enabled, **Fail back** visible only
   after `ha.healthy_for_s` (section 9).
3. **Paired, standby** — a read-only ribbon on the page; every mutating action disabled
   with the reason, while **Sync now**, **Test connection** and **Copy diagnostics** still
   work.
4. **Disabled** — not in the nav; a direct link shows the "turned off" card above.

**Live data.** `GET /api/ha` every 5 s while `document.visibilityState === "visible"`,
paused while hidden; `GET /api/ha/events?since=<seq>` appends transitions. The page does no
writes except the explicit actions. The `STANDBY — READ ONLY` banner stays in `App.tsx`
and shows on every page, not only this one, so an operator reading Settings on a standby
also knows why writes fail.

**Accessibility.** State changes announced through `aria-live="polite"`; every badge
carries text, never colour alone; copy buttons have labels; a disabled action says why in
both visible text and `title`.

**Files.** `web/src/pages/HA.tsx`, `web/src/pages/HA.test.tsx` (vitest with a fetched
`api`, in the style of `Certs.test.tsx`); `HAStatus`, `HAPeer`, `HATransition`,
`HAClass`, `HADiagnostics` in `web/src/types.ts`; the nav rule in `web/src/nav.ts` and
`web/src/nav.test.tsx`; the toggle in `web/src/pages/Settings.tsx` and
`web/src/pages/Settings.test.tsx`; the banner and fallback in `web/src/App.tsx`.

## Appendix C: data classes

| Class | Examples | Channel | Ack | Loss on crash |
|---|---|---|---|---|
| Config | sites, proxies, profiles, policies, certs, sealed secrets | snapshot, 500 ms debounce, 5-min reconcile | version + hash | up to 500 ms; `Sync now` before a planned move |
| Sessions | admin, trusted device, reset, gate visitor | outbox | per record | last unacknowledged record |
| Security decisions | bans, username bans, gate failures | outbox, priority | per record | under 1 s |
| Audit | audit rows and head | outbox, append-only | per record | last unacknowledged row |
| Alerts | pending notifications, agent deliveries | outbox | per record | duplicate possible; dedupe handles it |
| Events | request events, flows | optional async batch | batch | up to the lag setting |
| Node-local | cache, rate limits, metrics, uptime, GeoIP, access log, role | none | n/a | expected |

HA protects against a node failure. It does not protect against ransomware, an
accidental deletion that replicates to both nodes, or a bad configuration applied to
the pair. Keep the existing encrypted backups, and consider a pre-failover snapshot so
the exact state at handover is recoverable.
