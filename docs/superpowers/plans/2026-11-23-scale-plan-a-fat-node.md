# Plan A — Fat node: "one box absorbs the whole rack"

Status: **approved 2026-11-23, in build.** Built on its own branch and merged to `main`
once, after the last part passes review.
Owner: one agent, one branch. Window: **three weeks** of build (15 task-days), then one
review-and-merge pass. Releases: **1.61.0**, **1.62.0**. Build loop: the roadmap's
[Post-1.60 scale track](../ROADMAP.md).
Companion plan: [Plan C — game-server streaming](2026-11-23-scale-plan-c-game-streaming.md).

## Progress

| Task | State |
| --- | --- |
| A1 — measurement harness and baseline | **done** 2026-11-23: `cmd/perftool -proxy`, results in `docs/BENCHMARKS.md` and `perf/proxy-*.json` |
| A2 — byte budget, bounded queue, memory ceiling | **done** 2026-11-23: `budget.go`, `queue_ms`, measured in `docs/BENCHMARKS.md` |
| A3 — deadlines | next |
| A4 — cache and brotli, A5 — cache-first, A6 — transports, A7 — observability, A8 — docs and releases | not started |

## Why this plan exists

The product target is the middle of the self-hosted market: one operator, one or
two boxes, roughly 5–50 sites, a few hundred concurrent users, occasionally a
burst that looks like a small rack. The comparison against HAProxy is decided:
**we do not chase raw inspected requests per second.** HAProxy forwards bytes;
we run Coraza and the OWASP CRS on every inspected request, which costs roughly
0.8 ms of CPU per request in the current baseline. That cost is the product.

The promise this plan has to make true is narrower and more useful:

> One box keeps serving when the whole rack points at it: it does not refuse
> requests while CPU and memory are still available, it never grows memory
> without a ceiling, and the paths that do not need inspection (cache hits,
> WAF-off sites, byte relays) run at relay speed.

Today the box fails that promise in five specific ways:

| # | Defect | Evidence |
| --- | --- | --- |
| 1 | Admission is a count, not a budget. 128 in-flight × 8 MiB body is ~1 GiB of request memory; 128 is also reached long before 8 vCPUs are busy. | `internal/proxy/server.go:235`, `DefaultMaxInflight = 128` |
| 2 | Admission fails immediately. There is no queue, so a 50 ms burst is answered with 503 even though the box could absorb it. | `internal/proxy/server.go:253` `acquire()` uses `default:` |
| 3 | Every cache hit still pays the WAF, the body read and the routing pass. The cache lookup sits after `Policy.Inspect`. | `internal/proxy/handler.go:243` then `:288` |
| 4 | Compression is gzip-only and applied per response, including cache fills; there is no brotli and no precompressed cache variant. | `internal/proxy/response.go:239`, no brotli in `go.mod` |
| 5 | One shared `http.Transport` serves every upstream, so pool limits and DNS lifetimes cannot differ per site, and reload drops warmth. Per-upstream transports were explicitly left undelivered. | `internal/proxy/server.go:156`; `docs/ROADMAP.md` delivery status |

The WAF itself is not the target of this plan. Micro-optimising Coraza is a
separate, evidence-led exercise; what this plan does instead is stop paying for
inspection when the answer is already known, and stop the box from hurting
itself when it is busy.

## Measured baseline (do not regress these)

`perf/baseline.json`, recorded 2026-11-22, Go 1.27.4:

| Benchmark | ns/op | allocs/op |
| --- | ---: | ---: |
| `BenchmarkInspectBenign` | 803,571 | 2,691 |
| `BenchmarkInspectSQLi` | 690,996 | 2,567 |
| `BenchmarkMix` | 844,576 | 2,510 |

`make perf-gate` enforces these with a 2× time tolerance and 25 % allocation
tolerance. Any improvement this plan claims must be recorded with
`make perf-record` in the same change, with the before/after command in
`docs/BENCHMARKS.md`.

The sandbox cannot measure end-to-end throughput today; `cmd/perftool` only
replays the WAF mix in-process. Task A1 fixes that before anything else changes,
so every later claim has a number behind it.

## Goals (measurable)

| ID | Goal | Measure |
| --- | --- | --- |
| A-G1 | A burst is absorbed, not shed | 200 concurrent keep-alive clients on 4 sites, 30 s: zero 503/429 from capacity, p95 within 2× of idle |
| A-G2 | Memory has a ceiling | request buffers + cache + response buffers stay under the configured budget for the whole run; RSS flat after warm-up |
| A-G3 | Cache hits run at relay speed | cached-asset mix (1 KiB and 64 KiB bodies) ≥ 3× the WAF-on throughput on the same host |
| A-G4 | Modern encoding | brotli served when offered, gzip still served, cached bodies are not recompressed per hit |
| A-G5 | Upstream connections are stable | reload of an unchanged upstream accepts zero new upstream connections |
| A-G6 | Operators can see why | capacity panel shows in-flight, queued, shed, buffer bytes, cache hit ratio per site |
| A-G7 | No new migration risk | no schema change; settings and env only; the existing 1.60 database starts unchanged |

## Non-goals

- N-node control plane, PostgreSQL, Redis/NATS, shared cache, leader election.
  The two-node HA pair is the ceiling for this size of product; this plan must
  not make it harder, and adds no table or replication path.
- Matching HAProxy on inspected requests per second.
- HTTP/3, QUIC, UDP forwarding, game presets — Plan C.
- WAF rule-set changes, CRS tuning, paranoia-level defaults.
- Importers (NPM/Traefik/Caddy/HAProxy), mTLS, SSO.

## Decisions taken

| Decision | Choice | Why |
| --- | --- | --- |
| Admission model | byte budget **and** request count, with a short bounded queue | count alone cannot bound memory; immediate refusal wastes capacity |
| Queue wait | 250 ms default, per-site override | long enough to smooth a burst, short enough that a client sees a 503 rather than a stall |
| Queue fairness | per-site FIFO behind the per-site cap | one busy site already has its own cap; a global round-robin scheduler is more machinery than the failure justifies |
| Memory ceiling | `WAFPROXY_MEMORY_LIMIT` → `debug.SetMemoryLimit`, default 75 % of the cgroup limit when detectable | GC pressure is what actually takes the box down |
| Cache-first | **opt-in per site**, default off | skipping CRS on a cache hit is a real security trade; it must be a labelled choice, not a default |
| Encodings | brotli preferred, gzip fallback, identity | table stakes in 2026; the cache stores one variant per encoding |
| Transport | one per upstream, reused across reload | per-site pool sizes and DNS TTL; the old roadmap already promised it |
| Release shape | 1.61.0 = A1–A4 + A6, 1.62.0 = A5 + A7 + A8 | ship the safety work before the trade-off work |

## Task A1 — Measurement harness and baseline (1.5 days)

Extend `cmd/perftool` with a mode that drives the real pipeline instead of the
WAF engine alone:

```
perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=off
perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=on
perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=on -h2
perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=on -waf=block
perftool -waf  -load 5s                      # existing in-process mix
```

- Boot a `proxy.Server` directly (same constructor the tests use), two stub
  upstreams (`httptest` with a fixed body and `Cache-Control: max-age=60`), a
  temp SQLite database and four proxies.
- Use `http.Client` with `Transport.MaxIdleConnsPerHost = clients`, HTTP/1.1 and
  HTTP/2 runs.
- Report requests, rps, p50/p95/p99, bytes in/out, shed count, peak RSS
  (`runtime/metrics` or `/proc/self/status`).
- Write the result as JSON to `perf/proxy-<mode>.json` and a table into
  `docs/BENCHMARKS.md`. `-record` updates the file; without it, the tool prints
  and compares.

Files: `cmd/perftool/main.go` (new flags and `runProxy`), `cmd/perftool/proxy.go`
(new), `cmd/perftool/proxy_test.go`, `docs/BENCHMARKS.md`, and one result file per
mode under `perf/` (`perf/proxy-cache-off.json`, `perf/proxy-cache-on.json`, …).

Tests: `cmd/perftool/proxy_test.go` asserts a short run produces plausible
counters (requests > 0, p95 > 0, shed == 0 with a large budget).

Exit: the commands above run on the build host and the numbers are in
`docs/BENCHMARKS.md`, marked with the host and date.

## Task A2 — Byte budget, bounded queue, memory ceiling (3 days)

### Budget

`internal/proxy/budget.go` (new) owns admission:

```go
type budget struct {
    countMax, bytesMax int64
    count, bytes       atomic.Int64
    waiters            int64
    // slots is a channel-based weighted semaphore: a request reserves its
    // estimated size, then adjusts to the real size after the body is read.
}
func (b *budget) reserve(ctx context.Context, size int64) (release func(actual int64), ok bool)
```

- Estimate before reading the body: `Content-Length` when present and ≤
  `hardBody`, otherwise `min(hardBody, 64 KiB)`. Adjust once the body length is
  known. An estimate above `hardBody` is refused with 413, not queued.
- Defaults: `WAFPROXY_MAX_INFLIGHT` keeps its meaning (count, now default 256 for
  small bodies); new `WAFPROXY_MAX_BUFFERED_BYTES` default `512 MiB`. Both are
  validated against `WAFPROXY_MEMORY_LIMIT` at startup: cache budget + buffer
  budget must leave at least 128 MiB for the runtime, otherwise startup fails
  with the numbers in the message.
- Per-site and per-client caps stay exactly as they are (`capLimiter`,
  `clientLimiter`); they are checked first, so a noisy site never enters the
  global queue.

### Queue

- `WAFPROXY_QUEUE_MS`, default 250, `0` disables (today's behaviour). The per-site
  override is the `site_settings` key `queue_ms` (0–5000), read through
  `Store.SettingsFor` once per `Reload` and cached on the edge as `queueMS`, so a
  bulk site can wait while a latency-sensitive one does not.
- Wait on the weighted semaphore with `context.WithTimeout`; the handler's
  request context already carries cancellation from the client.
- On timeout: `503`, `Retry-After: 1`, event `stage="capacity"`,
  `rule="queue-timeout"`, counted as shed with reason `queue`.
- On an over-budget reservation: `503`, `Retry-After: 1`, reason `bytes`.

### Memory ceiling

- `WAFPROXY_MEMORY_LIMIT` accepts bytes (`1073741824`) or a size suffix
  (`1GiB`), applied with `debug.SetMemoryLimit` at boot. Default: 75 % of the
  cgroup v2 `memory.max` when readable, otherwise unset (current behaviour).
- Expose `runtime/metrics` heap/GC values through `/metrics` so the panel can
  show headroom, not just usage.

Files: `internal/proxy/budget.go`, `internal/proxy/budget_test.go`,
`internal/proxy/server.go` (`SetMaxInflight` → `SetBudget`), `internal/config/config.go`,
`internal/proxy/handler.go` (hand the reservation the body size), `cmd/wafproxy/main.go`,
the console's site Settings page (the field), `docs/CONFIGURATION.md`.

Store note — one mechanism, no struct field: the per-site queue lives in
`site_settings` under `queue_ms` only. `SetSettingsFor` already accepts every key
that is not host-wide, so the settings form saves it with no API change, and
`Store.SettingsFor(siteID)` returns it at `Reload` time. There is no
`model.Proxy.QueueMS` field and no `proxies` column: a struct field would only
carry a value that has to be stored somewhere first, and a column is exactly the
migration this plan avoids. `site_settings` is `ClassReplicated`, so the HA
snapshot carries the value without a new table.

Tests:

- `reserve` accounting under 1,000 concurrent goroutines never exceeds the byte
  ceiling and returns to zero.
- A saturated global budget with `queue_ms=200` serves the request when a slot
  frees at 100 ms, and returns 503 + `Retry-After` at 200 ms.
- Per-site cap still refuses before the global queue is entered.
- `queue_ms=0` reproduces today's immediate 503.
- Startup validation rejects `buffered + cache > limit - 128 MiB`.
- `debug.SetMemoryLimit(-1)` returns the configured value after boot.

Exit: with 200 clients and an 8 MiB-budget-per-request mix, no request is shed
while the byte budget has room, RSS stays below the ceiling, and `queue_ms=0`
still behaves exactly as 1.60 did.

## Task A3 — Slow-client and deadline hardening (0.5 day)

The WAN server sets `ReadHeaderTimeout` and `IdleTimeout` but no body or write
deadline (`internal/proxy/server.go:191`), so a client that trickles a body
holds a budget slot indefinitely — the one way a single attacker can defeat A2.

- Before `readBody`, set a read deadline with
  `http.NewResponseController(w).SetReadDeadline(now + bodyTimeout)`; default
  30 s, `WAFPROXY_BODY_TIMEOUT`, per-site `body_timeout_s` setting. Clear it
  (`time.Time{}`) before calling the upstream so a slow upstream is governed by
  the existing upstream timeout, not the client deadline.
- Keep `WriteTimeout` unset for streaming responses; the existing response cap
  and route timeout bound the exchange.
- Record `stage="protocol"`, `rule="body-timeout"` when the deadline fires.

Tests: an `httptest` handler with a pipe that writes one byte per 100 ms is cut
at the deadline, its budget slot is released, and a normal streaming response
(long-lived `Flusher` loop) is unaffected.

## Task A4 — Cache: brotli, variants, normalized key (3 days)

Current behaviour: `cacheKey` includes the raw `Accept-Encoding` string
(`internal/proxy/cache.go:57`), entries always store identity bytes
(`cache.go:105`), and the hit path writes identity bytes straight to `rw`
(`handler.go:291`). A browser sending `gzip, deflate, br` and one sending
`gzip` therefore keep duplicate entries, and neither gets a compressed cached
body.

- Normalize the negotiated encoding to one of `br`, `gzip`, `identity` and use
  that in the key. Parse q-values; `br` wins ties; `identity;q=0` with no
  supported encoding returns 406 for cacheable requests only if the stored
  upstream response was itself encoded — otherwise serve identity (never
  invent a 406 for a response the origin was willing to send plainly).
- Store identity once, and memoize compressed variants lazily on first use
  inside the entry (`sync.Once` per encoding). Compression cost is paid once
  per entry, not per hit. Variant bytes count against the same budget and
  per-host quota; eviction drops all variants together.
- Brotli: add `github.com/andybalholm/brotli` (pure Go, no cgo). Pool writers
  with `sync.Pool` keyed by quality; default quality 4 for cached responses
  (decided by a micro-benchmark in the task, recorded in `docs/BENCHMARKS.md`),
  `Accept-Encoding` negotiation in `response.go`.
- The gzip writer stays for uncached responses; `Vary: Accept-Encoding` is set
  once for any encoded response.

Tests: q-value table (`br;q=1, gzip;q=0.5`, `gzip;q=0, *;q=0`, `br;q=0.2, gzip;q=0.9`);
brotli and gzip round-trip through the cache; one entry per representation when
the client header differs only in ordering/spacing; variant bytes counted and
evicted; `Range` and `HEAD` stay uncached as today; a cached brotli body is not
recompressed on the second hit (assert encoder pool counter).

Exit: cached-asset throughput ≥ 3× the inspected path (A1 harness), and bytes
on the wire for a 64 KiB compressible asset drop by at least 60 % with brotli.

## Task A5 — Cache-first mode, opt-in per site (2 days)

This is the only change that intentionally skips the CRS, so it is a per-site
setting, off by default, with the trade written next to the checkbox.

When `site_settings.cache_pre_waf = "1"` and `cacheableRequest(r)` is true and a
fresh entry exists:

1. resolve the client address (unchanged),
2. run the decoy/ban/allow-list/rate-limit checks already in
   `Policy.Screen` plus the per-client limiter,
3. serve the cached variant with `stage="cache"`, `rule="cache-hit"`,
4. never call the upstream and never call `Policy.Inspect`.

On a miss the request follows today's path and fills the cache.

Skipped on purpose, and named in the UI copy: CRS request rules, normalization,
per-IP WAF rules that live in profiles, bot challenge, access gate. The setting
is therefore only offered when the site has no access gate and its WAF mode is
`block` or `detect` (not `off`, where it would buy nothing and hide the cost).

Tests:

- cache-first on: two identical GETs, the second never reaches the upstream
  (counter) and a WAF-engine invocation counter stays at one.
- a banned source is still refused from the cache path; a `Screen` rule
  (allow-list / rate limit) still applies; the access gate still returns before
  the cache when enabled (setting is rejected for gated sites).
- cache-first off: byte-for-byte identical behaviour to 1.60 (the existing
  cache tests cover it).
- purge invalidates and the next request inspects normally.

Exit: A1 harness `-cache=on` numbers at least 3× `-cache=off`, and the tests
above prove the policy surface that remains.

## Task A6 — Per-upstream transport, warm reload, DNS cache (2 days)

Today `Server.transport` is one `http.Transport` for every upstream
(`internal/proxy/server.go:156`), so `MaxIdleConnsPerHost` is a single number and
`Reload` throws away every warm connection.

- `internal/proxy/transport.go` (new): a registry keyed by upstream address +
  TLS verification mode, returning `*http.Transport` with:

  - `MaxIdleConns: 256`, `MaxIdleConnsPerHost: 64` (configurable per site via
    `site_settings.upstream_idle_conns`),
  - `IdleConnTimeout: 90s`, `ForceAttemptHTTP2: true`,
  - `DialContext` with a resolver cache: 30 s TTL, single-flight per host,
    fallback to the last good address for 5 minutes during a DNS outage,
  - explicit `TLSHandshakeTimeout` and `ExpectContinueTimeout`.

- `Reload` keeps a transport whose upstream config is unchanged, closes idle
  connections for a removed upstream, and swaps in a new transport for a
  changed one after the old one finishes its in-flight requests.
- Health probes keep their own short-timeout transport (they must not share the
  data path's idle pool).

Tests: an upstream `httptest` server counts accepted connections; two reloads
with no config change add zero; changing a site's upstream creates a new
connection and closes the old idle one; a resolver stub with a 1 s TTL is
consulted again after expiry; during a forced resolver error the last good
address is still dialed within 5 minutes and not after.

## Task A7 — Capacity observability and console (1.5 days)

- `/metrics` gains: `wafproxy_inflight_requests`, `_queued_requests`,
  `_shed_total{reason="count|bytes|queue|site|client"}`,
  `_buffer_bytes`, `_cache_bytes{site}`, `_cache_hits_total{site}`,
  `_cache_misses_total{site}`, `_heap_bytes`, `_gc_cycles_total`.
- `GET /api/capacity` (read permission, site-scoped for `host_admin`): per-site
  in-flight/queued/shed, buffer bytes, cache bytes/hit ratio, transport pool
  counts, memory limit and headroom.
- Dashboard card "Capacity": four numbers and a one-line hint when shed > 0
  ("raise the budget or add a site cap"), linking to the Operations page.
- Logs: capacity refusals appear with `stage=capacity`, so the existing
  filter finds them.

Tests: API shape and site scoping; metrics names exist after a request; the
card renders shed/queue values from a stubbed response (vitest).

## Task A8 — Docs, benchmark record, releases (1.5 days)

- `docs/CONFIGURATION.md`: the four new env vars and the per-site settings.
- `docs/OPERATIONS.md`: a sizing table (body size × concurrency → buffer budget)
  and a "what to do when the box sheds" checklist.
- `docs/BENCHMARKS.md`: A1 harness results before/after, WAF gate re-recorded,
  brotli compression ratio and cost.
- `README.md`: "Limits" updated; no claim of HAProxy parity.
- `CHANGELOG.md`: two entries, one per release.
- `VERSION` **1.61.0**, then **1.62.0**; `internal/version/version.go`,
  `web/package.json`, both compose pins, `SECURITY.md` support line; rebuild
  `internal/webui/dist`; `bash deploy/check-version.sh`; `make verify-release`.

## Verification

```bash
go build ./...
go test ./internal/proxy/... ./internal/waf/... ./internal/policy/... \
        ./internal/config/... ./internal/store/... ./internal/api/...
go run ./cmd/perftool -load 5s
go run ./cmd/perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=off
go run ./cmd/perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=on
cd web && npx tsc --noEmit && npx vitest run
make perf-gate            # after `make perf-record` for a deliberate improvement
bash deploy/check-version.sh
```

The end-to-end numbers must come from the build host and be labelled with its
CPU and date. Anything measured only in a microbenchmark is reported as such.

## Risks and their answers

| Risk | Answer |
| --- | --- |
| Byte accounting is wrong and the box OOMs | reservation is clamped to `hardBody`, adjusted downward after read, and the sum is asserted in a 1,000-goroutine test; the memory limit is the backstop |
| Queue turns a fast refusal into a stall | default 250 ms, and the client's own cancellation ends the wait; `queue_ms=0` restores 1.60 |
| Cache-first weakens protection more than users expect | off by default, refused for gated sites, the skipped stages are named in the UI, and it is audited on every toggle |
| Brotli costs more CPU than it saves | quality chosen by measurement, cached variants compressed once, `perf` gate records the result; gzip remains the fallback |
| Transport registry leaks on reload | registry refcounts users, closes idle conns on last release, tested with `httptest` connection counts |
| Skipping work voids the "WAF" claim | no default changes to inspection; only cache hits, which were already inspected when stored, can skip, and only when the operator says so |

## Order, weeks and commits

| Week | Tasks | Ends with |
| --- | --- | --- |
| 1 | A1, A2, A3 (5 days) | — |
| 2 | A6, A4 (5 days) | **1.61.0** committed on the branch |
| 3 | A5, A7, A8 (5 days) | **1.62.0** committed on the branch |
| 4 | deslop pass, reviews, one merge to `main` | both releases on `main` |

A1 → A2 → A3 → A6 → A4 (1.61.0) → A5 → A7 → A8 (1.62.0). One commit per task,
project message style, tests in the same commit. The 15 task-days are the build;
the week-4 pass is the review and merge the roadmap's build loop requires, which
is why the honest label for this plan is three weeks plus a merge day rather
than two weeks. If the window slips, 1.61.0 is a complete, shippable capacity
release without cache-first; 1.62.0 can land later without a second design.
