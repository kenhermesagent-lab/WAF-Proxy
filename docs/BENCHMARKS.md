# Benchmarks

Only numbers actually measured on the build host are listed. Nothing here is an estimate
presented as a measurement; unmeasured items are stated as such.

## Environment

| Item | Value |
|---|---|
| CPU | `19/01 @ 1996.249 MHz`, 2 vCPU (shared cloud sandbox) |
| OS / arch | Linux, amd64 |
| Go | 1.27.4 |
| Date | 2026-11-19 |

The sandbox has no Docker daemon, no real NIC and no separate client host, so end-to-end
proxy throughput and memory-under-load were **not** measured. The tables below are Go
microbenchmarks of the hot components.

## Prefix matching (`internal/netmatch`)

Built a table of 100,000 distinct `/24` prefixes, then measured one lookup per iteration.

```bash
go test ./internal/netmatch -run '^$' -bench 'BenchmarkMatch|BenchmarkAggregate' \
  -benchtime=300ms -benchmem
```

| Benchmark | ns/op | Allocations |
|---|---:|---:|
| Match, hit (100k prefixes) | 86.18 | 0 B/op, 0 allocs |
| Match, miss (100k prefixes) | 108.8 | 0 B/op, 0 allocs |
| Aggregate 10,000 prefixes | 8,439,042 (8.44 ms) | 1,247,486 B/op, 91 allocs |

Lookups are allocation-free and sub-microsecond. Aggregation only runs when a feed is
refreshed, not per request.

## WAF inspection (`internal/waf`)

Coraza v3 with the embedded OWASP CRS, paranoia level 1, anomaly threshold 5, no request
body. One `NewTransaction` + headers + `ProcessRequestBody` per iteration.

```bash
go test ./internal/waf -run '^$' -bench 'BenchmarkInspect' -benchtime=1000x -benchmem
```

| Request | ns/op | Allocations |
|---|---:|---:|
| Benign GET (1000 iterations) | 3,011,302 (3.01 ms) | 139,920 B/op, 2683 allocs |
| SQL injection GET (100 iterations) | 2,864,332 (2.86 ms) | 127,914 B/op, 2563 allocs |

The microbenchmark implies a single-core ceiling of roughly 330 inspected requests per
second on this CPU before TLS, proxying and event writes. That is adequate for a home/lab
edge, but it is the first stage to profile on a busier host. On real hardware measure with
your own workload; the microbenchmark is not a capacity guarantee.

## End-to-end proxy pipeline (`cmd/perftool -proxy`)

The real `proxy.Server` — TLS listener, routing, cache and event writer into a throwaway SQLite
database — in front of an `httptest` upstream, with 200 keep-alive clients over 4 hostnames and a
1 KiB compressible body per request. Each row is one 30 s run of the command in its first column.

| Run | Requests | rps | p50 | p95 | p99 | Shed | Errors | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `-cache=off` (h1) | 211,028 | 7,029 | 26.3 ms | 61.2 ms | 79.5 ms | 0 | 0 | 343 MiB |
| `-cache=on` (h1) | 1,560,753 | 51,846 | 3.2 ms | 9.1 ms | 14.0 ms | 0 | 0 | 189 MiB |
| `-cache=on` (h2) | 1,542,336 | 51,227 | 3.6 ms | 7.5 ms | 10.6 ms | 0 | 0 | 207 MiB |
| `-cache=on -waf=block` (h1) | 253,727 | 8,453 | 18.5 ms | 60.3 ms | 89.8 ms | 0 | 0 | 304 MiB |

```bash
go run ./cmd/perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=on -waf=block -record
```

| Item | Value |
|---|---|
| CPU | `AMD EPYC 7003 (Milan)`, 8 vCPU (shared cloud sandbox) |
| OS / arch | Linux, amd64 |
| Go | 1.27.4 |
| Date | 2026-11-23 |
| Client and proxy | same process, loopback |

What the numbers say, and do not:

- **A cache hit is 7× the uncached path** (51,846 vs 7,029 rps) and **6× the inspected path**
  (8,453 rps). The gap between `-cache=on` and `-cache=on -waf=block` is the cost of running
  Coraza on a request the cache could have answered: it is defect 3 of Plan A, measured.
- `errors` counts non-200 responses, so a shed request appears there as well; `shed` comes from
  the proxy's own capacity counter.
- Every client shares one loopback source address, so the run raises `dos_rps`/`dos_burst` out of
  the way. The per-source rate limit has its own tests; it is not what these rows measure.
- `bytes_out` in `perf/proxy-*.json` is what the client read off the wire: identity bytes without
  `-encoding`, the compressed body with it.
- One process, no real NIC and no separate client host: this is the pipeline's own ceiling, not a
  network measurement. `perf/proxy-*.json` carries each run's date and CPU, because a shared
  sandbox's neighbours change the numbers between runs.

### Admission: the queue absorbs the burst

200 keep-alive clients against a 128-request budget, uncached, on the same host. The first row is
what 1.60 did (shed at the door); the second is the same budget with the 250 ms queue.

| Run | Served | rps | p95 | p99 | Shed | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| `-inflight 128 -queue 0` | 182,941 | 6,094 | 64.7 ms | 86.4 ms | **162,630** | 320 MiB |
| `-inflight 128 -queue 250ms` | 213,480 | 7,112 | 61.0 ms | 81.9 ms | **0** | 316 MiB |
| `-inflight 256 -queue 250ms` (default) | 211,028 | 7,029 | 61.2 ms | 79.5 ms | **0** | 343 MiB |

With no queue, 47 % of the attempts on the box (162,630 of 345,571) were refused with a 503 while
the CPUs were busy serving the other 53 %. The queue turns the same budget into zero refusals and
17 % more completed requests, at the same p95: the wait is shorter than the time a slot takes to
come free. Latency in the queue-0 row is measured over served requests only, so it flatters the
shed requests it hides.

```bash
go run ./cmd/perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=off -inflight 128 -queue 0 -record
go run ./cmd/perftool -proxy -duration 30s -clients 200 -sites 4 -body 1024 -cache=off -inflight 128 -queue 250ms -record
```

### Encoded cache hits: one entry, a variant per encoding

A4 stores one identity copy of a cacheable response and builds `br` or `gzip` inside the entry on
the first hit that asks for it, so two clients whose `Accept-Encoding` differs only in order or
weights share one upstream fetch. For this run the stub asset is 64 KiB of page-shaped markup:
the same rows with varying numbers, because a repeated 8-byte string compresses to nothing and
would flatter both encodings. These rows therefore compare only within this table.

| Run | Requests | rps | p95 | Bytes per response | Peak RSS |
|---|---:|---:|---:|---:|---:|
| `-cache=off -encoding br` (miss, gzip on the wire) | 36,792 | 3,667 | 110.6 ms | 9,680 | 399 MiB |
| `-cache=on -encoding br` (hit, brotli variant) | 398,683 | 39,817 | 11.7 ms | 6,366 | 265 MiB |

```bash
go run ./cmd/perftool -proxy -duration 10s -clients 200 -sites 4 -body 65536 -inflight 256 -queue 250ms -cache=off -encoding br -record
go run ./cmd/perftool -proxy -duration 10s -clients 200 -sites 4 -body 65536 -inflight 256 -queue 250ms -cache=on  -encoding br -record
```

- **A cached asset is 10.9× the same request through the pipeline** (39,817 vs 3,667 rps) and its
  p95 falls from 110.6 ms to 11.7 ms.
- **Bytes on the wire for the 64 KiB asset: 6,366 instead of 65,536** — a 90 % drop — and 34 %
  below the 9,680 B gzip sends on a miss.
- The miss row is higher in peak RSS because it compresses the 64 KiB body for every request;
  the hit row pays that once per entry.

Brotli quality on a 64 KiB page-shaped body, one compression per entry:

| Quality | ns/op | Compressed bytes |
|---|---:|---:|
| 1 | 321,214 | 7,555 |
| **4** (cached default) | 942,236 | 6,364 |
| 9 | 3,118,462 | 6,890 |

The 6,364 B the quality benchmark compresses to is the same body the hit row above puts on the
wire, which is the check that the cache is serving the variant rather than re-compressing per hit.

```bash
go test ./internal/proxy -run '^$' -bench BenchmarkBrotliQuality -benchtime 2s
```

Quality 4 is the knee: 16 % smaller than quality 1 for 0.94 ms once per entry, while quality 9
costs three times the CPU and ends up larger on this body.

## Not measured

The plan's Phase 9 list also asked for:

- behaviour of the nftables set at 200k entries,
- 7-day query latency and database growth.

Requests/s and resident memory now come from `cmd/perftool -proxy` above, which runs the real
listener in one process. What it cannot show is a separate client host, a real network or a
container memory limit. Reproduce those on a Docker host:

```bash
# On a separate client, against a test proxy:
hey -z 60s -c 50 https://app.example.com/            # WAF block
# then set the proxy WAF mode to "off" and repeat.

# Memory while under load:
docker stats --no-stream wafproxy
```

Publish results with the CPU model, request mix, response size, WAF mode and profile — a
number without those is not comparable.

## Capacity planning on larger hosts (projected, not measured)

The numbers in this section are a **model** derived from the measured per-request cost above, not
measurements on those VMs. They are here so an operator can size a host and a request budget before
running their own load test, and every figure is labelled as a projection.

### Assumptions

- The measured WAF inspection cost is 3.01 ms per request on the shared 2 vCPU sandbox
  (~2.0 GHz). A dedicated current-generation vCPU at ~3.0 GHz is assumed to be **0.55×** as slow
  per request, i.e. about **1.65 ms** per inspected request per core.
- A practical host is kept below ~60 % sustained CPU so bursts and event writes have headroom.
- TLS, proxying and SQLite event writes are **not** included in the inspection figure; with the
  WAF off they are the remaining cost and were not measured here.
- Storage is a local SSD; SQLite is in WAL mode with a connection pool of 2× CPUs (capped at 32),
  overridable with `WAFPROXY_DB_CONNS`.

### Projected inspected-request ceiling

| Host | Injected cores for WAF | 100 % CPU (projected) | ~60 % CPU (projected) | Suggested `WAFPROXY_MAX_INFLIGHT` |
|---|---:|---:|---:|---:|
| 4 vCPU / 8 GB | 4 | ~2,400 rps | ~1,400 rps | 256 |
| 8 vCPU / 16 GB | 8 | ~4,800 rps | ~2,900 rps | 512 |
| 8 vCPU / 32 GB | 8 | ~4,800 rps | ~2,900 rps | 768 |

The 32 GB row is identical for CPU because the WAF is CPU-bound; the extra memory buys a larger
event-retention window, more page cache and a bigger body/connection budget, not more requests per
second. Paranoia level and the number of matched rules move this materially: measure the real
request mix before treating any row as a guarantee.

### Memory budget

| Component | Approximate resident cost |
|---|---|
| Go process, config and compiled WAF profiles | 80–150 MB (projected) |
| GeoIP city + ASN readers | 60–120 MB, memory-mapped |
| SQLite page cache and WAL | 64–256 MB depending on write rate |
| Buffered request bodies | up to `WAFPROXY_MAX_INFLIGHT` × the largest inspected body |

The last row is the one to watch. With the 8 MiB hard ceiling on a profile's inspected body (the
shipped profiles default to 128 KiB), 768 in-flight requests
is a theoretical 6 GB worst case; real traffic bodies are much smaller, but a host that accepts
large uploads should lower the per-profile body limit or the budget rather than rely on average
size.

### Knobs

| Setting | Where | Effect |
|---|---|---|
| `WAFPROXY_MAX_INFLIGHT` | environment | Cap on concurrent buffered requests, default 256. |
| `WAFPROXY_MAX_BUFFERED_BYTES` | environment | Cap on the request memory those requests hold, default 512 MiB (suffixes `KiB`/`MiB`/`GiB` accepted). |
| `WAFPROXY_QUEUE_MS` | environment | How long a request waits for budget before a 503, default 250; 0 refuses at once. Per-site override: the `queue_ms` setting. |
| `WAFPROXY_BODY_TIMEOUT` | environment | Seconds a client may take to send its body before a 408, default 30; 0 disables it. Per-site override: the `body_timeout_s` setting. |
| `WAFPROXY_MEMORY_LIMIT` | environment | Soft heap limit; default 75 % of the cgroup limit. Startup refuses a buffer budget that cannot fit under it. |
| `WAFPROXY_DB_CONNS` | environment | SQLite pool size; defaults to 2× CPU count (4–32). |
| Max inspected body | Settings / WAF profile | Per-request memory ceiling; the dominant term above. |
| Event retention | Settings | 1–30 days; the main driver of database growth. |
| Per-site response ceiling | WAF profile | Caps upstream response size, not concurrency. |

### How to verify on your host

Run the microbenchmark on the target machine to replace the 0.55× assumption with a real number:

```bash
go test ./internal/waf -run '^$' -bench BenchmarkInspect -benchtime=2000x -benchmem
```

Then measure end-to-end with a client on a separate host, WAF on and off, and record the CPU model,
request mix, response size, WAF mode and profile. A projected row above is not a substitute for that
test.
