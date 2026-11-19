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

## Not measured

The plan's Phase 9 list also asked for:

- end-to-end requests/s and added latency with the WAF on vs. off,
- resident memory at 1k and 5k rps,
- behaviour of the nftables set at 200k entries,
- 7-day query latency and database growth.

These need a Docker host with a real client generating traffic. Reproduce them there:

```bash
# On a separate client, against a test proxy:
hey -z 60s -c 50 https://app.example.com/            # WAF block
# then set the proxy WAF mode to "off" and repeat.

# Memory while under load:
docker stats --no-stream wafproxy
```

Publish results with the CPU model, request mix, response size, WAF mode and profile — a
number without those is not comparable.
