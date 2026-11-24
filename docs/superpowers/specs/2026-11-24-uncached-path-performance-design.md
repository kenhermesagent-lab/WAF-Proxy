# Uncached-path performance: safe wins and an end-to-end gate

Date: 2026-11-24

## Intent

An uncached request that runs the WAF is the whole capacity story: throughput is flat at
about 4.6k rps across 50, 200 and 400 clients, p95 grows 27 → 99 → 198 ms, shed is 0, and
the shape does not change with 1 or 16 sites. That is a CPU ceiling, not queueing. The
cause is understood: a Coraza + CRS transaction costs about 0.85 ms of CPU per request on
this host (3.0 ms on the 2-vCPU sandbox recorded in `docs/BENCHMARKS.md`), and it dominates
everything else in the request path.

The operator has chosen to keep the full CRS on every request, so the rule engine is out of
scope. What remains is everything around it, plus the fact that no CI check would notice a
throughput collapse: the perf job only microbenchmarks `Inspect`, with a 2× time tolerance,
and the end-to-end rows in `BENCHMARKS.md` are recorded by hand.

## Goals

- Remove CPU and allocation cost from the uncached path without changing what the WAF
  inspects or blocks. The bypass corpus and the response-inspection tests stay green.
- Make an end-to-end uncached regression a CI failure (rps floor, p95 ceiling), so the next
  change that halves throughput cannot ship green.

## Non-goals

- Changing paranoia levels, rule files, anomaly thresholds, or exceptions.
- A fast path that answers or skips the CRS (cache-first already exists and is opt-in).
- Response-body inspection changes, admission-budget changes, or a new cache policy.
- Claiming hardware-independent numbers. Every figure here is this sandbox.

## What the profile says

`perftool -proxy`, 200 clients, one site, uncached, WAF block, 15 s, CPU profile of the
whole process (client and proxy share the process):

| Cost centre | Share of CPU |
|---|---:|
| Coraza rule evaluation (`RuleGroup.Eval`) | 29 % |
| gzip compression (`flate.encode` + per-response `NewWriter`) | 13 % |
| GC assist and background marking | 11 % |
| Reverse-proxy copy and downstream writes | 14 % |
| Everything else (TLS, policy, router, events) | 33 % |

Two of those are ours and safely removable:

1. `gzipWriter` allocates a fresh `compress/gzip.Writer` for every compressible response,
   even though the cache path already keeps a `gzipPool` for exactly this reason. A
   compressor carries large buffers, so per-response allocation also feeds the 11 % GC.
2. `cacheWriter` buffers the whole response for every cache candidate and only discovers in
   `finish()` that `no-store` / `private` / `no-cache` forbids storing it. The decision is
   visible in the response headers in `WriteHeader`, so the body never needs copying.

Two smaller syscall/allocation wins sit in the same path:

3. Every request arms and clears a read deadline for a body, including GETs that cannot
   carry one; that is two `SetReadDeadline` syscalls per bodyless request.
4. `budget.reserve` creates a `time.Timer` even when a slot is free, which is every request
   below the ceiling.

The cache key and `Accept-Encoding` negotiation are also computed twice for cacheable
requests; one computation serves both the cache-first check and the cache writer.

## Approaches considered

- **Keep the CRS, cut everything around it (chosen).** The changes above. Expected gain is
  modest — the engine is 29 % and gzip/GC roughly 24 % of the profile, and not all of that
  is removable — but every win is behaviour-preserving and measurable. No detection change.
- **Opt-in fast path by request shape.** Large gain, but it stops inspecting a class of
  traffic with the CRS. Rejected by the operator.
- **Admission and queue tuning only.** Makes latency predictable without raising the
  ceiling. Rejected as the primary work; the existing budget already does this.

## Design

### Proxy changes (`internal/proxy`)

- `gzipWriter` takes its compressor from the existing `gzipPool` and returns it after
  `Close`. Identity responses and non-`gzip` clients are unaffected.
- `cacheWriter.WriteHeader` applies the same cacheability tests `responseCache.put` already
  enforces (status, `Set-Cookie`, `no-store`/`private`/`no-cache`, `max-age`, `Vary`), and
  sets `skip` when the response can never be stored. The store-time checks stay: they are
  the authority, and the request path must not be able to weaken them.
- A request that cannot carry a body (`ContentLength == 0` and no transfer encoding) skips
  the deadline arm/clear pair. A request that can carry one keeps the current behaviour.
- `budget.reserve` creates its timer only on the first miss, not on the admitted path.
- The cache key and negotiated encoding are computed once per request and reused.

### End-to-end gate

- `perftool -proxy` gains `-min-rps` and `-max-p95` (a duration). After a run it exits
  non-zero, naming the measured value, when the completion rate is below the floor or p95 is
  above the ceiling. Zero (the default) disables the check, so existing runs are unchanged.
- `make perf-proxy-gate` runs a short uncached, WAF-block load with conservative thresholds,
  and the CI performance job runs it after the microbenchmark gate.
- Thresholds are coarse on purpose: CI runners share CPUs and are slower than this sandbox.
  The gate catches a collapse (a lost fast path, double inspection, a serialised stage), not
  a 10 % drift. The recorded run and its CPU model go in `docs/BENCHMARKS.md`.

## Verification

- `go test ./...`, `make waf-corpus`, `gofmt`, `go vet`.
- Before/after `perftool -proxy` uncached runs on the same host, same flags.
- The quickstart demo (`examples/quickstart`) under the round-two probe list and an
  uncached load, confirming blocks still happen and the measured rps/p95.
- The new gate fails when the floor is set above what the host achieves, then passes at the
  committed thresholds.

## Result (measured)

The expectation of a modest gain was wrong. Two alternating runs of the old and new binaries in one
session, 50 uncached clients and the WAF blocking, went from 3,419/3,264 to 7,462/7,626 rps, with
p95 falling from 30.7/32.5 ms to 14.1 ms; 200 clients across 16 sites went from 3,429 to 6,883 rps
with p95 130 → 62 ms. Peak RSS fell from roughly 330 MiB to 167–317 MiB. The reason is that the
pooled compressor and the dropped response copy were the largest per-request allocators, so removing
them cut allocation pressure well beyond their share of the CPU profile. The same binary served the
quickstart demo at 3,734 rps / p95 3.4 ms and blocked all 21 round-two probes and all 76 corpus
probes that are expected to be blocked. Numbers and caveats are in `docs/BENCHMARKS.md`.

## Risks

- Absolute rps on a shared CI runner varies; a floor set from this sandbox would flake. The
  committed floor is deliberately low, which makes the guard coarse rather than precise.
- Pooling compressors keeps a reference to the writer until `Close`; every exit path in the
  handler already closes it, and a miss would only cost memory, not correctness.
- Skipping the buffer for uncacheable responses does not change the cache's authority: `put`
  still refuses anything the request path failed to notice.
