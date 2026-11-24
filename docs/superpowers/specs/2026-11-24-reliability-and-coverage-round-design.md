# Reliability and coverage round: design

Date: 2026-11-24
Status: implemented for review, not yet released

## Intent

Close the five gaps named in the follow-up review without touching the security
posture: the CRS still inspects every request, no rule or paranoia setting moves,
and nothing that drops traffic gets a weaker check. Where an item could only be
made faster or smaller by trading coverage for speed, it was left alone.

## Goals

- The uncached hop has a gate of its own, not only a WAF microbenchmark.
- Peak memory under load is understood and bounded by a documented, supported knob.
- The HA page says what has not been proven instead of implying production readiness.
- The packages that drop traffic or enforce tenant isolation have tests.
- A CI tag check does not need a manual re-run when the tag lands inside its window.

## Non-goals

- Any change to CRS rules, paranoia level, anomaly threshold or cache policy.
- A default GC or memory limit shipped in the binary: live heap depends on the
  operator's cache and profile count, and a blind limit would thrash GC.
- The NPM importer. `docs/ROADMAP.md` lists importers as deliberately deferred
  ("a parser plus a migration plan; a later, separate project"), and doing one
  properly needs an import path through the API, RBAC, audit and the site model.
  It stays the next separate project rather than a half-shipped parser here.

## What was done

### 1. Gate the pipeline, and check the budget wake path

`BenchmarkPipeline` in `internal/proxy` sends one request through the real
handler: routing, admission budget, upstream copy, response filters. `perftool`
runs it with the other three benchmarks and `perf/baseline.json` carries
213,661 ns/op at 170 allocations. The benchmark rotates 4,096 source addresses
because a single address trips the per-IP rate limit and would measure the 429
path instead.

The budget does not use `sync.Cond`; 1.65.5 replaced it with a channel handoff,
so there is no `Broadcast` herd to remove. Measured at 256 clients with a
64-slot budget and a 250 ms queue: 0 shed, p50 7.33 ms, p95 39.84 ms, peak RSS
246.7 MiB, against p50 11.08 / p95 26.92 / 359.1 MiB with no queueing at all.
Queueing trades tail latency for a smaller footprint; it does not collapse.

### 2. Memory

Measured on this host with `perftool -proxy -duration 5s -clients 50 -sites 1`:

| Mode | rps | p95 | Peak RSS |
|---|---:|---:|---:|
| relayed (`-cache=off -waf=off`) | 21,006 | 5.12 ms | 141.8 MiB |
| cached (`-cache=on`) | 44,696 | 2.55 ms | 127.9 MiB |
| inspected (`-waf=block`) | 7,211 | 14.16 ms | 327.5 MiB |

The inspected figure is Go's GC headroom, not live data: `GOGC=50` gives
222.5 MiB, `GOMEMLIMIT=160MiB` gives 174.5 MiB at the same p95 (14.03 ms), and
`GOMEMLIMIT=160MiB GOGC=off` gives 170.6 MiB at p95 13.38 ms. The relayed target
of under 150 MiB is already met, and the supported knob for the rest is the
runtime's own `GOMEMLIMIT`, documented in `docs/BENCHMARKS.md` rather than
hard-coded, because a limit below the operator's live cache would only burn CPU.

### 3. HA is labelled experimental in the console

The HA page carries a warning badge stating that the two-VM hardware gates and
the chaos soak have not run, with a pointer to the checklist in `docs/HA.md`.
`docs/HA.md` already said this; the console did not.

### 4. Coverage where traffic is dropped and tenants are separated

- `internal/urlguard` 0 % → 95.5 %: the full policy matrix, including metadata
  addresses by IP and alias, IPv4-mapped link-local addresses, scheme refusals
  and the private/loopback/link-local split between upstream, webhook and feed.
- `internal/ban` 19.0 % → 37.6 %: reconcile after an out-of-band delete,
  source-scoped removal, permanent stays permanent on refresh, demote, and the
  expiry sweeper removing both the enforcing entry and the row.
- `internal/siteres` 0 % → 25.0 %: default-only build, per-site store scoping,
  fallback for a deleted site, and rebuild after `Drop`.
- `internal/gate` (29.1 %) and `internal/intel` (25.3 %) are unchanged; their
  remaining untested paths are the login form and feed refresh, which need a
  fixture beyond this round.

### 5. CI sees a tag that landed during its own retry loop

`deploy/check-tags.sh --remote` read each tag's commit from the local clone, but
CI's checkout carries only the tags that existed when it ran. Once the tag
appeared on origin the ordering rule could not read it, `set -e` ended the
script with no message, and the retry loop in `ci.yml` burned its full two
minutes before failing the job. Remote mode now fetches a tag it does not hold,
and an unreadable newest tag fails with a named reason. A regression test clones
without tags and requires both a fresh tag to pass and a real backlog to fail.

## Bug found on the way

`internal/netmatch.Map.Range` held the read lock while calling the callback, and
`ban.purgeExpired` removes the entry it is handed. The first ban to expire
deadlocked the ban sweeper: the goroutine kept the lock, so the ban stayed
enforced forever, hit counters stopped flushing and reconcile stopped running.
`Range` now copies the entries before calling back, which fixes every caller;
two tests pin mutation inside the callback and early stop.

## Security stance

Every change is additive to enforcement: no rule, threshold, cache or gate
decision changed. The memory guidance does not alter what is inspected. The HA
badge reduces the chance of an operator trusting an unproven pair. The new ban,
urlguard and siteres tests exercise refusals rather than only happy paths.
