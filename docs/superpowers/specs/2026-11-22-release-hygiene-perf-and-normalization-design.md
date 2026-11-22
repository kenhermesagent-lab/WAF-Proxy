# Release hygiene, a performance gate, and normalization safety

Design for roadmap items **9, 8, 3**, approved in conversation on 2026-11-22 as the next batch.
Written before implementation, per the brainstorming gate; no product code exists yet.

## Why

The reviewer's list mixes four large projects with smaller work that makes those projects cheaper
to attempt. This batch is the second kind:

- **9 — release hygiene** so a released artefact can be traced to the source and version it claims.
- **8 — a measured performance gate** so a later change to the WAF path cannot quietly cost
  throughput without anyone noticing.
- **3 — normalization and false-positive safety** because two of its three parts are exploitable
  today, and the third decides whether the WAF is usable on real traffic.

## What already exists (checked, not assumed)

- `.github/workflows/ci.yml` runs gofmt, vet, `go test -race`, build, SPA build, a committed-bundle
  check, `npm audit`, updater shell tests and a Docker build. It does **not** check `VERSION`
  against `CHANGELOG.md`, produce an SBOM, or test a database from a previous release.
- `internal/waf/bench_test.go` and `internal/netmatch/bench_test.go` already benchmark the hot path;
  no baseline, no CI threshold, no end-to-end load figure.
- `internal/intel.Parse` parses feed prefixes without filtering loopback, private, link-local or
  cloud-metadata ranges. A feed can therefore contribute `127.0.0.1/32` or `10.0.0.0/8` to a ban
  set, and a poisoned feed can block the proxy's own health checks.
- `internal/waf.Inspect` does not examine parameter normalization at all: duplicate parameter names
  and double-encoded values reach Coraza as separate values rather than as a signal.

## #9 Release hygiene

Three slices, in order:

1. **Version consistency check.** A `make verify-release` target plus a CI step: `VERSION` parses as
   SemVer, the newest `CHANGELOG.md` section carries `## [x.y.z]` equal to `VERSION`, and — when the
   build runs in GitHub Actions on a `v*` tag — the tag equals `VERSION`. Fails with the exact
   mismatch printed.
2. **SBOM.** `make sbom` writes CycloneDX 1.5 JSON from `go list -m -json all`: component name,
   version and `pkg:golang/...` purl for every module in the build graph, the Go toolchain version,
   and the release version. Committed as a CI artefact, not to the repository. Chosen over adding
   `cyclonedx-gomod` because the format here is small and stable and a new build tool in every
   contributor's path is a bigger cost than a 60-line generator.

   *Shortcut: components carry no license or hash fields until something consumes them; add them
   when a scanner actually reads this file.*
3. **Upgrade test from the previous release.** A committed SQLite fixture produced by the current
   release (`testdata/db-v1.21.sqlite`, built by a small generator target from a seeded store) is
   opened by `store.Open`, then asserted readable: users, proxies, policies, lists and settings
   round-trip. This is the only test that would have caught a migration that drops a column.

**Not in this batch:** signing and notarised release artefacts. They need a key and a custody
decision the operator owns, and no useful intermediate exists.

## #8 Measured performance harness with a CI gate

- **Request mix.** A generator that builds the same ~200 requests every run (deterministic seed):
  benign GETs, benign POSTs with realistic forms, and known-bad payloads for the SQLi, XSS and RCE
  groups. It feeds `Engine.Inspect` directly, so the numbers do not depend on sockets or TLS.
- **Two measurements.** `go test -bench` over the existing benchmarks for per-request cost, and
  `make perf` which replays the mix through the in-process pipeline at a target rate and prints
  p50/p95/p99, request rate and allocation totals.
- **Gate.** `perf/baseline.json` pins ns/op and allocs/op per benchmark, recorded on the CI runner
  class. CI fails when a benchmark is more than 25% slower or allocates more than 25% more than the
  baseline, and prints the delta plus the exact command to re-record.

  25% is deliberately loose. Absolute latency thresholds on shared CI runners flap; a relative
  baseline catches the regressions that matter (an extra allocation per request, a regex compiled
  in the handler) while tolerating runner noise. When the runner image changes, the gate fails once
   with a clear "re-record the baseline" message rather than silently.

- **Not in this batch:** an external load generator (k6, vegeta) and multi-core scaling curves.
  They answer "what does this box do", which `make perf` already answers; the gate needs only
  "did this commit make the hot path worse".

## #3 Normalization and false-positive safety

One new package, `internal/norm`, called by `internal/waf` immediately before Coraza processes the
request. Three independent checks, each contributing to the existing anomaly score rather than
blocking on its own:

1. **Duplicate parameter names.** Parse the query string and, for form bodies, the parsed form;
   when one name appears more than once with different values, add an anomaly entry naming the
   parameter. Same value repeated is not flagged, so a legitimate `tag=a&tag=a` from a form does not
   score.
2. **Double-encoding mismatch.** Decode the raw query and body once more; when the second decode
   differs from the first, flag it and include both forms in the event detail. This is the
   `%253Cscript%253E` class: the proxy sees `%3Cscript%3E` and Coraza inspects that, while the
   application decodes again and sees `<script>`.
3. **Feed source guard.** `intel.Parse` drops loopback, private, link-local, multicast and
   cloud-metadata prefixes, counting them; `intel` logs the skipped count per fetch. Locally
   uploaded lists are **not** filtered: an operator may deliberately block `10.0.0.0/8` inside
   their own network, and silently dropping that would be a worse failure than the one being fixed.

**Mode.** A new setting `normalization_mode` with `off` (today's behaviour), `flag` (add anomaly,
log) and `block` (raise the anomaly score enough to cross the profile threshold). Default `flag`:
it is visible in the event log, it does not change what visitors experience, and an operator who
wants the protection turns it up deliberately. A per-profile override is not built until someone
asks; the global setting matches how WAF mode already works.

**Tests.** Table tests for the duplicate and double-encode cases across query and form bodies; a
feed-parse test asserting `127.0.0.1/32`, `10.0.0.0/8`, `169.254.1.1/32` and `fd00::/8` are dropped
while `203.0.113.0/24` is kept; an API test that `normalization_mode` round-trips and an invalid
value is refused; one pipeline test that a double-encoded XSS payload in `flag` mode is allowed but
recorded with the new anomaly, and in `block` mode is refused.

## Order and size

| Slice | Size | Depends on |
|---|---|---|
| 9.1 version check | S | — |
| 9.3 upgrade fixture | S–M | — |
| 9.2 SBOM | S | 9.1 (embeds the version) |
| 8.request mix + baseline + CI job | M | existing benchmarks |
| 3.feed guard | S | — |
| 3.duplicate + double-encode + mode | M | — |

Roughly three focused sittings. Nothing here changes the console apart from one setting row, so no
UI redesign is involved.

## Calls made here (correct them if wrong)

- **Signing deferred**, because it needs a key the operator must own.
- **SBOM is hand-rolled**, not a new tool.
- **The performance gate is relative**, not absolute.
- **Normalization defaults to flag**, not block, because a false positive in `block` mode takes a
  site down.
- **Local list uploads keep private ranges**, feeds do not.

## Out of scope

Items 1, 2, 4, 5, 6, 7, 10. Item 1 (declarative config) is agreed to be readable YAML export/import
only when it comes up, and item 10 shrinks to hashed audit plus MCP scopes for a small admin team.
