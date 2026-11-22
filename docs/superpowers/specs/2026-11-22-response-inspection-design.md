# Response-side inspection: "was the answer safe?"

Design for roadmap item **2**, written for approval before implementation. Decisions were recorded in
`2026-11-22-request-simulator-design.md`; this document turns them into an implementable scope.

## Why

Every check today looks at the request. A compromised or buggy upstream can still send a response
that carries an attack to the visitor's browser — a reflected XSS payload, a script tag from a
tampered template, an SQL error page that leaks the query — and the proxy forwards it untouched.
The CRS response rules (950–958 data leakage, plus the 959 outbound anomaly evaluation) already
exist in the embedded rule set; nothing runs them. They cover leaky error pages, not reflected XSS —
the XSS rules are request-phase only.

## What exists (checked)

- `httputil.ReverseProxy` is built per edge in `internal/proxy/server.go`. It has `Rewrite`,
  `Transport`, `FlushInterval` and an `ErrorHandler`, but **no `ModifyResponse`**. It is created
  once per host and shared by every request, so per-request state must travel in the request
  context, not in a struct field.
- The response path is `rw (responseWriter) → gzipWriter → cacheWriter? → capWriter? → ReverseProxy`.
  `capWriter` enforces `profile.MaxResponse`; the cache sits outside it. Nothing inspects content.
- `waf.Engine` compiles the CRS with per-profile exceptions and holds a Coraza instance. A fresh
  `tx := waf.NewTransaction()` is used per inspection and closed after it; response phases are not
  processed today.
- `policy.ProfileFor` gives the proxy edge its `model.Profile`, which already carries mode, anomaly
  threshold, paranoia and exceptions. `model.Profile.MaxResponse` is the cut-off (up to 64 MiB in
  presets) and is **not** a safe buffer size.
- Events carry `stage`, `rule_id`, `rule_msg`, `action`, `status`, so a response verdict needs no
  new columns.

## Decisions taken (from the approved simulator design)

- Inspect **bounded**: buffer up to a limit, then decide.
- Pass `text/event-stream`, protocol upgrades, range requests and oversize bodies straight through,
  and record them as uninspected with the reason.
- **Headers are always inspected**, even when the body is skipped.
- Blocking happens in `ModifyResponse`, before any header is flushed.

## Approaches considered

1. **Streaming inspection with a rolling buffer.** Inspect as bytes pass, cut the connection when a
   rule fires. Cheapest memory, but a rule that needs the whole body fires after the browser already
   has the prefix, and the client sees a truncated page with no status. Rejected as the default.
2. **Buffer the whole response, inspect, then copy.** Simplest correct answer for every body, but
   the ceiling presets allow up to 64 MiB per in-flight response; a handful of concurrent downloads
   would exhaust the box. Rejected.
3. **Bounded buffer with skip-and-record.** Read up to the inspection limit, inspect, and either
   replace the body with `buffered + rest` (allowed) or refuse it before the status line is written
   (blocked). Anything that cannot be inspected honestly is passed through and recorded. **Chosen.**

## Design

### Limit and scope

- New per-profile field `responses`: `off` (default) | `flag` | `block`. Off keeps today's
  behaviour for every existing site; an upgrade must not silently add latency or break a response.
- The inspection buffer is `profile.MaxBody` (the request body limit, 128 KiB default, 1 MiB at the
  top end), **not** `MaxResponse`. `MaxResponse` keeps cutting oversized responses exactly as now.
- A response larger than the buffer is forwarded **uninspected** and logged with the reason. This is
  the deliberate trade-off: no partial inspection, because CRS response rules are written against a
  complete body and a partial body produces both misses and false positives. A declared
  `Content-Length` over the limit skips without reading; chunked/undisclosed length is read up to
  the limit, and if it overruns, the bytes read are replayed ahead of the rest so the client still
  receives the whole response.
- Skipped, with the reason recorded:
  - `Content-Type: text/event-stream`
  - any `Upgrade` (WebSocket and other protocol switches)
  - a request with `Range` (206 partial content)
  - `Content-Encoding` other than empty/`identity` (the body is compressed; inspecting it is noise)
  - no body: `HEAD`, 204, 304
  - a declared length above the buffer
- Headers are processed for every response that is not an upgrade, including the skipped ones, so a
  dangerous `Set-Cookie` or `Content-Type` is still caught.

### WAF: response phase

Add to `internal/waf`:

```go
type ResponseInput struct {
    Status  int
    Proto   string
    Header  http.Header
    Body    []byte
}

func (e *Engine) InspectResponse(in ResponseInput) (Result, []Match)
```

It opens one transaction, calls `ProcessResponseHeaders`, writes and processes the buffered body,
and returns the best rule plus the full match list, reusing the same severity/aggregator/exceptions
logic as `InspectAll`. Exceptions already compiled as `SecRuleRemoveById` apply unchanged. The
transaction is separate from the request one: response rules only read `RESPONSE_*` variables, so a
second transaction is correct and keeps request latency unchanged. A transaction that starts at the
response phase never runs the CRS setup, so `compile` also sets the blocking/detection paranoia
levels, the outbound threshold and the anomaly score weights in a phase-3 `SecAction`; without them
the 959 outbound evaluation lets everything through.

Anomaly mode is honoured: in `flag` the rule is reported as a log; in `block` the response is
refused. A profile `mode: detect` still forwards but logs.

### Proxy: ModifyResponse

Per request, `ServeHTTP` puts a `*respVerdict` in the context. `ModifyResponse`:

1. Leaves upgrades and `text/event-stream` alone (recorded as skipped).
2. Buffers up to the limit (`io.LimitReader` + a check for another byte), runs
   `InspectResponse`, and sets the verdict on `*respVerdict`.
3. On a block, returns `errResponseBlocked` **before touching headers**. The existing `ErrorHandler`
   already refuses to write after headers are sent, so it answers a uniform 502. The status line and
   body never reach the client.
4. On allow/log, replaces `resp.Body` with `io.NopCloser(io.MultiReader(bytes.NewReader(buffered), rest))`
   and lets the normal path (gzip, cache, cap) run.

`respVerdict` carries stage, rule, message, action and a `skipped` reason, so the deferred event
writer sets `stage = "response-waf"` (or `response-skipped`) and the right action without new
plumbing. Blocked responses are never cached: `ModifyResponse` returning an error prevents the
cache writer from seeing a status.

Detection (`flag`) still forwards the body; the event shows `action: log`, `stage: response-waf`.

### API and UI

- `GET/PUT /api/profiles` accept `responses` with the same three values; invalid values are a 400,
  matching `normalization_mode`.
- Policies → WAF profiles gains a **Responses** select (`off` / `flag` / `block`) with one line of
  help: the buffer limit and that larger, streamed, ranged and compressed responses are not
  inspected.
- No new page or filter: the Logs stage filter gains `response-waf`.

### Events and operation

- Block: `stage=response-waf`, `rule_id=<id>`, `rule_msg=<label>: <message>`, `status=502` (the
  client sees 502 because the upstream's answer was refused; the site's status is unchanged in the
  log's `status` field only if the upstream had already sent one — it has not, since this happens
  before the status line).
- Skip: `stage=response-skipped`, `rule_id` is the reason (`sse`, `upgrade`, `range`, `encoded`,
  `too-large`, `no-body`), action `allow`.
- No audit entries: this is per-request enforcement, like the request WAF.

## Non-goals

- No decompression for inspection (a compressed body is skipped and recorded).
- No partial-body inspection, no trailer inspection, no response normalization.
- No per-route or per-content-type rules beyond the skip list above.
- No statistics page changes; item 5's `/metrics` can count the skip reasons later.

## Risks

- **Memory.** Each concurrently inspected response holds up to the buffer. With the 128 KiB default
  and the console's in-flight cap (128) the worst case is 16 MiB; a 1 MiB profile raises that to
  128 MiB. The field is documented next to `MaxBody` for that reason.
- **False positives.** A CRS response rule can refuse a legitimate page. Default `off` plus `flag`
  first is the intended rollout; the simulator does not cover responses (non-goal of item 4).
- **Latency.** First byte is delayed until the buffer is full, the body ends, or the limit is hit
  (bounded by the upstream's write time). Streaming sites should stay on `off`.

## Tests

- `waf`: header-only block; body block for an XSS payload in an HTML response; an excepted rule does
  not block; detect mode reports a match without blocking.
- `proxy`: blocked response returns 502 and the upstream body never reaches the client; allowed
  response is byte-identical (compare the full body); SSE, `Range`, `Content-Encoding: gzip`, HEAD
  and a body over the limit are forwarded and recorded as skipped with the reason; `flag` forwards
  but logs; a blocked response is not cached.
- `api`: profile `responses` round-trips and rejects an unknown value.
- `perf`: a benchmark of the buffered path stays inside the existing gate; record a new baseline if
  the deliberate cost moves allocations.

## Slices

1. `waf.InspectResponse` + tests (no wiring).
2. Profile field, API validation, UI select, Logs stage filter.
3. `ModifyResponse` buffering, verdict plumbing, event stage, proxy tests.
4. README/CHANGELOG, version bump, deslop, push.

Item **5** (observability) remains as recorded: 5a is `/metrics` plus audit CSV/JSON export; traces
are deferred.
