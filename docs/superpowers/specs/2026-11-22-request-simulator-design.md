# Request simulator: "why was this blocked?"

Design for roadmap item **4**, and the recorded decisions for items **2** and **5** that follow.
Approved in conversation on 2026-11-22: simulator first, then response-side inspection, then
observability. Written before implementation; no product code exists yet.

## Why

Today an operator sees one row in Events — `rule_id`, a label, a path — and has to infer which stage
refused the request and why. The only way to test a suspicion is to send the request again at the
live site and watch. That is slow, and when the answer is a false positive it is also the moment
someone edits a shared profile blind.

The simulator replays one request through the real pipeline, reports every stage's verdict and every
rule that matched, and can except the offending rule with the blast radius named before it is saved.

## What exists (checked)

- `policy.Screen` and `policy.Inspect` are the real pipeline and take a `policy.Request`; neither
  needs a socket. They are what the simulator will call.
- `waf.Engine.Inspect` collapses matched rules to one "best" rule plus a label, discarding the rest
  of `tx.MatchedRules()`. A simulator needs the whole list, so that traversal has to be factored out
  rather than duplicated.
- CRS exceptions live on `model.Profile.Exceptions` (comma-separated rule IDs) and a profile is
  shared by every proxy that names it. `ListProxies` gives the affected hosts; the New proxy dialog
  already picks a profile, so the concept is familiar.
- `model.Event` carries src IP, host, method, path, status, stage, rule ID, message and UA — enough
  to prefill a simulation except the body, which is not stored.
- RBAC maps routes by prefix; `POST /api/simulate` would otherwise be judged `settings.write`.
- Events already have a row detail panel; the entry point belongs there.

## Approaches considered

1. **Replay through the proxy against the live upstream.** Truest possible answer, but it sends
   traffic at a real backend, mutates rate-limit and ban state, and needs an upstream that is up.
   Rejected: the simulator must be safe to press on a production host.
2. **Static rule checker (WAF only).** Cheap, but it would say "allowed" for a request a ban or an
   IP allowlist would refuse, which is exactly the confusion this feature exists to remove. Rejected
   as the default.
3. **In-process pipeline replay with a full match list.** Calls the same `Screen`/`Inspect` code
   with a synthetic request, reports the per-stage verdict, lists every rule, skips only the stages
   that need external state (rate limit, forward-auth calls) and says so. **Chosen** — truthful for
   everything that can be decided locally, with no side effects.

## Design

### WAF: one traversal, two views

Extract the matched-rule walk into `Engine.InspectAll(r, body, ip) (Result, []Match)` where
`Match{RuleID, Message, Severity, Disruptive}` is one row. `Inspect` becomes a thin call that keeps
its current behaviour exactly (best rule, exception filtering, interruption handling); the simulator
uses the full list. Normalization findings ride along in `Result.Norm` as they already do, so the
simulator reports them too.

Refactor rule: the existing `Inspect` must return identical results before and after. The WAF and
policy test suites are the guard; a first commit is the refactor alone.

### Policy: a dry run

`Engine.Simulate(in SimRequest) SimResult`, both new types in `policy`:

- Runs, in pipeline order: the ban engine (`Match`, temporary and permanent), `Screen`, then WAF.
- Records a stage result for each, `{stage, verdict, reason, rule_ids}`.
- Rate limiting is **not** evaluated (it is per-address state; a simulation must not spend it) and
  is reported as `skipped: "rate limit is stateful"`.
- The access gate and forward auth are **not** performed. The result says what would happen:
  `gate_mode` of the proxy, and for `forward_auth` the provider name — no outbound request.
- Route selection runs last, read-only, and names the upstream and route that would serve the
  request, so a "why does this go to the wrong app" question is answered too.

### API

`POST /api/simulate`, JSON:

```json
{"proxy_id": 3, "method": "GET", "path": "/item", "query": "id=1%27+OR+1%3D1",
 "headers": {"X-Forwarded-For": "203.0.113.7"}, "body": "", "client_ip": "203.0.113.7"}
```

- `proxy_id` is required and must exist, else 404 — the simulator always answers for a real site.
- `client_ip` optional, defaults to `203.0.113.10` (a documentation address) so geo/ASN rules have
  something valid to read.
- `body` is read up to the proxy's WAF body limit and truncated beyond it, with a `truncated` flag
  in the response. Headers are capped at 32 entries and 8 KB total.
- Response: `{"verdict": {...}, "stages": [...], "matches": [...], "upstream": "...", "notes": [...]}`
  where `notes` carries the skipped stages.
- RBAC: `permissionFor` gets an explicit case for `/api/simulate` returning `policies.read` — the
  call is read-only despite being a POST.
- Nothing is audited and nothing is persisted: a simulation is not an event.

### Exception, with the blast radius

When a stage is blocked by a CRS rule, the response adds:

```json
{"exception": {"profile_id": 2, "profile": "Strict", "rule_id": 942100,
  "other_hosts": ["shop.example.com", "docs.example.com"]}}
```

`other_hosts` is computed from `ListProxies` filtered by profile, minus the site being simulated.
The UI's confirm dialog names them ("This also stops rule 942100 for shop.example.com and
docs.example.com"), and saving reuses the existing profile update (`PUT /api/profiles/{id}` with the
appended ID) — no new mutation endpoint, and the change lands in the audit log the way it does today.

### UI

Events → row action **Why?** opens a modal prefilled from the event: host (resolved to its proxy),
src IP, method, path and UA. Fields for query and body are editable (the body starts empty with a
one-line note that it is not recorded). The result renders as the ordered stage list with the
blocking stage marked, the matched rules, the upstream that would serve it, and the exception button
when one applies. Failures stay in the modal.

## Non-goals

- No replay against the real upstream, no response inspection, no synthetic traffic.
- No rate-limit, gate-session or forward-auth simulation (stated in the result, not guessed).
- No saved simulations, history or sharing; no bulk paste.
- No per-site exceptions; that remains a separate decision.

## Tests

- WAF: `InspectAll` returns several rule IDs for one SQL injection and `Inspect` still reports the
  same best rule as before the refactor (run the existing suites unchanged).
- Policy: a banned address, a blocked country and a CRS block each report the right stage; a clean
  request reports route selection and no block; a normalize-flagged request appears in the results.
- API: blocked and allowed simulations for a proxy, 404 for an unknown proxy, 400 for a non-loopback
  size overrun, and a viewer (traffic.read, no policies.read) is refused.
- Exception: `other_hosts` lists the other proxies on the profile and excludes the simulated one.
- UI: one component test for the modal's rendering of a blocked result, following the existing
  component-test pattern.

## Slices

1. WAF refactor: `InspectAll`, `Inspect` unchanged behaviour, tests green.
2. Policy `Simulate` + unit tests.
3. API endpoint + RBAC + tests.
4. Events row action, modal, exception confirm + component test.
5. README/CHANGELOG, version bump, deslop, push.

## Later items, decisions recorded

- **2 — response-side WAF** (next after this): bounded buffer. Buffer up to the profile body limit
  and inspect; pass `text/event-stream`, protocol upgrades, range requests and anything larger
  straight through, recorded as uninspected with the reason. Headers always inspected. Blocking
  happens in `ModifyResponse` before headers are flushed.
- **5 — observability** (after 2): split. 5a is a `/metrics` scrape endpoint over the counters that
  already exist plus audit CSV/JSON export; 5b is traces, deferred until there is a collector to
  send them to.
