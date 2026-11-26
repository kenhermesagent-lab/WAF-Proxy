# Security scan

**Status:** built for 1.77.0. Steps 0–7 below landed: the runner and differential core, the probe
path and preflight, the gate suite, fingerprints and the CVE join, the schedule and alerts, the
API and permissions, and the page and docs. The hostname-first path has not been exercised
against a real edge or hairpin-NAT path; the listener fallback is what a local run uses, so the
page's `edge` claim remains unproven.
**Page:** `#/security` — sidebar **System → Security scan**, between Cloudflare and Sites.
**Mockup:** [`docs/design/security-scan-mockup.html`](design/security-scan-mockup.html)

A built-in scanner that attacks this node's own published hostnames the way a stranger
would, records what each layer did with the request, and joins what it finds to public
vulnerability data so an operator knows whether the app behind the WAF needs a patch — and
what to put in front of it until the patch lands.

It is not a general-purpose penetration-testing tool, cannot be aimed at a third party, and
never changes anything on the backend application.

---

## 1. What it is allowed to do

Four rules bound the whole feature. Every one of them is enforced on the server, not in the
page, because the page is only a view.

| # | Rule | Enforcement |
|---|------|-------------|
| S1 | **Read-only toward the backend.** The scanner may send `GET`, `HEAD`, `OPTIONS` and `TRACE` to the application, and `POST` only to two endpoints it cannot choose: the proxy's own gate login, and the run's random probe path, which preflight has proven answers the application's own 404. No `PUT`, `PATCH`, `DELETE`, no form submissions, no uploads. | Method allowlist in the probe runner; a body probe is never built before preflight returned 404 for the probe path, and the upstream probe client refuses anything else before the request is built. |
| S2 | **Attack traffic is addressed to a path the app does not implement.** Body- and query-borne attack classes go to `/.wafscan/<run-id>/<seq>`, a random segment verified in preflight to return the app's own 404 with no side effect. A WAF miss therefore lands on a 404 handler, not on an application action. | Preflight probe; if the path answers `200` (a catch-all or SPA router) body probes are skipped and reported as *not run — catch-all route* rather than sent. |
| S3 | **Only the owner's own sites.** Targets are ids resolved server-side from proxy records the signed-in account may read; a run body never contains a URL. Ownership is re-checked when the run starts, so a site handed to another tenant mid-flight is refused. | Target resolver + per-run authorization; refusal is audited. |
| S4 | **Nothing is written to the app, and nothing is written to the console that changes a site.** The only console writes are the scan's own records, a test gate account if the operator created one for it, and the audit entry. | Separate store tables; the scanner has no access to the proxy config writer. |

Four consequences worth stating plainly:

- **It tries the published hostname first, then falls back to this node's listener.** The
  scanner dials `https://<hostname>` as a visitor would, so an edge in front of the name is
  exercised whenever the hostname is routable from inside the node. If the hostname does not
  resolve, its port is unreachable, or the request times out, the scanner dials the WAN listener
  the node bound (a wildcard bind dials loopback) at the listener's address and port, with the
  proxy's hostname as `Host` and as the certificate name. A connection that is accepted and then
  never answers within the probe timeout is a timeout like any other, so a hostname that takes
  the connection and stalls still falls back. A certificate error is not retried: the listener
  presents the same name, so the error is reported instead. The run records which endpoint
  answered: when the run proceeds after a fallback, its first evidence row names the listener
  and the failed hostname; a run that stops says so in its skip reason, including both
  endpoints when both fail. Every run records the path it actually took: `edge` when the
  response carries `CF-Ray` and the same probe id appears in the request log, `local` when it
  did not. A `local` run says so on the page, and its findings are worded as this node's WAF,
  never as the operator's edge.
- **A control probe decides whether "blocked" means anything.** One harmless request per class
  (`?id=1`, no payload) runs alongside the attack payloads. If the control is itself refused —
  Under Attack mode, a geo or ASN block, a rate limit — every block in that class becomes
  `inconclusive`, because the run cannot tell a targeted rule from a blanket refusal.
- **The scanner cannot ban the node it runs on.** A run mints a random token, sends it on every
  probe, and holds it only while the run is open. Traffic carrying a live token is exempt from
  the decoy and ban rules, so a `/.env` probe is still refused but no longer bans the address
  the node egresses from; a ban left by an earlier build is removed when the run ends. The
  token does **not** skip the rate or login limits: a run must see the same `429` a stranger
  gets, and the refusal writes no ban for the scanner.
  Limits (below) still cap it at 12 requests/second, abort it on `429`, and hold gate-login
  failures to two per run. A run that reaches an edge can still trip that edge's own limits.
- **A WAF miss is visible to the app.** A 404 is still handled by the application process. The
  probe path is random and read-only, so the app does nothing with it, but the request does
  arrive. That is the point: an unarmed scanner cannot prove a bypass.
- **An exposure finding is closed by a control and a proving rerun, not by a click alone.** The
  finding's row offers *Block & retest*: it adds the leaking path to that hostname's own block
  list, so the proxy answers the path (and everything below it) with `403` before the gate and the
  WAF, then reruns the target with trigger `remediation`. The finding resolves only when the new
  run's evidence shows the published path refused the probe or the application no longer serves
  it; a skipped, failed or still-reachable rerun leaves it open. The block never exempts the
  scanner, so the rerun observes the same refusal a stranger gets. The host's block list holds at
  most 32 paths, the same limit the editor enforces: a list already at 32 cannot take another
  path, so *Block & retest* answers `409` with the limit, stores nothing and starts no rerun. The
  stored list is left exactly as it was, so the operator removes a path (or blocks the leak
  another way) and retries. It closes reachability, not the leak: removing the file is still the
  application's job.

### The scanner's own threat model

The scanner is a privileged component that makes outbound requests, which is the shape of an
SSRF gadget. It gets the same treatment as any other request-building code.

| Risk | Control |
|------|---------|
| Someone points it at a third party | Targets come from proxy records; no free-form URL, host or header field exists in the API |
| Targets are used to reach link-local metadata | The direct-upstream probe uses the literal upstream address from the proxy record, never a name the operator typed; `169.254.0.0/16` and `fd00:ec2::254` are refused even there |
| Evidence leaks secrets | `Set-Cookie` values, `Authorization`, `?token=`/`?key=` query values and gate passwords are stripped before storage; only names and hashes are kept. Nothing from a path that exists to leak credentials is stored at all (below) |
| The test gate account becomes a back door | Accounts created for scanning are flagged `scan_only`, get no access to any hostname except the ones explicitly bound, and are listed on the Access gate page with the scanner as their origin |
| Probe traffic hides in the logs forever | Every probe carries `X-Scan-Probe: <run-id>-<seq>`, and the request log keeps the row; retention follows the log's own retention |
| A tenant scans the host console | A tenant run may only target proxies of its own site; console hostnames are host-console targets only |
| A client forges the ban exemption | The token is 32 random bytes minted per run, held in memory only while that run is open, never written to evidence or forwarded upstream; a token no run holds is treated as any other header |

---

## 2. The model: three layers, proven by comparison

The question the operator asks is "did it get through?" — and the honest answer is not a
status code from one request. It is a comparison.

Each probe is sent up to three times:

1. **Through the published path** — `Host: <hostname>` to the published hostname first (the
   edge path, plus whatever fronts it, as recorded by the path check above). If the hostname
   does not resolve, its port is unreachable or the request times out, the same request goes to
   the node's WAN listener at the address and port it bound.
2. **Directly to the upstream** — the same method, path, headers and body, sent to the
   upstream address in the proxy record, with `Host` preserved.
3. **A benign control** — the same method and path with a harmless value and no payload, so a
   blanket refusal is distinguishable from a targeted one. Controls are sent once per class,
   not once per probe.

The two responses are compared on status, body hash, `Server`, `X-Powered-By`, the app's own
marker headers and redirect target. Body comparison uses a similarity ratio and retries once,
so a timestamp in the footer produces *inconclusive*, not a fabricated *reached backend*.

| Verdict | Meaning | Consequence |
|---------|---------|-------------|
| `blocked-waf` | WAN response is a WAF refusal (`403`/`406`/`429` with the block body); the direct request returns something else | Protected. The rule id comes from the request log row carrying this probe's token, so the report names the signature that fired |
| `blocked-gate` | WAN response is the gate challenge (`302` to the gate, `401` on `XHR`); the app body is absent | Covered by a compensating control — reported as *covered*, never as *patched* |
| `reached-backend` | WAN response is byte-similar to the direct response | The layer in front of the app did not stop this class of request. Severity follows the payload class |
| `inconclusive` | Bodies differ for reasons unrelated to the request (dynamic content, A/B routing, `Set-Cookie` rotation), or the harmless control for that class was refused | Retried once, then reported as inconclusive; never raised as a finding |
| `not-run` | Preflight or a guard blocked the probe (catch-all route, stream not buffered, site opted out, class not applicable in this gate mode) | Shown in the run with the reason, and counted as uncovered |
| `not-blocked` | A WAN-only probe — a framing or wire shape `net/http` cannot replay, sent on its own connection — was not refused by the published path. The upstream half is skipped on purpose | Reported as *the edge accepted the shape*, never as patched or bypassed |

A finding is only raised after the same verdict appears twice in a row. A single flaky
response is noise, and noise is what makes operators stop reading.

---

## 3. Probe catalogue

Grouped by the layer being tested. `≈` marks a probe that needs the gate test account.
Everything totals about 66 probes and 120 requests per site, which is roughly 12 seconds at
the default rate.

### 3.1 Preflight (no attack traffic)

The published hostname answers, or the listener fallback answers over TLS with the hostname as
`Host` and SNI · which path the probe took (`edge` or `local`, see §1) · upstream answers ·
upstream TLS handshake, version
and cipher (if `https`) · whether the random probe path 404s · whether the benign control for
each class answers `2xx`/`4xx` as expected · streaming routes excluded · site enabled or in
maintenance · gate mode (`off`, `passphrase`, `accounts`, `accounts_totp`, `forward-auth`) ·
gate test account bound to this hostname.

### 3.2 Edge and protocol

Methods the site should not accept (`TRACE`, `PUT`, `DELETE`, `OPTIONS *`) · `Content-Type` the
profile refuses · body one byte over the site ceiling (expect `413`) · header count and size
ceilings · duplicate `Content-Length` · `Content-Length` + `Transfer-Encoding` disagreement
(CL.TE / TE.CL) · absolute-form request target · `HTTP/1.0` · `Host` with alternate casing and
trailing dot · `X-Forwarded-Host` / `X-Original-URL` override · null byte in path · `..%2f`
and `%252e%252e%252f` traversal · semicolon path parameters · overlong UTF-8 path.

The two framing-confusion probes are **WAN-only**. They are never replayed to the real
upstream: a connection desynchronised on purpose is a connection other people's requests are
using, and damaging the backend is not a read-only test. Their verdict comes from the WAN
response alone (`blocked`/`not blocked`), and the run says the upstream half was skipped.

### 3.3 WAF signature families

SQL injection (`UNION`, boolean, stacked, comment-obfuscated) · XSS (reflected, attribute,
`javascript:` URL, SVG event) · command injection (`;`, `|`, `$()`, backticks) · local file
inclusion and traversal · SSRF-shaped parameters · XXE in an XML body · Log4Shell JNDI in
`User-Agent`, `X-Api-Version` and a cookie · Shellshock `User-Agent` · restricted-header abuse
on a page view · oversized JSON depth · multipart boundary abuse. Twenty-one classes.

Every one is a read-only request against `/.wafscan/…` (S2). Two families are deliberately
excluded:

- **Time-based blind SQLi.** Proving it requires a measurable delay on a real query, which
  means the query has to run.
- **Scanner fingerprints and bot-filter probes** (`sqlmap`/`nikto` UA, known crawler UA,
  absent UA, UA/`Sec-CH-UA` mismatch). The bot filter has its own page and its own tests, a
  mismatch mostly proves that an existing feature works, and a burst of bot-shaped requests is
  the single highest ban risk in the list for the smallest return.

### 3.4 Access gate surface

This is the part the request called out: the gate itself must be tested, not just counted. The
login endpoint is `POST /__wafproxy/gate` (`gate.LoginPath`).

| Probe | Expected |
|-------|----------|
| G1 unauthenticated request to a protected path | challenge; app body absent |
| G2 gate static assets only under the gate prefix | no app asset served pre-auth |
| G3 tampered session cookie (one byte flipped) | rejected |
| G4 session fixation: pre-set cookie, then sign in | cookie rotated on sign-in |
| G5 old cookie after sign-out ≈ | rejected |
| G6 two wrong passphrases, 30 s apart | identical status, body and length |
| G7 ban ladder armed | the two G6 failures are recorded and the ladder thresholds are configured — reported *armed, not tripped* |
| G8 wrong password for a real account and for a name that does not exist ≈ | same status, body and length; no username enumeration |
| G9 cross-origin login `POST` with `Origin: https://evil.example` | refused |
| G10 `?next=//evil.example` and `?next=/\evil.example` after sign-in | stays on the site |
| G11 gate response caching | `no-store`; a second unauthenticated fetch cannot return the signed-in page |
| G12 path and method bypass around the gate | `//path`, `/path;.css`, `/PATH`, `/path%00`, `/path/..;/`, `Upgrade: websocket`, `Range` on a gated response — all challenged |
| G13 gate mode sanity | a hostname whose gate is `off` while the site is an admin UI is a configuration finding, not an attack |

`forward-auth` hostnames run a different three probes, because the gate is not ours:

| Probe | Expected |
|-------|----------|
| F1 provider unreachable | `503`; the site stays closed, never open |
| F2 client-supplied identity headers (`X-Auth-Request-User`, `X-Forwarded-User`, `Remote-User`) | stripped or ignored; only the provider's answer decides |
| F3 provider redirect | `302` to the provider, no app body |

G3–G12 are reported *not applicable* in `forward-auth` mode. F1 needs a provider the operator
is willing to see fail; where that is not arranged, it is reported **not tested**, never passed.

`≈` probes sign in with a dedicated gate account the operator creates once (Access gate →
Accounts, flagged `scan_only`), stored sealed like any other credential, used only for these
checks and signed out at the end of the run. Without that account the authenticated probes are
reported as **not tested**, and the page says so — a green gate result built on untested checks
would be worse than no result.

Three things this list does on purpose:

- **It never trips the lockout.** `gate.fail` records a failure, and three failures from one
  address in ten minutes add a 15-minute ban; five attempts on one username lock that account
  for 15 minutes. So G6 and G8 send **two** failures each, spaced, and the ladder is verified
  from configuration and from those two recorded rows. An operator who wants to see a ban happen
  can do it by hand.
- **It does not test the timing of the failure path.** The gate answers every failure with one
  uniform page and a dummy verify for unknown accounts; measuring a handful of response times
  would only add noise, exactly like the blind-SQLi exclusion above.
- **It no longer tries to replay a TOTP code.** That would require the scanner to hold the test
  account's TOTP seed — a live second factor in a scanner process — and the control is cheaper
  and better proven in the gate's own tests. The review found that control missing, so it is
  fixed before this feature is built (§12, step 0).
- **Header hardening is not scanned here.** HSTS, CSP, `X-Frame-Options` and the version banner
  on the gate page are what the protection profile's header audit already reports per hostname;
  a finding links there instead of duplicating it.

### 3.5 Backend and CVE mapping (unauthenticated, read-only)

Fingerprint: `Server`, `X-Powered-By`, generator meta, product status endpoints
(`/status.php`, `/api/version`, `/rest/system/info` where public), login-page markers. TLS
version and cipher of the upstream. Hygiene: HSTS, CSP, `X-Content-Type-Options`, cookie
`Secure`/`HttpOnly`/`SameSite`, directory listing, error-page stack trace.

Then exposure, by status code only: `/.git/config`, `/.env`, `/server-status` and
`/actuator/env`. For these the scanner keeps the status, the length and the header names —
**no body bytes at all**. A scanner must never keep a copy of the file that exists precisely
because it holds credentials; the finding says which path answered and which handler served it.

When the published path refuses a served file, the finding is still raised unless the refusal
comes from that host's own block list — the control the finding's *Block & retest* action
installs. A path covered by that list is no longer reported, and a reachable one is a high
finding again if the block is later removed.

Then the join: `product + version` → advisories → KEV flag → the finding that matters, e.g.
*"Nextcloud 27.1.2 matches CVE-2024-XXXX, added to KEV 2024-09-02; the WAF has no signature
for it and the gate is off. Add an access gate until you upgrade."*

The recommendation is always one of: **patch**, **compensate** (gate, WAF rule, remove
exposure), or **accept** (with a reason and a review date). The scanner never claims a
compensating control is a fix.

---

## 4. Severity

CVSS where a CVE exists; a plain internal scale where none does. The two are shown separately
so the page never implies precision it does not have.

| Level | Rule |
|-------|------|
| Critical | Attack reached the backend, class is directly exploitable (SQLi, RCE, auth bypass), and nothing compensates |
| High | Reached the backend with a lower-impact class, or a gate bypass, or a KEV CVE on a reachable component |
| Medium | Blocked, but only by a narrow or easily-evaded rule; gate off on a KEV-affected app; verbose error disclosure |
| Low | Hygiene: missing headers, version banner, cookie flags |
| Info | Layer reachable, no issue observed |

Posture is a **state**, not a grade: `exposed` (a finding reached the backend, or a gate check
failed), `covered` (everything blocked, and the compensating control is named), `unknown` (a
feed is stale, fingerprinting failed, or a control probe was refused). A number out of 100
across sites with different probe counts invites a comparison that means nothing, so the
weighted roll-up (KEV 40, unblocked reachable issue 30, gate weakness 20, hygiene 10) is used
only to order the attention list.

---

## 5. CVE intelligence: where it comes from and what it costs on disk

Three sources, chosen so the node stays small. Nothing here is a mirror of a national database.

| Source | Use | Cadence | Disk |
|--------|-----|---------|------|
| **CISA KEV** (`known_exploited_vulnerabilities.json`) | "is this being exploited right now?" — the only source that escalates a low CVSS to immediate | every 24 h, `ETag`/`If-Modified-Since`, weekdays are when CISA edits it | ~1.5–2 MB, one snapshot |
| **OSV** (`api.osv.dev/v1/query`) | advisories for a *backend* component + exact version, across npm, PyPI, Maven, Go, Packagist and container ecosystems; the CVSS vector already parses with `updates.CVSSv3Score` | on every run for components seen, plus a weekly re-query of everything watched | response cache capped at 8 MB, LRU |
| **Built-in fingerprints** | banner → product/version, ~60 signatures shipped in the binary | with the release | ~40–60 KB |

Deliberately excluded:

- **NVD, entirely.** OSV already returns the CVSS v3 vector and a summary, and KEV answers the
  only question that changes urgency. NVD would add CWE labels and prose through a
  third network dependency rate-limited to 5 requests per 30 seconds — for a description the
  operator can read on the advisory page the finding links to.
- **A full NVD mirror.** The yearly JSON feeds are tens of MB each compressed and the whole
  corpus runs to hundreds of MB on disk, for data that mostly answers questions nobody asked.
- **Nuclei and its template tree.** 50–80 MB of binary plus a template set that grows weekly,
  and it is a second moving engine to keep patched.
- **The node's own packages and build.** `internal/updates` already queries OSV for every host
  package and reports advisories on the Updates page; the scanner watches the applications
  behind the proxies, not itself.

Storage budget, default cap **30 MB**, oldest evidence pruned first:

```
KEV snapshot          2 MB
OSV cache            ≤8 MB
advisory rows       ≤10 MB
scan evidence        ≤8 MB   (hash, status, header names, rule id; body ≤2 KB only when reached-backend)
fingerprints        60 KB
```

### Freshness rules

- Each source has a cadence; a source older than **3× cadence** puts a banner on the page and
  turns dependent results into **unknown**.
- A failed fetch keeps the last good snapshot and records the failure; it never silently
  returns "no known vulnerabilities".
- Parsing is strict: HTTPS only, no cross-host redirects, size cap, schema check, hash stored
  alongside the snapshot so the page can show exactly what the node believed and when.
- Offline installs work: the shipped fingerprint table and the last KEV snapshot remain valid,
  so backend CVEs still match; only newly published advisories are missed until the next
  successful sync.

---

## 6. Run flow

```
manual "Run scan" ──or── schedule (leader node only)
            │
            ▼
   authorize: permission security.write
   + target ids → proxies visible to this account
            │
            ▼
   preflight: DNS · listener · path taken (edge|local) · upstream · TLS
              probe-path 404 · benign controls · streaming/opt-out · gate mode
            │
   ┌────────┴─────────┬──────────────────┐
   ▼                  ▼                  ▼
edge/protocol     WAF families      gate surface
(framing probes   (read-only,       (G1–G13 built-in,
 WAN-only)         token-tagged)     F1–F3 forward-auth,
                  │                  authenticated subset
                  │                  needs test account)
   └────────┬─────────┴──────────────────┘
            ▼
   differential compare with direct upstream
   (control refused → inconclusive, never a finding)
            │
    ┌───────┴────────┐
    ▼                ▼
blocked / gate    reached backend
    │                │
    │         fingerprint + CVE join (KEV, OSV)
    ▼                ▼
evidence + rule   finding + fix + compensating control
            │
            ▼
   run record · findings delta (new / still open / resolved)
            │
            ▼
   alerts (new high+ immediately, KEV even if low, digest otherwise)
```

A run is a sequence of immutable probe records plus a verdict per stage. Deleting a run
deletes evidence, never history that a finding existed.

---

## 7. Scheduling, alerting and limits

**Schedule.** Per-site, not global: daily / weekly / monthly, a start hour in local time,
a ±15 min jitter, and *skip when nothing changed* (proxy config hash + fingerprint hash +
WAF-Proxy version unchanged → the run is recorded as skipped, not repeated). Triggers on top
of the schedule:

- **After a configuration change** to the site's WAF, gate or routes — the common way a site
  becomes weak is an edit, not a release.
- **After a WAF-Proxy upgrade** — a regression check on the gate and the WAF corpus.
- **When a new KEV entry matches a watched component** — event-driven, the highest-value run
  there is, because it is exactly the situation where patching is urgent.

A certificate change is not a trigger: the certificate watcher already notices it, and the next
scheduled run re-checks TLS anyway.

**HA.** Only the leader runs schedules; a follower records why it skipped. A manual run on a
follower is refused with a pointer to the leader, so two nodes never scan the same WAN path
at once.

**Alerting.** Routed through the existing `notify` manager as a new event kind `security`,
with the new finding kinds `security_new`, `security_kev`, `security_resolved`. Channels are
whatever Notifications already has (Telegram, email, webhook). Settings: minimum severity,
immediate vs digest, notify on resolved, quiet hours, one alert per finding (dedupe by
finding key, not per run).

**Limits.** Probes per second (default 12), max concurrent runs (1), per-probe timeout (5 s),
response body cap (256 KB), total run budget (5 min), **two gate-login failures per run**
(the gate bans at three in ten minutes), abort on sustained `429`/`5xx` from the WAN path, and a
single **Pause all scans** switch. Per-site opt-out for hostnames whose upstream cannot tolerate
probing (a legacy appliance that logs every 404 as an incident).

---

## 8. Data model and API

New tables (SQLite, same store, covered by backup and HA):

```
scan_schedules  site_id · cadence · hour · day · enabled · triggers(json) · updated_by
scan_runs       id · site_id · trigger · actor · started_at · ended_at · verdicts(json)
                · skipped_reason · path(edge|local) · agent_node
scan_findings   key · site_id · stage · class · severity · cvss · kev · cve_ids
                · first_seen · last_seen · state(open|accepted|resolved) · note
scan_evidence   run_id · seq · stage · verdict · method · path · status · rule_id
                · body_hash · upstream_hash · similarity · body(≤2 KB, reached-backend only)
vuln_advisories id · source · package · range · severity · cvss · cve · kev · published
vuln_sources    source · last_ok · last_error · etag · sha256 · bytes · records
asset_components site_id · product · version · source · confidence · last_seen
```

API, tenant-scoped by `me.site`, permission `security.read` for everything and
`security.write` for anything that starts work:

```
GET    /api/security/overview                 states, coverage, attention list
GET    /api/security/runs?site=&limit=
POST   /api/security/runs                     {targets:[proxy_id], classes:[...]}
GET    /api/security/runs/{id}                stages + evidence
GET    /api/security/findings?state=&severity=
PATCH  /api/security/findings/{key}           {state, note}
POST   /api/security/findings/{key}/remediate  add the host's path block, rerun, resolve only on proof
GET    /api/security/feed                     sources, ages, disk use, sync log
POST   /api/security/feed/sync                {source}
GET    /api/security/schedule
PUT    /api/security/schedule                 per-site cadence + triggers
GET    /api/security/limits
PUT    /api/security/limits                   includes paused
```

Roles: Administrator gets read + write; Operator gets read + run, no schedule changes;
Viewer gets read; tenant owner gets read + run on its own site only. `security.write` is
never implied by `settings.read`.

---

## 9. Build order

Each step lands behind the page's own switch, so the feature is useful on day one with manual
runs and gets more useful as sources come online. Steps 0–2 are the load-bearing ones; the
rest can slip a release.

### Step 0 — the two gate bugs the review found

Land these before the scanner, or the gate suite spends its first release reporting a bug the
product already knows about.

- `internal/store/store.go` — add `gate_users.totp_last_step` to the base schema and to
  `migrateAddColumns`, mirroring the `users` column that already exists.
- `internal/store/gate.go` — `ConsumeGateTOTPStep(username string, step int64) (bool, error)`,
  an `UPDATE … WHERE totp_last_step < ?` shaped like the console's consume at
  `internal/store/store.go` (~line 1200).
- `internal/gate/gate.go` — use `auth.ValidateTOTPStep` and consume the step before
  `CreateGateSession`; today the gate calls `auth.ValidateTOTP`, which accepts the previous,
  current and next step without recording that one was used, so a code works repeatedly for
  about 90 seconds.
- `internal/gate/gate.go` — check `Origin` / `Sec-Fetch-Site` on `POST LoginPath` and refuse a
  cross-site post with the uniform failure page; today the login handler reads no origin
  header at all, so an attacker page can drive passphrase guesses from a victim's browser.
- Tests: `internal/gate/gate_totp_test.go` — `TestGateTOTPCodeRejectedOnReplay`,
  `TestGateTOTPPreviousStepRejected`; `internal/gate/gate_login_test.go` —
  `TestGateLoginRejectsCrossOriginPost`, `TestGateLoginUniformFailureForUnknownAccount`;
  `internal/store/gate_test.go` — `TestConsumeGateTOTPStepIsMonotonic`.

### Step 1 — runner and differential core

- `internal/scan/scan.go` — `Probe`, `Result`, `Verdict`, `Stage` types; no HTTP.
- `internal/scan/runner.go` — rate limit, run budget, `429`/`5xx` abort, method allowlist,
  `X-Scan-Probe` tagging.
- `internal/scan/diff.go` — status/header/body comparison, similarity, single retry.
- `internal/scan/redact.go` — header, cookie and query redaction.
- `internal/store/scan.go` — run, evidence and purge rows.
- Tests: `TestScanNeverMutatesUpstream` (the fake upstream records every method it sees),
  `TestRunnerStopsOnSustained429`, `TestDifferentialMarksInconclusiveOnDynamicBody`,
  `TestControlRefusalDowngradesBlocks`, `TestEvidenceRedactsSecrets`,
  `TestScanEvidencePurgeKeepsFindings`.

### Step 2 — probe path, preflight and the WAN corpus

- `internal/scan/preflight.go` — path taken (`edge`/`local`), probe-path 404, benign controls,
  gate mode, streaming and opt-out.
- `internal/scan/probes_edge.go`, `internal/scan/probes_waf.go` — the 21 classes, reusing the
  payload shapes already in `internal/waf/corpus_test.go`.
- Tests: `TestProbePathCatchAllSkipsBodyProbes`, `TestFramingProbesAreWanOnly` (the fake
  upstream asserts it never saw a CL.TE request), `TestLocalPathRecordedWhenNoCFRay`,
  `TestControlRefusalSkipsClass`.

### Step 3 — gate suite

- `internal/scan/probes_gate.go` — G1–G13, F1–F3, the two-failure cap, sign-out.
- `internal/store/gate.go` — `scan_only` flag and binding to target hostnames.
- `internal/api/handlers.go` (gate-user handlers) — create the scan account with a sealed
  credential, list it with the scanner as its origin.
- Tests: `TestGateProbesCapAtTwoFailures`, `TestGateProbesSkipInForwardAuthMode`,
  `TestGateProbeReportsNotTestedWithoutAccount`, `TestScanOnlyAccountBindsToTargetHosts`,
  `TestGateProbeRefusesConsoleHostname`.

### Step 4 — fingerprint and CVE join

- `internal/scan/fingerprint.go` + `internal/scan/fingerprints.json` (embedded) — banner and
  status-endpoint matching.
- `internal/scan/kev.go` — snapshot fetch with `ETag`, hash, strict parse, staleness.
- `internal/scan/advisories.go` — OSV queries and cache, reusing `updates.CVSSv3Score`.
- `internal/api/security_feed.go` — source state for the page.
- Tests: `TestFingerprintFromStatusEndpoint`, `TestStaleKEVMarksUnknownNeverClean`,
  `TestMalformedKEVRejectedAtomically`, `TestNoBodyStoredForSecretBearingPaths`,
  `TestOSVCacheStaysUnderCap`.

### Step 5 — schedule, alerts and HA

- `cmd/wafproxy/security_loop.go` — leader-only ticker beside `certWatch` and `geoAutoUpdate`.
- `internal/scan/schedule.go` — cadence, jitter, skip-when-unchanged, triggers.
- `internal/notify/notify.go` — the three `security` kinds in `EventKinds`.
- Tests: `TestSchedulerRunsOnLeaderOnly`, `TestScheduleSkipsWhenConfigUnchanged`,
  `TestNewKEVTriggersRunForMatchingComponent`, `TestSecurityKindsRoute`, plus a
  `internal/notify/notify_test.go` case for dedupe by finding key.

### Step 6 — API surface and permissions

- `internal/rbac/rbac.go` — a `security` area in `Areas`, and role seeds in
  `internal/store/roles.go`.
- `internal/api/rbac.go` — map `/api/security` in `permissionFor`.
- `internal/api/server.go` — the routes from §8; `internal/api/security.go` handles them.
- Tests: `TestTenantCannotScanForeignSite`, `TestSecurityRoutesRequirePermission`,
  `TestSecurityPermissionNotImpliedBySettings`, `TestRunRefusedWhenPaused`.

### Step 7 — page and docs

- `web/src/pages/Security.tsx`, `web/src/pages/Security.test.tsx`.
- `web/src/nav.ts` — System group, between Cloudflare and Sites, `icon: "radio"`, permission
  `security.read`; `web/src/App.tsx` route; `web/src/types.ts` if new shapes are needed.
- `docs/CONFIGURATION.md` section, `docs/openapi.yaml` via `go generate ./internal/api`,
  `SECURITY.md` (what the scanner does and does not claim), and this document's status line.
- Tests: tab rendering, role gating, and the "not tested" states rendering as not tested.

---

## 10. The page

Five tabs, one page, under Cloudflare in the sidebar and above Sites. Mockup:
[`docs/design/security-scan-mockup.html`](design/security-scan-mockup.html).

| Tab | Answers |
|-----|---------|
| **Overview** | Am I exposed right now? State per site, last run, the attack path with what stopped each probe class, and the three things that need action |
| **Scans** | What ran, on what, and what happened — run history plus a staged run detail with the differential evidence |
| **Findings** | What is wrong, where it was found, whether it is being exploited (KEV), what to do, and whether it is accepted |
| **Vulnerability feed** | Where the CVE data comes from, how fresh it is, what it costs on disk, which components are watched |
| **Schedule** | When scans run, what triggers them, who is told, and the safety limits |

Design notes: severity is color plus text (never color alone); the three-layer path is the
page's spine, repeated in the overview, the run detail and each finding; freshness is always
visible next to any CVE claim; every "protected" claim carries the evidence that proves it;
and no number is shown that the node cannot defend — states, not grades.

---

## 11. Residual risk

| Risk | Why it is acceptable | Mitigation |
|------|----------------------|------------|
| A WAF miss reaches the app's 404 handler | The request is read-only and the path is random and unimplemented | Catch-all detection skips body probes; per-site opt-out |
| The edge WAF is not exercised | The hostname is not routable from inside the node, so the scan falls back to the listener | `path: local` recorded and shown; findings name this node's WAF, never Cloudflare's |
| A control probe is refused, hiding real misses | Under Attack mode or a geo block refuses everything | Every class becomes `inconclusive`, never "blocked" |
| Edge rate limiting from probe bursts | Runs are short and capped | 12 req/s default, abort on `429`, jitter, quiet hours |
| The gate ban ladder fires on the scan's own address | Two failures stay under the three-in-ten-minutes threshold | Hard cap of two failures per run, no lockout probe |
| Fingerprints miss an unknown product | Banner matching is inherently partial | Report *unknown*, not *clean*; add signatures with releases |
| A compensating control is mistaken for a patch | Operators want the site to work today | "Covered, not patched" language, review date, retest after upgrade |
| TOTP replay is not tested live | Testing it needs the account's seed, i.e. a live 2FA secret in the scanner | Covered by gate unit tests (step 0), retested on every build |
| Gate account becomes shared | One account, one purpose | `scan_only` flag, listed with origin, sealed credential, rotated with other secrets |

---

## 12. Cut from v1, and why

| Cut | Why | Replaced by |
|-----|-----|-------------|
| Live TOTP replay and previous-step probes | Needs the test account's TOTP seed, so the scanner holds a live second factor | Gate unit tests; the missing control is fixed in step 0 |
| Bot-filter and scanner-UA families | A second feature's regression test, at the highest ban risk per request | The bot filter page and its own tests |
| Gate header hardening (old G13) | Duplicates the protection-profile header audit | A link from the finding to the header audit |
| NVD enrichment | OSV already carries the CVSS vector and summary; NVD adds prose at 5 requests/30 s | `updates.CVSSv3Score` and the OSV summary |
| OSV over WAF-Proxy's own packages | The Updates page already reports every host package advisory | Updates → security updates |
| Favicon-hash fingerprinting | Weak matches, and a body fetch per site for each | `Server`, generator meta and status endpoints |
| Bodies from `/.git/config`, `/.env`, `/actuator/env` | A scanner that copies a leaked credential file becomes the leak | Status, length and header names only |
| CL.TE / TE.CL replayed to the upstream | A desynchronised connection damages a backend other people are using | WAN-only framing probes, upstream half reported skipped |
| Certificate findings | The certificate watcher and the Certificates page own them | Preflight notes expiry and links there |
| Posture grade and per-site score | False precision across sites with different probe counts | `exposed` / `covered` / `unknown` |
| `Scan all`, `Retest`, `Export evidence`, `POST /pause` | Four ways to start one thing, and two of them are scope | One run action; `PUT /limits {paused}` |

---

*Security review shape: [security-auditor](../README.md) checklist — scope and authorization,
data flow across trust boundaries, adversarial review of each stage, severity by business
impact, validation of fixes, documented residual risk. This document is a design, not an
audit result, and the scanner is not a substitute for one.*
