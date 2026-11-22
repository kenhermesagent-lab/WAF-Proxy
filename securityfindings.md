# Security findings and hardening roadmap

**Subject:** WAF-Proxy v1.14.0 (`3949fc5`, `main`)
**Reviewed:** 2026-11-22
**Published on:** `f8c4a12` (v1.14.1) — that release only fixes the Policies-tab profile pages and bumps the
version; it changes none of the findings below.
**Basis:** an independent, hands-on review — source read, binaries rebuilt, live evasion probes against a real
instance, then compared with three production proxies the project invites comparison with (Caddy, Traefik,
HAProxy).

This file is written for the maintainer to act on. Every finding names the file and line, the evidence, and the
fix. Nothing here is inferred from the project's own reports; where a claim could not be verified in this
environment it says so.

---

## 1. How this was reviewed

| Step | What was done |
|---|---|
| Source | Full read of the Go tree (~30k lines): `internal/waf`, `proxy`, `policy`, `gate`, `api`, `store`, `intel`, `ban`, `notify`, `agentlink`, `updates`, `crypto`, `urlguard`, `safepath`, `mcp`, `deploy/`, `docs/`. |
| Build | `go1.27.4` (matches `go.mod`), `go build ./...`, `go vet ./...`, `gofmt -l`, `go test ./...`, `go test -race` on the changed packages. |
| Live | The real `cmd/wafproxy` binary in front of a JSON echo upstream, driven with the evasion classes from a WAF-bypass methodology: encoding tricks, content-type/parser differentials, HPP, chunked/framing splits, header injection, method overrides, path canonicalization, host/SNI, body limits, honeypot decoys. |
| New surface | The 1.11–1.14 features probed specifically: agent webhooks, delivery queue, ban roll-up, access-profile roles, and every new admin route for authz + CSRF. |
| Comparison | Caddy, Traefik and HAProxy assessed on documented behaviour and published advisories, not on benchmarks. |

Reproduce: `review/probe.sh` (WAF evasion matrix) and `review/probe3.sh` (new surface) against
`WAFPROXY_DATA_DIR=/tmp/wafdata`, `WAFPROXY_LISTEN_GUI=127.0.0.1:<port>`, `WAFPROXY_GUI_PRIVATE_ONLY=true`.
Loopback needs an explicit `ip_whitelist` for `127.0.0.1`, because the bundled threat feeds contain
`127.0.0.0/8` and would otherwise block every probe as a feed match.

## 2. Verification results

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `gofmt -l ./cmd ./internal` | clean |
| `go test -count=1 ./...` | **33/33 packages pass** |
| `go test -race` (agentlink, notify, store, ban, intel) | pass |
| `go test -race ./internal/policy` | **failed once, then passed 6×** → SF-07 |
| WAF evasion matrix (44 probes) | **no bypass found** (appendix A) |
| New admin routes, authz + CSRF | correct (appendix B) |
| Access-profile allow/deny semantics | correct (appendix C) |

## 3. Fixed since the v1.10.0 review

Recorded so the history stays honest, and so the fixes are not silently regressed:

| Previously reported | Status in 1.14.0 |
|---|---|
| Docker console on `0.0.0.0:8080` with an unauthenticated setup wizard | **Fixed.** `deploy/docker-compose.yml` binds `127.0.0.1:8080` and passes `WAFPROXY_GUI_PRIVATE_ONLY=true`; `deploy/install.sh:372-375` writes `WAFPROXY_LISTEN_GUI=<lan_ip>:<port>` and `WAFPROXY_GUI_PRIVATE_ONLY=true`. |
| `AppRepo` / README pointed at the non-existent `WAF-Proxy-Docker` | **Fixed.** `internal/updates/updates.go:45` is `kenhermesagent-lab/WAF-Proxy`, with the old name kept as an accepted alias in `AppRepoAliases`; `Makefile`, `Dockerfile` and the docs follow. |
| Admin console could plant code in the update checkout that the root helper builds | **Largely closed.** `install.sh` now clones a root-owned checkout into `/var/lib/waf-proxy/src`; `wafproxy.service` runs `ProtectSystem=strict` with `ReadWritePaths=/var/lib/waf-proxy/data` only, so the console user cannot write build input. Residual risk is the documented one: the helper still builds and installs from `origin` as root. |
| No LICENSE | **Fixed.** MIT. |

Appreciation where due: the ban roll-up (`internal/api/bans_rollup.go`) is genuinely fail-safe — it writes,
loads and entry-count-checks the threat list before deleting a single ban row, and removes a half-built feed if
the load fails. That is better engineering than most of the finding-fixing in this space.

---

## 4. Findings

Severity is impact × reachability in a realistic home-lab/LAN deployment. None of these is a remote
pre-auth compromise.

### SF-01 — Agent webhook endpoints skip the project's own SSRF guard

**Severity:** Medium (admin-authenticated)
**Where:** `internal/api/agents.go:22` (`validateAgentLink`), `internal/agentlink/agentlink.go:203`

`validateAgentLink` accepts anything `isHTTPURL` accepts — scheme and host only. Every other
operator-supplied outbound URL in the project goes through `internal/urlguard`:
`api/handlers.go:282` (proxy upstream, `urlguard.Upstream`), `api/restore.go:167`, `api/handlers.go:1631`
(feeds, `urlguard.Feed`), `notify/notify.go:473` (notification webhook, `urlguard.Webhook`). Agent links are
the one path that does not.

Evidence (live, appendix B):

```
POST /api/agents {"endpoint":"http://169.254.169.254/latest/meta-data/"}   -> 201 created
POST /api/agents {"endpoint":"http://127.0.0.1:18090/api/health"}          -> 201 created
PUT  /api/notifications {"webhook_url":"http://169.254.169.254/"}          -> 400 refused (for comparison)
POST /api/proxies {"upstreams":[{"url":"http://169.254.169.254"}]}         -> 400 refused (for comparison)
```

Delivery uses `http.DefaultClient`, which follows redirects and has no `CheckRedirect`, so even a check at save
time would be bypassed by a 302 to a link-local address. Consequences: the console turns into the SSRF pivot
`urlguard` exists to prevent; a typo'd or copied endpoint silently POSTs your anomaly stream (proxy hostnames,
baselines, IPs) to a metadata service or an unintended host; and the inconsistency invites exactly this kind of
"everyone assumes someone checks" bug elsewhere.

**Fix.**
1. `validateAgentLink`: `if err := urlguard.Check(endpoint, urlguard.Webhook); err != nil { return "the endpoint must be a public http(s) URL" }`.
2. In `Dispatcher.post`, use a package-level `&http.Client{Timeout: 5*time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}`.
3. Add the same check in `updateAgentLink`, and a test that posts both a metadata IP and a loopback URL.

### SF-02 — Session tokens are stored in cleartext

**Severity:** Medium (requires read access to the data dir or a backup)
**Where:** `internal/store/store.go:646-648`, schema `store.go:73-82`

`sessions.id` **is** the cookie value: `CreateSession(token, ...)` inserts the raw token, and `authed` looks the
cookie up by primary key (`api/server.go:307-316`). Anyone who reads `<data>/wafproxy.db` — a backup, an rsync,
a container volume, a support dump — holds live admin sessions that skip TOTP entirely, for up to the 7-day
absolute lifetime.

The password is argon2id and TOTP seeds are sealed with the console key; session storage is the one place the
project does not apply that standard.

**Fix.** Store `sha256(cookie_token)` as the key (or an HMAC under a key from `crypto.Box` so DB + file access is
still not enough), keep the raw token only in the cookie. Look up by hash; no schema change beyond the column
meaning, and a migration that drops existing rows is acceptable (people re-login). Add a test asserting the DB
does not contain the cookie value.

### SF-03 — `docker run` still gets the unsafe defaults; only compose and `install.sh` are safe

**Severity:** Low-Medium (deployment-dependent)
**Where:** `Dockerfile:44-46`, `internal/config/config.go:45-48`

The image itself still ships `ENV WAFPROXY_LISTEN_GUI=:8080`, and `GUIPrivateOnly` defaults to `false`
(`envBool` on an unset variable). Compose and the native installer now override both, so the headline is fixed —
but a bare `docker run -p 8080:8080 ghcr.io/.../wafproxy` publishes the unauthenticated setup wizard exactly as
it did before 1.12, and the project's own README quick start is not the only way people run containers.

**Fix.** Make the binary's default safe rather than the wrapper's: default `WAFPROXY_LISTEN_GUI` to
`127.0.0.1:8080` in the image **and** in `config.go`, and default `GUIPrivateOnly` to `true` with an explicit
opt-out (`WAFPROXY_GUI_PRIVATE_ONLY=false`) documented for anyone who genuinely terminates the console off-host.
Add a startup warning when the console listener is not loopback and private-only is off.

### SF-04 — Forced `X-Forwarded-For` rewrite: chaining is broken, and behind a tunnel the LAN check is void

**Severity:** Low standalone / High if the console is ever put behind Cloudflare Tunnel or another proxy
**Where:** `internal/proxy/server.go:209` (`pr.SetXForwarded()`), no trusted-proxy configuration anywhere

Every request's forwarding headers are replaced with the direct peer address, and the inbound
`X-Forwarded-For` / `X-Real-Ip` / `Forwarded` are stripped (`proxy/handler.go:324-326`). That is the right
default against spoofing, and it is what makes the "spoofed XFF" probe return `127.0.0.1` — but it is
unconditional. Consequences:

- Put Caddy, HAProxy or a tunnel in front and **every client becomes `127.0.0.1`**: access profiles, the
decoy/permanent-ban source, rate limiting and the audit log all see the fronting proxy. A single decoy hit
then permanently bans the proxy itself and takes every site down.
- `PrivateNetworksOnly` (`api/private.go:16`) accepts loopback, so a console reachable through the tunnel is
  "private" and the LAN-only guarantee silently evaporates.
- The README's "Security model and limitations" does not mention this, so nothing warns the operator.

Caddy solves this with `trusted_proxies`: **no proxy is trusted by default**, and headers are only honoured from
configured CIDRs. That is the model to copy.

**Fix.** Add `WAFPROXY_TRUSTED_PROXIES` (CIDR list, default empty = current behaviour). When the direct peer is
in the list, take the client address from the right-most untrusted entry of `X-Forwarded-For` and keep it in
`req.Context`; when it is not, keep today's overwrite. Apply the same rule to `PrivateNetworksOnly` and
`TailscaleOnly`. Document it in "Security model and limitations" with the tunnel case called out.

### SF-05 — The agent delivery queue has no admission control

**Severity:** Low
**Where:** `internal/store/deliveries.go:38-56`, `agentlink.go:60-79`, `PruneDeliveries`

Payloads are durable and retried with 1 h backoff up to 8 attempts — good — but `Publish` enqueues one row per
enabled link per event with no cap, and pruning only removes `delivered`/`suppressed` rows (capped at 200) and
`failed` rows older than 30 days. A detector that fires continuously against a dead agent grows the table and
the DB file without bound on a device that may be an SD card.

**Fix.** Cap `pending` rows per link (e.g. 1000, drop oldest with a counter), and stop enqueuing when a link has
been failing for more than N attempts — record a single "link is dead" state instead of a row per event.

### SF-06 — Global memory/concurrency ceiling is still absent

**Severity:** Low
**Where:** `internal/proxy/server.go:98` (`hardBody: 8 << 20`), `proxy/handler.go:392` (`io.ReadAll`)

The 8 MiB buffered body is per request, and nothing bounds concurrent requests. Only the streaming services have
a limit (`streaming.DefaultMaxConns = 256`). A few hundred concurrent 8 MiB uploads can exhaust a small host —
and this is the same bug class Caddy shipped a fix for in July 2026 ("unbounded body buffer DoS"). The 32 KiB
`MaxHeaderBytes` (`cmd/wafproxy/main.go:428`) and the read timeouts are good; the body path is the gap.

**Fix.** A global `semaphore.Weighted` or a counting listener for in-flight buffered requests, plus
`http.MaxBytesReader` semantics applied before `ReadAll`. Make the budget configurable and expose the current
count on the dashboard.

### SF-07 — `TestDecoyMatchesCanonicalPaths` is racy

**Severity:** Low (test quality; CI reliability)
**Where:** `internal/policy/policy.go:622`, `internal/policy/decoy_test.go:38`

The decoy ban is recorded in a goroutine (`go func() { e.bans.Add(...) }()`), so the test's "must not match"
cases can observe the ban created by its own earlier cases:

```
--- FAIL: TestDecoyMatchesCanonicalPaths (0.32s)
    "/.environment" matched the decoy but should not: {Stage:permanent-ban Rule:203.0.113.7/32
     Reason:decoy path requested: /.env}
```

Failed once in a full `go test -race ./internal/policy`; passed 6/6 afterwards. The asynchronous ban is fine in
production; the test needs to not race it — use a distinct source address per case, or drain/scope the ban
engine per subtest. Since CI runs `-race`, this is a red build waiting to happen on an unrelated PR.

### Cosmetic and documentation

- `README.md` still says "Not included in **1.3.0**" while `VERSION` is `1.14.0`; `PLAN.md` is still titled
  `WAF-Proxy-Docker`.
- `api/handlers.go:709` sets `"limited": len(list) == limit`, which reports `true` when the result set is
  exactly the limit. Use `len(list) == limit && limit < total`.
- Temporary bans are now silently capped at 24 h (`ban.MaxTempTTL`) even when a longer TTL is requested — a
  behaviour change worth a line in the changelog and the API error text.

---

## 5. One deployment note that is not a finding

`.env.example` ships `WAFPROXY_LISTEN_GUI=192.168.101.2:8080`, the author's LAN address. It is harmless as an
example, but it is copied verbatim by users who then wonder why the console does not come up. Use
`<this-host-lan-ip>:8080` in the comment and leave the value empty.

---

## 6. Where the project stands against Caddy, Traefik and HAProxy

Scored on the axes used throughout this review (1–10). These tools are **proxy engines**; WAF-Proxy is a
WAF + auth gate + ban console that terminates TLS. The single number is not comparable across columns — the
axes are.

| | WAF out of the box | Proxy core (parsing, smuggling, TLS, perf) | Admin console / auth | Secure defaults | Maturity & patch velocity |
|---|---|---|---|---|---|
| **WAF-Proxy 1.14.0** | **8** | 6 | **8** | 8 | 3 |
| **Caddy 2.11.x** | 2 native → 8 with `coraza-caddy` | 8.5 | n/a (no console; basic/forward_auth ≈ 6) | **8.5** (`trusted_proxies` trusts nobody by default) | 8 |
| **Traefik 2.11 / 3.7** | 2 OSS → 6 only on paid Hub | 7.5 | 5 (dashboard is a documented footgun) | 6.5 | 7 |
| **HAProxy 2.8 / 3.x** | 1 native → 7 with Coraza SPOA | **9.5** | 4 (static `userlist` basic auth, no UI) | 8 | **9** |

**Read the CVE histories with care.** Caddy, Traefik and HAProxy have long public advisory records *because*
they are audited and attacked constantly. WAF-Proxy has none because it is five weeks old and nobody has looked
at it but its author and this review. Absence of CVEs is not evidence of security.

What the others' 2026 advisories are worth studying for, because they are the bug classes this project will
eventually have:

- **Caddy** (four advisories on 2026-11-04 alone): `{host}`/`:authority` dot-segment escape out of a `{host}`
  based root; `file` matcher resolving `/file/./` past suffix-based path rules; `rewrite` re-decoding
  `{http.matchers.file.remainder}` past path-based deny rules; `php_fastcgi` authorization bypass via
  dot-segments. Earlier: unbounded body-buffer DoS and a `forward_auth` wrong-upstream bug (2026-07-10); hop-by-hop
  headers leaking through on `101 Switching Protocols` (2026-10-13, low); CVE-2026-27589 cross-origin config
  application through the local admin API `POST /load` (2026-02).
- **Traefik**: critical complete `digestAuth` bypass (unknown user → empty HA1, every v1/v2/v3 release,
  2026-08-21); high request/response smuggling where `Upgrade: h2c` puts the proxy into a raw byte tunnel that
  **bypasses the router and the entire middleware chain — authentication, IP allow-lists, rate limiting**
  (2026-09-07); ForwardAuth NTLM bypass via `Proxy-Authorization` (2026-11-12); unauthenticated ~18 MiB
  per-response memory DoS in Compress (2026-11-12).
- **HAProxy**: CVE-2021-40346 integer overflow in `htx_add_header` → smuggling that bypassed every
  `http-request` ACL; CVE-2023-25725 empty header names → headers disappearing (CVSS 9.1); CVE-2023-25950,
  CVE-2023-40225 (empty `Content-Length` forwarded), CVE-2023-45539 (`#` accepted in the URI path),
  CVE-2024-45506, CVE-2025-8671.

**The honest conclusion:** WAF-Proxy's WAF is the strongest of the four as shipped, and its auth gate and ban
loop have no counterpart in any of them. Its proxy core is the weakest, its privilege model needs more than
Caddy or Traefik (it requires `CAP_NET_ADMIN` for nftables), and it has no security process at all.

---

## 7. Roadmap: what "better than Caddy / Traefik / HAProxy" has to mean

"Better" cannot mean "better at everything" — HAProxy's parser has a decade of adversarial input behind it and
no amount of feature work closes that gap this year. The winning position is narrower and defensible:

> **Be the only one-box answer for "protect my self-hosted apps": a proxy core with no known framing bugs, a WAF
> that is tuned by default, an auth gate with MFA, and a ban loop — deployable in one command, with a security
> process that makes the small-team risk visible instead of hidden.**

That is a claim about *product*, backed by *engineering parity* in the places where the others are strong. Order
of work below is deliberate: correctness debt first, then parity, then differentiators. Shipping a feature on
top of SF-01/SF-02/SF-04 buys nothing.

### P0 — Close the debt before building anything (1–2 weeks)

| # | Work | Done when |
|---|---|---|
| P0-1 | SF-01 urlguard on agent endpoints + no-redirect client | A metadata and a loopback endpoint are rejected with 400, covered by tests |
| P0-2 | SF-02 hash session tokens at rest (HMAC under the console key) | A test reads the DB and cannot find a live cookie value |
| P0-3 | SF-03 safe defaults in the binary and the image, not only in compose | `docker run` with no env binds loopback and refuses non-private clients |
| P0-4 | SF-04 `trusted_proxies` (default none) honoured by the proxy, `PrivateNetworksOnly` and `TailscaleOnly` | A request through a trusted hop reports the real client IP; an untrusted hop is overwritten |
| P0-5 | SF-05/06 admission control: pending-row cap, global in-flight and buffered-body budget | A 500-request upload flood leaves RSS bounded; counters on the dashboard |
| P0-6 | SF-07 deterministic decoy test; `-race` green 20× in a row | CI is green without retries |
| P0-7 | `SECURITY.md` + private disclosure path + supported-versions policy | A reporter knows where to send a bug and what to expect back |

### P1 — Parity with the parts the others do better (1–2 months)

| # | Work | Why it wins |
|---|---|---|
| P1-1 | **A protocol-framing conformance suite.** Duplicate `Content-Length`, `CL`+`TE`, empty header names, `Upgrade: h2c`, `101` hop-by-hop handling, `Transfer-Encoding` case tricks, obs-fold, `#` in the URI, absolute-form targets, `:authority` vs `Host` disagreement, dot-segment canonicalization *as the upstream sees it*. Run it against the proxy on every commit. | Every serious CVE in Caddy, Traefik and HAProxy in the last five years is in this list. A published, passing suite is the cheapest credible answer to "your parser is young". |
| P1-2 | **`go test -fuzz` on the header parser, request line, path canonicalizer, cookie/URL parsers, and the CRS body decoder**, with a seeded corpus, run nightly for ≥1 h. | Finds the classes graders find. Caddy and HAProxy both get found this way. |
| P1-3 | **HTTP/3 and HTTP/2 with real framing tests**, not just ALPN. | Caddy and Traefik both ship h3; "no h3" is a visible gap for a 2026 proxy. |
| P1-4 | **Published benchmarks**: `h2load`/`wrk` request-path throughput and p99 at 1k/10k concurrent, with the WAF on and off, against Caddy and HAProxy on the same box, checked into `docs/`. | You cannot claim a place in this comparison table without numbers. Right now the only honest claim is "irrelevant at home-lab scale", which is fine and should be stated. |
| P1-5 | **Zero-downtime reload** (graceful listener handover) and config validation before apply. | HAProxy and Caddy both do this; a proxy that drops connections on config change is a lab toy. |
| P1-6 | **PROXY protocol v1/v2** and SNI-based routing polish, OCSP stapling, DNS-01 wildcard issuance, multi-CA fallback. | Table stakes for anyone replacing Caddy. |
| P1-7 | **Observability**: Prometheus/OpenTelemetry export, structured access logs in common formats (Combined, JSON, Caddy-style), trace IDs through the WAF verdict. | The differentiator only matters if the operator can see the verdict in their existing stack. |
| P1-8 | **Supply chain**: `govulncheck` + `npm audit` as a CI gate, SBOM per release, reproducible builds, signed releases (cosign), pinned GitHub Actions by SHA, and a dependency-update bot. | Caddy and HAProxy have processes here; this is the cheapest maturity to buy. |

### P2 — Differentiators that make the one-box claim real (quarter+)

| # | Work | Why it beats them |
|---|---|---|
| P2-1 | **CRS tuning workflow.** Per-rule false-positive suppression with the request that triggered it, replay it against the proposed exception, and a per-site policy that survives rule updates. | This is the actual pain of running Coraza on Caddy or HAProxy: nobody owns the tuning. Owning it is a product. |
| P2-2 | **Detection mode + shadow rules + virtual patching.** Run a new ruleset in log-only, show what it would have blocked, then promote. Ship CVE-specific virtual patches within hours of disclosure. | Neither Caddy nor HAProxy has any notion of this. It is the single strongest WAF story available. |
| P2-3 | **Built-in OIDC/forward-auth** (not just a passphrase gate): generic OIDC, group→host mapping, per-host session policy. | Replaces Authelia/Authentik for the home-lab user; the three proxies all punt to an external IdP. |
| P2-4 | **Per-site mTLS and device certificates**, with the same console lifecycle (issue, revoke, audit) as the accounts. | None of the three has a UI for it. |
| P2-5 | **Defence in depth beyond the WAF**: per-route rate limits/stick tables (HAProxy parity), bot fingerprinting (already partly there), request-body schema checks for known apps, and a "block by default" template per app type (Nextcloud, Jellyfin, Home Assistant, Proxmox). | Turns tuning knowledge into shipped defaults. |
| P2-6 | **Attack replay and learning**: store blocked requests (bounded, redacted), let the operator re-run a ruleset change against the last N days before applying. | Directly addresses the "WAF breaks my app" objection that keeps people on plain Caddy. |
| P2-7 | **HA / config sync** for two nodes, or a documented, tested `keepalived` recipe. | HAProxy's home turf; needed before anyone calls this production. |

### P3 — Maturity work that no feature can substitute for

- An **independent audit** of the proxy core and the admin API, published in full. Budget it before claiming
  production readiness, and say so in the README until it is done.
- A **bug bounty** or at least a public hall-of-fame and a 90-day disclosure policy.
- **Two-person review** on `internal/proxy`, `internal/waf`, `internal/gate`, `internal/updates` and anything
  under `deploy/`. A single-maintainer root helper is a structural risk, not a code bug.
- **Threat model document** (`docs/THREAT-MODEL.md`): what the WAF does and does not stop, what the console
  compromise means (admin → root via the update helper is by design; say it plainly), what the ban engine can be
  turned into (a self-DoS via decoy bans; note the recovery path), and the trust boundaries.

### Acceptance criteria for the headline claim

Do not write "better than HAProxy/Caddy/Traefik" in the README until these are true:

| Criterion | Target | How it is demonstrated |
|---|---|---|
| No known framing bypass | Full P1-1 suite green, plus fuzzing for 30 days with no new crash | CI artefact + fuzz corpus |
| Real client IP behind a proxy | `trusted_proxies` correct, tested end to end with Caddy and HAProxy in front | Integration test in `deploy/` |
| Safe by default | `docker run` alone cannot expose the wizard; console refuses non-private clients | Test that runs the image with no env |
| Session theft resists DB read | Cookie value absent from the database | Unit test |
| WAF false positives are operable | A user can suppress one rule for one host in under a minute, with the triggering request shown | UX test |
| Performance is known | Published numbers vs Caddy and HAProxy, WAF on and off | `docs/BENCHMARKS.md` |
| Disclosure works | `SECURITY.md`, a private channel, and a remediation SLA | Documented and exercised once |

---

## 8. Suggested first PR

If only one change lands this week, make it **P0-1 + P0-4 together** — `urlguard` on agent endpoints and a
trusted-proxy allowlist. Together they close the two findings that turn a safe default into a silent hole the
moment an operator adds a tunnel or a fronting proxy, which is exactly what a home-lab user does next. Both are
small, both are testable, and both are prerequisites for the comparison claims in section 6.

---

## 9. Limitations of this review

Stated plainly so nobody over-reads it:

- **Not a penetration test and not an audit.** It is a focused review plus a live evasion harness. A determined
  researcher with a week and a fuzzer will find things I did not.
- **Not tested here:** nftables kernel bans (no `CAP_NET_ADMIN` in the review sandbox — "Operation not
  permitted"), GeoIP/ASN stages (no database), real ACME issuance, Tailscale listeners, HTTP/2 and HTTP/3
  framing, and any non-loopback client (so `PrivateNetworksOnly` rejection was verified by code and unit test
  only). The Docker image was not built or run; only the native binary was.
- **No load or performance testing.** Any performance statement in section 6 is from documentation and design,
  not measurement.
- **Comparison scores are judgement**, on the axes stated, from documented behaviour and published advisories —
  not from testing Caddy, Traefik or HAProxy in this environment.
- **Scope of the WAF verdict.** "No bypass found" means the 44 probes in appendix A were all blocked. It does
  not mean the rule set is complete, and it says nothing about application-specific false negatives.

---

## Appendix A — WAF evasion matrix (all blocked unless stated)

The harness sends percent-encoded bytes; the literal payload strings are deliberately not reproduced in this
file. Re-run `review/probe.sh` for the exact inputs.

```
baseline GET /                                                                   200
SQLi, seven encodings          tautology, %u0027 form, double-encoded,                         403
                               mixed-case keywords, comment obfuscation,
                               null byte, tab/newline separators
XSS, five forms                script tag, SVG load handler, image error handler,              403
                               pseudo-scheme URI, and the same classes in a form body
LFI / traversal, four forms    relative, absolute, encoded dot-segments, doubled                 403
Body inspection                JSON body, PUT body, multipart field, charset=ibm037, HPP       403
Header injection               payload in Referer, payload in User-Agent                       403
Framing                        chunked split payload                                          403
                               Content-Length + Transfer-Encoding                    closed (000)
                               duplicate Content-Length                              closed (000)
TRACE                                                                                      400
X-HTTP-Method-Override: DELETE                                                             403
Unknown Host / unknown SNI                                                          closed (000)
Spoofed XFF / X-Real-Ip / Forwarded   replaced with 127.0.0.1; upstream saw neither of the other two
/a/b/../c                                    upstream received the normalised path /a/c
200 KB body (128 KB profile limit)                                                         413
Decoy list                      `.env` and three canonicalisation variants;                     403
                                the source stays banned afterwards
```

## Appendix B — New admin surface (v1.11–1.14)

```
POST /api/bans/rollup                no session          401
POST /api/bans/rollup                session, no CSRF    403
GET  /api/agents/1/deliveries        no session          401
POST /api/agents/1/retry             no session          401
POST /api/agents  endpoint=http://169.254.169.254/...    201   <-- SF-01
POST /api/agents  endpoint=http://127.0.0.1:18090/...    201   <-- SF-01
POST /api/agents  endpoint=file:///<system file>         400
PUT  /api/notifications webhook_url=http://169.254.169.254/  400
POST /api/proxies upstream=http://169.254.169.254        400
Permanent ban 203.0.113.0/24 -> POST /api/bans/rollup    200, feed file 0640, ban rows cleared after load
```

## Appendix C — Access-profile roles

```
no profile (global whitelist only)                       200
profile role=allow 10.0.0.0/8, client 127.0.0.1          403   (narrows the site)
profile role=deny on the list that allows 127.0.0.1      403   (deny beats the global whitelist)
profile role=allow 127.0.0.1, client allowed             200
  same host, SQLi                                        403   (profile does not weaken the WAF)
  same host, decoy /.env                                 403   (profile does not exempt the honeypot)
```

---

*Reviewed at `3949fc5` (v1.14.0), published on `f8c4a12` (v1.14.1). Re-run `review/probe.sh` and
`review/probe3.sh` after any change to `internal/proxy`, `internal/waf`, `internal/policy` or the admin routes.*
