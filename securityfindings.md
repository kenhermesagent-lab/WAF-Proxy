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
