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
| `go test -race ./internal/policy` | **failed once, then passed 6x** → SF-07 |
| WAF evasion matrix (44 probes) | **no bypass found** (appendix A) |
| New admin routes, authz + CSRF | correct (appendix B) |
| Access-profile allow/deny semantics | correct (appendix C) |
