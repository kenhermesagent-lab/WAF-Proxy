# WAF-Proxy — sandbox bypass assessment (demo instance only)

Date: 2026-11-21 · Target: WAF-Proxy 1.3.0 (`commit dev`) · Scope: a demo instance started inside this
sandbox on `127.0.0.1`, plus the code that runs it.

**Safety:** every request in this report went to `127.0.0.1` in this sandbox. No external host,
production system, real credential, token or key was used. All admin traffic used a throwaway
password and a locally generated TOTP secret.

---

## 1. Demo environment

| Component | How it ran here |
|---|---|
| Admin console | `127.0.0.1:18080`, `WAFPROXY_GUI_PRIVATE_ONLY=true` |
| Proxy (TLS) | `127.0.0.1:18443`, routes by `Host` |
| Upstream | small echo server on `127.0.0.1:18081` (echoes path and forwarding headers) |
| Profiles | built-in "Generic Web" (CRS, block mode, paranoia 1, anomaly 5, 128 KB body) |
| Proxies | `app.demo.example.com` (WAF on), `gate.demo.example.com` (passphrase gate), `bot.demo.example.com` (bot level light) |
| Ban enforcement | **software only** — `nftables unavailable: Operation not permitted (you must be root)` |

**Not possible in this sandbox, therefore not tested:** kernel nftables bans and the stealth/drop
rules, privileged ports (80/443), real GeoIP data, real ACME/DNS, Tailscale listeners, and
`PrivateNetworksOnly` rejecting a genuinely public source (every client here is loopback).

## 2. Method, and two traps worth knowing

- Requests were made with `curl -k --resolve <host>:18443:127.0.0.1` and with raw TLS sockets
  (Python `ssl` + hand-built requests) for framing tests.
- **Trap 1 — curl normalises paths.** curl collapses `/./` and `/x/../` before sending. Without
  `--path-as-is` you are testing curl, not the proxy. The first "bypass" I saw (`/./.env` → 200)
  was this artifact; re-running with `--path-as-is` produced the real finding below.
- **Trap 2 — bans live in memory.** Deleting a ban through `/api/bans` does not immediately clear
  the engine's in-memory view, so the next request is answered `403 temp-ban` and can look like a
  successful block. Findings below were re-confirmed after a process restart.

## 3. Findings

| # | Finding | Severity | Status |
|---|---|---|---|
| F-01 | Decoy (honeypot) paths are matched against the **raw** path, so `/./x`, `//x`, `/y/../x` walk past the rule | **Medium** | **Fixed** |
| F-02 | An IP **whitelist** silently disabled the decoy honeypot entirely, contradicting the documented design | **Medium** | **Fixed** (same patch) |
| F-03 | The access gate exempts four health paths, which pass unauthenticated to the upstream | Low (by design) | Documented |
| F-04 | The bot challenge only applies to `GET`/`HEAD` with `Accept: text/html`; omitting `Accept` skips it | Low (by design) | Documented |
| F-05 | Proof-of-work difficulty is tiny (2 hex chars at *light*, 4 at *aggressive*) | Low | Documented |
| F-06 | Five bad logins lock the `admin` username for 15 minutes for everyone (IP-independent) | Low (accepted trade-off) | Documented |
| F-07 | Default FireHOL level 1 feed contains `127.0.0.0/8`, so loopback clients are blocked until whitelisted | Informational | Observation |

### F-01 / F-02 — decoy honeypot bypass (Medium) — fixed

**Affected code (before fix):** `internal/policy/policy.go:479-505` — the decoy loop sat inside
`if !allowlisted { … }` and compared `strings.ToLower(req.Path)`.

**Reproduction** (demo proxy with `waf_mode: off`, decoy policy `/secret-admin`):

```bash
curl -sk --path-as-is --resolve app.demo.example.com:18443:127.0.0.1 \
  "https://app.demo.example.com:18443/secret-admin"      # 403  decoy | ban   (correct)
curl -sk --path-as-is --resolve app.demo.example.com:18443:127.0.0.1 \
  "https://app.demo.example.com:18443/./secret-admin"    # 200  route | allow (bypass)
curl -sk --path-as-is --resolve app.demo.example.com:18443:127.0.0.1 \
  "https://app.demo.example.com:18443//secret-admin"     # 200, upstream saw /secret-admin
curl -sk --path-as-is --resolve app.demo.example.com:18443:127.0.0.1 \
  "https://app.demo.example.com:18443/x/../secret-admin" # 200  route | allow (bypass)
```

**F-02 reproduction** (any WAF mode, decoy `/secret-admin`, whitelist `127.0.0.1`):

```bash
curl -sk --path-as-is --resolve app.demo.example.com:18443:127.0.0.1 \
  "https://app.demo.example.com:18443/secret-admin"      # 200 + zero bans
```

**Impact.** The decoy list is the deployment's scanner trap: touching the path is meant to mean
"confirmed hostile, ban permanently". With F-02 a whitelisted source — typically a monitoring box,
an office NAT, or a compromised "friendly" host — probed decoys with no ban at all. With F-01 any
scanner that normalized its path (`/./wp-config.php`, `//.env`, `/assets/../.env`) reached the real
file and was never banned. Neither finding is remote code execution; both defeat a detection
control and let reconnaissance continue. With the WAF enabled at paranoia 1 the CRS blocked several
of these payload shapes incidentally, which is why the issue only showed cleanly with
`waf_mode: off` (a supported configuration) or on decoy names CRS does not consider malicious
(`/secret-admin`, `/backup.zip`).

**Root-cause fix** (`internal/policy/policy.go`):

- the decoy loop now runs for every client, before the `!allowlisted` block, matching the comment
  that a whitelist exempts only country, ASN and feed policy;
- the comparison uses a new `canonicalPath` (`policy.go:599`) — `path.Clean` plus lowercasing —
  for both the request path and the configured entries (`policy.go:237`). The request keeps its
  original path; only the comparison is canonical.

**Verification after the fix** (same requests, rebuilt binary):

```
/secret-admin          403   decoy | ban
/./secret-admin        403   decoy | ban
//secret-admin         403   decoy | ban
/x/../secret-admin     403   decoy | ban
/%2e/secret-admin      403   decoy | ban
```

with the loopback whitelist still in place, i.e. the F-02 case now bans as well.

**Regression tests:** `internal/policy/decoy_test.go`
(`TestWhitelistDoesNotBypassDecoy`, `TestDecoyMatchesCanonicalPaths`, `TestCanonicalPath`) and the
end-to-end `internal/proxy/decoy_test.go` (`TestPipelineDecoyPathCannotBeObfuscated`, which also
asserts the upstream is never reached).

### F-03 — gate health paths bypass authentication (Low, by design)

`internal/gate/gate.go:107` exempts `/healthz`, `/health`, `/__health`, `/__wafproxy/health` and
`/.well-known/acme-challenge/*`. Unauthenticated reproduction:

```bash
curl -sk --resolve gate.demo.example.com:18443:127.0.0.1 \
  "https://gate.demo.example.com:18443/healthz"                       # 200, upstream JSON
curl -sk --resolve gate.demo.example.com:18443:127.0.0.1 \
  "https://gate.demo.example.com:18443/.well-known/acme-challenge/x" # 200, upstream JSON
```

Health checks and ACME cannot sit behind the gate, so this is intentional. The residual risk is
that anything the upstream serves at those exact paths is public; keep them free of detail.
No code change.

### F-04 — bot challenge skipped by omitting `Accept` (Low, by design)

`botguard.BrowserLike` (`internal/botguard/botguard.go:95`) only challenges `GET`/`HEAD` with
`Accept: text/html`:

```bash
curl -sk --resolve bot.demo.example.com:18443:127.0.0.1 -H 'Accept: text/html' \
  "https://bot.demo.example.com:18443/" | grep -o 'Checking your browser'   # challenged
curl -sk --resolve bot.demo.example.com:18443:127.0.0.1 \
  "https://bot.demo.example.com:18443/"                                      # 200 from upstream
```

This is how API clients keep working without a challenge. Treat the bot level as a nuisance filter
for browsers only, not as machine-traffic control. No code change.

### F-05 — weak proof of work (Low)

`Levels` (`internal/botguard/botguard.go:31`) maps light/standard/aggressive to 2/3/4 leading hex
zeros — 256 / 4,096 / 65,536 SHA-256 evaluations, milliseconds of GPU time. It raises the cost of
naive flooding only. No code change.

### F-06 — username lockout is an availability lever (Low, accepted)

`internal/api/server.go:520` allows 5 attempts per 15 minutes keyed by username and deliberately
not by IP, so an unauthenticated attacker can keep the real administrator locked out. This is the
documented trade-off that defeats distributed guessing; noted, not changed.

### F-07 — default feed blocks loopback (Informational)

During setup, every request from `127.0.0.1` was answered `403 feed | block — FireHOL level 1`
because that list includes `127.0.0.0/8`. Correct behaviour for a public edge, surprising on a
single host where the operator also browses locally; whitelisting the source is the intended fix.
Observed only, no change.

## 4. Controls that held

WAF (Generic Web, paranoia 1, block) — all over HTTPS with `Host`/SNI `app.demo.example.com`:

| Probe | Result |
|---|---|
| `?id=1' OR 1=1--`, mixed-case `UnIoN SeLeCt`, `/**/` comments, `%00`, `%u0027`, double-encoded `%2527` | 403 |
| `?q=<script>`, `<svg/onload=…>`, mixed-case `<ScRiPt>` | 403 |
| `../../etc/passwd`, `%2e%2e%2f`, `..%2f`, `%c0%ae` overlong UTF-8 | 403 |
| JSON body SQLi/XSS, `PUT` with SQLi, multipart field with SQLi, `charset=ibm037`, HPP `?id=1&id=…` | 403 |
| SQLi in `Referer`, `Cookie`, `User-Agent` | 403 |
| 200 KB body against a 128 KB limit | 413 |

Protocol and routing:

| Probe | Result |
|---|---|
| `Transfer-Encoding: chunked` with the payload split across chunks | 400 (dechunked, then inspected) |
| `Content-Length` + `Transfer-Encoding` together | 400 |
| Duplicate `Content-Length`, duplicate `Host`, absolute-form URI, NUL in `Host` | 400 |
| `TRACE` | 400 / 405 |
| HTTP/1.0 without `Host`, unknown host, `host.suffix.evil` | connection closed (blackhole) |
| `Host` upper-case, trailing dot, with port | routed correctly (normalised) |
| `X-Forwarded-For: 203.0.113.66` + `Forwarded` + `X-Real-Ip` | upstream saw only `127.0.0.1`; spoof stripped |
| `X-HTTP-Method-Override: DELETE` | removed before the upstream; also 403 by WAF |
| `OPTIONS *` | handled (profile allows OPTIONS) |

Access gate and bot challenge:

| Probe | Result |
|---|---|
| No cookie on `/` | login page, upstream not reached |
| Wrong passphrase | uniform failure; 3 within 10 min escalates to a ban |
| Forged `__wfp_gate` value | login page |
| Cookie issued for `gate.demo.example.com` replayed against `gate2.demo.example.com` | login page (session scoped per proxy) |
| `next=//evil.example`, `https://evil.example`, `/\evil.example`, `..//..//` | redirect to `/`; no open redirect |
| Bot challenge with `Accept: text/html` | challenge served; correct PoW → 303 + cookie |
| Wrong PoW solution | 400; repeated failures escalate to a ban |
| Solved bot cookie replayed with a different `User-Agent` | challenge again (cookie binds host + UA) |

Rate limiting: `rate_limit 5/5` produced `200×6` (burst), then `429` with `Retry-After`, then a
short ban (`403`) on continued hammering.

Admin API and sessions:

| Probe | Result |
|---|---|
| `/api/me`, `/api/events`, `/api/proxies`, `/api/settings`, `/api/crowdsec/install` without a session | 401 |
| `POST /api/logout` with a valid session but no `X-CSRF-Token` | 403 |
| `POST` with `X-HTTP-Method-Override: GET` to dodge CSRF | 405 (no such route; override unused) |
| Replaying the same TOTP code | 401 (step is claimed on first use) |
| `POST /api/setup` after setup completed | 409 |
| `/mcp` RPC without a token | 401 |
| Unknown JSON fields on API writes | rejected (`DisallowUnknownFields`) |

Also reviewed, not exercised: `internal/proxy/cache.go` (cache key includes `Host`, `RequestURI`
and encoding; requests with `Cookie`/`Authorization`/`Range` are never cached; `Vary` beyond
`Accept-Encoding` disables caching; only `200` with a positive `max-age` ≤ 300 s is stored) and
`internal/streaming` (allow list compares `netip` prefixes against `conn.RemoteAddr()`, so proxy
headers cannot influence it).

## 5. Residual risk

- Kernel-level enforcement (nftables drop, stealth mode) was **not** tested; only the software ban
  path was exercised.
- The TLS listener answered unknown SNI with a handshake error and the bare `Host` blackhole
  closed the connection; neither was tested with HTTP/2 clients.
- GeoIP-dependent stages (`asn_block`, country allow/deny) could not be exercised without a
  database; `asn_block` failed closed with "unknown country" until disabled.
- The demo ran with a self-signed certificate and `-k`; certificate handling was out of scope.

## 6. Cleanup

The demo processes (proxy and echo upstream) were stopped and the temporary directory holding the
demo database, cookie jar, scripts and logs was removed. The only workspace changes are the policy
fix, its tests and this report.
