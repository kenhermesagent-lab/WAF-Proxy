# Cloudflare Tunnel: design

Status: proposed, awaiting review. No code until this is approved.

## Summary

Add first-class Cloudflare Tunnel support to the console: a `cloudflared`
connector the proxy manages, a guided setup for publishing the admin console
and the proxied apps through Cloudflare, and end-to-end checks that prove a
public hostname actually reaches the origin. The page is one nav item with two
tabs, **Admin** and **Apps**, because the two halves share a connector and a
token but nothing else.

Token-only configuration (a tunnel token pasted into the console, with ingress
and DNS configured in the Cloudflare dashboard through the guide) ships first.
API mode (console creates the tunnel, ingress and DNS records through the
Cloudflare API) is the next slice and is designed for from the start so it does
not require a second data model.

## Goals

- An administrator who has never used Cloudflare can get from "nothing" to "the
  console answers on `console.example.com` through Cloudflare" by following the
  page, with a working check at every step.
- Apps can be published through the same tunnel, per site, without leaving the
  WAF in the path: Cloudflare terminates at the edge, the connector re-originates
  TLS to the WAF listener, so SNI, Host, policies, bans and logs behave exactly
  as they do today.
- The connector's lifecycle (install, start, stop, restart, version, logs) is
  visible and controllable from the console on a native install, and honestly
  reported as external on Docker.
- Nothing is claimed to work that has not been proven by a request through the
  edge.

## Non-goals

- Cloudflare WAF rules, caching, or page rules: Cloudflare stays the tunnel and
  the edge gate, WAF-Proxy stays the WAF.
- Replacing Tailscale. The two are independent; both can be on.
- Managing other people's Cloudflare accounts, multi-account, or zone selection
  beyond what the token/API token already grants.
- Installing `cloudflared` inside the Docker image. Docker uses a sidecar.

## Decisions taken during the brainstorm

| Decision | Choice |
| --- | --- |
| Page shape | One nav item, two tabs: Admin, Apps (existing `tabs` mechanism in `nav.ts`) |
| Credentials | Token-only first; API mode as the next build-in |
| Edge gate | Cloudflare Access recommended, with a minimum path documented |
| Install | Install button via the root helper; manual commands as the fallback |
| Auto-update | `cloudflared` joins `internal/updates/host-packages.txt` so the Updates page and the scheduled run upgrade it |
| Docker | Sidecar only, with instructions; the console reports it and cannot control it |
| Wizard visibility | The wizard *is* the enablement: it shows whenever the last check is not green, instead of being hidden until enabled |

## How it fits the existing code

The feature is deliberately assembled from patterns already in the tree:

- `internal/tailnet` + `internal/api/tailscale.go` — supervisor state, boot-time
  start from saved settings, `xxxView` JSON, SaveBar/restart UX.
- `internal/api/crowdsec_install.go` + `deploy/crowdsec-install.sh` +
  `HelperActionCrowdSecInstall` — a fixed install script run by the root helper
  with a polled status endpoint, no browser-supplied command.
- `internal/updates` — `host-packages.txt` catalog, package update path, and the
  `hostInfo.container` flag that tells the console it is in Docker.
- `internal/clientip` + `WAFPROXY_TRUSTED_PROXIES` — the trusted-proxy model the
  connector's client-IP handling extends.
- `web/src/pages/Tailscale.tsx`, `CrowdSec.tsx`, `Updates.tsx` — page layout,
  status cards, install/poll card, restart with confirmation.

## Architecture

```
browser ──TLS──▶ Cloudflare edge ──▶ cloudflared (child process, loopback)
                                           │  https://127.0.0.1:<wan>  (originServerName, noTLSVerify)
                                           ▼
                                     WAF-Proxy WAN listener ──▶ upstreams

console UI ──▶ /api/cloudflare/* ──▶ internal/cloudflared (supervisor)
                                          │ start/stop/restart child process
                                          │ read /ready + /metrics on 127.0.0.1:20241
                                          │ read token from sealed settings
                                          ▼
                                     cloudflared binary (PATH or /usr/local/bin)
```

The connector runs as a child of the proxy (`cloudflared tunnel run --token …`),
not as the distro's systemd unit. That is what makes start/stop/restart and
version tracking possible from the page. The installer therefore leaves
`cloudflared.service` disabled and the page says why.

### Publishing the admin console (Admin tab)

1. Install `cloudflared` (button or manual).
2. Create a tunnel in Cloudflare Zero Trust, copy its token.
3. Paste the token; the connector starts and shows connections.
4. In the tunnel's public-hostname config: hostname `console.example.com`,
   service `http://127.0.0.1:<gui-port>`. The console listener is plaintext and
   private-only, so there is no origin certificate and no origin-server-name
   field to fill in; the console is not one of the proxied hostnames and does
   not travel through the WAF listener.
5. Optionally (recommended) put an Access application in front of that hostname.
6. Check end to end from the console.

`WAFPROXY_GUI_PRIVATE_ONLY` still sees a loopback peer, so it keeps working
unchanged. Because an open port forward beside the tunnel is legitimate (see
"Two paths at once"), the Admin tab does not forbid it: it reports that the
direct path bypasses Access, and keeps the protection step unmet until the admin
chooses one of the documented fixes or acknowledges the cost.

Because Cloudflare terminates TLS, ACME HTTP-01 cannot complete for a tunnelled
hostname. The Admin tab treats the console certificate as "Cloudflare edge" and
the Certificates tab must agree (see Certificates below).

### Publishing apps (Apps tab)

Apps are the hostnames already configured per site in Proxies. Each hostname
gets a publish toggle. Published hostnames are routed by ingress rules to
`https://127.0.0.1:<wan-port>` with:

- `originRequest.originServerName` = the public hostname (so our SNI-based
  routing and policy keep working),
- `originRequest.noTLSVerify` = true (the origin certificate is Cloudflare's
  edge certificate, not something the local ACME store can validate),
- `httpHostHeader` left unset so the Host header stays the public hostname.

In token mode those rules live in the dashboard and the page shows them as
copyable values per hostname, plus a deep link to the tunnel's configuration
page. In API mode the console writes them itself; the same generator feeds both,
so token mode's copy blocks and API mode's PUT body cannot drift.

Apps are filtered by the active site, consistent with the rest of the console.
Publishing is host-scoped (one tunnel), so a host admin sees nothing here.

### Two paths at once (tunnel plus an open port)

A host can legitimately serve the same hostname through the tunnel *and* through
an inbound port forward. The two paths do not conflict: the tunnel arrives over
an outbound connection on loopback, the forward arrives on the WAN address, and
both reach the same listener. That is a valid choice — the direct path still
passes the WAF, and it keeps working if Cloudflare or the connector is down.

What it means is that Cloudflare's edge protections and any Access policy only
apply to the edge path; a direct request skips both. The console reports this
rather than guessing intent:

- **Apps:** the row shows "edge + direct origin" with the explanation above. Not
a failure, and not hidden, because "why is my request missing `CF-Ray`" and "why
did the Access policy not apply" are questions this answers before they are
asked. The guide offers the one-line nftables rule to accept :443 only from
Cloudflare's published ranges for anyone who wants the tunnel to be the only
path.
- **Admin console:** here it matters, because Access is the whole point of that
step. If the console answers on a public address while Access is enabled, the
Admin tab shows the protection step as **not satisfied**, with the two fixes
(bind the GUI to loopback or allow it only from Cloudflare's ranges, plus close
the forward). This is the one place the check is not merely advisory, and it
still explains rather than refuses: the admin can keep the open path and the
page will keep saying what that costs.

## Data model

No new tables. Everything is host settings, plus one per-site key:

| Key | Scope | Meaning |
| --- | --- | --- |
| `cloudflare_enabled` | host | The connector should be running |
| `cloudflare_tunnel_token` | host | Sealed with `internal/crypto.Box`, the same box as `notify_*` and `backup_*` secrets |
| `cloudflare_tunnel_id` | host | Optional; filled by API mode, or pasted for nicer dashboard links |
| `cloudflare_account_id` | host | Optional; API mode |
| `cloudflare_zone_id` | host | Optional; API mode |
| `cloudflare_api_token` | host | Sealed; API mode only, never required for token mode |
| `cloudflare_strict_origin` | host | Trust `CF-Connecting-IP` only from the connector; on by default when enabled |
| `cloudflare_published_hosts` | per site | JSON list of hostnames published through the tunnel |

The token is write-only over the API: `GET` returns `{"set": true}` and a masked
tail, never the value. Every write is audited as `cloudflare.update` with the
changed keys and no secret material, matching `tailscale.update`.

## Backend

New package `internal/cloudflared`:

```go
type Supervisor struct { /* binary path, version, cmd, log ring, last state */ }
func Detect() (path, version string, err error)      // PATH, /usr/local/bin, /usr/bin
func (s *Supervisor) Start(token string) error
func (s *Supervisor) Stop() error
func (s *Supervisor) Restart(token string) error
func (s *Supervisor) State() State                   // stopped|starting|running|error|external
func (s *Supervisor) Ready() (connections int, ok bool) // GET 127.0.0.1:20241/ready
func (s *Supervisor) Logs(n int) []string
```

- Boot: if `cloudflare_enabled` and a token exists, start the connector (same
  shape as the Tailscale block in `cmd/wafproxy/main.go`). A failed start is
  recorded in state and shown; it never blocks startup.
- Token refresh on save: restart only when the token changed.
- Version drift: `State()` compares the running binary's version (from the log
  line or a re-`Detect`) with the on-disk version; a difference surfaces as
  "binary updated; restart the connector" instead of silently running old code.
- Logs: last N lines in a ring buffer, exposed in the page's collapsible log.
  `cloudflared` auth errors are the single most common failure and must be
  readable without SSH.
- Metrics port: `cloudflared`'s readiness/metrics listener is started on
  `127.0.0.1:20241` (its default). It is not an admin setting: it is bound to
  loopback, only our own checks read it, and a second field invites a
  misconfiguration that breaks the connector for no benefit. The one escape
  hatch is `WAFPROXY_CLOUDFLARED_METRICS` in the service environment for a host
  where that port is already taken; the page shows the effective address
  read-only. The Docker sidecar publishes the same address on the host loopback
  so the container can still read it.

### Checks

A check is a small, explicit probe with a verdict and a reason. Three layers,
evaluated in order; each tab shows only the layers relevant to it.

| Check | Method | Passes when |
| --- | --- | --- |
| Binary | `Detect()` | A version is reported |
| Token saved | settings | A sealed value exists |
| Connector | `/ready` + state | At least one connection |
| Tunnel DNS | DNS lookup of the public hostname (resolver configurable, default system) | Resolves to Cloudflare addresses |
| Origin reachable | direct loopback request to the WAN listener with SNI | 200/3xx with the expected Host |
| Edge path | `GET https://<hostname>/` with `User-Agent: WAF-Proxy check` | Response carries `CF-Ray` **and** comes from the origin (via a check marker) |
| Direct origin (advisory) | Request the host's public address from the console host, with the same Host/SNI | Reported either way; see "Two paths at once" — never silently ignored, never a hard failure for apps |
| Access (admin) | `GET https://<console>/` | 302 to `*.cloudflareaccess.com` when Access is on; no redirect when it is off, which is *reported*, not failed |

The edge-path check is the only one that proves the tunnel. To make origin vs.
edge distinguishable without leaking internals, the origin stamps a per-host
check response header (`X-WAF-Origin: <random nonce held in settings>`) for
requests carrying the check user agent: the WAN listener for app hostnames, the
console for its own hostname. A response with `CF-Ray` and the nonce is end to
end; `CF-Ray` without it means something else answered (wrong ingress target,
stale tunnel, or another origin entirely).

Checks run on demand, and the connector/DNS pair also runs on page load (cheap,
no external request unless the user clicks "Check end to end"). Results are not
persisted beyond the process; the page shows timestamps.

## API

All under the existing session auth, `settings.read` / `settings.write`, and
`hideFor: ["host_admin"]` on the nav item. CSRF/origin rules are inherited.

| Route | Purpose |
| --- | --- |
| `GET /api/cloudflare` | Status: installed, version, state, connections, token set, enabled, ingress target, check summary, log tail |
| `PUT /api/cloudflare` | Enable/disable, token, tunnel id, strict origin |
| `POST /api/cloudflare/install` | Start the helper install; returns 202 with a poll cursor (mirrors `POST /api/crowdsec/install`) |
| `GET /api/cloudflare/install` | Poll install progress/result |
| `POST /api/cloudflare/connector` | `start`/`stop`/`restart` |
| `POST /api/cloudflare/check` | Run checks; body names the hostnames (never arbitrary URLs) |
| `GET /api/cloudflare/apps` | Hostnames for the active site with publish state and generated ingress rows |
| `PUT /api/cloudflare/apps` | Set published hostnames for the active site |

Hostnames handed to the check endpoint are validated against configured
hostnames for the site; the endpoint cannot be used as a generic fetcher.

### Client IP

Today `internal/clientip` trusts `X-Forwarded-For` only from configured
`WAFPROXY_TRUSTED_PROXIES`, and the proxy strips inbound forwarding headers.
With the tunnel on, the connector is loopback and always sets
`CF-Connecting-IP` plus XFF. Changes:

- `Resolver` gains an optional preferred header (`CF-Connecting-IP`) that is
  honoured only when the peer is trusted *and* the header is enabled by settings.
- The proxy's header-strip list gains `CF-Connecting-IP` for untrusted peers, so
  a direct request cannot claim an address.
- The enabled setting is written when the connector is enabled, removed on
  disable, so the trust exists only while a trusted local hop is actually in
  front of us.
- A test proves: tunnel on + loopback peer + `CF-Connecting-IP` → client address;
  tunnel off or foreign peer → ignored.

### Certificates

A hostname published through the tunnel cannot use an ACME HTTP-01 challenge
(the edge intercepts :80) and the edge certificate is what browsers see.
`internal/api/certs` gains a "tunnelled" predicate derived from the published
list:

- no issuance attempt and no renewal timer for tunnelled hostnames,
- the Certificates tab shows the chip **Cloudflare edge** with an explanation,
  not a red "missing certificate",
- if a hostname is un-published, normal ACME behaviour returns on the next
  check.

## Install and updates

### Install button

New fixed script `deploy/cloudflared-install.sh`, installed by `install.sh` next
to `crowdsec-install`, run through a new `HelperActionCloudflaredInstall`:

- adds Cloudflare's apt repository and keyring, `apt-get install cloudflared`,
- runs `systemctl disable --now cloudflared` so only the console's child process
  owns the connector,
- verifies `cloudflared --version` and reports it,
- takes no arguments; the browser cannot pass a URL, package or command.

The page polls `GET /api/cloudflare/install` while it runs (the CrowdSec card is
the template). Where the helper is absent or the host is not apt-based, the
button is disabled with the reason and the same commands are offered as
copy-paste, keeping the existing Updates-page convention.

### Scheduled updates

`cloudflared` is appended to `internal/updates/host-packages.txt` and
`docs/INSTALL.md`, so the Updates page lists it and the scheduled
`check`/`apply` run upgrades it from the repository the installer added. Package
updates do not restart the service, so the status endpoint's version-drift
detection prompts a connector restart, which is a one-click action on the page.

### Docker

Docker cannot apt-install into the read-only container, and the helper manages
the host, not the container. So:

- The console detects container mode through the helper's existing
  `hostInfo.container` (the same answer the Updates page already uses) and
  replaces the install card with sidecar instructions.
- We ship `deploy/docker-compose.cloudflared.yml`, an override that adds a
  `cloudflared` service with `network_mode: host`, the token from
  `deploy/.env` (never written into compose), `restart: unless-stopped`, and the
  metrics port mapped on loopback.
- Documented commands: `docker compose -f deploy/docker-compose.yml -f
  deploy/docker-compose.cloudflared.yml up -d`, token creation in the dashboard,
  and how to read its logs (`docker compose logs -f cloudflared`).
- Because the console container also uses host networking, it can still reach
  the sidecar's `127.0.0.1:20241` metrics endpoint and run every check. Only
  start/stop/restart is unavailable, and the page says exactly that instead of
  showing a button that cannot work.
- The tunnel token in Docker lives in `deploy/.env` (host-owned). The page shows
  instructions and never asks for it, so there is one source of truth.

## Frontend

`web/src/nav.ts`: `{ id: "cloudflare", label: "Cloudflare", icon: "cloud",
permission: "settings.read", hideFor: ["host_admin"] }` in the System group, next
to Tailscale. Slice 1 ships the page without tabs; slice 2 adds
`tabs: [{id:"admin", label:"Admin"}, {id:"apps", label:"Apps"}]` with
`defaultTab: "admin"` together with the Apps view, so no tab is ever empty.

The icon set has no `cloud` glyph today (closest are `globe`, `network`,
`server`), so the slice adds one to `web/src/components/Icon.tsx` rather than
borrowing an unrelated symbol; a cloud outline keeps the Cloudflare page
distinct from Tailscale's `network`.

`web/src/pages/Cloudflare.tsx` (page shell, shared status strip, `tab` prop from
`PageHead`), `CloudflareAdmin.tsx`, `CloudflareApps.tsx`.

Shared strip: connector badge (Not installed / Stopped / Running · 2 connections
/ External · Docker / Error), version, tunnel id with a dashboard deep link,
Enable switch, and the "last verified" line. Errors print the connector's own
last line rather than a generic message.

Admin tab: numbered steps, each with explanation, copy blocks and a Check button.

1. **Install the connector** — what `cloudflared` is, why outbound. Install
   button, or manual commands, or the Docker sidecar card.
2. **Create the tunnel** — where in Zero Trust, what a tunnel is (an outbound
   connection, no open ports), copy the token.
3. **Connect it** — paste the token, Save, watch connections appear. Errors here
   are almost always a wrong/copied-partially token; say so.
4. **Publish the console hostname** — service `http://127.0.0.1:<gui-port>`, the
   dashboard fields spelled out, plus the warning that the console must not be
   reachable on the public IP.
5. **Protect it with Access** (recommended) — create the application on the
   hostname, a policy for named emails or a domain with OTP, session length, and
   a service token + bypass for `/api/health` so monitors survive. States the
   double login plainly and how to remove it (put Access in front only, keep the
   console login as the second factor).
6. **Verify** — the check table above, with the end-to-end result as the
   headline.

Apps tab: table of the active site's hostnames with publish toggles, the
generated ingress values per hostname (copyable in token mode), per-row status
(not published / DNS missing / edge ok / origin mismatch), and a single
"Check all" plus per-row "Check". A short preamble explains that apps keep
going through the WAF, and that Cloudflare adds TLS-at-edge, DDoS and hiding the
origin — not a second WAF.

SaveBar semantics follow Tailscale: saving settings does not restart anything
until Save; enabling starts the connector, disabling stops it.

## Security

- Token sealed with `internal/crypto.Box`; never returned, never logged, masked
  in diagnostics (`diagnostics_test.go` gets a case).
- No browser-supplied executable input: fixed install script, fixed connector
  argv, validated hostnames.
- `CF-Connecting-IP` trusted only from a trusted local peer and only while the
  connector is enabled; stripped from untrusted peers.
- Access guidance includes the failure it creates (API clients need service
  token headers) so nobody "fixes" it by disabling Access.
- Enabling the tunnel must not widen what the console listens on; the check for
  "console reachable on the public IP" is part of verification, and the guide
  tells the admin to bind the GUI to loopback when a tunnel is the only path in.

## Failure modes and messages

| Symptom | Message |
| --- | --- |
| Binary missing | "cloudflared is not installed" + install button or commands |
| Token empty | "No tunnel token saved" |
| Connector exits immediately | last log line, and "tokens are long; make sure the whole value was copied" |
| `/ready` has 0 connections | "Connector is running but not registered with Cloudflare" |
| DNS resolves to the origin, not Cloudflare | "The hostname is not proxied; the request bypasses Cloudflare" |
| No `CF-Ray` | "The response did not come from Cloudflare" |
| `CF-Ray` but no origin nonce | "Cloudflare answered, but not from this proxy — check the ingress service" |
| ACME on a tunnelled host | "Edge certificate; issuance skipped" |
| App also answers on a public address | "edge + direct origin" on the row, with the trade-off spelled out; informational |
| Console also answers on a public address with Access on | "Access is bypassed on the direct path", protection step unmet, fixes listed |

## Testing

- `internal/cloudflared`: state machine with a fake binary (start, crash, ready
  probe, version drift, restart on token change) and a log-ring test.
- `internal/api/cloudflare_test.go`: settings round-trip including token
  redaction, enable/disable, audit entries, install polling, hostname validation
  for checks, `host_admin` denial, Docker (container flag) behaviour.
- `clientip`: `CF-Connecting-IP` accepted only under the documented conditions;
  proxy strips it otherwise.
- `certs`: tunnelled hostnames are skipped and labelled.
- Web: `Cloudflare.test.tsx` for the step gating and SaveBar, `CloudflareApps.test.tsx`
  for the publish toggles and row states.
- Manual: one real tunnel end to end on the demo host, and a Docker compose run
  with the sidecar override.

## Delivery slices

1. **Admin, token mode, native install** — supervisor, settings, install helper,
   checks, Admin tab, client-IP trust, `host-packages` entry, docs. Certificate
   suppression is not in this slice: in token mode the hostnames being published
   are configured in the dashboard, so there is nothing to mark yet.
2. **Apps** — per-site published hostnames, ingress rows, per-row checks, and the
   certificate suppression that only matters once app hostnames are published.
3. **API mode** — API token, create/attach tunnel, write ingress + DNS CNAME,
   verify; reuses the same generator and checks.
4. **Docker polish** — override file, sidecar detection copy, docs page.

Each slice ends with the version bump, CHANGELOG entry and rebuilt bundle the
project already requires.

## Decisions from review

1. **Dual path.** A tunnel and an inbound port forward can coexist, and the
   proxy keeps working either way: the tunnel arrives on loopback, the forward
   arrives on the WAN address, both reach the same listener. For apps this is a
   reported state, not a failure. For the console it means Access is bypassed on
   the direct path, so the protection step stays unmet until the admin closes
   the forward, restricts :443 to Cloudflare's ranges, or explicitly accepts it
   (the page keeps the trade-off visible). See "Two paths at once".
2. **Metrics port.** Fixed at `127.0.0.1:20241`, not an admin field, with
   `WAFPROXY_CLOUDFLARED_METRICS` as the only override for a port conflict. It is
   a loopback readiness endpoint that only our checks read; making it a setting
   adds a way to break the connector and nothing else.
3. **No copyable ingress YAML.** In token mode the tunnel config is
   remotely-managed by Cloudflare: `cloudflared` receives it from the edge, so a
   local YAML would be fiction. The page gives the dashboard field values per
   hostname (service URL, origin server name, no-TLS-verify) with copy buttons.
   YAML exists only as an appendix for people who deliberately run a
   locally-managed tunnel outside the console, and the page says so.
