# Native Tailscale access — design

**Status:** approved 2026-11-21; implementation in progress.

## Intent

Let a self-hosted WAF-Proxy be reached privately over a native Tailscale
installation, without exposing either the admin console or the application
through the public WAN.

There are two independent switches, both **off by default**:

1. **Admin over Tailscale** — keep the existing LAN console and add a second
   console listener on the host's `tailscale0` IPv4 address. The LAN listener
   and its RFC1918 rule remain unchanged.
2. **Proxy app traffic over Tailscale** — add a second TLS/SNI proxy listener
   on the same `tailscale0` address. A remote tailnet device opens the app's
   normal HTTPS hostname; split DNS resolves that hostname to this WAF; the WAF
   terminates TLS, runs the existing inspection pipeline, and forwards to the
   LAN application.

The second switch includes a small authoritative DNS responder on the tailnet
address. Tailscale split DNS can forward a domain to a nameserver, but it cannot
store a direct A-record override for a custom domain. Without this responder the
feature would only work for operators who already run internal DNS.

## Decisions already made

- The admin path is an **additional** route; LAN access is not removed.
- The data path uses the **app's normal hostname** and a split-DNS override,
  not a `*.ts.net` URL and not a Host rewrite.
- The feature is native to the host's Tailscale installation. No Tailscale
  sidecar container is required.
- No Tailscale CLI control, auth key, API token, or tailnet-policy mutation is
  performed by the web UI.

## Current constraints

- The admin GUI is a single HTTP listener on the stored LAN address, optionally
  wrapped by `PrivateNetworksOnly` (RFC1918 + loopback).
- The proxy is a single TLS listener on the stored WAN address. Routing is by
  SNI/Host and the configured per-site certificates.
- The systemd unit runs as `wafproxy` with `CAP_NET_BIND_SERVICE` and
  `CAP_NET_ADMIN`, so it can bind 443/8443/53 without root.
- Docker uses host networking. A host-installed Tailscale interface is visible
  to the container, but Docker is not the primary target for this feature.
- Tailscale ACLs are default-deny when a policy is configured. Access must be
  granted explicitly for the tailnet ports used here.
- Tailscale Serve HTTP mode only proxies to `http://127.0.0.1` and terminates
  TLS. Serve TCP can preserve the client address only through the PROXY
  protocol, which this proxy does not parse.

## Approaches considered

### A. Direct listeners on `tailscale0` — chosen

Bind the existing admin handler and proxy handler to the Tailscale IPv4 address.
Add a small DNS responder on the same address for the proxy hostnames.

- Preserves the WAF's TLS/SNI behaviour, certificates, Host header and real
  client IP (`100.64.0.0/10`).
- No Tailscale CLI privilege, sidecar, loopback listener or PROXY-protocol
  parser is needed.
- Requires two extra listeners and a DNS service.
- Admin is HTTP inside the WireGuard tunnel, like the existing LAN console.
- Tailnet ACLs remain the network gate; the existing password + TOTP remain the
  application gate.

### B. Tailscale Serve for admin + Serve TCP for data — rejected

Serve gives the admin console a trusted `*.ts.net` certificate, but its HTTP
proxy needs a loopback backend, and its TCP path loses the real source address
unless the backend parses the PROXY protocol. Using Serve for both also creates
a port-443 ownership conflict between the admin and data planes. This is more
moving parts and more security-sensitive than A.

### C. Serve-only single app — rejected

A `*.ts.net` URL can point at one chosen app, but the backend sees the tailnet
Host rather than the app's Host, and the design stops working as soon as there
is more than one site. It also bypasses the existing hostname/certificate model.

## Design

### 1. Detection and saved settings

At startup, detect the host's Tailscale IPv4 address from the `tailscale0`
interface (first global IPv4 in `100.64.0.0/10`). Do not shell out to the
Tailscale CLI. Expose detection through the authenticated API.

Store two independent booleans in the existing settings table:

- `tailscale_admin_enabled`
- `tailscale_proxy_enabled`
- `tailscale_dns_enabled` (default on; only meaningful with the proxy switch)

Values are `"1"` / `"0"`. Default is `"0"` for the two access switches and
`"1"` for DNS. They are not added to the general Settings form or the public
settings backup; a dedicated API owns them.

If Tailscale is not installed, `tailscale0` is down, or it has no IPv4 address:

- the page reports **unavailable** with the reason;
- both switches are disabled;
- an enabled setting from an earlier boot is not fatal: the service logs a
  warning and serves only the existing LAN/WAN listeners. This prevents a
  Tailscale outage from taking the whole proxy down.

### 2. Admin listener

When `tailscale_admin_enabled` is on and an address is available, start the
same admin handler on `[tailscale-ip]:<gui_port>`, in addition to the LAN
listener.

The tailnet listener is wrapped by a new `TailscaleOnly` middleware that
accepts only sources in `100.64.0.0/10`. The LAN listener keeps
`PrivateNetworksOnly` and does not accept CGNAT addresses. The existing session,
CSRF, password and TOTP rules are unchanged.

The page shows:

- `http://<tailscale-ip>:<gui_port>`
- the same URL using the MagicDNS name when it can be discovered; otherwise the
  IP is the canonical copyable value.

This listener is HTTP inside Tailscale's encrypted WireGuard transport. It does
not get a public certificate and does not use Tailscale identity headers. The
admin must still sign in with password + TOTP/recovery code.

If the GUI port equals the chosen proxy port, both tailnet listeners would
collide on the same address. The API rejects that combination with a clear
message; the LAN and WAN listeners may still use the same port on different
addresses as they do today.

### 3. Proxy listener and split DNS

When `tailscale_proxy_enabled` is on and an address is available, start the
existing proxy on `[tailscale-ip]:<wan_port>`. The proxy uses the same edge
table, certificates, WAF, bans and upstreams. The only difference is the bind
address and the client source address (`100.x` instead of the WAN client).

Remote devices must resolve the app hostname to the tailnet address. With
`tailscale_dns_enabled` on, run a small DNS responder bound only to
`[tailscale-ip]:53` (UDP and TCP). Tailscale split DNS is configured in the
Tailscale admin console with:

- Nameserver: the WAF's tailnet IPv4
- Restrict to domain: the WAF base domain (for example
  `example.duckdns.org`)

The responder is authoritative for that domain and answers only A queries for
hostnames that exist as configured proxies. It returns the WAF tailnet IPv4 with
a short TTL. It does not recurse, does not answer arbitrary names, does not
provide AAAA records, and returns NXDOMAIN/REFUSED for everything else. It is
bound to the tailnet address, so it is not reachable from the WAN or LAN.

Examples of the resulting flow:

```
Tailscale device
  https://app.example.duckdns.org
        │  split DNS → 100.x.y.z
        ▼
WAF tailnet listener 100.x.y.z:443 (TLS, SNI app.example.duckdns.org)
        │  WAF pipeline
        ▼
LAN app 192.168.101.10:8080
```

The DNS responder is an implementation detail of the proxy switch, but it has
its own toggle so an operator with an existing internal resolver can turn it
off. If the DNS listener cannot bind, the proxy listener still starts and the
page reports the DNS error; the operator can fix port 53 and restart or use
their own resolver.

### 4. API and console

New authenticated endpoints:

- `GET /api/tailscale` — availability, detected IPv4, MagicDNS name if known,
  saved/active switch state, listener status/errors, admin URL, base domain,
  proxy port, DNS state, restart-required flag.
- `PUT /api/tailscale` — two/three booleans; validates address availability and
  port collision; writes settings and audit entry; returns restart-required.

A new **Tailscale** page in the console, between **Streaming** and **Policies**:

- status card with detected address and availability reason;
- **Admin console over Tailscale** toggle;
- **Proxy app traffic over Tailscale** toggle;
- **Answer split DNS on the tailnet** toggle (shown under the proxy switch);
- copyable admin URL and DNS setup values;
- plain-language ACL and split-DNS instructions;
- **Restart required** notice after a change, with the existing restart action
  or a link to Streaming → Restart service.

No automatic restart is performed. A restart is the same supervised restart
already used for listener changes.

### 5. Installer and docs

`deploy/install.sh` detects `tailscale` and `tailscale0` but does not install
Tailscale or run `tailscale up` automatically. It prints the official install
and login commands when Tailscale is absent or disconnected, and continues.
This avoids piping a remote installer into a root shell and avoids blocking an
unattended `--yes` run on browser authentication.

The installer still writes only LAN/WAN listener values. Tailscale access is
enabled after first login, from the Tailscale page, because it is authenticated
state stored in SQLite and must not be enabled before the wizard claims the
administrator account.

Documentation additions:

- native install: install Tailscale with the official package instructions,
  run `tailscale up`, then enable the switches;
- ACL example for `tcp:443`, `tcp:8443`, `udp:53`, `tcp:53`;
- split-DNS setup and how to verify with `dig`;
- note that Tailscale clients see the WAF as `100.x`, not their LAN address;
- Docker: works when Tailscale is installed on the host with host networking,
  but is not the primary supported path. The compose defaults bind wildcard
  LAN/WAN addresses, so set concrete `WAFPROXY_LISTEN_GUI` and
  `WAFPROXY_LISTEN_WAN` addresses before enabling tailnet listeners.

### 6. Startup, shutdown and failure behaviour

- Resolve the tailnet address once at boot. If it changes, the page reports a
  restart is required; listeners are not rebound live.
- Add all listener addresses before starting. If a tailnet bind fails, log the
  exact address and error, keep the other listeners running, and expose the
  error on the Tailscale page. Do not exit the process.
- On `SIGTERM`, shut down all admin, proxy and DNS listeners.
- A Tailscale outage removes reachability but does not stop the LAN/WAN paths.
- If `tailscale0` is absent at boot, no tailnet work is attempted.

## Security model

- Tailnet access is gated by the tailnet ACL and, for admin, by the existing
  password + TOTP. The Tailscale IPv4 range is accepted only on the admin
  tailnet listener, never on the LAN listener.
- The admin tailnet listener is HTTP over WireGuard. It is not exposed to the
  public internet and does not trust Tailscale identity headers.
- The proxy tailnet listener uses the existing TLS certificates and WAF rules.
  Client IPs are the real `100.x` tailnet addresses; bans and rate limits apply.
- The DNS responder is authoritative, non-recursive, tailnet-bound, and answers
  only configured proxy hostnames. It cannot be used as an open resolver.
- The UI never invokes `tailscale`, reads auth keys, writes the tailnet policy,
  or accepts a Tailscale API token.
- No Tailscale Funnel or public exposure is added.

## Tests

- Unit: Tailscale IPv4 selection from interface addresses; rejection of
  non-`100.64/10` and missing interfaces.
- Unit: `TailscaleOnly` accepts `100.64.0.1`/`100.127.255.254`, rejects RFC1918,
  public and IPv6 sources.
- Unit/integration: DNS handler answers A for a configured proxy, is
  case-insensitive and trailing-dot tolerant, returns NXDOMAIN for unknown
  names, refuses other domains, and serves both UDP and TCP.
- API: status reports unavailable/enabled/active/restart-required; PUT rejects
  a GUI/proxy port collision and an unavailable Tailscale address; settings and
  audit are written.
- Listener: multiple proxy/admin addresses are deduplicated and each serves the
  existing TLS/HTTP path; a failed extra bind does not stop the primary.
- UI: Vitest states for unavailable, disabled, enabled, DNS error and restart
  required.
- Regression: existing Go tests, race tests, web tests/typecheck/build,
  `make build`, gofmt/vet, systemd unit verification.
- Manual: a QEMU or other disposable Linux host with a dummy `tailscale0`
  address can verify binding and the DNS answer. A real tailnet login, ACL and
  split-DNS propagation cannot be verified in this environment and will be
  reported as an explicit limitation.

## Out of scope for this change

- Tailscale Serve/Funnel, `.ts.net` certificate issuance, identity-header login.
- Automatic Tailscale installation, `tailscale up`, auth-key handling, or ACL
  editing.
- Subnet routers and exit-node routing.
- Tailnet-only admin (the chosen behavior keeps LAN access).
- IPv6 tailnet listeners; this design uses the Tailscale IPv4 address.
- Multi-user roles and per-tailnet-user authorization.

## Approval

The user has selected Approach A and “add alongside LAN”. This document adds
the embedded split-DNS responder required to make that approach turnkey.
Implementation starts only after this document is approved.
