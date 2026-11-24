# MCP gateway for security agents

WAF-Proxy exposes a Model Context Protocol endpoint at `/mcp`. It lets a standalone agent
(Hermes, or any MCP Streamable HTTP client) review traffic and posture, block an address or
access-gate username, revoke visitor sessions, and cut a live media-relay stream. It is
intentionally a fixed operations API, not a remote shell, package manager or configuration
tool: reads cover the console's state, writes stay in the containment family.

`GET /api/mcp` returns the live catalog in `tools`, so the console and API clients list the
tools the running build actually has instead of a hardcoded copy.

## Enable and authenticate

### Console-issued token (recommended)

1. Sign in to the admin console.
2. Open **AI Agent Access**.
3. Choose **New agent token**, name it for the agent or host, and copy the value shown once.
4. Give the agent that token. Store it in the agent's secret store, not in a command line or a
   committed file.

The token is stored as a SHA-256 hash. Revoking it takes effect on the next request. The
**AI Agent Access** page lists the prefix, creation time and last use, but cannot recover the
plaintext.

### Environment token (headless installs)

Set in `/etc/wafproxy/wafproxy.env` and restart `wafproxy`:

```bash
WAFPROXY_MCP_TOKEN=<at-least-32-random-characters>
WAFPROXY_MCP_ACTOR=hermes-agent
```

The token acts on the default site — the console that issues it — so its logs, gate accounts
and settings are the ones that console shows. `list_sites` names every tenant on the install,
but a tenant's rows are not readable through this token.

Console-issued tokens choose their tools individually: the create dialog lists the catalog and a
token can be limited to, for example, `query_logs` and `get_ip_activity`. `tools/list` hides the
rest and `tools/call` refuses them. A token created under 1.24's `read`, `ban` or `session` group
is translated to the tools that group covered; a token with no scopes keeps every tool, and so
does the environment token.

`WAFPROXY_MCP_ACTOR` is the audit name for that static token. An environment token cannot be
revoked from the console; remove the variable and restart to disable it. Generate the value
with `openssl rand -base64 32`.

The endpoint uses the same listener as the admin console. The native installer binds that
listener to the LAN and enables `WAFPROXY_GUI_PRIVATE_ONLY`; keep it that way. Do not expose
`/mcp` on the WAN. For an agent on another network, use Tailscale or another private tunnel, or
put a TLS-terminating reverse proxy in front of the console listener.

## Protocol

- Transport: MCP Streamable HTTP, one `POST /mcp` endpoint.
- Content type: request and response are `application/json`.
- Authentication: `Authorization: Bearer <token>`.
- Origin: a request with an `Origin` header must match the console host, otherwise HTTP 403.
- Versions accepted: `2025-03-26`, `2025-06-18`, `2025-11-25` and `2026-07-28`. The request may
  send `MCP-Protocol-Version`; an unsupported value is HTTP 400.
- `GET /mcp` is not a standalone SSE stream and returns HTTP 405. `DELETE /mcp` returns 204 for
  compatibility with older session-aware clients.
- Requests are rate-limited to 120 per source IP per minute. Bodies are capped at 1 MiB.
- Notifications (JSON-RPC requests without an `id`) are accepted with HTTP 202 and no body.

The server is stateless. A 2025 client may send `initialize`; the response echoes a supported
protocol version and advertises only the `tools` capability. A 2026 client may call
`server/discover` first, then `tools/list` and `tools/call` directly. `ping`,
`resources/list` and `prompts/list` are also implemented so discovery clients do not fail.

### Quick check

```bash
TOKEN='<agent token>'
curl -sS http://192.168.1.10:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

List the tools:

```bash
curl -sS http://192.168.1.10:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

Call one:

```bash
curl -sS http://192.168.1.10:8443/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_ip_activity","arguments":{"ip":"203.0.113.9"}}}'
```

A tool result has both a human-readable `content[0].text` JSON block and machine-readable
`structuredContent`. Tool-level failures return `isError: true`; malformed JSON-RPC or an
unknown tool returns a JSON-RPC error.

## Hermes / generic client configuration

Use the HTTP MCP transport with a fixed `Authorization` header:

```json
{
  "mcpServers": {
    "wafproxy": {
      "type": "http",
      "url": "http://192.168.1.10:8443/mcp",
      "headers": { "Authorization": "Bearer <agent token>" }
    }
  }
}
```

If the client only supports a command-based MCP server, use its HTTP bridge rather than
inventing a shell wrapper. Do not put the token in a process argument that appears in `ps` or
shell history.

## Tools

All mutating tools require `reason` and are audited. `reason` is stored in the audit detail and,
for bans and username blocks, in the block record.

### Read tools

| Tool | Arguments | Returns |
|---|---|---|
| `get_security_overview` | none | Active IP ban count, kernel status, 1h/24h traffic and block totals, top source IPs and stages, recent blocked events, active gate sessions, username blocks |
| `query_logs` | `src_ip`, `host`, `action`, `stage`, `blocked_only`, `since_minutes` (1–10080, default 60), `limit` (1–500, default 50) | Matching events newest first, total matching, returned count, `bytes_out`, blocked count |
| `list_anomalies` | `limit` (1–200, default 50) | Recent outbound-spike, request-rate and login-burst detections with the proxy, the measured value and its baseline |
| `get_ip_activity` | `ip` | 24h request/block/byte totals, covering ban, recent events, live gate sessions |
| `list_proxies` | none | Proxy id, hostname, enabled, gate mode, WAF mode, maintenance |
| `get_proxy` | `hostname` or `id` | One host's gate/WAF modes, TLS certificate, WAF profile, balancing and health-check settings, in-flight limits and upstream pool |
| `list_sites` | none | Every site (tenant) with its console host, enabled state and the current site id, so a hostname or event can be attributed to its owner |
| `list_certificates` | none | TLS certificates with issuer, source, status, renewal mode, expiry and days left |
| `list_waf_profiles` | none | WAF profiles with mode, paranoia level, anomaly threshold, response inspection and body caps |
| `get_stream_status` | `id` (service), `limit` (1–200, default 20) | Media-relay services with bind state, listen address, active streams and sessions, totals, refusals and the busiest live sessions |
| `query_audit` | `actor`, `action` (substring), `limit` (1–200, default 50) | Administrator audit entries newest first, including the `mcp.*` rows agents write |
| `list_blocks` | none | Active IP/CIDR bans and username blocks |
| `list_gate_users` | none | Gate usernames, TOTP state, blocked state and block reason |
| `list_sessions` | `limit` (1–1000, default 200) | Live gate sessions with non-secret `ref`, username, IP, proxy hostname, user agent, timestamps |

### Containment tools

| Tool | Arguments | Effect |
|---|---|---|
| `block_ip` | `ip`, `reason`, `permanent` (default false), `ttl_seconds` (0–31536000, default 86400; `0` means 24 hours unless `permanent` is set) | Adds an IP or CIDR to the same ban engine used by the console and nftables |
| `unblock_ip` | `ip`, optional `reason` | Removes the exact ban row; reports a broader covering prefix without removing it |
| `block_username` | `username`, `reason`, `ttl_seconds` (0 = permanent), `revoke_sessions` (default true) | Blocks gate logins and revokes the account's live sessions |
| `unblock_username` | `username`, optional `reason` | Lifts the username block; existing sessions stay revoked |
| `revoke_session` | `session_ref`, `reason` | Deletes one gate session by its 32-character ref |
| `revoke_sessions_for_ip` | `ip`, `reason` | Deletes every live gate session opened from that address |
| `cut_stream_ip` | `ip`, `reason` | Cuts every live media-relay stream from that address and audits the cut; `block_ip` is the durable ban |

`block_ip` refuses loopback, unspecified, multicast, link-local and prefixes broader than `/8`
for IPv4 or `/16` for IPv6. A temporary ban is enforced in the proxy immediately and in
nftables when kernel enforcement is available. Existing streaming connections are cut by the
ban engine, matching a console-created ban.

`get_stream_status` and `cut_stream_ip` report `attached: false` or a clear error when the
running process has no media relay, so a token's catalog does not change between hosts with
and without the relay configured.

## What the agent still cannot do

- Read or write arbitrary files, run shell commands, install packages, restart the service or
  change proxy, certificate, WAF, site or settings configuration. The read tools report that
  state; they do not edit it.
- Read a session cookie, password hash, TOTP secret, API token or TLS private key.
- Manage host packages or update the binary. Those remain separate, audited console features.
- Act on the administrator's password or 2FA.

The agent has the security operations listed above, so treat its token like an operator
credential. Use a separate token per agent and revoke it when the agent is retired or its host
is rebuilt.

## Containment playbook

A reasonable agent loop:

1. `get_security_overview` to see the current state and whether the address is already blocked.
2. `query_logs` for the suspicious `src_ip`, or `get_ip_activity` for byte and path context.
3. If the evidence is scanning or credential abuse, `block_ip` with a specific reason and a
   temporary TTL. Reserve `permanent: true` for confirmed hostile infrastructure.
4. If the evidence is a compromised gate account, `block_username` with
   `revoke_sessions: true`.
5. If the evidence is an active data transfer, `list_sessions` (filter by IP in
   `get_ip_activity`), then `revoke_session` for the narrowest ref. Use
   `revoke_sessions_for_ip` only when every session from that address is hostile.
6. Re-read the relevant logs or `list_blocks` to confirm the effect. Report the action and
   reason; do not silently retry a failed destructive call.

## Audit and troubleshooting

Every call is written to the audit log as `mcp.<tool>` with actor `mcp:<token name>` (or
`mcp:<WAFPROXY_MCP_ACTOR>`). The console's **Settings → Recent administrator activity** and
`GET /api/audit` show those rows.

| Symptom | Check |
|---|---|
| HTTP 401 | Token is missing, misspelled, revoked, or belongs to a different install. Create a new token on **AI Agent Access**. |
| HTTP 403 | `Origin` does not match the console host. Remove the header or configure the client's base URL correctly. |
| HTTP 400 `unsupported MCP protocol version` | Send one of the four supported `MCP-Protocol-Version` values, or omit the header. |
| HTTP 405 on GET | This endpoint does not provide a server-initiated SSE stream; use POST for every request. |
| Tool returns `isError: true` | Read the JSON `error`; common causes are a missing `reason`, a too-broad CIDR, a loopback address, or an expired session ref. |
| No gate sessions listed | The proxy may not use gate modes, or the sessions expired. Check **Access gate** and `gate_ttl_hours`. |
| Block has no kernel effect | Check **Settings → Kernel ban enforcement**. Without `nft` or `CAP_NET_ADMIN`, the proxy-level ban still applies. |
