# AI Agent Access — design proposal

Date: 2026-11-22 · Status: **awaiting approval** · Scope: one project, four slices

## Intent

The console can detect and block, but every decision currently waits for a human. The aim is to let an
operator attach an AI agent that watches the same signals the console sees, acts fast on the obvious
cases (block, cut live sessions), asks the admin before or immediately after acting, and reverts when
the admin says "that was me". Alongside it, a small curated signature pack so the agent has something
concrete to block on beyond CRS and the IP feeds.

## Why now

Attack traffic is automated and fast; the window between an exfiltration start and the admin noticing is
the whole risk. The console already has the enforcement primitives (ban engine with session cut-off,
streaming drop, CrowdSec bouncer) and an MCP gateway with token auth — what is missing is the trigger and
the decision path.

## Goals

- An agent, external (Hermes) or in-console (a pasted provider key), can be attached to the console and
  receives anomaly events with enough context to decide.
- Events carry the numbers that caused them (rate, bytes, window, proxy, source IPs/ASNs), not a bare alert.
- Actions are audited, reversible, and bounded: the agent can block and cut, then ask; unblocking is one click.
- An admin can mute whole classes of events without losing the others.
- Signatures are versioned in-repo, editable through the console and callable over MCP.

## Non-goals (v1)

- No automatic outbound reporting to AbuseIPDB/CrowdSec from the agent. Reporting is outbound and public;
  the existing CrowdSec bouncer integration stays the reporting path, and the agent only recommends.
- No model training, no embedding search, no per-request inline LLM calls in the data path.
- No container installation of agent runtimes — same constraint as the identity providers.
- No new signature engine: signatures are matched by the existing Coraza/CRS path plus a path/pattern list.

## Constraints

- Go standard library plus what the repo already vendors; no new runtime dependency for the event bus.
- Secrets (provider keys, agent shared secrets) sealed with `crypto.Box`, never returned by the API.
- One process; the console restarts itself during updates, so agent state must be durable in SQLite.
- The MCP gateway is the only agent-facing API surface; every new action is an MCP tool with the same token
  scopes, so a bug in the console UI cannot become a bypass.

## Approaches considered

1. **Agent polls the console** (`GET /api/agent/events?since=`). Simple, survives agent downtime, but a
   slow poll means a slow block, which defeats the point.
2. **Console pushes to the agent** (webhook POST to a URL the agent exposes, HMAC-signed, retries with
   backoff), with the console holding the state machine (open → acknowledged → resolved). Fast, and the
   console keeps the audit trail even when the agent dies.
3. **Model in the request path** — the console calls an LLM per suspicious request. Rejected: latency,
   cost, and a model failure becomes an outage.

Chosen: **2, with 1 available as a catch-up endpoint**. The pusher is one goroutine with a bounded queue;
when the agent is unreachable the event is stored and retried, and the console applies its own default
(recommended by the admin in settings) if nobody answers within the window.

## Design

### Agent links (replaces the Agent access page: **AI Agent Access**)

`agents` table: `id, name, kind (webhook|provider), enabled, endpoint_url, secret (sealed), provider
(openai|anthropic|gemini|openai_compatible), model, api_key (sealed), scopes, created_at`.

- **kind=webhook** — the console POSTs events to `endpoint_url` with `X-Wafproxy-Signature:
  sha256=HMAC(secret, body)`; the agent calls back through MCP.
- **kind=provider** — the console itself runs the loop by calling the provider's chat API with the event
  payload and a fixed tool schema (block, unblock, mute-event, report). Used when no external agent exists.
  The key is sealed; the model id is an allowlist per provider.

Both share one dispatcher, one audit trail, and one approval state machine, so an external agent and an
in-console provider behave identically to the admin.

### Event pipeline

Detector runs on the existing metrics tick (per proxy, 1-minute buckets, already in memory):

- `egress_spike`: response bytes in the window exceed `baseline × factor` and an absolute floor
  (baseline = median of the last 60 windows, so a quiet night doesn't trigger).
- `rate_spike`: requests/s exceed a configured threshold or 3× baseline, with the top client IPs/ASNs.
- `auth_burst`: gate failures or 401/403 rate above threshold for one host.

Each event: `id, kind, proxy_id, started_at, metrics (json), top_sources (json), state, agent_id, verdict,
reason`. Routing reuses `notify.EventKinds` so an admin can mute `egress_spike` alone — the same mechanism
just added for CrowdSec.

### Decision and approval

- Agent verdict arrives via MCP (`agent.decide`) with `action ∈ {allow, block, block_and_cut, escalate}`,
  a reason and a confidence. Trusted actions (block, cut) execute immediately, are audited, and open an
  approval asking the admin "was this you?" through the existing notification channels.
- Admin answer (`/api/agent/events/{id}/approve|revert`) either keeps the ban or lifts it and, for
  "that was me", adds the source to a temporary allowlist with an expiry so the agent doesn't re-block.
- No answer within `agent_confirm_minutes` (default 30): the ban stands, the event stays open, and the
  console sends one reminder — never a stream.

### Signature pack

`signatures` table plus a `signatures/*.yaml` pack shipped in the repo (OWASP top-10 payload shapes,
scanner/bot paths, credential-stuffing patterns, exfil-shaped query strings). Each rule: `id, name,
category, pattern, target (path|query|body|header|ua), action (block|log), severity, enabled`.
Loading is additive: repo rules are inserted on boot if missing, operator edits and enabled flags survive.
Matching: path/query/header/UA rules go into the existing CRS rule set as custom rules; body rules are
documented as CRS-only in v1 (`shortcut: body matching only through CRS, upgrade if a body rule is needed`).
The agent reads and mutates them through `signature.list/enable/disable`.

### MCP additions

`agent.list`, `agent.decide`, `event.list`, `event.get`, `signature.list`, `signature.enable`,
`signature.disable`, `ban.temp`, `ban.permanent`, `ban.remove`, `stream.disconnect`. Each is scoped and
audited with the agent name as actor.

### UI

AI Agent Access: link list (name, kind, endpoint, last seen, enabled), link form with a "send test event"
button, and a per-link event log. Threat intel gains a *Signatures* card (list, toggle, edit pattern).
Dashboard gains an *Agent activity* strip: events open, actions taken last 24h, pending approvals.

## Security notes

- HMAC on every webhook; the agent's secret shown once. Replay protection: `X-Wafproxy-Timestamp` within
  5 minutes plus an event id the console won't accept twice.
- Provider keys sealed; model calls pinned to an allowlist per provider and never echoed to the browser.
- The agent's MCP token is scoped to the tools above; `agent.decide` cannot rewrite settings, keys or users.
- Bans made by an agent are marked `source=agent:<name>` in the ban list, so a bad agent is auditable and
  removable in bulk.
- Rate-limit agent decisions per event (one verdict) and per minute, so a looping model cannot ban /0.

## Slices

1. **Event pipeline + storage + routing** (no agent): detect, store, notify, show on a page. Testable
   without any model.
2. **AI Agent Access page + webhook link + HMAC + test event**; MCP `event.*` tools.
3. **Decision + approval loop** (block, cut, revert, allowlist, timeout), audited.
4. **Provider-backed loop** (pasted key, fixed tool schema) and **signature pack** with console + MCP.

Each slice ships with tests and its own changelog entry; slices 1–2 are useful on their own.

## Open questions

- Baseline window (60 minutes) and defaults for the three thresholds — I propose egress `factor 4x` over a
  5 MB/5-min floor, rate `200 rps` or `3x` baseline, auth burst `20/min`; tunable in Settings.
- Whether "escalate" should also open a ticket in an external system (Slack/Linear). Out of scope in v1.
