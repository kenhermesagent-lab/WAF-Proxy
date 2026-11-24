## What this page is for
Behavioural detections: patterns across requests that a single-request rule would miss, such as one client sweeping many paths.

## Concepts
- **Anomaly** — a score over a window, not a single match.
- **Threshold** — the score at which an anomaly is recorded. Recording is not blocking.
- **Baseline** — what normal looks like for this hostname, learned from recent traffic.

## First tasks
- Read the recent anomalies before changing a threshold; one busy client can look like an attack.
- Raise a threshold if a legitimate integration trips it, and note why.

## Following an event out
Click an event to open its detail: the value, the baseline it was measured against, and the upstreams the site's traffic is forwarded to, with the IP whitelist that covers each one.

- An upstream inside a whitelisted subnet or IP is expected traffic. **Mute destination** stops outbound-spike detections for that site and acknowledges the open ones; the destination stays listed under **Muted destinations** until you unmute it.
- A site is only muted once every enabled upstream is muted, so one unexpected destination still raises a spike.
- Muting covers outbound spikes only. Request-rate spikes, login-failure bursts and their notifications are unaffected.
