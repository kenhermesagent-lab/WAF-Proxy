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
Click an event to open its detail: the value, the baseline it was measured against, where the site's outbound traffic goes, and the sources its IP whitelists allow.

- **Where the outbound traffic goes** — the site's upstreams and the addresses they resolve to. **Mute destination** marks one as expected.
- **Where it comes from** — the entries of the enabled IP whitelist policies that apply to the site. **Mute source** marks a trusted client as expected, so an upload from that public IP is no longer a spike.
- A mute acknowledges the open outbound spikes for the site. A new spike is still suppressed only while every enabled upstream is a muted destination, or every byte in the window came from muted sources: one unexpected destination or one other client still raises one.
- Muted rows are listed under **Muted traffic** until they are unmuted.
- Muting covers outbound spikes only. Request-rate spikes, login-failure bursts and their notifications are unaffected.
