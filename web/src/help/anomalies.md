## What this page is for
Behavioural detections: patterns across requests that a single-request rule would miss, such as one client sweeping many paths.

## Concepts
- **Anomaly** — a score over a window, not a single match.
- **Threshold** — the score at which an anomaly is recorded. Recording is not blocking.
- **Baseline** — what normal looks like for this hostname, learned from recent traffic.

## First tasks
- Read the recent anomalies before changing a threshold; one busy client can look like an attack.
- Raise a threshold if a legitimate integration trips it, and note why.
