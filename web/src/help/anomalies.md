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
Click an event to open its detail: the value, the baseline it was measured against, where the data left for, and the backends the site sends to.

- **Where the data left for** — the clients that received the site's bytes in the window, ranked by volume, with the total delivered and the request count. A **public** address is data that left the network; a **LAN** one stayed on it. A whitelisted client is already expected, so it needs no mute.
- **Investigate** opens the source's full record: whois, AbuseIPDB, the hosts and paths it touched.
- **Mute** marks that client's traffic as expected. **Ban 24h** and **Ban permanently** add it to Policies; both are audited and enforced at the proxy and in nftables.
- **Backends this site sends to** — the configured upstreams, marked **internal** or **public**. Muting a backend treats its traffic as expected; an internal backend is normal request forwarding, not data leaving the network.
- A whitelisted client is expected without a mute, and a mute acknowledges the open outbound spikes for the site. A new spike is still suppressed only while every enabled upstream is a muted backend, or every byte in the window came from a whitelisted or muted client: one unexpected client still raises one.
- Muted rows are listed under **Muted traffic** until they are unmuted.
- Muting covers outbound spikes only. Request-rate spikes, login-failure bursts and their notifications are unaffected.
