# Console screenshots

The images in this directory come from a demo install (`demo.home.arpa`) and **contain
sample data**: the sites, bans, events, feeds and certificates were created for the
documentation, not taken from a real deployment. They are here so the guides can show what a
page looks like before you open it.

They were captured from the **v1.62.2** console (the version in the About card of each
capture), with two tenant sites, nine proxies, certificates, bans, threat feeds and a week of
traffic shaped by a daily curve. Everybody sees the full gallery in the
[README console tour](../../README.md#console-tour); the guides below reuse the same files.

| Image | Page | Also used in |
| --- | --- | --- |
| [dashboard.png](dashboard.png) | Dashboard: needs-attention queue, live rates, attack globe, per-site traffic | [Operations](../OPERATIONS.md), [Docker install](../install/01-docker.md) |
| [statistics.png](statistics.png) | Statistics: outcomes, per-site series, countries, uptime | [Configuration reference](../CONFIGURATION.md) |
| [proxies.png](proxies.png) | Proxies: hostnames, upstream health, per-site settings | [First site](../install/03-first-site.md), [Configuration reference](../CONFIGURATION.md) |
| [policies.png](policies.png) | Policies: bans, global profile, WAF and protection profiles | [Configuration reference](../CONFIGURATION.md) |
| [sources.png](sources.png) | Sources: threat feeds, local lists, per-address investigation | [Configuration reference](../CONFIGURATION.md) |
| [intel.png](intel.png) | Threat intel: feed health and rollup | [Configuration reference](../CONFIGURATION.md) |
| [logs.png](logs.png) | Logs: event search, stages, the request simulator | [Operations](../OPERATIONS.md), [Configuration reference](../CONFIGURATION.md) |
| [anomalies.png](anomalies.png) | Anomaly events: behavioural detections with baselines | [Configuration reference](../CONFIGURATION.md) |
| [activity.png](activity.png) | Activity: audit log with before/after diffs | [Configuration reference](../CONFIGURATION.md) |
| [access.png](access.png) | Access gate: site accounts, TOTP, lockouts | [Configuration reference](../CONFIGURATION.md) |
| [certs.png](certs.png) | Certificates: issuance, renewal policy, expiry | [Configuration reference](../CONFIGURATION.md) |
| [agent.png](agent.png) | AI Agent Access: MCP endpoint and per-tool tokens | [Configuration reference](../CONFIGURATION.md) |
| [notifications.png](notifications.png) | Notifications: channels and per-event routing | [Configuration reference](../CONFIGURATION.md) |
| [streaming.png](streaming.png) | Streaming: byte-relay forwarders for media and game servers (taken before the 1.63.0 grouping) | [Configuration reference](../CONFIGURATION.md) |
| [settings.png](settings.png) | Settings: network, protection, retention, backup, GeoIP | [Configuration reference](../CONFIGURATION.md) |
| [readiness.png](readiness.png) | Readiness: scored hardening checklist | [Security policy](../../SECURITY.md), [Configuration reference](../CONFIGURATION.md) |
| [updates.png](updates.png) | Updates: application and host packages | [Configuration reference](../CONFIGURATION.md) |
| [sites.png](sites.png) | Sites: tenant sites, console hosts and owned hostnames | [README console tour](../../README.md#console-tour) |
| [ha.png](ha.png) | High availability: cluster state and node pairing | [README console tour](../../README.md#console-tour) |

Not pictured: **Tailscale**, **Cloudflare** and **Account**. Their fields are documented in the
[configuration reference](../CONFIGURATION.md#sites) instead of here.

To retake them, run the console on a demo data directory against a build whose About card you
want to show, seed a few sites and a week of events, sign in on the default console host and
capture each page at 1440 px wide. The High availability capture was taken with HA enabled and
an unpaired node, which is the state a fresh install shows before pairing.
