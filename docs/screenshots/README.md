# Console screenshots

The images in this directory come from a two-NIC demo install of this exact build
(`demo.home.arpa`) and **contain sample data**: the sites, bans, events, feeds and
certificates were created for the documentation, not taken from a real deployment.
They are here so the guides can show what a page looks like before you open it.

| Image | Page | Used in |
| --- | --- | --- |
| [dashboard.png](dashboard.png) | Dashboard: needs-attention queue, live rates, attack globe, per-site traffic | [README](../../README.md), [Operations](../OPERATIONS.md), [Docker install](../install/01-docker.md) |
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
| [streaming.png](streaming.png) | Streaming: byte-relay forwarders for Plex and Jellyfin | [Configuration reference](../CONFIGURATION.md) |
| [settings.png](settings.png) | Settings: network, protection, retention, backup, GeoIP | [Configuration reference](../CONFIGURATION.md) |
| [readiness.png](readiness.png) | Readiness: scored hardening checklist | [Security policy](../../SECURITY.md), [Configuration reference](../CONFIGURATION.md) |
| [updates.png](updates.png) | Updates: application and host packages | [Configuration reference](../CONFIGURATION.md) |

To retake them, run the console on a demo data directory, seed a few sites and a
day of events, and capture each page at 1440 px wide.
