## What this page is for
Totals over time, so you can tell whether protection is working without reading individual requests.

## Concepts
- **Overview** — counts per outcome: allowed, blocked and challenged.
- **Uptime monitor** — scheduled probes of your hostnames, separate from live traffic. It sits above the date range and stays on screen whichever tab is open.
- **Access gate logins** — sign-ins to gate-protected sites, which are not WAF decisions.
- **Utilization** — CPU, memory, WAN throughput and the hourly request and block counts, kept for 30 days, so a
  block spike can be lined up with the load that came with it.

## First tasks
- Open Traffic to compare success and error counts for each hostname.
- Check Uptime after changing a backend, before users report it.
