## What this page is for
Live traffic for every proxied hostname: what arrived, what the WAF blocked, and which sources are being refused right now.

## Concepts
- **Request** — one HTTP call that reached the proxy. A blocked request was answered by the WAF instead of by your backend.
- **Ban** — an address refused for a while, either by a rule you wrote or by the ban engine after repeated abuse.
- **Retention** — events older than the retention window in Settings are deleted, so history has a fixed size.

## First tasks
- Open a hostname in the proxy table to show that hostname's requests in Logs.
- Quiet page and no hostnames yet? Create one under Proxies, then send a request through it.
