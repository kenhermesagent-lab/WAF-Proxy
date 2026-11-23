## What this page is for
The hostnames this box serves. Each one forwards traffic to backends on your network after the WAF has looked at the request.

## Concepts
- **Hostname** — a single-label subdomain of your base domain, for example `app.example.com`. The apex domain is reserved.
- **Upstream** — the real server, as `http://192.168.1.20:8080`. Loopback and LAN addresses are expected here.
- **Profile** — the set of rules applied to a hostname. Inherit leaves it to the access profile or the default.

## First tasks
- Create a hostname, point DNS at this box and send one request through it.
- Issue a certificate for the hostname before anyone visits it over HTTPS.
- Watch the hostname's counters on the Dashboard to confirm traffic is flowing.
