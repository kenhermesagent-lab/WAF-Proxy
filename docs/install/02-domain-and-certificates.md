# Point a domain and get a certificate

Part of [Installation](../INSTALL.md).

## 4. Firewalla and DuckDNS

1. DuckDNS keeps the A record for `example.duckdns.org`; DuckDNS mirrors A/AAAA and the single
   TXT record to `*.example.duckdns.org`, so subdomains resolve without extra records.
2. On the Firewalla, create a port forward: WAN `443` → `192.168.1.20:443`.
   **Do not enable SNAT/masquerade on that rule**; the proxy needs real client IPs for
   GeoIP, bans and rate limits.
3. Port 80 is not required for DNS-01. Forward it only if you choose the **HTTP-01** challenge;
   **TLS-ALPN-01** needs no extra port and is answered on 443.
4. Optional second layer: block the bare apex `example.duckdns.org` at the Firewalla. The
   proxy already closes it without a response.

Because DuckDNS stores exactly one TXT record per domain, request **one wildcard
certificate** (`*.example.duckdns.org` plus the apex as SAN). The certificate manager
serialises ACME orders so two challenges cannot overwrite each other.

## 5. First certificate

GUI → **Certificates** → **Request certificate**:

- Domains: `*.example.duckdns.org,example.duckdns.org`
- Challenge: `DNS-01` (wildcards require it)
- Provider: `duckdns`
- Credentials: leave blank if the wizard stored the token, otherwise paste
  `{"token":"..."}`.

For a single hostname without a DNS provider, choose **HTTP-01** (forward port 80 to the
proxy) or **TLS-ALPN-01** (already answered by the HTTPS listener) and leave the provider and
credentials empty. Both need the name to resolve to this host and to be reachable from
Let's Encrypt.

Issuance is asynchronous; the row moves from `pending` to `issued` and shows the expiry.
Use the row's **Auto-renew** menu to choose **Monthly**, **Every 2 months**, **Every 3 months**,
or **1 month before expiry** (the default). Let's Encrypt certificates last 90 days, so the
three-month choice is capped at seven days before expiry. Renewal is checked every 12 hours;
the next date is shown under the menu. Use the staging toggle in Settings while testing to
avoid Let's Encrypt rate limits.
