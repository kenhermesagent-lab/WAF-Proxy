## What this page is for
Live traffic for every proxied hostname: what arrived, what the WAF blocked, what still reached your applications, and which sources are being refused right now.

## Concepts
- **Request** — one HTTP call that reached the proxy. A blocked request was answered by the WAF instead of by your backend.
- **Reached app** — an allowed request that landed on a login, admin or token endpoint. It is the other half of the picture: the proxy let it through and your application answered it.
- **Near miss** — a detection that fired without blocking: a WAF profile in detect mode, a logged bundle rule or a logged feed match. It would be a refusal under a stricter setting.
- **Ban** — an address refused for a while, either by a rule you wrote or by the ban engine after repeated abuse.
- **Retention** — events older than the retention window in Settings are deleted, so history has a fixed size.

## Reading the attack map
- The globe draws blocked attacks as red, amber and violet arcs. Teal dashed arcs are requests that got through to an authentication or administration endpoint.
- The three numbers above the panel are blocked, reached app and near miss for the selected 1h, 6h or 24h window. The bar under them splits screened traffic into refused and allowed, so a quiet map still shows exposure.
- **Blocked** ranks regions and lists recent refusals with their stage and rule. **Reached** ranks the endpoints that were hit, with the status your application returned (`200` landed, `3xx` bounced to a login, `401`/`403` refused by the app after the proxy allowed it) and the sources that got in. **Near miss** lists the rules that logged only.
- Click a country or a hotspot to isolate it; all three tabs follow the selection.

## First tasks
- Open a hostname in the proxy table to show that hostname's requests in Logs.
- Quiet page and no hostnames yet? Create one under Proxies, then send a request through it.
- Put a WAF profile in detect mode and the requests it would have blocked appear under **Near miss** instead of stopping them, which is how a new rule set is trialled.
