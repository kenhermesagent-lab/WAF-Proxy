## What this page is for
Reaching the console over Tailscale instead of exposing it, so administration stays off the public internet.

## Concepts
- **Tailnet** — your private Tailscale network; addresses in it look like `100.x.y.z`.
- **Listener** — the console or the proxy bound to this host's tailnet address, so the tailnet reaches it without a firewall port.
- **Split DNS** — answers proxy hostnames on the tailnet only, so a fleet device resolves the app to this host.

## First tasks
- Join this host to the tailnet, then enable the admin listener and open the console at its tailnet address.
- Keep the console bound to the LAN address even after Tailscale works.
