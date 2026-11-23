## What this page is for
Reaching the console over Tailscale instead of exposing it, so administration stays off the public internet.

## Concepts
- **Tailnet** — your private Tailscale network; addresses in it look like `100.x.y.z`.
- **Serve** — publishes the console on the tailnet without opening a firewall port.
- **Exit node** — unrelated to the console; it routes other traffic, not administration.

## First tasks
- Join this host to the tailnet, then open the console at its tailnet address.
- Keep the console bound to loopback or the LAN address even after Tailscale works.
