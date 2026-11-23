## What this page is for
Publishing the console through Cloudflare Tunnel so it needs no port forward, public IP or certificate of its own.

## Concepts
- **Connector** — the `cloudflared` process this console starts and stops with your saved token.
- **Tunnel token** — the credential for the tunnel, sealed in the database and shown only by its last characters.
- **Public hostname** — the DNS name you attach to the tunnel in the Cloudflare dashboard; it is public unless Access protects it.
- **Access** — Cloudflare's identity check in front of the hostname. It is separate from the console's own accounts.

## First tasks
- Install the connector, create the tunnel, paste its token and add the console hostname as `http://127.0.0.1:<gui-port>`.
- Turn on the Enable switch and run the checks; a green origin check proves the request came back to this console.
- Add an Access application before sharing the hostname with anyone.

## Worth knowing
- The tunnel and a port forward can coexist, but the direct path bypasses Access; the direct-origin check reports when it exists.
- With the tunnel on, the WAF filters the `CF-Connecting-IP` address rather than the loopback peer.
- App hostnames and API-created tunnels are later work; this page covers the console in token mode.
