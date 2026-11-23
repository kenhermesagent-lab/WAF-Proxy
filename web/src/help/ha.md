## What this page is for
Running two nodes as one service: pair them, see which one is active, and move the traffic by hand when you need to.

## Concepts
- **Role** — `standalone`, `active` or `standby`. The role lives in a file beside the database, so restoring a backup cannot silently change who serves.
- **Pair** — the two nodes share a cluster id and a master key; the joining node verifies the other's fingerprint over a pinned TLS link.
- **Epoch** — a counter that rises with every move. A node that sees a higher epoch stops serving instead of racing the other one.
- **Witness** — an optional third party that grants a short lease; an active that cannot renew it stops serving.

## First tasks
- Turn on **Settings → High availability** on both nodes after starting them with `WAFPROXY_HA_ENABLE=1`.
- Create a pair on one node, then join from the other with the code, address and fingerprint.
- Run a **failover** as a dry run first; the real move drains writes and needs the cluster id typed again.

## Worth knowing
- HA is off by default and changes nothing about a single-node install.
- A standby is read-only: configuration edits are refused while it follows the active.
- A paired standby cannot be switched off from Settings, because with HA off nothing takes over; unpair first.
- The two-node hardware lab gates have not been run yet, so test a pair before trusting it with production traffic.
