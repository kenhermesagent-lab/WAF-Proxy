# Installation

Pick the page for the task in front of you. They follow the order of a first
deployment, but each one stands alone once the stack is running.

| Task | Page |
| --- | --- |
| Start the stack in Docker and finish the wizard | [Run it in Docker](install/01-docker.md) |
| Point a domain at the host and get a certificate | [Domain and certificates](install/02-domain-and-certificates.md) |
| Publish the first site | [First site](install/03-first-site.md) |
| Add CrowdSec or streaming (Plex, Jellyfin) | [Optional integrations](install/04-crowdsec-and-streaming.md) |
| Run it on a host without Docker | [Bare metal with systemd](install/05-bare-metal.md) |
| Reach the console over Tailscale | [Native Tailscale access](install/06-tailscale.md) |
| Upgrade, uninstall or keep the host updated | [Upgrades and removal](install/07-upgrades-and-removal.md) |

Running the container needs only the first page; everything after it is
configuration in the console. The bare-metal page is an alternative to Docker,
not an extra step.

See also: [documentation index](README.md), [operations runbook](OPERATIONS.md),
[API reference](openapi.yaml).
