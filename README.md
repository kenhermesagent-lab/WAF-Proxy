# WAF-Proxy-Docker

Self-hosted reverse proxy with an integrated WAF, IPS-style ban engine, bot protection,
GeoIP policy, live attack globe, and a dark web GUI. Go backend, React frontend, single
Docker Compose stack.

**Status:** planning. The complete design and phased delivery plan live in [PLAN.md](PLAN.md).

## Target deployment

```
Internet → Firewalla 192.168.191.1 → DNAT 443 → 192.168.191.2 (this stack, 443 only)
                                                    ↓
                                       backends 192.168.101.x (source 192.168.101.2)
```

- Inbound: `443/tcp` only, bound to a WAN address chosen during setup.
- Outbound to backends: bound to a separate LAN address.
- Admin UI: LAN only.
- Public names: `*.kendk.duckdns.org` (one subdomain per proxy); the apex is blackholed.

## Planned phases

| Version | Phase |
|---|---|
| 0.1.0 | Foundation, setup wizard, admin TOTP |
| 0.2.0 | Proxy core (Zoraxy parity) |
| 0.3.0 | TLS, ACME wildcard certificates, per-proxy assignment |
| 0.4.0 | Policies, bans, blackhole, GeoIP, WAN/LAN netflow |
| 0.5.0 | WAF and protection profiles |
| 0.6.0 | Threat intel feeds and IoC watch |
| 0.7.0 | CrowdSec and bot protection |
| 0.8.0 | Observability and attack globe |
| 0.9.0 | Notifications (Telegram, Gmail/SMTP) |
| 1.0.0 | Visitor TOTP, backup/restore, hardening |

Versioning: each phase completion bumps the minor version; the patch number is for fixes and
add-ons within a phase. Every push to `main` carries a version and a changelog entry.

## Documentation

- [PLAN.md](PLAN.md) — architecture, request pipeline, data model, phases, risks
- [CHANGELOG.md](CHANGELOG.md) — release history and conventions
- [VERSION](VERSION) — current version (`0.0.0` until Phase 0 ships)
