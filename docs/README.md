# Documentation

**Install**
- [Run it in Docker](install/01-docker.md)
- [Domain and certificates](install/02-domain-and-certificates.md)
- [First site](install/03-first-site.md)
- [Optional integrations](install/04-crowdsec-and-streaming.md)
- [Bare metal with systemd](install/05-bare-metal.md)
- [Native Tailscale access](install/06-tailscale.md)
- [Upgrades and removal](install/07-upgrades-and-removal.md)

**Configure**
- [Admin configuration reference](CONFIGURATION.md) — every page, field, option, default and
  environment variable, and what each one changes

**Operate**
- [Operations runbook](OPERATIONS.md) — health, logs, backup, alerting, diagnostics, canary
- [API reference](openapi.yaml) — generated from the routes the console serves, with
  request and response schemas for sites, bans, certificates, notifications and anomaly
- [MCP gateway](MCP.md)
- [Conformance](CONFORMANCE.md)
- [Benchmarks](BENCHMARKS.md)

**Project**
- [Roadmap and delivery status](ROADMAP.md)
- [Changelog](../CHANGELOG.md)

The API reference is generated: run `go generate ./internal/api` after adding or
changing a route, and commit both `internal/api/server.go` and
`docs/openapi.yaml`. `go test ./internal/openapi` fails when the committed file is
stale, so drift is caught before it ships.
