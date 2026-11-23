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

**Look at it**
- [Screenshots](screenshots/README.md) — every console page, captured from a demo install with
  sample data

**Operate**
- [Operations runbook](OPERATIONS.md) — health, logs, backup, alerting, diagnostics, canary
- [High availability plan](HA.md) — proposed active/standby pair: pairing and keepalived
  runbooks, failover and failback procedures, security prerequisites, a Settings toggle and a
  System page behind it, and a phased build plan with per-phase gates and a debugging playbook
- [HA build execution plan](HA-BUILD.md) — the same phases cut into ordered, PR-sized tasks
  with files, verification commands, per-task done criteria and the first five pull requests
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
