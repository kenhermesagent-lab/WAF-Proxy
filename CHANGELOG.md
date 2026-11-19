# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

**Release convention**

- `MAJOR.MINOR.PATCH`, tracked in `VERSION` (single source of truth).
- Each completed plan phase bumps **MINOR**: `0.1.0` → `0.2.0` → … → `1.0.0`.
- Fixes and add-ons inside a shipped phase bump **PATCH**: `0.4.1`, `0.4.2`.
- Every push to `main` has a matching section here and an annotated tag `vX.Y.Z`.

## [Unreleased]

### Added
- Full project plan in [PLAN.md](PLAN.md): architecture, request pipeline, data model,
  10 phases (`0.1.0` → `1.0.0`), resource budget, security model, risks.
- Dual-homed WAN/LAN deployment model (443-only, Firewalla DNAT without SNAT).
- `kendk.duckdns.org` domain strategy: wildcard subdomains, apex blackholed at the proxy,
  single wildcard certificate because DuckDNS stores one TXT record per domain.
- Host sizing guidance for a 2–4 vCPU / 8 GB / 50 GB VM, including disk breakdown and
  conntrack tuning (PLAN.md §9.1).
- Fingerprint hardening (§5.5): header stripping, uniform rejections, no upstream error leakage,
  fixed TLS profile, with an explicit list of what cannot be hidden.
- ASN blocking, decoy paths with instant bans, IPv6 parity and per-proxy IP allowlist in Phase 3.
- Request-smuggling defences, host-header hygiene, method allowlists and detect-first onboarding
  in Phase 4.
- Per-proxy access gate (passphrase or accounts + TOTP) with a progressive ban ladder, replacing
  the narrower visitor-TOTP scope in Phase 9.

## [0.1.0] — planned

Phase 0 — Foundation: repo scaffold, dark SPA shell, SQLite store, setup wizard
(network binding, domain, admin + TOTP), session auth, health/version API, release tooling.

## [0.0.0] — 2026-11-19

Planning baseline. No application code yet.
