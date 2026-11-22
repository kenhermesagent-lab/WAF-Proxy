# Presets and feeds — design

2026-11-22 · Status: approved 2026-11-22

## Intent

Two catalog gaps in the console:

- **Application presets** stop at six apps. Operators of the common self-hosted stack re-enter the
  same WAF profile by hand, and the existing `notes` field is never shown in the dialog.
- **Threat feeds** advertise nine built-ins, one of which (EDROP) has been a stub since Spamhaus
  merged it into DROP in April 2024, and another (URLhaus) now answers `410 Gone` because abuse.ch
  requires an Auth-Key. Operators must open a feed to change its action, and the catalog is short.

The work adds 13 presets with visible guidance and turns the feed catalog into a maintained list
with actions that can be changed from the row.

## Decisions already made

- **Presets: data + guidance.** Extend the preset data and render `notes` under the existing preset
  summary in the New proxy dialog. No new preset types, no policy side effects.
- **Feeds: extend the catalog.** Add eight keyless built-ins, disabled by default; add a per-row
  action dropdown; remove the dead EDROP row from existing databases.
- **Extra apps:** Vaultwarden, Gitea/Forgejo, Paperless-ngx, Grafana, Uptime Kuma, Mealie,
  Navidrome, PhotoPrism, Syncthing, n8n, BookStack, Cal.com, and the *arr suite.
- **No push.** The pipeline ends with a local commit; publishing stays a separate request.

## Presets

`internal/preset/preset.go` gains 13 entries. All fields already exist and become an ordinary,
editable WAF profile, exactly like the current six. `Notes` (2 lines each) are new copy, not new
schema. The dialog adds them as a short bullet list under the methods/body/login summary.

| ID | App | Body | Response | Login (rps/burst) | Admin paths (private ranges) |
|---|---|---:|---:|---|---|
| `vaultwarden` | Vaultwarden | 32 MiB | 32 MiB | `/identity/connect/token` 3/5 | `/admin` |
| `gitea` | Gitea / Forgejo | 64 MiB | stream | `/user/login` 5/10 | `/-/admin`, `/api/v1/admin` |
| `paperless` | Paperless-ngx | 64 MiB | 64 MiB | `/accounts/login/`, `/api/token/` 5/10 | `/admin`, `/api/admin` |
| `grafana` | Grafana | 8 MiB | 32 MiB | `/login`, `/api/login` 5/10 | `/admin`, `/org`, `/api/admin` |
| `uptime-kuma` | Uptime Kuma | 2 MiB | 8 MiB | `/login`, `/api/auth/login` 5/10 | `/settings`, `/api/settings` |
| `mealie` | Mealie | 16 MiB | 16 MiB | `/login`, `/api/auth/token` 5/10 | `/admin`, `/api/admin` |
| `navidrome` | Navidrome | 2 MiB | stream | `/login`, `/auth/login` 10/20 | none |
| `photoprism` | PhotoPrism | 64 MiB | stream | `/library/login`, `/api/v1/session` 3/5 | `/library/settings`, `/api/v1/settings` |
| `syncthing` | Syncthing | 2 MiB | 8 MiB | none | `/rest`, `/settings` |
| `n8n` | n8n | 32 MiB | 32 MiB | `/rest/login`, `/signin` 5/10 | `/settings`, `/rest/settings`, `/rest/users` |
| `bookstack` | BookStack | 32 MiB | 32 MiB | `/login` 5/10 | `/settings` |
| `calcom` | Cal.com | 8 MiB | 16 MiB | `/auth/login`, `/api/auth` 5/10 | `/settings/admin`, `/api/v1/admin` |
| `arr` | *arr suite (Sonarr, Radarr, Lidarr, Readarr, Prowlarr) | 8 MiB | 32 MiB | `/login`, `/api/v3/login`, `/api/v1/login` 5/10 | `/settings`, `/system`, `/api/v3/config`, `/api/v1/config` |

Methods are `GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS` for every new preset; Syncthing and Navidrome
drop `PATCH`. CRS exceptions start at `920350,920440` (API/upload false positives); Gitea,
BookStack and PhotoPrism also get `921110`. Every admin path starts with the private ranges.

Guidance notes (exact copy written in code) cover the trade-off each app forces: uploads over the
body cap, streamed media/clones left uncapped, WebSockets that must stay enabled, API keys and
webhooks that are credentials, ports that are not proxied (Gitea SSH, Syncthing 22000), and admin
areas that belong on the private allowlist.

Non-goals: no access-profile, protection-profile or streaming preset; no per-preset "apply"
button; no change to how a profile is created or named.

## Feeds

### Removals (existing databases)

Both rows are built-ins that cannot work without credentials:

- **Spamhaus EDROP** — `edrop.txt` is a 277-byte stub: "This list has been merged into
  spamhaus.org/drop/drop.txt" (Spamhaus, 10 April 2024). Today it parses to zero entries.
- **URLhaus hosts** — `https://urlhaus.abuse.ch/downloads/text/` answers `410 Gone`; abuse.ch moved
  exports behind a free Auth-Key in October 2026. The feed can never refresh again.

`seedFeeds()` gains an idempotent cleanup before inserting:

```sql
DELETE FROM feeds WHERE builtin = 1 AND name IN ('Spamhaus EDROP', 'URLhaus hosts')
```

A custom feed an operator created with the same name is untouched (`builtin = 0`). Removing a
built-in row does not touch the merged in-memory table until the next refresh, which rebuilds from
the remaining rows. No schema change.

**Please confirm the URLhaus removal** — it is the same class of breakage as EDROP, but you named
only EDROP.

### Additions (eight, all disabled by default, action `block`, interval 3600 s)

Every URL was fetched on 2026-11-22 and parsed with the existing `intel.Parse` (comment, `#`/`;`
suffix, CIDR and IPv6 tolerant). Approximate live counts:

| Name | URL | Entries |
|---|---|---:|
| Blocklist.de attackers | `https://lists.blocklist.de/lists/all.txt` | 22,700 |
| GreenSnow blocklist | `https://blocklist.greensnow.co/greensnow.txt` | 1,800 |
| Binary Defense banlist | `https://www.binarydefense.com/banlist.txt` | 900 |
| CINS Army | `https://cinsscore.com/list/ci-badguys.txt` | 15,000 |
| BruteForceBlocker | `https://danger.rulez.sk/projects/bruteforceblocker/blist.php` | 580 |
| IPSum level 3 | `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt` | 20,000 |
| Spamhaus DROP IPv6 | `https://www.spamhaus.org/drop/dropv6.txt` | 90 |
| ET firewall block list | `https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt` | 1,770 |

Spamhaus is fetched hourly, matching its published minimum. The others publish at least that
often; a disabled feed costs nothing until enabled. Duplicates across lists are collapsed by the
existing merged table.

Deliberately not added: ThreatFox, URLhaus and SSLBL (Auth-Key or stale), full-bogon lists (they
would block RFC1918 and Tailscale sources at the WAF), and ASN-only lists (the parser reads IPs).

### Per-feed action

The **Action** cell in **Threat intel → Feeds** becomes a compact `select` for every non-local
feed: `block`, `challenge`, `log only`. Changing it issues the existing
`PUT /api/feeds/:id` with the row and reloads after the request; failures keep the old value and
raise the page error. Local uploads keep a fixed `block` badge because the server already forces
it. No API or model change.

## Docs and release

- README: built-in feed count (nine → fifteen), the two removals, the new list, and the preset list
  (six → nineteen) with a line that notes now appear in the dialog.
- `VERSION` → **1.21.0** (feature phase) and a matching `CHANGELOG.md` section.
- No new dependencies, no schema migration, no configuration.

## Risks

- Feed availability is outside our control; a list that closes shows an error state and can be
  disabled, and the last-good list is retained by the existing guardrails.
- Large lists add memory only when enabled; the merged table is already bounded by the existing
  5× growth freeze.
- Preset values are starting points, not guarantees; the dialog already says the profile is
  editable and CRS exceptions should be checked in detect mode.
- Deleting two built-in rows is not reversible in the UI, but either can be re-added as a custom
  feed if it becomes usable again.

## Verification

- `go test ./...`, `gofmt`, `go vet`, `deadcode`.
- Preset consistency test extended: every preset has at least one note, all IDs unique.
- Store test: seeding twice removes EDROP/URLhaus and adds the eight exactly once; a custom feed
  with the same name survives.
- Web tests: preset notes render in the dialog; changing a feed action sends the PUT and a local
  feed keeps the fixed badge; `tsc`, vitest, production build.
- Demo DB (existing `/tmp/wafcheck`) boots with the new seeds and shows 15 built-ins with no EDROP
  or URLhaus, then all pages re-checked for console/API errors.

## Approval notes (2026-11-22)

Approved as written, with these answers to the questions the build raised:

- **Global named lists** are attached under **Policies → Global Profile** (the renamed *Countries,
  IPs, ASN* tab). A global whitelist is checked before the global blocklists and before the
  explicit block policies; a global blocklist applies to every proxy. A host's own
  access-profile lists stay narrower and still decide for that host. Stored in settings
  (`global_whitelist_ids`, `global_blocklist_ids`), no schema change.
- **ASN recommendations** ship as hosting/cloud plus a short provider-owned VPN set (Mullvad,
  Proton VPN, NordVPN, Surfshark), each inserted as an ordinary ASN policy.
- **Moving a permanent ban back to temporary** gives it 24 hours from the move, matching the
  existing temporary-ban cap.

## Pipeline

After approval: run `/deepseek-4-1-flash-coding` for this feature on branch
`pipeline/presets-and-feeds` — brief and the frozen external facts above, UI/UX review, build in
slices, review, deslop, security, then a local commit on `main`. Nothing is pushed.
