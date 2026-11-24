## What this page is for
Install-wide settings: network binding, protection defaults, backup, updates and the readiness checklist.

## Concepts
- **Host-wide settings** — network, updates and backup apply to the whole box; a tenant console cannot change them.
- **Readiness** — what a hardened install has that a working one may not; every row links to its fix.
- **Retention** — how long requests and bans are kept. Shorter means less disk and less history.
- **Backup copies** — the schedule keeps its own count of files; the optional daily tier keeps a
  second count, so a month of weekly copies and the last seven daily ones age out independently.

## First tasks
- Work down the Readiness checklist once the first hostname serves traffic.
- Enable a backup schedule before you need it.
