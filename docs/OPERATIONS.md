# Operations runbook

## Daily checks

![Dashboard: live rates, the host's CPU and memory dials and the attack globe](screenshots/dashboard.png)

*The dashboard of the demo install these pages were checked against; its sites, bans and events
are sample data.*

- **Dashboard** — WAN/LAN throughput, blocked ratio, top blocked sources, per-proxy live
  request and traffic rates, and the attack globe (1 h / 6 h / 24 h, category filters).
- **Statistics** — date-range request outcomes, hourly traffic, per-proxy shares, visitor
  countries and backend uptime. A red probe means the backend returned 5xx or timed out; the
  down/recovery transition is also sent to the **Backend up/down** notification channels.
- **Policies → Temp/Permanent bans** — unexpected permanent bans usually mean a decoy hit
  or a feed false positive; both carry a reason and source.
- **Certificates** — expiry and `last_error`. Renewal is checked every 12 hours; the default
  policy renews a month before expiry (`Every 3 months` is capped at seven days before expiry).
- **Threat intel** — a feed stuck in `frozen` means the 5× growth guardrail tripped;
  inspect before enabling it again. Uploaded `.txt`/`.csv` lists appear as local feeds and are
  always global blocks. To replace one, delete it first and upload the new file.
- **GeoIP** — Settings shows the city and ASN file dates. Reinstall monthly if country/ASN
  policy matters; DB-IP Lite publishes monthly. A failed install leaves the previous files
  loaded and shows the download error.
- **CrowdSec** — the dedicated page shows last successful poll, applied decisions and last
  error. A blank LAPI or key disables the bouncer without restarting WAF-Proxy.
- **Updates** — the application card names the remote commit. A failed rebuild leaves the old
  binary/container running and shows the helper output.
- **High availability (when enabled)** — `GET /api/ha` says which node is `serving` and why. A
  standby reporting `serving: false` is normal; an active that does is not. Watch replication:
  outbox depth should return to zero, and the acknowledged sequence should keep up with the
  active's writes. A paired standby stays out of service while HA is off; that is a refusal, not
  a fault. Details in [HA.md](HA.md).
- **Logs** — filter by stage `waf` or `access-gate` after changing a profile or gate.
- Native (systemd) installs: replace `docker exec wafproxy ...` with `sudo wafproxy ...`,
  `docker compose ... logs` with `journalctl -u wafproxy -f`, and restart with `sudo systemctl restart wafproxy`. Prefix the
  one-shot `wafproxy unban` command with `WAFPROXY_DATA_DIR=/var/lib/waf-proxy/data`, because the unit
  environment does not apply to it.
- Service log: `docker compose -f deploy/docker-compose.yml logs --tail=200 wafproxy`, or
  `journalctl -u wafproxy --lines=200` for the systemd install.

## Recovery

### Unban an address

GUI → Policies → Temp bans / Permanent → **Unban**. Or, if the GUI is unreachable:

```bash
docker exec wafproxy unban 203.0.113.7
```

The running process reconciles the in-memory table from SQLite every 30 seconds, so the ban
lifts without a restart. On the systemd install use
`sudo env WAFPROXY_DATA_DIR=/var/lib/waf-proxy/data wafproxy unban 203.0.113.7`; the data lives in
`/var/lib/waf-proxy/data`, not a Docker volume.

### Locked out of the admin GUI

The GUI listener is exempt from every ban and binds to the LAN address only. Check that you
are on the LAN and using the stored `LAN_IP:GUI_PORT`. If the browser has no session, sign in
with password + TOTP, or a single-use recovery code.

### Lost password and TOTP and recovery codes

There is no online reset (that would be a backdoor), but the binary can repair an account
without the console:

```bash
sudo env WAFPROXY_DATA_DIR=/var/lib/waf-proxy/data wafproxy recover \
  --user admin --password 'a-new-12-plus-passphrase' --reset-totp
```

`recover` finds the account on any site, rewrites the password hash, signs it out everywhere
(sessions, remembered browsers and outstanding password-reset links) and, with `--reset-totp`,
disables its authenticator — sign in with the new password and add a new one from **Account →
This account**. Only the account you name is touched.

If the database itself is unusable, stop the stack, back up the data volume, and remove
`wafproxy.db` to re-run the setup wizard. This deletes proxies, bans, feeds, certificates and
settings. Restore a JSON backup afterwards to recover configuration (secrets and certificates
excluded).

### GeoIP install fails

- Settings shows the last error. The console tries the current month's DB-IP Lite URL and then
  the previous month.
- The data directory needs about 200 MB free for the compressed and expanded files, plus the
  old databases.
- Both files are validated as MMDB before either is replaced, so a timeout or invalid download
  does not break country/ASN policy.

### CrowdSec shows configured but never polls

- Open **CrowdSec → Test connection**. A rejected key means the bouncer was deleted on the
  engine; recreate it with `cscli bouncers add wafproxy` and paste the new key.
- LAPI URL is `http://127.0.0.1:8081` for the Compose sidecar and normally
  `http://127.0.0.1:8080` for a stock native engine. The bouncer connects outbound; do not
  expose the LAPI to the WAN.
- The engine must be running separately. WAF-Proxy configures the bouncer, not the engine.

### The CrowdSec install button is missing or fails

- It only appears on a native host: inside a container the console refuses to install host
  packages, so use the Compose sidecar. It also needs the privileged helper — if the page says
  the helper is not installed, re-run `sudo ./deploy/install.sh`.
- Failures are shown in the card with the captured output. `journalctl -u wafproxy-updates -n
  100` shows the helper side. Common causes: no outbound HTTPS to `install.crowdsec.net` and the
  CrowdSec package repository, or a host that is not Debian/Ubuntu.
- After a successful install the page reports the engine version and whether it is running. If
  the engine is installed but not running, `journalctl -u crowdsec -n 50` shows why; the
  installer leaves the package's own configuration in place rather than overwriting it.

### Application update fails

- The progress bar names the stage the updater reached, so a run that stalls on `rebuilding the
  console` is a Node problem and one that stalls on `building the binaries` is a Go toolchain
  problem, without reading the log first.
- Native: the Updates page shows the captured pull/build output; `journalctl -u
  wafproxy-updates -n 100` shows the helper's start/stop and timeout errors. Check `git`, `make`,
  Go 1.27 and Node 26 are available to the checkout owner
  (`/usr/local/go/bin` and `$HOME/toolchain/go/bin` are included). A dirty checkout is
  refused; commit or stash local changes first. The public repository needs no credentials;
  a private fork needs the owner's git credential helper or SSH key.
- Docker: the Updates page shows the captured pull/build output; `journalctl -u
  wafproxy-docker-updates -n 100` shows helper failures. The helper needs Docker Compose v2, the
  Docker socket, the original `deploy/.env` and a clean checkout. The public repository needs
  no credentials; a private fork needs the checkout owner's git credential helper or SSH key.
- A failed build does not replace the running binary or container. Fix the cause and press the
  button again.

### Certificate issuance fails

- Read the certificate row's `last_error` and the container log.
- Wrong DNS credentials are the common cause; re-save them on the Certificates page.
- With DuckDNS, only one TXT record exists. Request the wildcard, not per-host certificates.
- If Let's Encrypt rate-limited you, enable the staging toggle, verify issuance, then switch
  back and use **Renew**.

### `502`/`504` from a proxy

The uniform error page hides upstream details by design; the reason is in the container log
(`upstream error`). Check the backend from the host using the LAN source address, then the
proxy's up/down badge. Health checks probe `GET /` every 10 seconds and eject after three
failures.

### A game server does not connect

Work from the card outward; each step names what to look at.

1. **Protocol.** The card's protocol must match what the client sends. A UDP game behind a `tcp`
   card, or the reverse, sends nothing the listener sees, so nothing appears in the log. Test
   from a client with `nc -zvu <wan> <port>` (UDP) and `nc -zv <wan> <port>` (TCP), and confirm
   the host holds the socket with `ss -lunp` / `ss -ltnp`.
2. **Port range.** A card listens on `port` … `port + count - 1` and forwards that range 1:1 onto
   `upstream_port` (or the port in **Server**). Valheim's 2456–2458 needs count `3` and a
   port-range rule on the router; a range that would run past 65535 is refused when you save.
3. **Allow list and bans.** An empty allow list accepts any client the firewall lets in, but
   **Refuse sources that are not on an allow list** with no list attached refuses everyone. A
   whitelist attached under **Blocklists and whitelists** narrows the card further, a banned source
   is refused at the listener, and country entries match nothing without GeoIP. Refusals appear in
   **Logs** under `stream-ban`, `stream-list`, `stream-allow` or `stream-cap`, with the listen port
   that was hit.
4. **Upstream and its firewall.** **Server** is the game host and port on the LAN. The game must
   listen on an address the proxy can reach, not only `127.0.0.1`, and its firewall must allow the
   proxy's source address. Test from the proxy host with `nc -zv <server> <port>` (TCP) or
   `nc -zvu <server> <port>` (UDP).
5. **Router.** Forward TCP and UDP as separate rules for a `both` card, DNAT only and no SNAT, and
   use a port-range rule for a range. A client inside the LAN needs NAT loopback (hairpin) to
   reach the WAN address; without it, connect to the server directly.
6. **File descriptors and sessions.** The cap is per card (default 256 sessions, 8 per source). If
   `ss -u -a` keeps climbing while the game is idle, the idle timeout is not reclaiming sessions;
   `cat /proc/$(pidof wafproxy)/limits` shows the descriptor limit the unit set (`8192`).
7. **High availability.** Only the serving node binds the port; a standby holding no game port is
   correct. `wafproxy ha status` names the serving node, and a failover drops live sessions by
   design.

### Kernel bans unavailable

The GUI shows `kernel: nftables unavailable` with a reason. Userspace bans still work, but
blocked packets receive a response instead of a silent DROP. Usual causes: `nft` missing,
missing `NET_ADMIN`, or `no-new-privileges` enabled (which disables the image's file
capabilities).

### Access gate loops or nobody can sign in

- Gate accounts are managed on the **Access gate** page; a proxy allowlist that names no
  existing account denies everyone.
- The ladder bans an IP after 3 failures in 10 minutes for 15 minutes. Unban from Policies
  or the CLI.
- Gate modes reset to `off` after a restore. Re-enable the mode and re-set the passphrase.

### HA did not start

When the stored switch is on but the HA loops failed to bind — usually the control socket
under the data directory is held by another process, or an HA listener port is taken —
`GET /api/ha` reports `runtime_error`, moves are refused, and the HA page shows **HA did not
start**.

1. Read the message on the page, or `sudo wafproxy ha status --json` when the console is down.
2. Remove the cause: stop whatever holds the control socket, fix its directory permissions, or
   free the HA link port. Never delete a socket that a live process still owns.
3. Press **Retry startup** (or re-authenticate and call `POST /api/ha/retry`) to run the same
   start the boot path uses; no service restart is needed once the cause is gone. **Copy
   diagnostics** attaches the current state to a report.

## Release tags

The tag gate (`deploy/check-tags.sh --remote --branch main`) passes only when every dated
`CHANGELOG.md` section at or above 1.61.0 has an annotated tag on origin that points at the commit
where `VERSION` reads as that version and the section already exists. Tags cannot be pushed from a
checkout without credentials, so the gaps are filled by a job that has them:

The job also runs by itself on a push to `main` that changes `CHANGELOG.md` or `VERSION`, which is
exactly when a version gains its dated section, so a release is tagged without anyone opening the
Actions page. It skips tags `origin` already has, so a push that changes neither file never starts
it and any other run creates nothing. To fill the backlog by hand:

1. Actions → **Create release tags** → **Run workflow** on `main`.
2. Leave `versions` empty to tag every dated section, or list the ones you want. `dry_run` starts
   as `true`: the run prints each version with the commit it would tag and pushes nothing.
3. Run it again with `dry_run` off. Each missing tag is created at its release commit, pushed, and
   the job ends by running the gate against `origin`.

The version still in `VERSION` is tagged at its newest qualifying commit, so the release ships every
fix and every note it ended up with instead of the draft that first stamped the number; a version
that has since been succeeded is tagged at the commit that cut it, because a later merge can briefly
stamp the old number again and that tag would look cut after the release that followed it. A version
whose section was dated while `VERSION` stayed on an older number fails the job instead
of being tagged somewhere nearby. Tags origin already has are skipped, so a re-run only fills gaps.
When a release has more than one commit where `VERSION` reads as it does, the tag names one that did
not change a file under `.github/workflows/`, since those are the commits a token can push.

A ref the job creates with `GITHUB_TOKEN` raises no `push` event, so `release.yml` never starts from
it and the tag would have no release, no binaries and no Latest badge — which is what happened to
`1.61.0` through `1.65.0`. The job therefore finishes by dispatching `Release` for every tag
`CHANGELOG.md` dates that has no release yet (`gh release view` decides), and it does that even when a
earlier tag was refused, so one unpushable tag cannot hold the rest of the releases back.

A tag cannot be pushed with the runner's token when it would introduce a change under
`.github/workflows/`, and GitHub reads that over the whole range since the previous tag rather than
just the tagged commit. `v1.62.3`'s range carries the dependency refresh that edited `ci.yml` and
`release.yml`, so no commit of that release is pushable by the App. The repository secret `TAG_PUSH_TOKEN` — a token
with `repo` and `workflow` — is what the job prefers when it exists: git's remote carries it and the API
calls use it too, so such a tag is pushed without help. Without that secret the job
names the tag instead, and that one is pushed from a clone with the operator's own credentials. The script tries the API as well (tag object plus ref, no commits
travelling), and one refused tag does not hide the ones after it — every version is attempted and the
job ends red naming each one that failed.

The same work is available locally as `bash deploy/create-release-tags.sh --dry-run`, then without
`--dry-run` to push. A tag that exists only in the local checkout makes the script stop: it points
at a commit nobody receives, so delete it with `git tag -d v1.2.3` and re-run.

## Upgrading a high-availability pair

Upgrade the **standby first**, then move the service, then upgrade the old active. Never upgrade
both nodes at once, and do not run a move while either node is rebuilding.

1. **Record the state.** `wafproxy ha status` on both nodes, and `GET /api/ha` for the role,
   epoch and `serving`. Confirm which node holds the virtual address and that the pair is
   healthy (`paired: true`, no `split-brain-risk`, outbox depth falling).
2. **Check the pair is ready.** `wafproxy ha upgrade --check` prints both nodes' release,
   schema and protocol. It exits non-zero when they disagree on schema or protocol, because a
   move or a join would be refused, and exits zero with a warning when only the releases differ
   (the normal state halfway through an upgrade).
3. **Sync before you start.** **Sync now** on the active (`wafproxy ha sync`) so the standby holds
   the current configuration. A planned move drains new configuration writes first and refuses to
   start while an edit is still landing.
4. **Upgrade the standby.** Rebuild or pull the new image on the standby and restart its service.
   The node comes back in its standby role; it does not take the address. Check `wafproxy ha
   status` and `/api/ha`: the version is new, the role is still `standby`, and replication resumes.
5. **Move the service.** **Fail over** (dry run first, then for real) from the console, or
   `wafproxy ha failover`. The old active stops serving, the new active serves, keepalived moves
   the address and the epoch increases. Wait for the console and the site to answer, then confirm
   the old node reports `standby`.
6. **Upgrade the old active.** It is now the standby, so the same restart is safe. It rejoins as a
   standby following the new active; check replication catches up and the outbox drains.
7. **Fail back when convenient**, or leave the roles as they are. A fail back is only offered once
   the pair has been healthy for the configured interval; the flap guard parks automatic moves
   after too many in an hour.

If the new release changes the database schema, the first node to start migrates it; the other
node then refuses to join or promote while its schema is older, with the fix shown in the
preflight. Upgrade the standby first for exactly this reason: the active keeps serving on the old
schema until the move, and the new one is already current when it takes over. The stored
`ha_enabled` switch is left exactly as the operator set it by an upgrade.

Roll back by rebuilding the previous release on the node you are working on. Do not roll back a
node that has already applied a newer schema while the other node is serving; restore the pair's
backup on both nodes instead (see [Backup and restore](#backup-and-restore)).

## Sites

One process serves several sites. Each row of configuration belongs to exactly one, and each
site's console is reached at its own `console_host`:

- `wafproxy sites list` shows the sites, their console hosts and their slug.
- `wafproxy sites add --slug acme --name "Acme" --console-host console.acme.example
  --admin ops --print-password` creates the site and its first administrator in one step.
- `wafproxy sites rename`, `wafproxy sites remove --slug <slug> --yes` change or drop one.
  `default` cannot be removed; it owns every row written before sites existed.
- A console reached on a site's host reads and writes that site's rows only: proxies,
  certificates, bans, policies, lists, feeds, gate accounts, administrators, admins'
  sessions, events, analytics, audit trail and saved log views. A session issued by one
  console does not authenticate on another.
- Process-wide settings stay host-wide and are refused on any console but `default`:
  `wan_ip`, `wan_port`, `wan_iface`, `lan_ip`, `lan_iface`, `gui_port`,
  `admin_allow_cidrs`, `home_lat`, `home_lon`, `auto_update_enabled`, `auto_update_time`,
  `geoip_auto_update`, `crowdsec_enabled`, `crowdsec_url`, `crowdsec_key` and the three
  `tailscale_*` switches.
- A kernel ban is host-wide even though the ban record belongs to the site that observed
  it: the address is dropped for every site, and the console of the site that raised it is
  the one that lists it. `wafproxy unban <ip>` removes it from the record and the kernel.
- Events are retained per site from that site's own `retention_days`, so one site keeping
  a month of history does not shorten another site's week.
- A hostname belongs to one site. Restoring a backup whose hostname is already in use is
  refused for that row and reported in `problems`.
- Each console host needs its own certificate; the listener selects it by SNI, so two
  consoles on one process each present the certificate issued for their hostname.
- Switching sites means signing in at the other console's hostname. There is no shared
  single sign-on, by design.
- An administrator whose role holds `sites.read` sees a switcher in the console's topbar; the
  choice is sent as `X-WAF-Site` on every request and remembered in the browser. The switch is
  still served by one process, so certificates and console hosts do not change with it.
- Policy, notification channels, anomaly thresholds, the canary target and the ACME account are
  one instance per site. Each reads that site's rows and settings, so editing one console never
  recompiles or rewrites another site's configuration. Only the default site's values feed the
  process-wide knobs (inspected-body cap, stealth mode, interface names); another site's console
  shows those read-only.
- The built-in `host_admin` role runs one site and nothing else: no sites area, so no Sites page
  and no switcher, and the server ignores a site header from it. Give it to a tenant's own
  operator, not to the host's administrator.
- Deleting a site removes its hostnames, certificates, bans, gate accounts, administrators,
  events, audit trail and saved views. The console refuses to delete the site whose console the
  request came from; sign in on `default` to remove it.

## Backup and restore

- Settings → **Download JSON** exports one site's settings, proxies, upstreams, routes,
  policies, feeds and bans, named `wafproxy-<slug>-backup.json`. It intentionally excludes
  secrets, DNS credentials, certificates/private keys and password hashes; uploaded local
  blocklist files must be uploaded again.
- `wafproxy backup --site <slug>` writes the same document for one site;
  `wafproxy backup --all` writes one encrypted file per site plus a `sites.json` manifest.
- Restore is additive and writes only into the site whose console posted it: existing
  hostnames are skipped and reported in `problems`.
- After a restore: re-enter DNS credentials, re-issue certificates, reset gate secrets and
  passwords as needed. Gate modes are forced to `off`.
- The export is plaintext. Store it accordingly; it contains internal addresses and policy.

## Capacity and disk

- 2 vCPU / 4 GB / 30 GB is the floor; 4 vCPU / 8 GB / 50 GB is comfortable for a home edge.
- SQLite WAL needs a local SSD; do not put `/data` on NFS/SMB.
- Events default to 7 days (1–30 in Settings). Hourly flow rollups keep long-term volume
  small. Watch the database size in the logs at debug level and the host disk.
- Raise `net.netfilter.nf_conntrack_max` on the host if session counts climb; a scan flood
  can exhaust the default table and look like an outage.
- The WAF is the expensive stage. Measured Coraza+CRS cost on the reference sandbox was
  about 3 ms per inspected request per core (see [BENCHMARKS.md](BENCHMARKS.md)); size for
  bursts, and use `Static/CDN` or a higher-profile tuning only where appropriate.

### Sizing the request budget

Admission is a byte budget as well as a request count, so size `WAFPROXY_MAX_BUFFERED_BYTES` for
body size × concurrency:

| In flight | Body limit | Budget to allow |
| ---: | ---: | ---: |
| 256 | 128 KiB | 32 MiB |
| 256 | 1 MiB | 256 MiB |
| 128 | 8 MiB | 1 GiB |

The default 512 MiB covers 256 requests at the default 128 KiB body limit with room for the cache
and the runtime. Boot refuses a budget that cannot fit under `WAFPROXY_MEMORY_LIMIT` once the
128 MiB response cache and a 128 MiB runtime floor are added, so a value the box cannot hold fails
at startup instead of under load.

### When the box sheds

The Capacity card, `GET /api/capacity` and `/metrics` say why, so the answer follows the counter:

| Counter | What it means | What to change |
| --- | --- | --- |
| `shed` `queue` | Requests waited the full queue window and still found no slot. | Raise `queue_ms` to ride out a longer burst, or raise `WAFPROXY_MAX_INFLIGHT` / the byte budget if the host has the memory. |
| `shed` `bytes` | One request is bigger than the whole budget. | Raise `WAFPROXY_MAX_BUFFERED_BYTES`, or lower `max_body` so it is refused with a 413 instead. |
| `shed` `site` | One site's own cap is full. | Raise that proxy's max in-flight, or accept the queue for that site. |
| `shed` `client` | One source is spending the site's budget. | Keep the per-client cap or rate limit on that site rather than raising it globally. |
| `queued` high, `shed` flat | The box is absorbing the burst. | Nothing, unless p95 latency climbs with it. |
| Cache misses high | The origin sends no usable `max-age`, or the body is over 512 KiB. | Fix the origin's cache headers; only HTTP 200 with `Cache-Control: max-age` up to 300 is stored. |

A `503` from capacity always carries `Retry-After: 1` and is logged with `stage=capacity`, so the
event log shows the same refusals the counters count.

## Security notes

- The GUI is plain HTTP on the LAN. Keep it on a trusted segment, or put it behind a TLS
  terminator if the LAN is not trusted. Session cookies are `HttpOnly`, `SameSite=Lax`, and
  marked `Secure` when TLS is present.
- The master key lives in `/data/master.key` (or `WAFPROXY_MASTER_KEY`). Losing it makes
  encrypted settings and DNS credentials unreadable. Back it up separately from the database.
- The access log under `/logs` contains client IPs and user agents. Treat it as personal
  data and rotate it with the host's log policy.
- Never expose the CrowdSec LAPI beyond loopback; the compose file binds `127.0.0.1:8081`.

## Request IDs and JSON access logs

Every request gets an `X-Request-Id` response header. A client or upstream load
balancer may supply one (letters, digits, `.`, `_`, `-`, at most 64 characters);
unsafe or oversized values are replaced rather than echoed.

Set `WAFPROXY_ACCESS_LOG_FORMAT=json` alongside `WAFPROXY_ACCESS_LOG` to write
one JSON object per request instead of nginx combined format. The object carries
the request ID, host, source, method, path, status, bytes, latency, stage, rule
and action, so a failed request can be traced to the stage that rejected it.
The default stays nginx combined format for CrowdSec's nginx parser.


## Admin console over HTTPS

The console can serve TLS from the certificates the gateway already manages. Issue or
upload a certificate whose names include the console host (for example
`console.home.arpa` from the internal CA), then set:

```
WAFPROXY_LISTEN_GUI=127.0.0.1:8080   # host:port only, no scheme
WAFPROXY_LISTEN_GUI_TLS=1           # 1/true/yes/on enables TLS on that listener
WAFPROXY_GUI_HOST=console.home.arpa # hostname only, no scheme or port
```

`WAFPROXY_LISTEN_GUI` is passed straight to `net.Listen`, so a URL scheme or path is
not accepted. The certificate is chosen by `WAFPROXY_GUI_HOST`, which is lowercased
and matched against the certificate's names.

The listener refuses to start when no valid certificate matches the host, so a typo
cannot silently leave the console on plain HTTP. The certificate is resolved on every
handshake, not captured at boot: a renewal or a replacement upload reaches the console
without restarting the process. The boot check still runs once so a missing
certificate fails early. Browsers need the internal root
(`GET /api/certs/internal/root`) or a public CA for that name.

## Revoking a certificate

`POST /api/certs/{id}/revoke` revokes an ACME certificate with the CA that issued it,
then deletes the local record. Uploaded and internal certificates have no ACME account;
they are deleted locally. If the CA refuses, the endpoint returns `502` with the reason
and keeps the certificate. Deleting a certificate without revoking it remains available
through `DELETE /api/certs/{id}`.


## Threshold alerting

The detector evaluates one-minute windows per proxy against a rolling baseline and
raises three event kinds: `egress_spike` (outbound bytes above both a floor and a
multiple of the median), `rate_spike` (requests per second above both a floor and a
multiple of the median) and `auth_burst` (failed logins in one minute). Thresholds are
stored as settings and edited with `PUT /api/anomaly/settings`:

| Setting | Meaning | Default |
| --- | --- | --- |
| `anomaly_enabled` | detector on/off | `1` |
| `anomaly_egress_mb` | egress floor per minute | `5` |
| `anomaly_egress_factor` | multiple of the baseline | `4` |
| `anomaly_rate_rps` | request-rate floor | `200` |
| `anomaly_rate_factor` | multiple of the baseline | `3` |
| `anomaly_auth_burst` | failed logins per minute | `20` |

Each raised event is stored once and refreshed while the condition stays open, so a
long spike is one row, not one row per minute. Alerts are routed through the same
notification channels and event matrix as bans (`notify_routes`, with the older
`notify_events` list still honoured), and deduplication uses the key
`anomaly:<kind>:<proxy id>`: a second alert with the same key inside 24 hours is
dropped before it reaches the queue.

## Testing a notification channel

`POST /api/notifications/test` with `{"channel":"telegram"|"email"|"webhook"}` sends a
real message through the configured channel, bypassing the event toggles and the
digest — the button in the console calls this endpoint. A missing or unknown channel
returns `400`. It returns `200` when the provider accepted the message and `502` with
the provider's error when a configured channel failed, so a bad token or webhook URL
fails visibly instead of silently. The test message is not
deduplicated: every click sends one.


## Diagnostics bundle

`GET /api/diagnostics` returns a JSON support bundle: version, Go version, platform,
listener addresses, configuration counts, certificate metadata (domains, status, source,
expiry, last error) and the settings map. Secret-bearing keys (`token`, `secret`,
`password`, `*_key`, `credential`, `webhook`, `*_url`) are replaced with `[redacted]`;
other URLs keep their host and path but lose credentials, query strings and fragments.
Copy the response into a ticket; it contains no keys, session tokens or password
hashes.

`GET /api/diagnostics/bundle` returns the same material as a zip for attaching to a
ticket: `version.json`, `settings.json` (redacted), `listeners.json`,
`certificates.json`, `errors.json` (failed alert deliveries, certificate errors,
anomalies and recent 5xx responses), `logs.txt` (the last 500 lines of the access log,
256 KiB at most) and `README.txt`. Log lines have query strings replaced and values
following `token`, `key`, `secret`, `password`, `authorization` or `apikey` masked, in
both `key=value` and quoted JSON forms. The bundle is only produced for an
authenticated session and is marked `no-store`. Client IPs are kept because they are
usually the point of the investigation; review `logs.txt` before sharing if that
matters.

## Synthetic canary

`POST /api/canary` probes one site end to end and reports each stage in order, naming
the first stage that failed:

```
{"ok": false, "host": "app.example.com", "failed_stage": "upstream",
 "stages": [{"name":"config","ok":true}, {"name":"dns","ok":true}, ...]}
```

The body may carry `{"proxy_id": 3}` or `{"host": "app.example.com"}`; with neither,
the first configured site is used. The probe resolves the name, opens a TCP connection, performs its own TLS handshake
with the site's hostname as SNI, and requests `/.well-known/wafproxy-canary`. Stages are
`config`, `dns`, `connect`, `tls`, `route`, `waf` and `upstream`. The TLS stage inspects
the presented certificate itself: an expired certificate fails with
`certificate expired on <date>`, a certificate for another name fails with the
verification error naming the expected and presented names, and a protocol-level
failure reports `handshake failed`. The leaf expiry is also returned as
`cert_expires_at`. A plain connect failure stays on the `connect` stage, so an
unreachable port is never reported as a certificate problem. After the HTTP request,
`403`/`429` fail at **waf**, `421` fails at **route**, `502`/`503`/`5xx` fail at
**upstream**, and any other status passes. It returns `200` when every stage passed and
`502` with the same body when one did not.

The probe runs from the gateway itself, so the site must answer on its public hostname
from that host (split-horizon DNS, hairpin NAT or an internal name may be needed). It
checks the externally reachable path, not a specific WAF rule.


## Private ACME directory

To issue from a private ACME server (step-ca, Pebble, an internal CA) instead of Let's
Encrypt, point the client at its directory and give it the PEM trust root:

```
WAFPROXY_ACME_DIRECTORY=https://acme.internal:14000/dir
WAFPROXY_ACME_CA_FILE=/etc/wafproxy/acme-ca.pem
```

`WAFPROXY_ACME_DIRECTORY` takes precedence over the staging toggle. The CA file is
only used for the ACME API connection; issued certificates still chain to whatever
that CA signs. The account key and registration are stored once and reused for both
issuance and revocation.

Pebble end-to-end check (opt-in, needs `pebble` with `httpPort` 5002 and this test's
listener on the same port):

```
PEBBLE_DIRECTORY=https://localhost:14000/dir \
PEBBLE_CA=$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@*/test/certs/pebble.minica.pem \
go test ./internal/acme -run Pebble -v
```

The test issues a real certificate through the exported `proxy.PlainHTTPHandler`, then
asserts a second, unresolvable name fails and is stored as `error`, and that ordinary
traffic on the listener redirects to HTTPS.


### Scheduled canary

The gateway probes one site on a timer, so a broken path is noticed without an
operator clicking the button. Settings:

| Setting | Meaning | Default |
| --- | --- | --- |
| `canary_enabled` | run the schedule | on (`0` disables) |
| `canary_host` | site to probe; empty uses the first configured site | empty |
| `canary_interval_s` | seconds between probes, 30–86400 | `300` |
| `canary_retries` | extra attempts after a failed probe, 0–10 | `2` |

Each cycle runs the probe, retries a failure up to `canary_retries` times, and records
the last result: host, ok, failing stage, detail, connect latency in milliseconds,
consecutive failed cycles and the check time. Failures notify the **Backend up/down**
class once per outage (dedupe key `canary:<host>`, no alert on every retry); a
recovery sends one message and resets the counter, under its own
`canary:<host>:recovered` key so the outage dedupe cannot swallow it. Ordinary probe results are not
notified.

The last result is part of `GET /api/health`:

```
"canary": {"enabled": true, "host": "app.example.com", "ok": false,
           "failed_stage": "tls", "detail": "tls: certificate expired on ...",
           "latency_ms": 18, "cert_expires_at": "...", "checked_at": "...",
           "consecutive_failures": 2}
```

Health still returns `200` while the canary is failing; the field is diagnostic, and
`?ready=1` keeps answering only for proxy readiness. The probe runs from the gateway
over the public hostname, so it needs the same DNS/hairpin setup as the manual
`POST /api/canary`.

## Incident reports from a runbook

The console's Incident report drawer is rendered by the server, so an on-call
runbook can fetch and keep the same Markdown without a browser. Both routes
need the session cookie and the `traffic.read` permission, and both answer
`text/markdown` with an `incident-*.md` download name:

```sh
# Everything known about one source over the last 24 hours.
curl -s -b jar.txt 'https://console.example.com/api/ips/203.0.113.7/incident.md?hours=24' -o incident-203.0.113.7.md

# The Logs page report for any filter set (ip, host, country, stage, action, blocked).
curl -s -b jar.txt 'https://console.example.com/api/events/incident.md?host=app.example.com&stage=waf&hours=1' -o incident-app.example.com.md
```

The body carries the summary, verdict counts, the newest 50 events and the audit
actions that mention the subject; an empty window says so instead of inventing
a timeline.

## Release tags

A release is published with an annotated `vX.Y.Z` tag on the commit that carries its
`CHANGELOG.md` section. Pushing a tag runs only the `release` job at the tagged commit — publishing a batch of old
tags does not start a full build per tag — and that job fails when the tag name
disagrees with `VERSION`, or when the newest `CHANGELOG.md` section or
`internal/version/version.go` disagrees with it. Branch pushes still run every
job. To create a tag:

```sh
git tag -a v1.47.19 -m 1.47.19            # the release commit, annotated
git push origin HEAD:main --follow-tags   # branch plus its annotated tags
git push origin v1.47.19                  # or one tag on its own
```

Pushing a tag runs the `release` workflow, which builds and signs the binaries
and publishes that tag's `CHANGELOG.md` section as the GitHub release body, so the
written notes are what operators read. A tag with no section fails the job instead
of publishing an empty release. The same push builds the container image, boots it
and checks `/api/health` reports the same version, then pushes
`ghcr.io/<owner>/wafproxy:<version>` for `linux/amd64` and `linux/arm64`; an image
that fails the boot is never published, a manifest missing either architecture
fails the job, and `:latest` moves only when the version being released is the
highest one the registry holds an image for. Published images, not tags, decide
that: a tag exists for the whole push before its image does, so gating on tags
made each release defer to whichever tag appeared during its push and left
`:latest` behind. A tag whose image failed never counts, and an older tag
dispatched later cannot move `:latest` backwards.
After the push the job pulls the tag back from the registry and boots that copy,
so a truncated upload or a package the workflow can write but not read fails the
release instead of a user's first `docker pull`. Dispatching the workflow for an existing tag builds its image the same
way, so a release cut before this rule can still get one.

The release GitHub marks **Latest** is the one that asked for it: the API marks
every newly published release latest unless the call says `--latest=false`, so a
batch of old tags would otherwise leave whichever job finished last on the badge.
The job asks for `--latest` only when the tag is the newest on `origin` and asks
for `--latest=false` otherwise, which also repairs the badge when an old tag is
dispatched again. Runs started by pushing a tag use the workflow as it stood at
that tag, so after publishing a backlog set the badge by hand:

```sh
gh release edit v1.64.0 --latest                 # the release operators should land on
gh api repos/<owner>/<repo>/releases/latest --jq .tag_name   # prove it
```

GitHub reads the workflow from the tagged commit, so a tag pushed before a job
existed never runs that job: its release keeps generated notes and it never
reaches the registry. `deploy/redispatch-tags.sh` dispatches `release.yml` from
`main` once per tag — every tag from **1.61.0** to `VERSION` when none are named,
which is the backlog such a change leaves behind — and refuses a tag that is not
on origin, since there would be nothing to check out:

```sh
./deploy/redispatch-tags.sh --dry-run   # list the runs first
./deploy/redispatch-tags.sh             # one run per release tag
./deploy/redispatch-tags.sh v1.64.0     # a single tag
```

Every run builds and signs on its own, so a backlog costs a runner each. The
script only dispatches; `gh run list --workflow release.yml` follows the results.

`make verify-release` runs `deploy/check-tags.sh`, which fails when a
`CHANGELOG.md` section from **1.61.0** on has no annotated tag, when the tag is
lightweight, when it sits on a commit that does not carry that section, when
`VERSION` at that commit is missing or is not the version the tag names, when
the tag is not reachable from the branch you are on, when its commit is not on
`main` — a release nobody can pull — when a tag names a version
the `CHANGELOG.md` does not date (a stray tag, even when its commit did reach
`main`), or when a version's release commit is newer than the newest release, so
it was cut after one that had already shipped. Sections below 1.61.0 predate
the rule and are not checked. A tag above the version this checkout's `VERSION`
names need not be dated here either: it is a release cut later, so re-running
the gate on an old commit does not go red because a newer release shipped, while
the order rule still reads it.

It enforces on `main` only, because a release branch writes its new section
before the tag can exist; it skips (and says so) on any other branch, pull
request or detached head. Run it against the tags in your clone, and with
`--remote` to ask `origin` instead, which proves the tag was published rather
than just created here:

```sh
make verify-release                              # on main: local tags
bash deploy/check-tags.sh --remote --branch main  # what origin holds
```

Moving a tag onto the commit that really cut its version is not a late release:
the order rule reads the release commit's date, not the tag's, so
`git tag -f -a v1.61.0 <commit> -m 1.61.0` is the fix, not a new mistake. The
newest release is the highest version tagged at or above the floor, and a tag
that names no dated version is a stray whether or not `main` carries its
commit — delete it, or date the section and cut the release properly.

`scripts/release.sh` runs the check before it prints its push commands, when its own
release commit is not on `main` yet, so it passes `--skip-on-main`; the `--remote`
run after the push is what proves the tag landed. It refuses a working tree with
uncommitted changes, a `vX.Y.Z` tag that already exists, a version older than the
newest tag, and a version with no `CHANGELOG.md` section, and it removes its own
tag again when the check fails, leaving the release commit at `HEAD`.

CI runs `bash deploy/check-tags.sh --remote` on every push and pull request; the
`release` job fails only on `main`, where a section without its tag is a real
mistake. A checkout does not fetch tags, which is why CI asks the remote, and the
`release` job checks out full history so it can prove each tag is on `main`.

Check what the remote really holds:

```sh
git ls-remote --tags origin               # annotated tags list the ref and its ^{} peel
git cat-file -t v1.47.19                  # "tag", not "commit": the object is annotated
git describe --tags --abbrev=0        # the nearest annotated tag, as tooling sees it
```

### Verifying a download

Every binary and `SHA256SUMS` is signed keyless with cosign and carries a build-provenance
attestation. The signature certificate names this repository's `release.yml` workflow instead of
a key, and the Fulcio/Rekor entry records when it was made, so verification needs no secret and no
key of ours. Each file ships with a `<name>.sigstore.json` bundle.

```sh
# Resolve the latest tag from the redirect, so this example never goes stale;
# for an older release set version to that tag instead.
version=$(curl -fsS -o /dev/null -w '%{redirect_url}' \
  https://github.com/kenhermesagent-lab/WAF-Proxy/releases/latest)
version=${version##*/tag/v}
base="https://github.com/kenhermesagent-lab/WAF-Proxy/releases/download/v${version}"

for f in SHA256SUMS wafproxy_${version}_linux_amd64; do
  curl -fsSLO "$base/$f"
  curl -fsSLO "$base/$f.sigstore.json"
  cosign verify-blob "$f" \
    --bundle "$f.sigstore.json" \
    --certificate-identity-regexp \
      '^https://github\.com/kenhermesagent-lab/WAF-Proxy/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
done

sha256sum -c SHA256SUMS
gh attestation verify wafproxy_${version}_linux_amd64 --repo kenhermesagent-lab/WAF-Proxy
```

The identity regexp accepts a tag push (`…@refs/tags/` plus the tag) and a manual run from `main`
(`…@refs/heads/main`); pin it to `refs/tags/` when the release must have been built from a tag. A
failure on the identity means the bytes came from somewhere other than this workflow, whatever the
checksum says.

