# Operations runbook

## Daily checks

- **Dashboard** — WAN/LAN throughput, blocked ratio, top blocked sources, per-proxy live
  request and traffic rates, and the attack globe (1 h / 6 h / 24 h, category filters).
- **Statistics** — date-range request outcomes, hourly traffic, per-proxy shares, visitor
  countries and backend uptime. A red probe means the backend returned 5xx or timed out; the
  down/recovery transition is also sent to the **Backend up/down** notification channels.
- **Policies → Temp/Permanent bans** — unexpected permanent bans usually mean a decoy hit
  or a feed false positive; both carry a reason and source.
- **Certificates** — expiry and `last_error`. Renewal is automatic inside 30 days.
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

There is no online reset (that would be a backdoor). Stop the stack, back up the data volume,
and remove `wafproxy.db` to re-run the setup wizard. This deletes proxies, bans, feeds,
certificates and settings. Restore a JSON backup afterwards to recover configuration
(secrets and certificates excluded).

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

- Native: the Updates page shows the captured pull/build output; `journalctl -u
  wafproxy-updates -n 100` shows the helper's start/stop and timeout errors. Check `git`, `make`,
  Go 1.27 and Node 22 are available to the checkout owner
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

## Backup and restore

- Settings → **Download JSON** exports settings, proxies, upstreams, routes, policies,
  feeds and bans. It intentionally excludes secrets, DNS credentials, certificates/private
  keys and password hashes; uploaded local blocklist files must be uploaded again.
- Restore is additive: existing hostnames are skipped and reported in `problems`.
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
WAFPROXY_LISTEN_GUI=http://127.0.0.1:8080   # ignored once TLS is on
WAFPROXY_LISTEN_GUI_TLS=1
WAFPROXY_GUI_HOST=console.home.arpa
```

The listener refuses to start when no valid certificate matches the host, so a typo
cannot silently leave the console on plain HTTP. Browsers need the internal root
(`GET /api/certs/internal/root`) or a public CA for that name.

## Revoking a certificate

`POST /api/certs/{id}/revoke` revokes an ACME certificate with the CA that issued it,
then deletes the local record. Uploaded and internal certificates have no ACME account;
they are deleted locally. If the CA refuses, the endpoint returns `502` with the reason
and keeps the certificate. Deleting a certificate without revoking it remains available
through `DELETE /api/certs/{id}`.
