# Operations runbook

## Daily checks

- **Dashboard** — WAN/LAN throughput, blocked ratio, top blocked sources, globe.
- **Policies → Temp/Permanent bans** — unexpected permanent bans usually mean a decoy hit
  or a feed false positive; both carry a reason and source.
- **Certificates** — expiry and `last_error`. Renewal is automatic inside 30 days.
- **Threat intel** — a feed stuck in `frozen` means the 5× growth guardrail tripped;
  inspect before enabling it again.
- **Logs** — filter by stage `waf` or `access-gate` after changing a profile or gate.
- Container log: `docker compose -f deploy/docker-compose.yml logs --tail=200 wafproxy`.

## Recovery

### Unban an address

GUI → Policies → Temp bans / Permanent → **Unban**. Or, if the GUI is unreachable:

```bash
docker exec wafproxy unban 203.0.113.7
```

The running process reconciles the in-memory table from SQLite every 30 seconds, so the ban
lifts without a restart.

### Locked out of the admin GUI

The GUI listener is exempt from every ban and binds to the LAN address only. Check that you
are on the LAN and using the stored `LAN_IP:GUI_PORT`. If the browser has no session, sign in
with password + TOTP, or a single-use recovery code.

### Lost password and TOTP and recovery codes

There is no online reset (that would be a backdoor). Stop the stack, back up the data volume,
and remove `wafproxy.db` to re-run the setup wizard. This deletes proxies, bans, feeds,
certificates and settings. Restore a JSON backup afterwards to recover configuration
(secrets and certificates excluded).

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
  keys and password hashes.
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
