# Upgrade, remove and keep it updated

Part of [Installation](../INSTALL.md).

## 9. Upgrade

Back up first (Settings → Download JSON exports configuration without secrets).

```bash
git pull
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
```

The schema is applied idempotently on boot. Restore the JSON if a configuration was lost;
gate modes are reset to `off` and certificates must be re-issued because private keys are
not exported.

## 10. Uninstall

```bash
docker compose -f deploy/docker-compose.yml down
# configuration and database:
docker volume rm wafproxy_data
```

This is destructive. Export the backup first if the configuration may be reused.

## 13. Application and host updates

The **Updates** page has an application section and a native host-package section. Applying an
application update is available on native systemd installs and on Docker Compose installs that
have run the optional host updater. Host-package updates remain native-only.

### 13.1 What is tracked

The page uses a fixed catalog of the host packages the native service needs:

| Package | Used for |
|---|---|
| `ca-certificates` | ACME and upstream TLS trust roots |
| `nftables` | Kernel-mode ban enforcement (`nft`) |
| `tzdata` | Host time-zone data used by the console |
| `cloudflared` | Cloudflare Tunnel connector, when the Cloudflare page installed it |

It shows the installed version, the candidate version from the apt index, and whether the
candidate comes from a distribution security repository. High and critical advisories are
matched with the [OSV database](https://osv.dev/) for the installed package version; low and
medium advisories are intentionally not shown on this page. A security-repository update with
no published CVSS record is shown as a security update with an unknown severity instead of
being hidden.

Checking advisories sends only the package name, distribution version and installed version to
`api.osv.dev`. It does not send hostnames, proxy traffic, credentials, settings or certificates.

Go modules and the React console are compiled into the WAF-Proxy binary. They are listed as
application dependencies on the page but are not changed by the host upgrade helper; deploy a
new WAF-Proxy release to update them.

### 13.2 The privileged helper

The console service runs with `NoNewPrivileges=yes`, so it cannot use `sudo`. `install.sh`
installs two pieces instead:

- `/var/lib/waf-proxy/bin/wafproxy-updated` — a root-owned helper service, linked as
  `/usr/local/bin/wafproxy-updated`;
- `/etc/systemd/system/wafproxy-updates.service` — the unit that starts it.

The helper listens on `/run/wafproxy-updates/updates.sock` with mode `0660`, owned by
`root:wafproxy`. It accepts only `check` (apt index refresh), `apply` for an exact package from
the compiled catalog, `app-check` and `app-update` (the fixed repository scripts). Package names are
validated again by both the console and the helper; arbitrary package names, shell commands,
repository URLs and options are rejected. The console still keeps its reduced capabilities
and never runs apt or a build itself.

`install.sh` records the checkout path and its owner in `/etc/wafproxy/self-update.conf` and
installs `/var/lib/waf-proxy/lib/self-update` and `self-update-check`. That script can run on a
host that has not been through `install.sh` since 1.13: it creates the install root, moves state
out of `/var/lib/wafproxy` and installs the environment file the unit expects, exactly as the
installer does. The default checkout is
the root-owned clone at `/var/lib/waf-proxy/src`, so neither a home directory nor an
operator's git credentials are needed; a host where the clone could not be created falls back
to the directory the installer ran from. The check runs `git fetch` there. The public repository
needs no token or login; a private fork uses the recorded user's existing git credentials. The application action refuses changes to tracked files (untracked build output and the
regenerated console bundle do not count), restores `internal/webui/dist` to the checkout so a
previous build cannot block the pull, runs `git pull --ff-only`, then `make build` and `make ui`
when `npm` is available (a host without Node, or without registry access, updates with the
console bundle the release commits), installs both binaries into `/var/lib/waf-proxy/bin` and
refreshes the helper scripts, reloads systemd units, restarts the helper and then restarts
`wafproxy.service` so the new binary is loaded. It never accepts an
argument from the browser, and the data directory is untouched. If the button does not finish,
`sudo journalctl -u wafproxy-updates -n 80 --no-pager` has the pull and build output.

The updater is its own rollback: before installing it copies the binaries its current unit
names, both unit files, the `/usr/local` symlinks and, on an upgrade from 1.13, the state
directory it moved. A build, install or restart failure restores all of it, restarts the
previous version and prints what it did; the same line is written to
`/var/lib/waf-proxy/data/last-app-update` and shown on the Updates page, so an operator who is
signed out during the restart still sees the outcome. If the service does not come back at all,
run `sudo ./deploy/install.sh` from the checkout: it repairs the paths the updater could not. Only install
from a repository you trust: the helper builds that checkout's code. A checkout recorded from
the console must have the same origin as the running build (`owner/repository`, in any git
remote spelling); the helper refuses one that points at another repository, so an administrator
cannot use the field to install code from a repository the operator never approved.

```bash
sudo systemctl status wafproxy-updates
sudo journalctl -u wafproxy-updates -f
```

If the helper is missing or stopped, the Updates page lists installed and candidate versions
but disables the Update buttons and shows the reason. Re-run `sudo ./deploy/install.sh` after
building to install/repair it.

### 13.3 Checking and applying

1. Open **Updates**. The application card compares the running build with `main` and offers
   **Update application** when a newer version/commit exists.
   If the card says the button is unavailable, it also shows why. A running helper with no
   recorded checkout shows a **WAF-Proxy checkout directory** field: enter the absolute path of
   the git checkout that holds `deploy/` and the helper records it (`/etc/wafproxy/self-update.conf`),
   after which the button works. The origin must match the repository this build was compiled
   from (a fork builds with `make REPO=owner/repo` or the `REPO` build arg); any other origin is
   refused. The helper only records the path; it never copies code out of the checkout. If the
   page reports the installed update scripts missing, re-run `sudo ./deploy/install.sh` from the
   checkout. The commands below the field are the manual fallback, not the expected path.
   The console asks the root helper for the recorded checkout and script state, because a
   container's `/etc` and `/usr/local` are not the host's.
2. Click **Check for updates** to refresh the repository check and, on native, the apt index.
3. Click **Update** on one host package, confirm, and wait for apt to finish. The page refreshes
   and shows the helper output.
4. For an application update, confirm the button and leave the page open. The rebuild runs in
   the background; the page reconnects and reports the new commit when the service returns.
   Docker recreates the container, so the page may briefly show connection errors while that
   happens.

Only one helper operation runs at a time. The distribution package manager remains the
authority: if no newer candidate exists, the page reports that instead of inventing a version.
Applying a package update does not automatically restart WAF-Proxy; an application update
does.

### 13.4 Docker application updates

Docker cannot run a build or access its own socket from inside the console container. Install
the optional host updater once from the checkout, after the image has been built at least once:

```bash
sudo ./deploy/install-docker-updater.sh
```

It copies `wafproxy-updated` out of the running container, installs `wafproxy-self-update.sh`,
`wafproxy-self-update-check.sh` and the `wafproxy-update-lib.sh` they source as
`/var/lib/waf-proxy/lib/self-update`, `self-update-check` and `wafproxy-update-lib.sh`,
installs `wafproxy-docker-updates.service`, records the checkout path,
its owner and `deploy/.env`, and starts the root helper. The console reports the button
available only when that helper confirms both scripts and the checkout exist on the host;
the container itself cannot see those paths. Compose mounts `/run/wafproxy-updates` into the console, so the
**Update application** button then pulls the checkout as its owner, rebuilds the image with
the new `VERSION`,
`COMMIT` and `BUILD_DATE`, and recreates only the `wafproxy` service. The named data volume,
crowdsec sidecar and host settings are retained.

Without the updater the page still checks for a newer application build, explains the
limitation, and shows the manual command:

```bash
git pull --ff-only
# Keep the image tag in deploy/.env aligned with the new VERSION file.
if grep -q '^VERSION=' deploy/.env; then
  sed -i "s/^VERSION=.*/VERSION=$(cat VERSION)/" deploy/.env
else
  echo "VERSION=$(cat VERSION)" >> deploy/.env
fi
docker compose -f deploy/docker-compose.yml up -d --build
```

Host-package buttons remain unavailable in Docker; those packages come from the rebuilt image.
