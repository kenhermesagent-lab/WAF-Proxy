#!/usr/bin/env bash
# Install the optional host-side updater for a Docker Compose deployment.
# Run this from the checkout after the image has been built once:
#
#   sudo ./deploy/install-docker-updater.sh
#
# It copies wafproxy-updated out of the running container, installs the fixed
# updater script and starts a root service that exposes only that action on a
# root:10001 Unix socket. Compose mounts the socket directory into the console.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $EUID -ne 0 ]]; then
  echo "install-docker-updater.sh: run as root (sudo ./deploy/install-docker-updater.sh)" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "install-docker-updater.sh: docker is required" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "install-docker-updater.sh: Docker Compose v2 is required" >&2
  exit 1
fi

compose=(docker compose -f "$(pwd)/deploy/docker-compose.yml")
container="$("${compose[@]}" ps -q wafproxy)"
if [[ -z "$container" ]]; then
  echo "install-docker-updater.sh: the wafproxy container is not running; start the stack first" >&2
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
if ! docker cp "$container:/usr/local/bin/wafproxy-updated" "$tmp" 2>/dev/null; then
  echo "install-docker-updater.sh: this image has no wafproxy-updated; rebuild it with 'docker compose up -d --build' first" >&2
  exit 1
fi
install -m 0755 "$tmp" /usr/local/bin/wafproxy-updated
install -d -m 0755 /usr/local/lib/wafproxy /etc/wafproxy
install -m 0755 deploy/wafproxy-self-update.sh /usr/local/lib/wafproxy/self-update
install -m 0755 deploy/wafproxy-self-update-check.sh /usr/local/lib/wafproxy/self-update-check
install -m 0644 deploy/wafproxy-docker-updates.service /etc/systemd/system/wafproxy-docker-updates.service

remote="$(git config --get remote.origin.url 2>/dev/null || true)"
if [[ -z "$remote" || ! -d .git ]]; then
  echo "install-docker-updater.sh: no git checkout found in $(pwd); application updates cannot be applied" >&2
  exit 1
fi
update_user="$(stat -c '%U' . 2>/dev/null || true)"
if [[ "$update_user" == "root" || "$update_user" == "" ]]; then
  update_user=""
fi

{
  printf 'WAFPROXY_UPDATE_SOURCE_DIR=%q\n' "$(pwd)"
  printf 'WAFPROXY_UPDATE_USER=%q\n' "$update_user"
  printf 'WAFPROXY_UPDATE_BRANCH=%q\n' "$(git symbolic-ref --short HEAD 2>/dev/null || echo main)"
  printf 'WAFPROXY_UPDATE_MODE=%q\n' "docker"
  if [[ -f deploy/.env ]]; then
    printf 'WAFPROXY_UPDATE_ENV_FILE=%q\n' "$(pwd)/deploy/.env"
  fi
} >/etc/wafproxy/self-update.conf
chmod 0644 /etc/wafproxy/self-update.conf

systemctl daemon-reload
systemctl enable --now wafproxy-docker-updates.service

# The socket mount is part of the compose file. Recreating the container here
# applies it without touching the named data volume.
"${compose[@]}" up -d wafproxy
container="$("${compose[@]}" ps -q wafproxy)"
for _ in $(seq 1 30); do
  if [[ -n "$container" ]] && docker exec "$container" test -S /run/wafproxy-updates/updates.sock 2>/dev/null; then
    echo "Docker application updater installed; one-click updates are enabled in the Updates page."
    exit 0
  fi
  sleep 1
done
echo "install-docker-updater.sh: the updater socket is not visible inside the container." >&2
echo "Check 'systemctl status wafproxy-docker-updates' and that compose mounts /run/wafproxy-updates." >&2
exit 1
