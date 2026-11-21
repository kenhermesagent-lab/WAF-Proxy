#!/usr/bin/env bash
# Root-owned application updater invoked only by wafproxy-updated over its
# privileged Unix socket. It takes no arguments: the checkout, its owner and
# the deployment mode are fixed at install time in
# /etc/wafproxy/self-update.conf.
set -euo pipefail

# The service has no terminal; fail instead of waiting for a git password.
# Public checkouts fetch anonymously; a private fork needs the owner's existing
# git credential helper or SSH key.
export GIT_TERMINAL_PROMPT=0

conf=/etc/wafproxy/self-update.conf
if [[ ! -r "$conf" ]]; then
  echo "self-update is not configured: $conf is missing" >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$conf"
: "${WAFPROXY_UPDATE_SOURCE_DIR:?WAFPROXY_UPDATE_SOURCE_DIR is required}"
mode="${WAFPROXY_UPDATE_MODE:-native}"
branch="${WAFPROXY_UPDATE_BRANCH:-main}"
src="$WAFPROXY_UPDATE_SOURCE_DIR"
update_user="${WAFPROXY_UPDATE_USER:-}"

as_user() {
  if [[ -n "$update_user" ]]; then
    local home path node
    home="$(getent passwd "$update_user" | cut -d: -f6)"
    path="$home/.local/bin:$home/toolchain/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"
    for node in "$home"/.nvm/versions/node/*/bin; do
      if [[ -d "$node" ]]; then path="$node:$path"; fi
    done
    runuser -u "$update_user" -- env HOME="$home" PATH="$path" "$@"
  else
    "$@"
  fi
}

if [[ ! -d "$src/.git" ]]; then
  echo "self-update source is not a git checkout: $src" >&2
  exit 1
fi
if ! command -v git >/dev/null; then
  echo "self-update needs git on the host" >&2
  exit 1
fi

dirty="$(as_user git -C "$src" status --porcelain)"
if [[ -n "$dirty" ]]; then
  echo "refusing to update: the checkout has local changes" >&2
  echo "$dirty" >&2
  exit 1
fi

as_user git -C "$src" pull --ff-only origin "$branch"
cd "$src"

if [[ "$mode" == "docker" ]]; then
  if ! command -v docker >/dev/null; then
    echo "self-update needs docker on the host" >&2
    exit 1
  fi
  version="$(cat VERSION)"
  env_file="${WAFPROXY_UPDATE_ENV_FILE:-$src/deploy/.env}"
  if [[ -f "$env_file" ]]; then
    tmp="$(mktemp)"
    if grep -q '^VERSION=' "$env_file"; then
      awk -v version="$version" '
        /^VERSION=/ && !seen { print "VERSION=" version; seen = 1; next }
        { print }
      ' "$env_file" >"$tmp"
    else
      cp "$env_file" "$tmp"
      printf 'VERSION=%s\n' "$version" >>"$tmp"
    fi
    # Copy back instead of renaming so the operator's ownership and mode stay.
    cat "$tmp" >"$env_file"
    rm -f "$tmp"
  fi
  args=(compose)
  if [[ -f "$env_file" ]]; then
    args+=(--env-file "$env_file")
  fi
  args+=(-f deploy/docker-compose.yml up -d --build wafproxy)
  VERSION="$version" COMMIT="$(git rev-parse --short HEAD)" \
    BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" docker "${args[@]}"
  echo "rebuilt and recreated the WAF-Proxy container from $(cat VERSION) ($(git rev-parse --short HEAD))"
  exit 0
fi

if ! command -v make >/dev/null; then
  echo "self-update needs make on the host" >&2
  exit 1
fi
as_user make -C "$src" all

for file in bin/wafproxy bin/wafproxy-updated deploy/wafproxy.service deploy/wafproxy-updates.service; do
  if [[ ! -e "$src/$file" ]]; then
    echo "self-update build did not produce $file" >&2
    exit 1
  fi
done

install -m 0755 "$src/bin/wafproxy" /usr/local/bin/wafproxy
install -m 0755 "$src/bin/wafproxy-updated" /usr/local/bin/wafproxy-updated
install -m 0644 "$src/deploy/wafproxy.service" /etc/systemd/system/wafproxy.service
install -m 0644 "$src/deploy/wafproxy-updates.service" /etc/systemd/system/wafproxy-updates.service
systemctl daemon-reload

echo "installed $(cat VERSION) from $(git rev-parse --short HEAD); the console will restart to load it"
