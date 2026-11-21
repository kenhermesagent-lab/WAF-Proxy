#!/usr/bin/env bash
# Root-owned repository check used by the Updates page. It fetches the
# recorded checkout with that checkout owner's git credentials, so a private
# repository works without putting a token in the console.
set -euo pipefail

# The service has no terminal; fail instead of waiting for a git password.
export GIT_TERMINAL_PROMPT=0

conf=/etc/wafproxy/self-update.conf
if [[ ! -r "$conf" ]]; then
  exit 1
fi
# shellcheck source=/dev/null
source "$conf"
: "${WAFPROXY_UPDATE_SOURCE_DIR:?WAFPROXY_UPDATE_SOURCE_DIR is required}"
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

as_user git -C "$src" fetch --quiet origin "$branch"
sha="$(as_user git -C "$src" rev-parse "origin/$branch")"
version="$(as_user git -C "$src" show "origin/$branch:VERSION" | tr -d '[:space:]')"
date="$(as_user git -C "$src" show -s --format=%cI "origin/$branch")"
url="$(as_user git -C "$src" config --get remote.origin.url || true)"
printf '%s\t%s\t%s\t%s\t%s\n' "$sha" "$version" "$date" "$url" "$branch"
