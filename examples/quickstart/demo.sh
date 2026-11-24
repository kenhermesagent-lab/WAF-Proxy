#!/usr/bin/env bash
# Seed the quickstart install and prove the WAF does something.
#
#   docker compose up -d && ./demo.sh
#
# It creates the administrator (no authenticator: this is a throwaway install),
# imports demo.yaml, then sends one ordinary request and one SQL injection
# through the proxy. Safe to re-run.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUI=${WAFPROXY_GUI:-http://127.0.0.1:8080}
SITE_HOST=${WAFPROXY_DEMO_HOST:-demo.local}
WAN_PORT=${WAFPROXY_DEMO_PORT:-8443}
ADMIN=${WAFPROXY_DEMO_ADMIN:-admin}
PASSWORD=${WAFPROXY_DEMO_PASSWORD:-demo-password-123}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

say "Waiting for the console at $GUI"
for _ in $(seq 1 90); do
  curl -fsS "$GUI/api/setup/status" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$GUI/api/setup/status" >/dev/null 2>&1 || fail "the console never answered on $GUI"

status=$(curl -fsS "$GUI/api/setup/status")
if [[ $status == *'"needs_setup":true'* ]]; then
  say "Creating the administrator (no TOTP: throwaway demo install)"
  if [[ -n ${WAFPROXY_SETUP_BIN:-} ]]; then
    "$WAFPROXY_SETUP_BIN" setup --user "$ADMIN" --password "$PASSWORD" --base-domain "$SITE_HOST"
  else
    docker compose -f "$HERE/docker-compose.yml" exec -T wafproxy \
      wafproxy setup --user "$ADMIN" --password "$PASSWORD" --base-domain "$SITE_HOST"
  fi
fi

say "Signing in"
login=$(curl -fsS -c "$JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN\",\"password\":\"$PASSWORD\"}" "$GUI/api/login") ||
  fail "login failed; the administrator password is not the demo default (set WAFPROXY_DEMO_PASSWORD)"
csrf=$(printf '%s' "$login" | sed -n 's/.*"csrf":"\([^"]*\)".*/\1/p')
[[ -n $csrf ]] || fail "the console did not return a CSRF token"

say "Importing demo.yaml"
imported=$(curl -fsS -b "$JAR" -H "X-CSRF-Token: $csrf" \
  -H 'Content-Type: application/x-yaml' --data-binary "@$HERE/demo.yaml" \
  "$GUI/api/config/import.yaml") || fail "the import was refused"
printf '%s\n' "$imported"

curl_base=(curl -skS --resolve "$SITE_HOST:$WAN_PORT:127.0.0.1" -o /dev/null -w '%{http_code}')

say "1/2  An ordinary request"
allowed=$("${curl_base[@]}" "https://$SITE_HOST:$WAN_PORT/")
printf 'GET /                     -> HTTP %s\n' "$allowed"

say "2/2  A SQL injection"
blocked=$("${curl_base[@]}" "https://$SITE_HOST:$WAN_PORT/?id=1%27%20OR%20%271%27%3D%271")
printf "GET /?id=1' OR '1'='1    -> HTTP %s\n" "$blocked"

say "Result"
if [[ $allowed == 200 && $blocked == 403 ]]; then
  printf 'Allowed: %s   Blocked: %s\n' "$allowed" "$blocked"
  printf 'Console: %s (sign in as %s)\n' "$GUI" "$ADMIN"
  printf 'Blocked request is in Logs with its stage and rule.\n'
else
  fail "expected 200 then 403, got $allowed then $blocked — check docker compose logs wafproxy"
fi
