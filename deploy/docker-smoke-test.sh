#!/usr/bin/env bash
# Starts a built image the way deploy/docker-compose.yml does and fails unless it
# really serves: the console's health, SPA shell and bundle, then a request
# through the proxy to an upstream. Catches an empty internal/webui/dist, a
# listener that never binds and a broken entrypoint before a user's host does.
set -euo pipefail

image=${1:?usage: docker-smoke-test.sh <image> [expected-version]}
want=${2:-}
name="wafproxy-smoke-$$"
url="http://127.0.0.1:${SMOKE_PORT:-8080}"
wan=${SMOKE_WAN_PORT:-8443}
base=smoke.test
site="app.${base}"
upstream_port=19090
work=$(mktemp -d)
upstream=""

cleanup() {
  if [[ -n $upstream ]]; then
    kill "$upstream" 2>/dev/null || true
  fi
  docker logs "$name" >&2 2>/dev/null || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# The upstream is a plain file server on the host; with host networking the
# container reaches it exactly as it would reach a real backend on the LAN.
mkdir -p "$work/upstream"
echo "smoke upstream answered" >"$work/upstream/index.html"
python3 -m http.server "$upstream_port" --bind 127.0.0.1 --directory "$work/upstream" >/dev/null 2>&1 &
upstream=$!

# Host networking mirrors the shipped Compose file: the console binds loopback
# and the proxy binds the first-boot WAN port. The two capabilities are the ones
# Compose grants, and they are not optional: the binary carries them as file
# capabilities, so without them in the bounding set the exec itself fails with
# "operation not permitted".
docker run -d --name "$name" --network host \
  --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE "$image" >/dev/null

ready=""
for _ in $(seq 1 60); do
  if curl -fsS --max-time 5 "$url/api/health" -o "$work/health.json" 2>/dev/null; then
    ready=1
    break
  fi
  # Only a container that has finished failing is a failure: right after
  # `docker run -d` it can still be in "created" before it is started.
  case $(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo gone) in
    exited | dead | gone)
      echo "the container exited before the console answered" >&2
      docker logs "$name" 2>&1 | tail -40 >&2 || true
      exit 1
      ;;
  esac
  sleep 1
done
if [[ -z $ready ]]; then
  echo "the console never answered $url/api/health" >&2
  exit 1
fi

# Compare without whitespace so the check does not depend on JSON spacing.
health=$(tr -d '[:space:]' <"$work/health.json")
grep -qF '"status":"ok"' <<<"$health" || {
  echo "health did not report ok: $(cat "$work/health.json")" >&2
  exit 1
}
if [[ -n $want ]]; then
  grep -qF "\"version\":\"${want}\"" <<<"$health" || {
    echo "health reports $(cat "$work/health.json"), want version ${want}" >&2
    exit 1
  }
fi

curl -fsS --max-time 10 "$url/" -o "$work/index.html"
grep -q 'id="root"' "$work/index.html" || {
  echo "the console did not serve its SPA shell" >&2
  exit 1
}

asset=$(grep -oE 'src="/assets/[^"]+\.js"' "$work/index.html" | head -1 | cut -d'"' -f2)
if [[ -z $asset ]]; then
  echo "the SPA shell references no bundle asset" >&2
  exit 1
fi

curl -fsS --max-time 10 "$url$asset" -o "$work/bundle.js"
size=$(wc -c <"$work/bundle.js")
if ((size < 1000)); then
  echo "bundle ${asset} is ${size} bytes, expected a real build" >&2
  exit 1
fi

# A console that answers but cannot proxy is still broken, so drive the path a
# visitor takes: create the first admin, log in, point a hostname at the
# upstream, then fetch it through the WAN listener. No certificate exists yet,
# so this also covers the proxy's fallback handshake.
code=$(curl -sS --max-time 10 -o "$work/setup.json" -w '%{http_code}' -X POST "$url/api/setup" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"smoke\",\"password\":\"smoke-test-password\",\"base_domain\":\"${base}\",\"wan_ip\":\"127.0.0.1\",\"lan_ip\":\"127.0.0.1\",\"wan_port\":${wan},\"gui_port\":8080}" || true)
if [[ $code != 201 ]]; then
  echo "setup returned ${code:-no response}: $(cat "$work/setup.json" 2>/dev/null)" >&2
  exit 1
fi

# Setup enrolls the authenticator straight away, so the password alone cannot
# sign in: use one of the recovery codes the setup response returns.
recovery=$(python3 -c "import json;print(json.load(open('$work/setup.json'))['recovery_codes'][0])")
code=$(curl -sS --max-time 10 -c "$work/jar" -o "$work/login.json" -w '%{http_code}' -X POST "$url/api/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"smoke\",\"password\":\"smoke-test-password\",\"recovery\":\"${recovery}\"}" || true)
csrf=$(grep -o '"csrf":"[^"]*"' "$work/login.json" 2>/dev/null | cut -d'"' -f4 || true)
if [[ $code != 200 || -z $csrf ]]; then
  echo "login returned ${code:-no response}: $(cat "$work/login.json" 2>/dev/null)" >&2
  exit 1
fi

# A fresh install has no certificate, and the proxy refuses a handshake for a
# name it cannot serve, so issue one from the internal CA first.
code=$(curl -sS --max-time 10 -b "$work/jar" -o "$work/cert.json" -w '%{http_code}' -X POST "$url/api/certs/internal" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: ${csrf}" \
  -d "{\"domains\":[\"${site}\"]}" || true)
cert=$(python3 -c "import json;print(json.load(open('$work/cert.json')).get('id',''))" 2>/dev/null || true)
if [[ $code != 201 || -z $cert ]]; then
  echo "issuing a certificate returned ${code:-no response}: $(cat "$work/cert.json" 2>/dev/null)" >&2
  exit 1
fi

code=$(curl -sS --max-time 10 -b "$work/jar" -o "$work/proxy.json" -w '%{http_code}' -X POST "$url/api/proxies" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: ${csrf}" \
  -d "{\"hostname\":\"${site}\",\"cert_id\":${cert},\"upstreams\":[{\"url\":\"http://127.0.0.1:${upstream_port}\"}]}" || true)
if [[ $code != 201 ]]; then
  echo "creating ${site} returned ${code:-no response}: $(cat "$work/proxy.json" 2>/dev/null)" >&2
  exit 1
fi

proxied=$(curl -fsS --max-time 15 -k --resolve "${site}:${wan}:127.0.0.1" "https://${site}:${wan}/" || true)
if ! grep -q 'smoke upstream answered' <<<"$proxied"; then
  echo "${site} did not reach the upstream; the proxy answered: ${proxied:-nothing}" >&2
  exit 1
fi

echo "console answered: health ok, SPA shell served, ${asset} is ${size} bytes; ${site} proxied to the upstream"
