#!/usr/bin/env bash
# Starts a built image the way deploy/docker-compose.yml does and fails unless
# the console really answers: /api/health, the SPA shell, and the bundle asset
# the shell names. Catches an empty or stale internal/webui/dist, a listener
# that never binds, and a version that never made it into the binary.
set -euo pipefail

image=${1:?usage: docker-smoke-test.sh <image> [expected-version]}
want=${2:-}
name="wafproxy-smoke-$$"
url="http://127.0.0.1:${SMOKE_PORT:-8080}"
work=$(mktemp -d)

cleanup() {
  docker logs "$name" >&2 2>/dev/null || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# Host networking mirrors the shipped Compose file: the console binds loopback
# and the proxy binds the first-boot WAN port. NET_ADMIN is not granted, so
# kernel-mode bans are skipped; the console path under test does not need them.
docker run -d --name "$name" --network host "$image" >/dev/null

ready=""
for _ in $(seq 1 60); do
  if curl -fsS --max-time 5 "$url/api/health" -o "$work/health.json"; then
    ready=1
    break
  fi
  if [[ $(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo false) != true ]]; then
    echo "the container exited before the console answered" >&2
    exit 1
  fi
  sleep 1
done
if [[ -z $ready ]]; then
  echo "the console never answered $url/api/health" >&2
  exit 1
fi

grep -q '"status":"ok"' "$work/health.json" || {
  echo "health did not report ok: $(cat "$work/health.json")" >&2
  exit 1
}
if [[ -n $want ]]; then
  grep -qF "\"version\":\"${want}\"" "$work/health.json" || {
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

echo "console answered: health ok, SPA shell served, ${asset} is ${size} bytes"
