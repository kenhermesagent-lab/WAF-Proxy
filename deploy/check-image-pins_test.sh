#!/usr/bin/env bash
# Regression test for check-image-pins.sh: a tag, a tag with a short digest and
# a digest on the wrong algorithm must fail; pinned and scratch stages must pass.
set -euo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/repo"
digest=sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280

seed() {
  rm -rf "$root"
  mkdir -p "$root/deploy"
  cp "$src/check-image-pins.sh" "$root/deploy/check-image-pins.sh"
  cat >"$root/Dockerfile" <<DOCKERFILE
FROM golang:1.27-alpine@${digest} AS build
RUN true

FROM scratch
COPY --from=build /out/app /app
DOCKERFILE
}

check() {
  ( cd "$root" && bash deploy/check-image-pins.sh >/dev/null 2>&1 )
}

seed
if ! check; then
  echo "a fully pinned Dockerfile failed the image pin check" >&2
  exit 1
fi

expect_fail() {
  local name=$1 from=$2
  seed
  printf '%s\n' "$from" >>"$root/Dockerfile"
  if check; then
    echo "${name} did not fail the image pin check" >&2
    exit 1
  fi
}

expect_fail "a bare tag" "FROM alpine:3.21"
expect_fail "a tag with a truncated digest" "FROM alpine:3.21@sha256:bc214871"
expect_fail "a digest on the wrong algorithm" "FROM alpine:3.21@sha512:${digest#sha256:}"
expect_fail "a comment after FROM" "FROM alpine:3.21@${digest} # 3.21"

echo "image pin check rejects tags and short digests"
