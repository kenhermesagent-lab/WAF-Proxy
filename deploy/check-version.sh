#!/usr/bin/env bash
# Fails when VERSION, the newest CHANGELOG.md section and a release tag disagree.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=$(tr -d '[:space:]' < "$root/VERSION")

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION is not MAJOR.MINOR.PATCH: '${version}'" >&2
  exit 1
fi

top=$(grep -m1 '^## \[' "$root/CHANGELOG.md" | sed -E 's/^## \[([^]]+)\].*/\1/')
if [[ $top != "$version" ]]; then
  echo "CHANGELOG.md newest section is '${top:-none}', VERSION is ${version}" >&2
  exit 1
fi

# The default only matters for a build that skipped the ldflags, but a stale
# one is what a `go run` or a stray `go build` reports as its version.
default=$(sed -nE 's/^[[:space:]]*Version *= *"([^"]+)".*/\1/p' "$root/internal/version/version.go" | head -1)
if [[ $default != "$version" ]]; then
  echo "internal/version/version.go default is '${default:-none}', VERSION is ${version}" >&2
  exit 1
fi

# Only set by GitHub Actions; a local run checks the two files above.
if [[ ${GITHUB_REF_TYPE:-} == tag ]]; then
  tag=${GITHUB_REF_NAME#v}
  if [[ $tag != "$version" ]]; then
    echo "tag '${GITHUB_REF_NAME}' does not match VERSION ${version}" >&2
    exit 1
  fi
fi

echo "release metadata consistent at ${version}"
