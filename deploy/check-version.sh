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

# Only set by GitHub Actions; a local run checks the two files above.
if [[ ${GITHUB_REF_TYPE:-} == tag ]]; then
  tag=${GITHUB_REF_NAME#v}
  if [[ $tag != "$version" ]]; then
    echo "tag '${GITHUB_REF_NAME}' does not match VERSION ${version}" >&2
    exit 1
  fi
fi

echo "release metadata consistent at ${version}"
