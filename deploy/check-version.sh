#!/usr/bin/env bash
# Fails when VERSION, the newest CHANGELOG.md section and a release tag disagree.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=$(tr -d '[:space:]' < "$root/VERSION")

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION is not MAJOR.MINOR.PATCH: '${version}'" >&2
  exit 1
fi

# An `Unreleased` heading holds work that is not a release yet and never carries
# a version, so the newest section that has to agree with VERSION is the first
# one that names a version.
top=""
while IFS= read -r section; do
  name=$(sed -E 's/^## \[([^]]+)\].*/\1/' <<<"$section")
  if [[ ${name,,} == unreleased ]]; then
    continue
  fi
  top=$name
  break
done < <(grep '^## \[' "$root/CHANGELOG.md")
if [[ $top != "$version" ]]; then
  echo "CHANGELOG.md newest released section is '${top:-none}', VERSION is ${version}" >&2
  exit 1
fi

# The default only matters for a build that skipped the ldflags, but a stale
# one is what a `go run` or a stray `go build` reports as its version.
default=$(sed -nE 's/^[[:space:]]*Version *= *"([^"]+)".*/\1/p' "$root/internal/version/version.go" | head -1)
if [[ $default != "$version" ]]; then
  echo "internal/version/version.go default is '${default:-none}', VERSION is ${version}" >&2
  exit 1
fi

# The security policy, the console package and the Compose defaults also name
# the release; a stale copy misleads whoever reads them next.
minor="${version%.*}"
supported=$(sed -nE 's/^\| *([0-9]+\.[0-9]+)\.x *\| *Yes *\|.*/\1/p' "$root/SECURITY.md" | head -1)
if [[ $supported != "$minor" ]]; then
  echo "SECURITY.md supports '${supported:-none}.x', VERSION is ${version}" >&2
  exit 1
fi

npm=$(sed -nE 's/^[[:space:]]*"version": "([^"]+)".*/\1/p' "$root/web/package.json" | head -1)
if [[ $npm != "$version" ]]; then
  echo "web/package.json version is '${npm:-none}', VERSION is ${version}" >&2
  exit 1
fi

# The lockfile records the package version twice at its head; a stale copy is
# what `npm ci` and a release audit read.
lock=$(sed -n '1,12p' "$root/web/package-lock.json" | sed -nE 's/^[[:space:]]*"version": "([^"]+)".*/\1/p' | sort -u)
if [[ $lock != "$version" ]]; then
  echo "web/package-lock.json records '${lock:-none}', VERSION is ${version}" >&2
  exit 1
fi

pins=$(grep -oE 'VERSION:-[0-9]+\.[0-9]+\.[0-9]+' "$root/deploy/docker-compose.yml" || true)
if [[ -z $pins ]]; then
  echo "deploy/docker-compose.yml does not pin a VERSION" >&2
  exit 1
fi
while IFS= read -r pin; do
  if [[ $pin != "VERSION:-$version" ]]; then
    echo "deploy/docker-compose.yml pins '${pin}', VERSION is ${version}" >&2
    exit 1
  fi
done <<< "$pins"

# Only set by GitHub Actions; a local run checks the files above.
if [[ ${GITHUB_REF_TYPE:-} == tag ]]; then
  tag=${GITHUB_REF_NAME#v}
  if [[ $tag != "$version" ]]; then
    echo "tag '${GITHUB_REF_NAME}' does not match VERSION ${version}" >&2
    exit 1
  fi
fi

echo "release metadata consistent at ${version}"
