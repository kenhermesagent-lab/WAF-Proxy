#!/usr/bin/env bash
# Regression test for check-version.sh: every release input must be able to
# fail the check on its own, and a consistent tree must pass.
set -euo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/repo"

seed() {
  rm -rf "$root"
  mkdir -p "$root/deploy" "$root/internal/version"
  cp "$src/check-version.sh" "$root/deploy/check-version.sh"
  printf '1.2.3\n' >"$root/VERSION"
  printf '# Changelog\n\n## [1.2.3] - 2026-01-01\n\n- test\n' >"$root/CHANGELOG.md"
  printf 'package version\n\nvar (\n\tVersion = "1.2.3"\n\tCommit  = "dev"\n)\n' >"$root/internal/version/version.go"
  unset GITHUB_REF_TYPE GITHUB_REF_NAME
}

check() {
  ( cd "$root" && bash deploy/check-version.sh >/dev/null 2>&1 )
}

seed
if ! check; then
  echo "a consistent tree failed the release check" >&2
  exit 1
fi

set_version() { printf '1.2.4\n' >"$root/VERSION"; }
set_bad_version() { printf '1.2\n' >"$root/VERSION"; }
set_changelog() { printf '## [1.2.2] - 2026-01-01\n' >"$root/CHANGELOG.md"; }
set_default() { printf 'package version\n\nvar (\n\tVersion = "1.2.2"\n)\n' >"$root/internal/version/version.go"; }
set_tag() { export GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.2.4; }

expect_fail() {
  local name=$1 mutate=$2
  seed
  "$mutate"
  if check; then
    echo "${name} did not fail the release check" >&2
    exit 1
  fi
}

expect_fail "VERSION outside MAJOR.MINOR.PATCH" set_bad_version
expect_fail "a VERSION that disagrees with CHANGELOG.md" set_version
expect_fail "a CHANGELOG.md section that disagrees with VERSION" set_changelog
expect_fail "a stale internal/version/version.go default" set_default
expect_fail "a release tag that disagrees with VERSION" set_tag

seed
export GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.2.3
if ! check; then
  echo "a matching tag failed the release check" >&2
  exit 1
fi

echo "release check rejects every mismatch"
