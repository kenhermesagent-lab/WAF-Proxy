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
  mkdir -p "$root/deploy" "$root/internal/version" "$root/web"
  cp "$src/check-version.sh" "$root/deploy/check-version.sh"
  printf '1.2.3\n' >"$root/VERSION"
  printf '# Copy to deploy/.env and adjust\nVERSION=1.2.3\nTZ=UTC\n' >"$root/.env.example"
  printf '#!/usr/bin/env bash\nversion=$(cat VERSION)\n' >"$root/deploy/install.sh"
  printf '# Changelog\n\n## [1.2.3] - 2026-01-01\n\n- test\n' >"$root/CHANGELOG.md"
  printf 'package version\n\nvar (\n\tVersion = "1.2.3"\n\tCommit  = "dev"\n)\n' >"$root/internal/version/version.go"
  printf '| Version | Supported |\n|---|---|\n| 1.2.x | Yes |\n| 1.1.x and older | No |\n' >"$root/SECURITY.md"
  printf '{\n  "name": "ui",\n  "version": "1.2.3"\n}\n' >"$root/web/package.json"
  printf '{\n  "name": "ui",\n  "version": "1.2.3",\n  "packages": {\n    "": {\n      "name": "ui",\n      "version": "1.2.3"\n    }\n  }\n}\n' >"$root/web/package-lock.json"
  printf 'services:\n  wafproxy:\n    build:\n      args:\n        VERSION: ${VERSION:-1.2.3}\n    image: wafproxy:${VERSION:-1.2.3}\n' >"$root/deploy/docker-compose.yml"
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

# An `Unreleased` heading is not a release, so the version below it is the one
# that has to agree with VERSION.
unreleased_top() {
  printf '# Changelog\n\n## [Unreleased]\n\n- next\n\n## [1.2.3] - 2026-01-01\n\n- test\n' >"$root/CHANGELOG.md"
}
unreleased_over_stale() {
  printf '# Changelog\n\n## [Unreleased]\n\n- next\n\n## [1.2.2] - 2026-01-01\n\n- test\n' >"$root/CHANGELOG.md"
}
seed
unreleased_top
if ! check; then
  echo "an Unreleased heading failed the release check" >&2
  exit 1
fi
seed
unreleased_over_stale
if check; then
  echo "a stale section under Unreleased passed the release check" >&2
  exit 1
fi

set_version() { printf '1.2.4\n' >"$root/VERSION"; }
set_bad_version() { printf '1.2\n' >"$root/VERSION"; }
set_changelog() { printf '## [1.2.2] - 2026-01-01\n' >"$root/CHANGELOG.md"; }
set_default() { printf 'package version\n\nvar (\n\tVersion = "1.2.2"\n)\n' >"$root/internal/version/version.go"; }
set_tag() { export GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.2.4; }
set_security() { sed -i 's/| 1.2.x | Yes |/| 1.1.x | Yes |/' "$root/SECURITY.md"; }
set_npm() { sed -i 's/"version": "1.2.3"/"version": "1.2.2"/' "$root/web/package.json"; }
set_lock() { sed -i 's/"version": "1.2.3"/"version": "1.2.2"/g' "$root/web/package-lock.json"; }
set_compose() { sed -i 's/VERSION:-1.2.3/VERSION:-1.2.2/' "$root/deploy/docker-compose.yml"; }
set_env_example() { sed -i 's/^VERSION=.*/VERSION=1.2.2/' "$root/.env.example"; }
set_installer_literal() { printf '#!/usr/bin/env bash\nVERSION=1.20.0\n' >"$root/deploy/install.sh"; }

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
expect_fail "a SECURITY.md supported version that disagrees with VERSION" set_security
expect_fail "a web/package.json version that disagrees with VERSION" set_npm
expect_fail "a web/package-lock.json version that disagrees with VERSION" set_lock
expect_fail "a Compose default that disagrees with VERSION" set_compose
expect_fail ".env.example VERSION that disagrees with VERSION" set_env_example
expect_fail "a deploy script that hardcodes a version" set_installer_literal
expect_fail "a release tag that disagrees with VERSION" set_tag

seed
export GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.2.3
if ! check; then
  echo "a matching tag failed the release check" >&2
  exit 1
fi

echo "release check rejects every mismatch"
