#!/usr/bin/env bash
# The updater's first step is a `git pull --ff-only` in a checkout that a build
# has already written to. This reproduces that checkout in a throwaway pair of
# repositories and proves the restore step in deploy/wafproxy-update-lib.sh is
# what lets the pull succeed: without it git refuses, with it the update lands.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=deploy/wafproxy-update-lib.sh
source "$root/deploy/wafproxy-update-lib.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

git -c init.defaultBranch=main init -q "$work/upstream"
git -C "$work/upstream" config user.email ci@example.invalid
git -C "$work/upstream" config user.name ci

# A checkout the way a host has one: the version file and the committed console
# bundle that the repository tracks.
mkdir -p "$work/upstream/internal/webui/dist/assets"
printf '1.16.1\n' >"$work/upstream/VERSION"
printf 'console v1\n' >"$work/upstream/internal/webui/dist/assets/index-old.js"
printf '<script src="/assets/index-old.js"></script>\n' >"$work/upstream/internal/webui/dist/index.html"
git -C "$work/upstream" add -A
git -C "$work/upstream" commit -qm "release 1.16.1"

git clone -q "$work/upstream" "$work/src"

# A new release: the bundle is rebuilt, so the old asset is gone and a new hash
# appears, which is what every console change does.
printf '1.17.2\n' >"$work/upstream/VERSION"
printf 'console v2\n' >"$work/upstream/internal/webui/dist/assets/index-new.js"
printf '<script src="/assets/index-new.js"></script>\n' >"$work/upstream/internal/webui/dist/index.html"
git -C "$work/upstream" rm -q internal/webui/dist/assets/index-old.js
git -C "$work/upstream" add -A
git -C "$work/upstream" commit -qm "release 1.17.2"

# Now dirty the checkout the way `npm run build` does: the tracked file changes
# and the freshly built asset sits there under its own name.
printf 'console built here\n' >"$work/src/internal/webui/dist/assets/index-old.js"
printf 'console v2\n' >"$work/src/internal/webui/dist/assets/index-new.js"
[ -n "$(git -C "$work/src" status --porcelain)" ] || fail "the build simulation left the checkout clean"

if git -C "$work/src" pull --ff-only origin main >/dev/null 2>&1; then
  fail "git pull succeeded on a built checkout; the test no longer reproduces the bug"
fi

restore_console_bundle "$work/src"

if ! git -C "$work/src" pull --ff-only origin main >/dev/null 2>&1; then
  git -C "$work/src" pull --ff-only origin main || true
  fail "git pull still refuses after the restore step"
fi
[ "$(cat "$work/src/VERSION")" = "1.17.2" ] || fail "the checkout is not on the new release"
[ -f "$work/src/internal/webui/dist/assets/index-new.js" ] || fail "the new bundle is missing after the pull"

# The same function runs again at the start of the next update, so it must be
# harmless against an already clean checkout.
restore_console_bundle "$work/src"
[ -z "$(git -C "$work/src" status --porcelain)" ] || fail "the restore step left changes behind"

echo "PASS: a built checkout blocks git pull, and the updater's restore lets it through"
