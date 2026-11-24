#!/usr/bin/env bash
# Regression test for check-tags.sh: a tagged release passes, and a missing,
# lightweight, misplaced or unpushed tag fails on its own. Sections below the
# 1.61.0 floor stay untagged and must not fail.
set -euo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/repo"

git_init() {
  git -C "$1" init -q -b main
  git -C "$1" config user.email release@example.com
  git -C "$1" config user.name "Release Test"
  git -C "$1" config commit.gpgsign false
  git -C "$1" config tag.gpgsign false
}

changelog() {
  local versions=("$@") out='# Changelog' v
  for v in "${versions[@]}"; do
    out+=$'\n\n'"## [$v] - 2026-01-01"$'\n\n'"- test"
  done
  printf '%s\n' "$out" >"$root/CHANGELOG.md"
}

commit() {
  git -C "$root" add -A
  git -C "$root" commit -qm "$1"
}

# The fixture: 1.60.1 shipped before the rule, 1.61.0 and 1.61.1 after it.
seed() {
  rm -rf "$root"
  mkdir -p "$root/deploy"
  cp "$src/check-tags.sh" "$root/deploy/check-tags.sh"
  git_init "$root"
  changelog 1.60.1
  commit "1.60.1"
  changelog 1.61.0 1.60.1
  commit "1.61.0"
  git -C "$root" tag -a v1.61.0 -m "Release 1.61.0"
  changelog 1.61.1 1.61.0 1.60.1
  commit "1.61.1"
  git -C "$root" tag -a v1.61.1 -m "Release 1.61.1"
}

check() { ( cd "$root" && bash deploy/check-tags.sh "$@" >/dev/null 2>&1 ); }

seed
if ! check; then
  echo "a tagged tree failed the tag check" >&2
  exit 1
fi


expect_fail() {
  local name=$1 mutate=$2
  shift 2
  seed
  "$mutate"
  if check "$@"; then
    echo "${name} did not fail the tag check" >&2
    exit 1
  fi
}

add_section() { changelog 1.61.2 1.61.1 1.61.0 1.60.1; commit "1.61.2"; }
light_tag() { add_section; git -C "$root" tag v1.61.2; }
annotated_tag() { add_section; git -C "$root" tag -a v1.61.2 -m "Release 1.61.2"; }
misplaced_tag() {
  add_section
  git -C "$root" tag -a v1.61.2 -m "Release 1.61.2" "$(git -C "$root" rev-list --max-parents=0 HEAD)"
}

expect_fail "a section with no tag" add_section
expect_fail "a lightweight tag" light_tag
expect_fail "a tag on a commit that does not carry the section" misplaced_tag

# A tag the clone has but origin does not is still a broken release.
seed
git init -q --bare "$work/origin.git"
git -C "$root" remote add origin "$work/origin.git"
git -C "$root" push -q origin main --follow-tags
if ! check --remote; then
  echo "a fully pushed tree failed the remote tag check" >&2
  exit 1
fi
annotated_tag
git -C "$root" push -q origin main
if check --remote; then
  echo "a tag that only exists locally passed the remote tag check" >&2
  exit 1
fi
if ! check; then
  echo "the local check failed for a tag that exists in the clone" >&2
  exit 1
fi
git -C "$root" tag -d v1.61.2 >/dev/null
git -C "$root" tag v1.61.2
git -C "$root" push -q origin "refs/tags/v1.61.2:refs/tags/v1.61.2"
if check --remote; then
  echo "a lightweight tag on origin passed the remote tag check" >&2
  exit 1
fi

echo "tag check rejects every missing, lightweight, misplaced or unpushed tag"
