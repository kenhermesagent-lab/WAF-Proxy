#!/usr/bin/env bash
# Regression test for check-tags.sh: a tagged release passes, and a missing,
# lightweight, misplaced, unpushed or misnumbered tag fails on its own. Sections
# below the 1.61.0 floor stay untagged and must not fail.
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
  # The convention the check enforces: the newest section and VERSION agree.
  printf '%s\n' "${versions[0]}" >"$root/VERSION"
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

# CI exports GITHUB_REF, which would otherwise pick the branch for every
# fixture; the cases that care about it pass it explicitly.
check() { ( cd "$root" && env -u GITHUB_REF bash deploy/check-tags.sh "$@" >/dev/null 2>&1 ); }

seed
if ! check; then
  echo "a tagged tree failed the tag check" >&2
  exit 1
fi

# A release branch adds its section before the tag can exist, so the rule only
# runs on main; --branch main enforces it from anywhere.
seed
changelog 1.61.2 1.61.1 1.61.0 1.60.1
commit "1.61.2"
git -C "$root" checkout -q -b release/1.61.2
if ! check; then
  echo "a release branch failed the tag check before its tag can exist" >&2
  exit 1
fi
if check --branch main; then
  echo "--branch main did not enforce the rule" >&2
  exit 1
fi
if ! ( cd "$root" && GITHUB_REF=refs/pull/7/merge bash deploy/check-tags.sh >/dev/null 2>&1 ); then
  echo "a pull request failed the tag check" >&2
  exit 1
fi
if ( cd "$root" && GITHUB_REF=refs/heads/main bash deploy/check-tags.sh >/dev/null 2>&1 ); then
  echo "a main push passed with an untagged new section" >&2
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

# An `unreleased` header is a section without a release behind it, so it must
# not be required to have a tag; the dated sections around it still are.
seed
printf '# Changelog\n\n## [1.61.2] — unreleased\n\n- test\n\n## [1.61.1] - 2026-01-01\n\n- test\n\n## [1.61.0] - 2026-01-01\n\n- test\n\n## [1.60.1] - 2026-01-01\n\n- test\n' >"$root/CHANGELOG.md"
commit "1.61.2 unreleased"
if ! check --branch main; then
  echo "an unreleased section was required to have a tag" >&2
  exit 1
fi
# A dated header at the same version is a release and does need one.
printf '# Changelog\n\n## [1.61.2] — 2026-01-02\n\n- test\n\n## [1.61.1] - 2026-01-01\n\n- test\n\n## [1.61.0] - 2026-01-01\n\n- test\n' >"$root/CHANGELOG.md"
commit "1.61.2 released"
if check --branch main; then
  echo "a dated section without a tag passed the tag check" >&2
  exit 1
fi

mismatched_version() {
  add_section
  printf '1.99.0\n' >"$root/VERSION"
  commit "1.61.2 with another VERSION"
  git -C "$root" tag -a v1.61.2 -m "Release 1.61.2"
}

expect_fail "a section with no tag" add_section
expect_fail "a lightweight tag" light_tag
expect_fail "a tag on a commit that does not carry the section" misplaced_tag
expect_fail "a tag whose commit carries another VERSION" mismatched_version

# A tag for a version the CHANGELOG does not date is a stray release, even when
# its commit is on main — the v1.62.4 shape once its branch landed.
stray_tag() { add_section; git -C "$root" tag -a v1.61.5 -m "Release 1.61.5"; }
expect_fail "a tag for a version CHANGELOG.md does not ship" stray_tag

tag_dated() { GIT_COMMITTER_DATE="$2" git -C "$root" tag -a "v$1" -m "Release $1"; }

# Order is decided by the release commit's date, so the fixture pins commits
# rather than tags and does not race the clock: the older version's commit is
# either before or after the newer release's commit.
late_fixture() {
  local newer_commit=$1 older_commit=$2
  changelog 1.63.0 1.61.1 1.61.0 1.60.1
  GIT_COMMITTER_DATE="$newer_commit" commit "1.63.0"
  tag_dated 1.63.0 "$newer_commit"
  printf '# Changelog\n\n## [1.61.2] - 2026-01-02\n\n- test\n\n## [1.63.0] - 2026-01-01\n\n- test\n\n## [1.61.1] - 2026-01-01\n\n- test\n\n## [1.61.0] - 2026-01-01\n\n- test\n' >"$root/CHANGELOG.md"
  printf '1.61.2\n' >"$root/VERSION"
  GIT_COMMITTER_DATE="$older_commit" commit "1.61.2"
  tag_dated 1.61.2 "$older_commit"
}

seed
late_fixture "2030-01-01T00:00:00 +0000" "2031-01-01T00:00:00 +0000"
if check --branch main; then
  echo "a release cut after a newer one passed the tag check" >&2
  exit 1
fi
# Cut before the newer release, the same version is ordinary history.
seed
late_fixture "2030-01-01T00:00:00 +0000" "2029-01-01T00:00:00 +0000"
if ! check --branch main; then
  echo "releases cut in order failed the tag check" >&2
  exit 1
fi

# Re-cutting a tag onto the commit that really cut its version is the fix this
# check recommends, so a later tag date must not read as a late release.
seed
changelog 1.63.0 1.61.1 1.61.0 1.60.1
GIT_COMMITTER_DATE="2030-01-01T00:00:00 +0000" commit "1.63.0"
tag_dated 1.63.0 "2030-01-01T00:00:00 +0000"
GIT_COMMITTER_DATE="2031-06-01T00:00:00 +0000" git -C "$root" tag -f -a v1.61.1 -m "Release 1.61.1" "$(git -C "$root" rev-parse 'v1.61.1^{}')" >/dev/null
if ! check --branch main; then
  echo "re-cutting an older tag failed the tag check" >&2
  exit 1
fi
# A tag below the floor predates the rule and is history, not a stray.
seed
git -C "$root" tag -a v1.60.1 -m "Release 1.60.1"
if ! check --branch main; then
  echo "a tag below the floor failed the tag check" >&2
  exit 1
fi

# Both stray forms are caught on origin, not only in the clone.
seed
git init -q --bare "$work/origin3.git"
git -C "$root" remote add origin "$work/origin3.git"
git -C "$root" push -q origin main --follow-tags
git -C "$root" tag -a v1.61.5 -m "Release 1.61.5"
git -C "$root" push -q origin refs/tags/v1.61.5
if check --remote --branch main; then
  echo "a stray tag on origin passed the remote tag check" >&2
  exit 1
fi
seed
late_fixture "2030-01-01T00:00:00 +0000" "2031-01-01T00:00:00 +0000"
git init -q --bare "$work/origin4.git"
git -C "$root" remote add origin "$work/origin4.git"
git -C "$root" push -q origin main --follow-tags
if check --remote --branch main; then
  echo "an out-of-order tag on origin passed the remote tag check" >&2
  exit 1
fi

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

# A tag on a branch that never reached main is a release nobody receives, which
# is what a v1.62.4 tag pointed at.
seed
git init -q --bare "$work/origin2.git"
git -C "$root" remote add origin "$work/origin2.git"
git -C "$root" push -q origin main --follow-tags
git -C "$root" checkout -q -b release/1.61.2
changelog 1.61.2 1.61.1 1.61.0 1.60.1
commit "1.61.2"
git -C "$root" tag -a v1.61.2 -m "Release 1.61.2"
git -C "$root" push -q origin release/1.61.2 refs/tags/v1.61.2
if check --remote --branch main; then
  echo "a tag on an unmerged branch passed the remote tag check" >&2
  exit 1
fi
if check --branch main; then
  echo "a tag on an unmerged branch passed the local tag check" >&2
  exit 1
fi
# release.sh checks its own tag before it pushes, so it asks for the on-main rule
# to be left to the post-push --remote run.
if ! check --branch main --skip-on-main; then
  echo "the release script's pre-push check failed on the on-main rule" >&2
  exit 1
fi
# Once that branch lands, the same tag is a release people receive.
git -C "$root" checkout -q main
git -C "$root" merge -q --no-ff release/1.61.2 -m "land 1.61.2"
git -C "$root" push -q origin main
if ! check --remote --branch main; then
  echo "a tag on a branch merged into main failed the remote tag check" >&2
  exit 1
fi

# CI checks out main without tags, so the tag a push has just created exists only
# on origin. The order rule has to read it from there; before it did, the loop
# in ci.yml retried for two minutes and exited without printing a reason.
seed
git init -q --bare -b main "$work/origin6.git"
git -C "$root" remote add origin "$work/origin6.git"
git -C "$root" push -q origin main --follow-tags
git clone -q --no-tags "$work/origin6.git" "$work/ci-clone"
if ! ( cd "$work/ci-clone" && env -u GITHUB_REF bash deploy/check-tags.sh --remote --branch main >/dev/null 2>&1 ); then
  echo "a freshly pushed tag failed the remote check from a clone without tags" >&2
  exit 1
fi
# The same clone shape must still go red for a real backlog, or the fix would
# have traded the failure for a blind pass.
changelog 1.61.2 1.61.1 1.61.0 1.60.1
commit "1.61.2"
git -C "$root" push -q origin main
git clone -q --no-tags "$work/origin6.git" "$work/ci-clone-backlog"
if ( cd "$work/ci-clone-backlog" && env -u GITHUB_REF bash deploy/check-tags.sh --remote --branch main >/dev/null 2>&1 ); then
  echo "an untagged section passed the remote check from a clone without tags" >&2
  exit 1
fi

echo "tag check rejects every missing, lightweight, misplaced, unpushed, misnumbered or unmerged tag"
