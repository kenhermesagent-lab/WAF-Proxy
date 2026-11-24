#!/usr/bin/env bash
# Exercises create-release-tags.sh against a throwaway repository, so the tag it
# picks and the push it makes are real git operations rather than a rehearsal.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

git init -q --bare "$tmp/origin.git"
git init -q -b main "$tmp/work"
cd "$tmp/work"
git config user.email test@example.com
git config user.name Test
git remote add origin "$tmp/origin.git"

release() { # release VERSION -> a commit that stamps VERSION and dates the section
  local v=$1
  printf '%s\n' "$v" >VERSION
  {
    printf '## [%s] — 2026-01-01\n\n- thing\n\n' "$v"
    [[ -f CHANGELOG.md ]] && cat CHANGELOG.md
  } >CHANGELOG.tmp
  mv CHANGELOG.tmp CHANGELOG.md
  git add VERSION CHANGELOG.md
  GIT_COMMITTER_DATE="2026-01-0$((++n))T00:00:00" git commit -q -m "Release $v"
}

n=0
release 1.61.0
release 1.61.1
git push -q origin main

script="$root/deploy/create-release-tags.sh"

# A dry run says what it would do and leaves the remote untouched.
out=$(bash "$script" --remote origin --dry-run)
grep -q "would tag v1.61.0" <<<"$out" || fail "dry run did not name v1.61.0: $out"
grep -q "would tag v1.61.1" <<<"$out" || fail "dry run did not name v1.61.1: $out"
[[ -z $(git ls-remote --tags origin) ]] || fail "the dry run pushed a tag"

# A real run creates annotated tags on the release commits.
out=$(bash "$script" --remote origin)
grep -q "tagged v1.61.0" <<<"$out" || fail "v1.61.0 was not created: $out"
[[ $(git cat-file -t v1.61.0) == tag ]] || fail "v1.61.0 is not annotated"
for v in 1.61.0 1.61.1; do
  remote_commit=$(git ls-remote --tags origin "refs/tags/v$v^{}" | cut -f1)
  [[ $remote_commit == "$(git rev-parse "v$v^{}")" ]] ||
    fail "v$v points at $remote_commit on origin, not the release commit"
  [[ $(git show "v$v^{}:VERSION") == "$v" ]] || fail "v$v does not carry VERSION $v"
done

# A re-run finds the tags present and creates nothing.
out=$(bash "$script" --remote origin)
grep -q "v1.61.0 already on origin" <<<"$out" || fail "a re-run did not skip v1.61.0: $out"
grep -q "created 0 tag(s)" <<<"$out" || fail "a re-run created a tag: $out"

# A version whose section was dated while VERSION stayed behind is an error, not
# a tag on some commit that happens to be nearby.
git tag -d v1.61.1 >/dev/null
git push -q origin :refs/tags/v1.61.1
{
  printf '## [1.99.0] — 2026-01-09\n\n- thing\n\n'
  cat CHANGELOG.md
} >c.tmp && mv c.tmp CHANGELOG.md
git add CHANGELOG.md
git commit -q -m "Date a section without stamping it"
git push -q origin main
if out=$(bash "$script" --remote origin 1.99.0 2>&1); then
  fail "tagged a version no commit stamps: $out"
fi
grep -q "no commit on main carries the dated 1.99.0 section" <<<"$out" ||
  fail "the refusal did not explain itself: $out"
[[ -z $(git ls-remote --tags origin "refs/tags/v1.99.0") ]] || fail "v1.99.0 was pushed"

echo "create-release-tags_test: ok"
