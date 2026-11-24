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

# A commit older than VERSION must not end the walk.
printf '# test\n' >README.md
git add README.md
git commit -q -m "Start"

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

# The version being cut is tagged at the newest commit that carries it, so the
# release ships the fixes and the notes added after the first stamp instead of
# the draft that stamped VERSION.
python3 - <<'PY'
p = 'CHANGELOG.md'
s = open(p).read()
s = s.replace('## [1.61.1] \u2014 2026-01-01\n', '## [1.61.1] \u2014 2026-01-01\n\n- a later fix\n', 1)
open(p, 'w').write(s)
PY
git commit -q -am "Add a later fix to the 1.61.1 notes"
git push -q origin main
git tag -d v1.61.1 >/dev/null
git push -q origin :refs/tags/v1.61.1
out=$(bash "$script" --remote origin --dry-run)
grep -q "would tag v1.61.1 at $(git rev-parse --short=12 HEAD)" <<<"$out" ||
  fail "v1.61.1 was not tagged at the newest commit that carries it: $out"

# A version whose section was dated while VERSION stayed behind is an error, not
# a tag on some commit that happens to be nearby.
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

# A tag whose commit changed a workflow file is refused by a GitHub App token.
# The script creates that tag through the API instead, which sends no commits.
git tag -d v1.61.0 >/dev/null
git push -q origin :refs/tags/v1.61.0
cat >"$tmp/origin.git/hooks/pre-receive" <<'HOOK'
#!/usr/bin/env bash
while read -r _ _ ref; do
  if [[ $ref == refs/tags/v1.61.0 ]]; then
    echo 'remote: error: refusing to allow a GitHub App to create or update workflow `.github/workflows/ci.yml` without `workflows` permission' >&2
    exit 1
  fi
done
HOOK
chmod +x "$tmp/origin.git/hooks/pre-receive"
GIT_DIR=$tmp/origin.git git config user.email test@example.com
GIT_DIR=$tmp/origin.git git config user.name Test
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
path= tag= obj=
for a in "$@"; do
  case $a in
    repos/*) path=$a ;;
    tag=*) tag=${a#tag=} ;;
    object=*) obj=${a#object=} ;;
  esac
done
case $path in
  */git/tags)
    GIT_DIR=$ORIGIN git tag -f -a "$tag" "$obj" -m "Release ${tag#v}" >/dev/null
    GIT_DIR=$ORIGIN git rev-parse "$tag"
    ;;
esac
GH
chmod +x "$tmp/bin/gh"
export GH_LOG="$tmp/gh.log" ORIGIN="$tmp/origin.git" GITHUB_REPOSITORY=test/repo
out=$(PATH="$tmp/bin:$PATH" bash "$script" --remote origin 1.61.0)
grep -q "through the API" <<<"$out" || fail "the refusal did not fall back to the API: $out"
[[ $(GIT_DIR=$tmp/origin.git git cat-file -t v1.61.0 2>/dev/null) == tag ]] ||
  fail "the fallback did not leave an annotated tag on origin"
grep -q "git/tags" "$GH_LOG" || fail "the fallback never called git/tags"
rm -f "$tmp/origin.git/hooks/pre-receive"

echo "create-release-tags_test: ok"
