#!/usr/bin/env bash
# Regression test for redispatch-tags.sh: the range it dispatches, that
# --dry-run touches nothing, and that a tag nobody pushed is refused.
set -euo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/repo"
stubs="$work/bin"

# The script reads VERSION from the checkout it sits in and the tags from origin,
# so the fixture supplies both: a tree for VERSION and a stub git for ls-remote.
seed() {
  rm -rf "$root" "$stubs"
  mkdir -p "$root/deploy" "$stubs"
  cp "$src/redispatch-tags.sh" "$root/deploy/redispatch-tags.sh"
  printf '1.65.0\n' >"$root/VERSION"
  # 1.60.0 is below the floor, 1.66.0 is above VERSION: neither may be dispatched.
  printf '1.60.0\n1.61.1\n1.61.0\n1.64.0\n1.66.0\n1.65.0\n' >"$work/origin-tags"

  cat >"$stubs/git" <<'SH'
#!/usr/bin/env bash
if [[ ${1:-} == ls-remote ]]; then
  while IFS= read -r version; do
    printf 'abc123\trefs/tags/v%s\n' "$version"
  done <"$REDISPATCH_TEST_TAGS"
  exit 0
fi
echo "unexpected git call: ${*}" >&2
exit 1
SH
  cat >"$stubs/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${*}" >>"$REDISPATCH_TEST_GH_LOG"
SH
  chmod +x "$stubs/git" "$stubs/gh"
  : >"$work/gh.log"
}

run() {
  ( cd "$root" && PATH="$stubs:$PATH" \
    REDISPATCH_TEST_TAGS="$work/origin-tags" \
    REDISPATCH_TEST_GH_LOG="$work/gh.log" \
    ./deploy/redispatch-tags.sh "$@" )
}

dispatched() {
  sed -n 's/.*-f tag=//p' "$work/gh.log" | sort -V | tr '\n' ' ' | sed 's/ $//'
}

fail() {
  echo "$1" >&2
  exit 1
}

seed
run >/dev/null
[[ $(dispatched) == "v1.61.0 v1.61.1 v1.64.0 v1.65.0" ]] ||
  fail "default range dispatched '$(dispatched)', expected 1.61.0 through VERSION 1.65.0 only"

# Every run has to name a workflow, a ref and one tag; a stray call would mean
# the loop ran twice for something.
[[ $(wc -l <"$work/gh.log") == 4 ]] || fail "a run per tag became $(wc -l <"$work/gh.log") gh calls"
while IFS= read -r call; do
  [[ $call == "workflow run release.yml --ref main -f tag=v"* ]] || fail "unexpected gh call: ${call}"
done <"$work/gh.log"

seed
run --dry-run >"$work/dry.out" 2>&1
[[ ! -s $work/gh.log ]] || fail "--dry-run called gh: $(tr '\n' ';' <"$work/gh.log")"
grep -q 'would dispatch release.yml from main for: v1.61.0 v1.61.1 v1.64.0 v1.65.0' "$work/dry.out" ||
  fail "--dry-run did not list the range it would dispatch"

seed
if run v1.99.0 >"$work/missing.out" 2>&1; then
  fail "a tag that is not on origin was dispatched"
fi
[[ ! -s $work/gh.log ]] || fail "an unpushed tag still reached gh"
grep -q 'v1.99.0 is not on origin' "$work/missing.out" || fail "the refusal did not say why"

seed
run v1.61.1 >/dev/null
[[ $(dispatched) == "v1.61.1" ]] || fail "a named tag dispatched '$(dispatched)'"

echo "redispatch dispatches one run per tag from 1.61.0 to VERSION, and refuses an unpushed tag"
