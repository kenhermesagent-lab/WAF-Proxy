#!/usr/bin/env bash
# Regression test for latest-tag.sh: the candidate moves :latest only when it is
# the highest published version, so an older tag dispatched later cannot move the
# tag backwards and a version whose image failed to push does not count.
set -euo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
helper="$src/latest-tag.sh"
worked=0

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# expect <exit-code> <candidate> <published-versions> <text that must appear>
expect() {
  local want=$1 candidate=$2 published=$3 needle=$4 out status=0
  out=$(printf '%s\n' "$published" | "$helper" "$candidate" 2>&1) || status=$?
  [[ $status == "$want" ]] || fail "candidate ${candidate} exited ${status}, wanted ${want}: ${out}"
  [[ $out == *"$needle"* ]] || fail "candidate ${candidate} printed '${out}', wanted '${needle}'"
  worked=$((worked + 1))
}

expect 0 1.65.8 "$(printf '1.65.6\nlatest\n1.65.8\n')" "1.65.8 is the highest published version"
expect 1 1.65.7 "$(printf '1.65.6\nlatest\n1.65.8\n')" "1.65.8 is)"
expect 0 1.65.10 "$(printf '1.65.9\n1.65.4\n')" "1.65.10 is the highest"
# The registry's own aliases and anything that is not a release are not versions.
expect 0 1.65.8 "$(printf 'latest\nsha-abc\n2026-11-24\n')" "no published version"
# A version that failed to push leaves no tag, so it cannot hold latest back.
expect 0 1.65.8 "$(printf '1.65.6\n')" "1.65.8 is the highest published version"
# Duplicates and a leading v are tolerated in the listing.
expect 0 1.65.8 "$(printf '1.65.8\nv1.65.8\n1.65.8\n')" "1.65.8 is the highest published version"

# An empty registry is a fresh namespace, not a reason to skip.
status=0
out=$("$helper" 1.65.8 </dev/null 2>&1) || status=$?
[[ $status == 0 && $out == *"no published version"* ]] || fail "empty listing did not move latest: ${out}"

# The helper must refuse to run without a candidate rather than defaulting one.
status=0
out=$("$helper" </dev/null 2>&1) || status=$?
[[ $status != 0 ]] || fail "a missing candidate was accepted"

echo "latest-tag.sh moves latest only to the highest published version (${worked} cases)"
