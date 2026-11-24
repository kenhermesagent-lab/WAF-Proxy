#!/usr/bin/env bash
# Fails when a CHANGELOG.md release section has no matching annotated vX.Y.Z tag.
#
# The rule starts at 1.61.0. The sections below it shipped before the convention
# was enforced and were never tagged, so checking them would report history
# forever instead of a mistake. Local mode (the default) reads the tags in this
# clone and proves each one sits on the commit that carries its section; a
# checkout does not fetch tags, so CI asks origin with --remote instead.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
floor=1.61.0
mode=local
remote=origin

while [[ $# -gt 0 ]]; do
  case $1 in
    --remote) mode=remote ;;
    --remote=*) mode=remote; remote=${1#--remote=} ;;
    *)
      echo "usage: $0 [--remote[=REMOTE]]" >&2
      exit 2
      ;;
  esac
  shift
done

[[ $(printf '%s\n1.0.0\n' "$floor" | sort -V | head -1) == 1.0.0 ]] || {
  echo "floor '$floor' is not a version" >&2
  exit 2
}

# Every section at or above the floor; older ones predate the rule.
versions=()
while IFS= read -r v; do
  if [[ $(printf '%s\n%s\n' "$floor" "$v" | sort -V | head -1) == "$floor" ]]; then
    versions+=("$v")
  fi
done < <(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$root/CHANGELOG.md" |
  sed -E 's/^## \[([0-9.]+)\]$/\1/')

if [[ ${#versions[@]} -eq 0 ]]; then
  echo "CHANGELOG.md has no section at or above $floor" >&2
  exit 1
fi

fail() {
  local version=$1 problem=$2 fix=$3
  echo "${version}: ${problem}" >&2
  echo "  fix: ${fix}" >&2
  exit 1
}

if [[ $mode == local ]]; then
  if ! git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
    echo "not a git checkout: use --remote to check the tags origin holds" >&2
    exit 2
  fi
  for v in "${versions[@]}"; do
    tag="v$v"
    if ! git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
      fail "$v" "CHANGELOG.md has a section but there is no $tag tag" \
        "git tag -a $tag <release commit> -m \"Release $v\""
    fi
    if [[ $(git -C "$root" cat-file -t "refs/tags/$tag") != tag ]]; then
      fail "$v" "$tag is lightweight, not annotated" \
        "git tag -d $tag && git tag -a $tag <release commit> -m \"Release $v\""
    fi
    commit=$(git -C "$root" rev-parse "refs/tags/$tag^{}")
    # grep without -q: it has to read the whole body, or it closes the pipe
    # early and pipefail reports git show's SIGPIPE as a missing section.
    if ! git -C "$root" show "${commit}:CHANGELOG.md" 2>/dev/null | grep -E "^## \[$v\]" >/dev/null; then
      fail "$v" "$tag points at ${commit:0:7}, which does not carry the $v section" \
        "move the tag to the commit that cut $v: git tag -f -a $tag <commit> -m \"Release $v\""
    fi
    if ! git -C "$root" merge-base --is-ancestor "$commit" HEAD; then
      fail "$v" "$tag is not an ancestor of HEAD" \
        "check out the branch that carries the release, or fetch the tag's commit"
    fi
  done
  echo "release tags match the CHANGELOG.md sections from $floor (${#versions[@]} releases)"
else
  if ! listing=$(git -C "$root" ls-remote --tags "$remote" 2>/dev/null); then
    echo "cannot list the tags on '${remote}'" >&2
    exit 2
  fi
  for v in "${versions[@]}"; do
    if ! grep -qE "refs/tags/v$v$" <<<"$listing"; then
      fail "$v" "CHANGELOG.md has a section but ${remote} has no v$v tag" \
        "git push $remote v$v"
    fi
    # An annotated tag lists the ref and its ^{} peel; a lightweight one only
    # lists the commit it happens to point at.
    if ! grep -qE "refs/tags/v$v\^\{\}$" <<<"$listing"; then
      fail "$v" "v$v on ${remote} is lightweight, not annotated" \
        "git tag -d v$v && git tag -a v$v <release commit> -m \"Release $v\" && git push $remote v$v"
    fi
  done
  echo "release tags on ${remote} match the CHANGELOG.md sections from $floor (${#versions[@]} releases)"
fi
