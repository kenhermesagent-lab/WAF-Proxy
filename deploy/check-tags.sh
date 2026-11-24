#!/usr/bin/env bash
# Fails when a CHANGELOG.md release section has no matching annotated vX.Y.Z tag,
# when VERSION at the tagged commit is not the version the tag names, or when the
# tag's commit is not on main (a release nobody can pull).
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
branch=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --remote) mode=remote ;;
    --remote=*) mode=remote; remote=${1#--remote=} ;;
    --branch) shift; branch=${1:-}; [[ -n $branch ]] || { echo "--branch needs a name" >&2; exit 2; } ;;
    --branch=*) branch=${1#--branch=}; [[ -n $branch ]] || { echo "--branch needs a name" >&2; exit 2; } ;;
    *)
      echo "usage: $0 [--remote[=REMOTE]] [--branch NAME]" >&2
      exit 2
      ;;
  esac
  shift
done

[[ $(printf '%s\n1.0.0\n' "$floor" | sort -V | head -1) == 1.0.0 ]] || {
  echo "floor '$floor' is not a version" >&2
  exit 2
}

# Only main enforces the rule: a release branch adds its section before the tag
# can exist, so checking there would fail every release until it shipped.
if [[ -z $branch ]]; then
  case ${GITHUB_REF:-} in
    refs/heads/*) branch=${GITHUB_REF#refs/heads/} ;;
    refs/tags/*) branch=main ;; # a tagged commit is release history
    refs/*) branch=pull-request ;;
  esac
fi
if [[ -z $branch ]] && git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
  if ! branch=$(git -C "$root" symbolic-ref --quiet --short HEAD); then
    if git -C "$root" describe --tags --exact-match >/dev/null 2>&1; then
      branch=main
    else
      branch=detached
    fi
  fi
fi
if [[ $branch != main ]]; then
  echo "release tags are enforced on main; skipped on '${branch:-unknown}' (--branch main checks anyway)"
  exit 0
fi

# Every released section at or above the floor. Older ones predate the rule,
# and a `— unreleased` header is not a release yet, so only a dated header counts.
versions=()
while IFS= read -r v; do
  if [[ $(printf '%s\n%s\n' "$floor" "$v" | sort -V | head -1) == "$floor" ]]; then
    versions+=("$v")
  fi
done < <(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\][[:space:]]*[—\-][[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}' "$root/CHANGELOG.md" |
  sed -E 's/^## \[([0-9.]+)\].*/\1/')

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

# The tag names the release, so VERSION at its commit has to agree: a tag on a
# commit stamped with another version publishes misnumbered binaries. Remote
# mode lists tags without their commits, so it fetches the one tag it needs.
version_at() {
  local tag=$1 commit=$2 version
  if ! git -C "$root" cat-file -e "${commit}^{commit}" 2>/dev/null; then
    [[ $mode == remote ]] || return 1
    git -C "$root" fetch --quiet --no-tags "$remote" "+refs/tags/${tag}:refs/tags/${tag}" >/dev/null 2>&1 || return 1
  fi
  version=$(git -C "$root" show "${commit}:VERSION" 2>/dev/null | tr -d '[:space:]')
  [[ -n $version ]] || return 1
  printf '%s\n' "$version"
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
    if ! tagver=$(version_at "$tag" "$commit"); then
      fail "$v" "cannot read VERSION at ${commit:0:7}, where $tag points" \
        "tag the commit that stamped VERSION $v"
    fi
    if [[ $tagver != "$v" ]]; then
      fail "$v" "$tag points at ${commit:0:7}, whose VERSION is ${tagver}" \
        "tag the commit that stamped VERSION $v: git tag -f -a $tag <commit> -m \"Release $v\""
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
  if ! main_tip=$(git -C "$root" ls-remote "$remote" refs/heads/main 2>/dev/null | cut -f1); then
    echo "cannot read main from '${remote}'" >&2
    exit 2
  fi
  if [[ -z $main_tip ]]; then
    echo "'${remote}' has no main branch to compare the tags against" >&2
    exit 2
  fi
  # A tag on a commit main never took is a release nobody can pull, so the check
  # proves reachability. merge-base needs connected history, which a CI checkout
  # of one commit does not have, so deepen once rather than answer from a graft.
  if [[ $(git -C "$root" rev-parse --is-shallow-repository) == true ]]; then
    if ! git -C "$root" fetch --quiet --unshallow "$remote" >/dev/null 2>&1; then
      echo "cannot deepen this shallow clone to prove each tag is on ${remote}/main" >&2
      exit 2
    fi
  fi
  if ! git -C "$root" cat-file -e "${main_tip}^{commit}" 2>/dev/null; then
    git -C "$root" fetch --quiet --no-tags "$remote" "+refs/heads/main:refs/remotes/${remote}/main" >/dev/null 2>&1 || true
  fi
  if ! git -C "$root" cat-file -e "${main_tip}^{commit}" 2>/dev/null; then
    echo "cannot read ${remote}/main (${main_tip:0:7}) in this clone" >&2
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
    commit=$(awk -v want="refs/tags/v$v^{}" '$2 == want { print $1 }' <<<"$listing")
    if ! tagver=$(version_at "v$v" "$commit"); then
      fail "$v" "cannot read VERSION at ${commit:0:7} on ${remote}, where v$v points" \
        "tag the commit that stamped VERSION $v"
    fi
    if [[ $tagver != "$v" ]]; then
      fail "$v" "v$v on ${remote} points at ${commit:0:7}, whose VERSION is ${tagver}" \
        "tag the commit that stamped VERSION $v"
    fi
    if ! git -C "$root" merge-base --is-ancestor "$commit" "$main_tip"; then
      fail "$v" "v$v on ${remote} points at ${commit:0:7}, which is not on ${remote}/main" \
        "merge that commit to main, or retag v$v on a commit main carries"
    fi
  done
  echo "release tags on ${remote} match the CHANGELOG.md sections from $floor (${#versions[@]} releases)"
fi
