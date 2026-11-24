#!/usr/bin/env bash
# Fails when a CHANGELOG.md release section has no matching annotated vX.Y.Z tag,
# or when VERSION at the tagged commit is not the version the tag names.
#
# The rule starts at 1.61.0. The sections below it shipped before the convention
# was enforced and were never tagged, so checking them would report history
# forever instead of a mistake. Local mode (the default) reads the tags in this
# clone and proves each one sits on the commit that carries its section; a
# checkout does not fetch tags, so CI asks origin with --remote instead. Both
# modes also prove the tagged commit is on main, because a tag on an unmerged
# branch is a release nobody receives; and every tag at or above the floor has
# to name a version this CHANGELOG dates and to have been cut before a newer
# one, so a stray v1.62.4 tag cannot hide on a commit that did reach main.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
floor=1.61.0
mode=local
remote=origin
branch=""
skip_on_main=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --remote) mode=remote ;;
    --remote=*) mode=remote; remote=${1#--remote=} ;;
    --branch) shift; branch=${1:-}; [[ -n $branch ]] || { echo "--branch needs a name" >&2; exit 2; } ;;
    --branch=*) branch=${1#--branch=}; [[ -n $branch ]] || { echo "--branch needs a name" >&2; exit 2; } ;;
    # release.sh runs this before it prints the push commands, so its own release
    # commit is not on main yet; the post-push --remote run is what proves that.
    --skip-on-main) skip_on_main=1 ;;
    *)
      echo "usage: $0 [--remote[=REMOTE]] [--branch NAME] [--skip-on-main]" >&2
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

# The main tip every release tag has to sit under. A shallow clone cannot prove
# ancestry, so say that instead of reporting a tag as unmerged.
if [[ $(git -C "$root" rev-parse --is-shallow-repository 2>/dev/null) == true ]]; then
  echo "this clone is shallow, so it cannot prove a tag is on main: run 'git fetch --unshallow origin' (CI: actions/checkout with fetch-depth: 0)" >&2
  exit 2
fi
main_sha=""
if [[ $mode == remote ]]; then
  main_sha=$(git -C "$root" ls-remote "$remote" refs/heads/main 2>/dev/null | cut -f1 || true)
  if [[ -z $main_sha ]]; then
    echo "cannot read main from '${remote}'" >&2
    exit 2
  fi
  if ! git -C "$root" cat-file -e "${main_sha}^{commit}" 2>/dev/null; then
    git -C "$root" fetch --quiet --no-tags "$remote" "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1 || true
  fi
  if ! git -C "$root" cat-file -e "${main_sha}^{commit}" 2>/dev/null; then
    echo "this clone does not have main's commit ${main_sha:0:7}: run 'git fetch origin main'" >&2
    exit 2
  fi
else
  # Refresh main from origin first: a stale main reports a tag that did land as
  # unmerged, which is the one verdict this rule must not get wrong.
  if git -C "$root" remote get-url origin >/dev/null 2>&1; then
    git -C "$root" fetch --quiet --no-tags origin "+refs/heads/main:refs/remotes/origin/main" >/dev/null 2>&1 ||
      echo "cannot refresh origin/main; comparing against the last fetched copy" >&2
    main_sha=$(git -C "$root" rev-parse -q --verify refs/remotes/origin/main 2>/dev/null || true)
  else
    main_sha=$(git -C "$root" rev-parse -q --verify refs/heads/main 2>/dev/null || true)
  fi
  if [[ -z $main_sha ]]; then
    echo "this clone has no main to compare against: skipped the on-main rule" >&2
  fi
fi

# With no main to compare against the rule cannot be answered here; CI's
# --remote run is the one that proves it.
on_main() { [[ -n $skip_on_main || -z $main_sha ]] || git -C "$root" merge-base --is-ancestor "$1" "$main_sha"; }

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

# Remote mode reads origin's tags once, here, because the tag list and the
# section rule below both need it.
if [[ $mode == remote ]]; then
  if ! listing=$(git -C "$root" ls-remote --tags "$remote" 2>/dev/null); then
    echo "cannot list the tags on '${remote}'" >&2
    exit 2
  fi
fi

# A tag names a release, so the tags themselves are checked: each one at or
# above the floor must name a version this CHANGELOG dates, and must have been
# cut before a newer tag did. A v1.62.4 tag made after 1.63.0 shipped is the
# second case, and its commit being on main does not make it a release.
# The date that decides order is the release commit's, not the tag's: re-cutting
# a tag that landed on the wrong commit moves only the tag date, and that is the
# fix this check itself recommends, so it must not read as a late release.
commit_time() {
  local tag=$1 commit
  if ! commit=$(git -C "$root" rev-parse -q --verify "refs/tags/$tag^{}" 2>/dev/null); then
    return 1
  fi
  if ! git -C "$root" cat-file -e "${commit}^{commit}" 2>/dev/null && [[ $mode == remote ]]; then
    git -C "$root" fetch --quiet --no-tags "$remote" "+refs/tags/${tag}:refs/tags/${tag}" >/dev/null 2>&1 || return 1
  fi
  git -C "$root" log -1 --format=%ct "$commit" 2>/dev/null
}

tagged=()
if [[ $mode == remote ]]; then
  while IFS= read -r v; do
    [[ -n $v ]] && tagged+=("$v")
  done < <(awk '$2 ~ /^refs\/tags\/v[0-9]+\.[0-9]+\.[0-9]+$/ { sub("refs/tags/v", "", $2); print $2 }' <<<"$listing")
else
  while IFS= read -r v; do
    [[ -n $v ]] && tagged+=("$v")
  done < <(git -C "$root" tag -l 'v[0-9]*' 2>/dev/null | sed -E 's/^v//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' || true)
fi

# Below the floor the convention did not exist yet, so v1.55.2 and v1.60.0 are
# history rather than strays.
kept=()
if [[ ${#tagged[@]} -gt 0 ]]; then
  for v in "${tagged[@]}"; do
    if [[ $(printf '%s\n%s\n' "$floor" "$v" | sort -V | head -1) == "$floor" ]]; then
      kept+=("$v")
    fi
  done
fi

if [[ ${#kept[@]} -gt 0 ]]; then
  shipped=" ${versions[*]} "
  for v in "${kept[@]}"; do
    if [[ $shipped != *" $v "* ]]; then
      fail "$v" "tag v$v names a version CHANGELOG.md does not ship" \
        "delete the stray tag, or date a $v section and cut it properly: git tag -d v$v"
    fi
  done

  newest=$(printf '%s\n' "${kept[@]}" | sort -V | tail -1)
  newest_time=$(commit_time "v$newest")
  while IFS= read -r v; do
    [[ -z $v || $v == "$newest" ]] && continue
    when=$(commit_time "v$v")
    # A release whose own commit is newer than the newest release was cut late,
    # whatever its tag date says. An older tag re-cut onto its original commit
    # keeps its old commit date, so it stays ordinary history.
    if [[ -n $when && -n $newest_time && $when -gt $newest_time ]]; then
      fail "$v" "v$v was cut after the newer v$newest shipped, so the release went out of order" \
        "delete it, and cut the version before a newer one ships: git tag -d v$v"
    fi
  done < <(printf '%s\n' "${kept[@]}")
fi

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
    if ! on_main "$commit"; then
      fail "$v" "$tag points at ${commit:0:7}, which is not on main" \
        "land the branch that carries $v first: a tag on an unmerged branch is a release nobody receives"
    fi
  done
  echo "release tags match the CHANGELOG.md sections from $floor (${#versions[@]} releases)"
else
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
    if ! on_main "$commit"; then
      fail "$v" "v$v on ${remote} points at ${commit:0:7}, which is not on main" \
        "land the branch that carries $v first: a tag on an unmerged branch is a release nobody receives"
    fi
  done
  echo "release tags on ${remote} match the CHANGELOG.md sections from $floor (${#versions[@]} releases)"
fi
