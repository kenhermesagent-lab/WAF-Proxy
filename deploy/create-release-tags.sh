#!/usr/bin/env bash
# Cuts the annotated vX.Y.Z tags that CHANGELOG.md dates but origin lacks.
#
# A release tag has to name the commit that stamped VERSION to that version and
# does not carry the section, so the commit is found rather than guessed: the
# candidates are the commits that touched VERSION, and only those where VERSION
# reads back as the release and CHANGELOG.md already dates the section, on main,
# survive. The oldest one is the release commit; a later commit that repeats the
# version (a merge that kept it) is not the release.
#
# Nothing is created for a tag that is already on the remote, so a re-run only
# fills the gaps. A version with no such commit is an error, not a skip: the
# tag would name the wrong release or none.
set -euo pipefail

# The checkout to tag, whatever directory the script is called from: the test
# runs it against a throwaway repository the same way a runner runs it here.
root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "create-release-tags: run this from inside the repository checkout" >&2
  exit 1
}
floor=1.61.0
remote=origin
dry_run=0
requested=()

die() {
  echo "create-release-tags: $*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
usage: create-release-tags.sh [--remote NAME] [--dry-run] [VERSION...]

  --remote NAME   remote to create the tags on (default: origin)
  --dry-run       print what would be tagged without creating or pushing
  VERSION...      versions to tag (default: every dated CHANGELOG section)

A tag is only created where the commit's VERSION reads back as the release and
its CHANGELOG.md dates the section, so the remote tag gate can pass.
USAGE
}

while (($# > 0)); do
  case $1 in
    --remote)
      [[ $# -ge 2 ]] || die "--remote needs a name"
      remote=$2
      shift 2
      ;;
    --remote=*)
      remote=${1#--remote=}
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    -*)
      die "unknown option $1 (try --help)"
      ;;
    *)
      requested+=("$1")
      shift
      ;;
  esac
done

cd "$root"

# The versions the changelog dates, newest first, at or above the floor.
shipped=()
while IFS= read -r v; do
  shipped+=("$v")
done < <(sed -nE 's/^## \[([0-9]+\.[0-9]+\.[0-9]+)\] .*/\1/p' CHANGELOG.md |
  awk -v floor="$floor" '{ print }' | sort -rV |
  while IFS= read -r v; do
    if [[ $(printf '%s\n%s\n' "$floor" "$v" | sort -V | head -1) == "$floor" ]]; then
      printf '%s\n' "$v"
    fi
  done)

if ((${#shipped[@]} == 0)); then
  die "CHANGELOG.md dates no release at or above $floor"
fi

versions=("${requested[@]}")
if ((${#versions[@]} == 0)); then
  versions=("${shipped[@]}")
else
  for v in "${versions[@]}"; do
    [[ " ${shipped[*]} " == *" $v "* ]] || die "CHANGELOG.md has no dated $v section"
  done
fi

main=$(git ls-remote --heads "$remote" refs/heads/main | cut -f1)
[[ -n $main ]] || die "$remote has no main branch"
if ! git cat-file -e "${main}^{commit}" 2>/dev/null; then
  git fetch --quiet --no-tags "$remote" '+refs/heads/main:refs/remotes/'"$remote"'/main' ||
    die "cannot fetch main from $remote"
fi

listing=$(git ls-remote --tags "$remote")

# commit_for VERSION -> prints "<commit> <release time>" of the release commit.
commit_for() {
  local version=$1 best= best_time=
  local c v t
  while IFS= read -r c; do
    v=$(git show "${c}:VERSION" 2>/dev/null | tr -d '[:space:]')
    [[ $v == "$version" ]] || continue
    # grep without -q: it has to read the whole body, or it closes the pipe
    # early and pipefail reports git show's SIGPIPE as a missing section.
    git show "${c}:CHANGELOG.md" 2>/dev/null | grep -E "^## \[${version}\] " >/dev/null || continue
    git merge-base --is-ancestor "$c" "$main" 2>/dev/null || continue
    t=$(git log -1 --format=%ct "$c")
    if [[ -z $best_time || $t -lt $best_time ]]; then
      best=$c
      best_time=$t
    fi
  done < <(git log --all --format=%H -- VERSION)
  [[ -n $best ]] || return 1
  printf '%s %s\n' "$best" "$best_time"
}

created=0
for v in "${versions[@]}"; do
  if grep -qE "^[0-9a-f]+[[:space:]]+refs/tags/v${v}$" <<<"$listing"; then
    echo "v$v already on $remote"
    continue
  fi
  if ! read -r commit when < <(commit_for "$v"); then
    die "v$v: no commit on main carries the dated $v section with VERSION $v; nothing to tag"
  fi
  when=$(date -u -d "@$when" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "?")
  if ((dry_run)); then
    echo "would tag v$v at ${commit:0:12} ($when)"
    continue
  fi
  if git rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
    die "v$v exists locally at $(git rev-parse --short "v$v^{}") but not on $remote; \
delete it with: git tag -d v$v, then re-run"
  fi
  git tag -a "v$v" "$commit" -m "Release $v"
  git push --quiet "$remote" "refs/tags/v$v:refs/tags/v$v" ||
    die "v$v was tagged at ${commit:0:12} but $remote refused the push"
  echo "tagged v$v at ${commit:0:12} ($when) and pushed it to $remote"
  created=$((created + 1))
done

if ((dry_run)); then
  echo "dry run: $((${#versions[@]} - created)) version(s) checked, nothing pushed"
else
  echo "created $created tag(s) on $remote"
fi
