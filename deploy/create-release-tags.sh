#!/usr/bin/env bash
# Cuts the annotated vX.Y.Z tags that CHANGELOG.md dates but origin lacks.
#
# A release tag has to name a commit where VERSION reads as that version and
# CHANGELOG.md already dates its section, so the commit is found rather than
# guessed. The version still in VERSION is tagged at the newest such commit, so a
# release carries every fix and every note it ended up with; a version already
# succeeded takes the oldest, which is the commit that cut it. Using the newest
# commit for a succeeded version would pick a later merge that briefly stamped the
# old number again, and the tag would look cut after the release that followed it.
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

# One walk of main, newest first, records the first and the last qualifying commit
# of each version. Only VERSION is read per commit, so the whole history is cheap.
# A GitHub App token may not push a tag whose commit changed a workflow file, so
# the commits that did are recorded separately and only used when a release has
# no other commit to name.
touches_workflows() {
  git show --name-only --format='' "$1" 2>/dev/null | grep -q '^\.github/workflows/'
}

declare -A newest_commit=() newest_when=() oldest_commit=() oldest_when=()
declare -A newest_safe=() newest_safe_when=() oldest_safe=() oldest_safe_when=()
while IFS= read -r c; do
  # || true: a commit older than the file has no VERSION, and pipefail would
  # otherwise end the run on the first one.
  v=$(git show "${c}:VERSION" 2>/dev/null | tr -d '[:space:]' || true)
  [[ -n $v ]] || continue
  # grep without -q: it has to read the whole body, or it closes the pipe
  # early and pipefail reports git show's SIGPIPE as a missing section.
  git show "${c}:CHANGELOG.md" 2>/dev/null | grep -E "^## \[${v}\] " >/dev/null || continue
  t=$(git log -1 --format=%ct "$c")
  if [[ -z ${newest_commit[$v]:-} ]]; then
    newest_commit[$v]=$c
    newest_when[$v]=$t
  fi
  if ! touches_workflows "$c"; then
    if [[ -z ${newest_safe[$v]:-} ]]; then
      newest_safe[$v]=$c
      newest_safe_when[$v]=$t
    fi
    oldest_safe[$v]=$c
    oldest_safe_when[$v]=$t
  fi
  oldest_commit[$v]=$c
  oldest_when[$v]=$t
done < <(git rev-list "$main")

# push_tag TAG COMMIT -> puts the annotated tag on the remote.
#
# GITHUB_TOKEN is a GitHub App, and an App may not push a tag whose commit changed
# a file under .github/workflows: "refusing to allow a GitHub App to create or
# update workflow ... without `workflows` permission", even though that commit is
# already on main. A tag created through the API sends no commits at all, which is
# not the operation that rule guards, so the refusal falls back to it.
push_tag() {
  local tag=$1 commit=$2 out sha
  if out=$(git push --quiet "$remote" "refs/tags/${tag}:refs/tags/${tag}" 2>&1); then
    echo "tagged ${tag} at ${commit:0:12} and pushed it to ${remote}"
    return 0
  fi
  if [[ $out != *"without \`workflows\` permission"* ]]; then
    echo "${tag} was tagged at ${commit:0:12} but ${remote} refused the push:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  if [[ -z ${GITHUB_REPOSITORY:-} ]] || ! command -v gh >/dev/null; then
    echo "${tag}: ${remote} refused a tag whose commit changes a workflow file, and the API fallback needs GITHUB_REPOSITORY and gh" >&2
    return 1
  fi
  if ! sha=$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/tags" \
    -f tag="$tag" -f message="Release ${tag#v}" -f object="$commit" -f type=commit --jq .sha 2>/dev/null) ||
    [[ -z $sha ]]; then
    echo "${tag}: ${remote} refused the push and git/tags refused the tag object; the job needs a token with the workflow scope" >&2
    return 1
  fi
  if ! gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
    -f ref="refs/tags/${tag}" -f sha="$sha" >/dev/null 2>&1; then
    echo "${tag}: created the tag object ${sha:0:12} but git/refs refused the ref; the job needs a token with the workflow scope" >&2
    return 1
  fi
  echo "tagged ${tag} at ${commit:0:12} through the API (the push carries a workflow change an App may not push)"
}

created=0
failed=()
for v in "${versions[@]}"; do
  if grep -qE "^[0-9a-f]+[[:space:]]+refs/tags/v${v}$" <<<"$listing"; then
    echo "v$v already on $remote"
    continue
  fi
  if [[ -z ${oldest_commit[$v]:-} ]]; then
    die "v$v: no commit on main carries the dated $v section with VERSION $v; nothing to tag"
  fi
  if [[ $v == "${shipped[0]}" ]]; then
    commit=${newest_safe[$v]:-${newest_commit[$v]}}
    when=${newest_safe_when[$v]:-${newest_when[$v]}}
  else
    commit=${oldest_safe[$v]:-${oldest_commit[$v]}}
    when=${oldest_safe_when[$v]:-${oldest_when[$v]}}
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
  # One tag the remote refuses must not hide the ones after it.
  if ! push_tag "v$v" "$commit"; then
    git tag -d "v$v" >/dev/null
    failed+=("${v} (${commit:0:12}, $when)")
    continue
  fi
  created=$((created + 1))
done

if ((${#failed[@]} > 0)); then
  printf 'create-release-tags: %d tag(s) could not be created on %s:\n' "${#failed[@]}" "$remote" >&2
  printf '  v%s\n' "${failed[@]}" >&2
  exit 1
fi

if ((dry_run)); then
  echo "dry run: $((${#versions[@]} - created)) version(s) checked, nothing pushed"
else
  echo "created $created tag(s) on $remote"
fi
