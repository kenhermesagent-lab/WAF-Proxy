#!/usr/bin/env bash
# Dispatch release.yml from main once per release tag. GitHub runs the workflow
# file from the tagged commit, so a tag pushed before a job was added never runs
# that job: its release keeps generated notes and it never reaches the registry.
#
#   ./deploy/redispatch-tags.sh                  # every tag from 1.61.0 to VERSION
#   ./deploy/redispatch-tags.sh v1.64.0          # just that tag
#   ./deploy/redispatch-tags.sh --dry-run        # print the runs, do nothing
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage: ./deploy/redispatch-tags.sh [--dry-run] [vX.Y.Z ...]

With no tags, dispatches release.yml from main for every tag on origin from
1.61.0, the first release that ships a dated CHANGELOG.md section, up to VERSION.
EOF
}

# Below this the CHANGELOG convention did not exist, so there is no section for a
# dispatch to publish.
floor=1.61.0

dry_run=0
want=()
for arg in "$@"; do
  case $arg in
    --dry-run) dry_run=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    v[0-9]*)
      [[ $arg =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
        echo "'${arg}' is not a vX.Y.Z tag" >&2
        exit 2
      }
      want+=("$arg")
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is not installed; install the GitHub CLI and run it once to sign in" >&2
  exit 1
fi

# Tags come from origin: a tag that was never pushed has nothing to check out,
# and dispatching it would fail after costing a runner.
on_origin=$(git ls-remote --tags --refs origin 'v[0-9]*' | sed 's|.*refs/tags/v||' | sort -V)
if [[ -z $on_origin ]]; then
  echo "origin has no release tags; push the tags first" >&2
  exit 1
fi

newest=$(tr -d '[:space:]' < VERSION)
if ((${#want[@]} == 0)); then
  while IFS= read -r version; do
    [[ $(printf '%s\n%s\n' "$floor" "$version" | sort -V | head -1) == "$floor" ]] || continue
    [[ $(printf '%s\n%s\n' "$newest" "$version" | sort -V | head -1) == "$version" ]] || continue
    want+=("v$version")
  done <<<"$on_origin"
fi

if ((${#want[@]} == 0)); then
  echo "nothing to dispatch: origin has no tag between v${floor} and v${newest}" >&2
  exit 1
fi

for tag in "${want[@]}"; do
  if ! grep -qx -- "${tag#v}" <<<"$on_origin"; then
    echo "${tag} is not on origin; push the tag first" >&2
    exit 1
  fi
done

if ((dry_run)); then
  echo "would dispatch release.yml from main for: ${want[*]}"
  for tag in "${want[@]}"; do
    printf '  gh workflow run release.yml --ref main -f tag=%s\n' "$tag"
  done
  exit 0
fi

echo "dispatching release.yml from main for: ${want[*]}"
for tag in "${want[@]}"; do
  gh workflow run release.yml --ref main -f tag="$tag"
  echo "  dispatched ${tag}"
done

# Each run builds, signs and publishes on its own, so a backlog queues rather
# than racing: watch them by name instead of waiting here.
printf '\nwatch with: gh run list --workflow release.yml --limit %d\n' "${#want[@]}"
