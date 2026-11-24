#!/usr/bin/env bash
# Decides whether the :latest image tag should move to the version being released.
#
# Usage: latest-tag.sh <candidate-version>   (published versions on stdin)
#
# Reads the versions that actually have an image in the registry, one per line
# (the ":latest" tag and anything that is not MAJOR.MINOR.PATCH are ignored), and
# exits 0 when the candidate is the highest of them, 1 when it is not. A registry
# with no published version yet has nothing to compare against, so the candidate
# moves; and because the candidate is part of the comparison, the listing being
# a moment behind the push that just finished does not hide it.
#
# The candidate is compared against published images rather than tags on origin
# because a tag exists a whole image push before its image does: gating on tags
# made every release defer to the next tag while its push was in flight, so
# :latest fell behind and could freeze there if the newer release failed.
set -euo pipefail

candidate=${1:?usage: latest-tag.sh <candidate-version>}

published=$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' || true)

if [[ -z $published ]]; then
  echo "the registry lists no published version yet, so ${candidate} becomes latest"
  exit 0
fi

highest=$(
  { printf '%s\n' "$candidate"; printf '%s\n' "$published"; } | sort -Vu | tail -1
)

if [[ $candidate == "$highest" ]]; then
  echo "${candidate} is the highest published version"
  exit 0
fi

echo "${candidate} is not the highest published version (${highest} is), so latest stays where it is"
exit 1
