#!/usr/bin/env bash
# Keeps docs/OPERATIONS.md in step with deploy/check-tags.sh: every rejection the
# check can print has to be described in the runbook, so a new rule cannot land
# undocumented the way the stray-tag and out-of-order rules did.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
script=$root/deploy/check-tags.sh
runbook=$root/docs/OPERATIONS.md

# Each row is: kind | phrase the check prints | phrase the runbook uses for it.
# `guard` rows are defensive read failures rather than release rules, so they
# only have to be recognised here, not explained in the runbook.
table=(
  'rule|names a version CHANGELOG.md does not ship|does not date'
  'rule|so the release went out of order|newer than the newest release'
  'rule|has a section but|has no annotated tag'
  'rule|is lightweight, not annotated|lightweight'
  'rule|which does not carry the .* section|does not carry that section'
  'rule|cannot read VERSION|`VERSION` at that commit is missing'
  'rule|whose VERSION is|not the version the tag names'
  'rule|is not an ancestor of HEAD|not reachable from the branch you are on'
  'rule|which is not on main|not on `main`'
)

if [[ ! -f $script || ! -f $runbook ]]; then
  echo "expected deploy/check-tags.sh and docs/OPERATIONS.md under ${root}" >&2
  exit 2
fi

mapfile -t messages < <(sed -n 's/^[[:space:]]*fail "\$v" "\([^"]*\)".*/\1/p' "$script")
if [[ ${#messages[@]} -eq 0 ]]; then
  echo "found no failure messages in deploy/check-tags.sh: has its shape changed?" >&2
  exit 1
fi

for message in "${messages[@]}"; do
  phrase=""
  for row in "${table[@]}"; do
    IFS='|' read -r _ pattern candidate <<<"$row"
    if [[ $message =~ $pattern ]]; then
      phrase=$candidate
      break
    fi
  done
  if [[ -z $phrase ]]; then
    echo "check-tags.sh can reject with '${message}'" >&2
    echo "  add a row for it to the table in $(basename "${BASH_SOURCE[0]}") and say it in docs/OPERATIONS.md" >&2
    exit 1
  fi
done

for row in "${table[@]}"; do
  IFS='|' read -r kind pattern phrase <<<"$row"
  [[ $kind == rule ]] || continue
  if ! grep -qF "$phrase" "$runbook"; then
    echo "docs/OPERATIONS.md does not mention '${phrase}', which check-tags.sh enforces ('${pattern}')" >&2
    exit 1
  fi
done

echo "every failure in check-tags.sh is described in docs/OPERATIONS.md"
