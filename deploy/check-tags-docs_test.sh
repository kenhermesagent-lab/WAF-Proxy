#!/usr/bin/env bash
# Keeps docs/OPERATIONS.md in step with the release tooling: every refusal that
# deploy/check-tags.sh or scripts/release.sh can print has to be described in the
# runbook, so a rule cannot land undocumented the way the stray-tag and
# out-of-order rules did.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runbook=$root/docs/OPERATIONS.md
tags=$root/deploy/check-tags.sh
release=$root/scripts/release.sh

# Each row is: kind | source | phrase the tool prints | phrase the runbook uses.
# `guard` rows are bad invocations rather than release rules, so they only have
# to be recognised here, not explained in the runbook.
table=(
  'rule|tags|names a version CHANGELOG.md does not ship|does not date'
  'rule|tags|so the release went out of order|newer than the newest release'
  'rule|tags|has a section but|has no annotated tag'
  'rule|tags|is lightweight, not annotated|lightweight'
  'rule|tags|which does not carry the .* section|does not carry that section'
  'rule|tags|cannot read VERSION|`VERSION` at that commit is missing'
  'rule|tags|whose VERSION is|not the version the tag names'
  'rule|tags|is not an ancestor of HEAD|not reachable from the branch you are on'
  'rule|tags|which is not on main|not on `main`'
  'rule|release|working tree is dirty|working tree with uncommitted changes'
  'rule|release|already exists|tag that already exists'
  'rule|release|newest tag; a release has to be newer|older than the newest tag'
  'rule|release|has no section for|no `CHANGELOG.md` section'
  'rule|release|the tag check failed|removes its own tag again when the check fails'
  'guard|release|usage:|'
)

for file in "$runbook" "$tags" "$release"; do
  [[ -f $file ]] || { echo "expected ${file} to exist" >&2; exit 2; }
done

messages_of() {
  case $1 in
    tags) sed -n 's/^[[:space:]]*fail "\$v" "\([^"]*\)".*/\1/p' "$tags" ;;
    release) sed -nE 's/^[[:space:]]*echo "(refusing: [^"]*|usage: [^"]*)" >&2.*/\1/p' "$release" ;;
    *) echo "unknown source $1" >&2 ; exit 2 ;;
  esac
}

# Line wrapping must not decide whether a sentence is present.
runbook_text=$(tr '\n' ' ' <"$runbook" | tr -s ' ')

for source in tags release; do
  mapfile -t messages < <(messages_of "$source")
  if [[ ${#messages[@]} -eq 0 ]]; then
    echo "found no messages in ${source}: has its shape changed?" >&2
    exit 1
  fi
  for message in "${messages[@]}"; do
    matched=""
    for row in "${table[@]}"; do
      IFS='|' read -r _ row_source pattern candidate <<<"$row"
      [[ $row_source == "$source" ]] || continue
      if [[ $message =~ $pattern ]]; then
        matched=1
        break
      fi
    done
    if [[ -z $matched ]]; then
      echo "${source} can refuse with '${message}'" >&2
      echo "  add a row for it to the table in $(basename "${BASH_SOURCE[0]}") and say it in docs/OPERATIONS.md" >&2
      exit 1
    fi
  done
done

for row in "${table[@]}"; do
  IFS='|' read -r kind _ pattern phrase <<<"$row"
  [[ $kind == rule ]] || continue
  if [[ $runbook_text != *"$phrase"* ]]; then
    echo "docs/OPERATIONS.md does not mention '${phrase}', which the release tooling enforces ('${pattern}')" >&2
    exit 1
  fi
done

echo "every refusal in check-tags.sh and release.sh is described in docs/OPERATIONS.md"
