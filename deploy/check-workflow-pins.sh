#!/usr/bin/env bash
# Fails when a workflow uses an action by tag or branch: a moved ref runs code
# nobody reviewed, whoever signed the release. Only a full 40-character commit
# SHA passes, plus two refs that cannot move: a local ./action and a
# docker://image@sha256:<digest>.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
shopt -s nullglob
files=("$root"/.github/workflows/*.yml "$root"/.github/workflows/*.yaml)
if ((${#files[@]} == 0)); then
  echo "no workflow files under .github/workflows" >&2
  exit 1
fi

bad=0
for file in "${files[@]}"; do
  while IFS= read -r match; do
    line_no=${match%%:*}
    ref=${match#*:}
    ref=${ref#*uses:}
    ref=${ref%%#*}   # drop a trailing comment, such as "# v4.4.0"
    ref=${ref//\"/}
    ref=${ref//\'/}
    ref=$(printf '%s' "$ref" | xargs)

    case $ref in
      ./*) continue ;;
      docker://*)
        [[ $ref =~ @sha256:[0-9a-f]{64}$ ]] && continue
        ;;
      *)
        [[ $ref =~ ^[^@[:space:]]+@[0-9a-f]{40}$ ]] && continue
        ;;
    esac

    echo "${file#"$root"/}:${line_no}: uses '${ref}' instead of a full commit SHA" >&2
    bad=1
  done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' "$file" || true)
done

if ((bad)); then
  echo "pin every action to a 40-character commit SHA" >&2
  exit 1
fi

echo "every workflow action is pinned to a commit"
