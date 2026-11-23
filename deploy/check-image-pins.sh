#!/usr/bin/env bash
# Fails when the Dockerfile names a base image by tag without a digest: a moved
# tag changes what a reviewed build compiles against. `scratch` and a local
# stage name need no digest.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
file="$root/Dockerfile"
if [[ ! -f $file ]]; then
  echo "no Dockerfile at the repository root" >&2
  exit 1
fi

bad=0
while IFS= read -r match; do
  line_no=${match%%:*}
  base=${match#*:}
  base=${base%%#*} # drop a trailing tag comment, such as "# 3.21"
  base=${base#*FROM}
  base=$(printf '%s' "${base%% AS *}" | xargs)
  base=${base%% as *}

  # Drop build flags such as --platform=$BUILDPLATFORM.
  if [[ $base == --* ]]; then
    base=$(printf '%s' "$base" | cut -d' ' -f2-)
  fi

  case $base in
    "" | scratch) continue ;;
  esac
  # A digest must be the full sha256 (64 hex); a truncated one does not resolve.
  if [[ $base =~ @sha256:[0-9a-f]{64}$ ]]; then
    continue
  fi
  echo "Dockerfile:${line_no}: FROM ${base} is not pinned by digest" >&2
  bad=1
done < <(grep -nE '^[[:space:]]*FROM[[:space:]]' "$file" || true)

if ((bad)); then
  echo "pin every base image to a tag@sha256:<digest>" >&2
  exit 1
fi

echo "every base image is pinned by digest"
