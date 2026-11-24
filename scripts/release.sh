#!/usr/bin/env bash
# Release helper: validates the tree, stamps VERSION, builds, commits the bump
# and cuts the annotated tag. It never pushes; that stays a deliberate step.
set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 X.Y.Z" >&2
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "refusing: working tree is dirty; commit the release section and its metadata first" >&2
  exit 1
fi

if git rev-parse "v$version" >/dev/null 2>&1; then
  echo "refusing: tag v$version already exists" >&2
  exit 1
fi

# A version below the newest tag ships history out of order and leaves a gap for
# the tag check to chase, which is how 1.61.x went out untagged.
latest=$(git tag -l 'v[0-9]*' --sort=-v:refname | head -1)
if [[ -n $latest ]] && [[ $(printf '%s\n%s\n' "${latest#v}" "$version" | sort -V | tail -1) != "$version" ]]; then
  echo "refusing: $latest is the newest tag; a release has to be newer than it" >&2
  exit 1
fi

if ! grep -q "^## \[$version\]" CHANGELOG.md; then
  echo "refusing: CHANGELOG.md has no section for $version" >&2
  exit 1
fi

echo "$version" > VERSION
make ui build

# The tag has to sit on the commit that carries the section and the new VERSION,
# so the bump is committed here rather than left behind. `git add -A` rather
# than `-am` because a console build can emit new hashed assets.
if [[ -n "$(git status --porcelain)" ]]; then
  git add -A
  git commit -m "release: $version"
fi

docker build -t "wafproxy:$version" \
  --build-arg VERSION="$version" \
  --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" .

git tag -a "v$version" -m "Release $version"

# A release that leaves this false is the mistake the tag rule exists to catch.
if ! bash deploy/check-tags.sh --branch main; then
  git tag -d "v$version"
  echo "refusing: the tag check failed, so v$version was removed again; the release commit stays at HEAD" >&2
  echo "if this clone is missing release history, run 'git fetch --tags origin' and retry" >&2
  exit 1
fi

cat <<EOF
Built wafproxy:$version and tagged v$version
Next:
  git push origin HEAD:main --follow-tags
  bash deploy/check-tags.sh --remote --branch main   # the tag is on origin, not just here
  docker tag wafproxy:$version ghcr.io/<owner>/wafproxy:latest && docker push ...
EOF
