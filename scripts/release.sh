#!/usr/bin/env bash
# Release helper: validates the tree, stamps VERSION and CHANGELOG, and builds.
# It never commits, tags or pushes; those remain deliberate manual steps.
set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 X.Y.Z" >&2
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "refusing: working tree is dirty" >&2
  exit 1
fi

if git rev-parse "v$version" >/dev/null 2>&1; then
  echo "refusing: tag v$version already exists" >&2
  exit 1
fi

if ! grep -q "^## \[$version\]" CHANGELOG.md; then
  echo "refusing: CHANGELOG.md has no section for $version" >&2
  exit 1
fi

echo "$version" > VERSION
make ui build
docker build -t "wafproxy:$version" \
  --build-arg VERSION="$version" \
  --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" .

cat <<EOF
Built wafproxy:$version
Next:
  git commit -am "release: $version"
  git tag -a v$version -m "$version"
  git push origin HEAD:main --follow-tags
  bash deploy/check-tags.sh --remote --branch main   # the tag is on origin, not just here
  docker tag wafproxy:$version ghcr.io/<owner>/wafproxy:latest && docker push ...
EOF
