#!/usr/bin/env bash
# Regression test for check-workflow-pins.sh: a tag, a branch, a short SHA and
# a floating image tag must each fail, and a fully pinned workflow must pass.
set -euo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/repo"
sha=11d5960a326750d5838078e36cf38b85af677262
digest=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

write_workflow() {
  mkdir -p "$root/.github/workflows"
  cat >"$root/.github/workflows/ci.yml" <<YAML
jobs:
  test:
    steps:
      - uses: $1
      - uses: ./.github/actions/local
YAML
}

seed() {
  rm -rf "$root"
  mkdir -p "$root/deploy"
  cp "$src/check-workflow-pins.sh" "$root/deploy/check-workflow-pins.sh"
  write_workflow "actions/checkout@${sha} # v4.4.0"
}

check() {
  ( cd "$root" && bash deploy/check-workflow-pins.sh >/dev/null 2>&1 )
}

seed
if ! check; then
  echo "a fully pinned workflow failed the pin check" >&2
  exit 1
fi

expect_fail() {
  local name=$1 ref=$2
  seed
  write_workflow "$ref"
  if check; then
    echo "${name} did not fail the pin check" >&2
    exit 1
  fi
}

expect_fail "an action version tag" "actions/checkout@v4"
expect_fail "an action branch" "actions/checkout@main"
expect_fail "an abbreviated commit" "actions/checkout@11d5960"
expect_fail "a SHA with a trailing tag" "actions/checkout@${sha}@v4"
expect_fail "a floating image tag" "docker://alpine:3.21"
expect_fail "an image digest that is not sha256" "docker://alpine@sha512:${digest#sha256:}"

echo "pin check rejects tags, branches and short SHAs"
