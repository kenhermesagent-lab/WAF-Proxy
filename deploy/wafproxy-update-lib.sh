#!/usr/bin/env bash
# Shared by the two callers that pull an update checkout: the updater itself
# and the restore test in deploy/test-self-update-restore.sh. Keeping it here
# means the test exercises the code that runs on a host, not a copy of it.

# restore_console_bundle <checkout> [runner...]
#
# Puts internal/webui/dist back to what the checkout records. `npm run build`
# rewrites the tracked bundle and leaves asset names under new hashes, and git
# refuses a fast-forward that would overwrite either, so both have to go before
# `git pull --ff-only`. The optional runner is the updater's as_user wrapper,
# which runs the commands as the checkout's owner.
restore_console_bundle() {
  local src="$1"
  shift
  "$@" git -C "$src" checkout -- internal/webui/dist 2>/dev/null || true
  "$@" git -C "$src" clean -fdq -- internal/webui/dist 2>/dev/null || true
}
