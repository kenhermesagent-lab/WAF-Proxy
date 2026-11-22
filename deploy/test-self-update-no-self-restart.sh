#!/usr/bin/env bash
# Regression guard for the native updater.
#
# wafproxy-self-update.sh runs as a child of wafproxy-updates.service. systemd's
# default KillMode=control-group sends SIGTERM to every process in the unit's
# cgroup when that unit is stopped, so a `systemctl try-restart
# wafproxy-updates.service` inside the script kills the script itself. That
# happened right after the build: the new binaries were installed, but the
# console was never restarted and the Update button kept offering the same
# version.
#
# The restart is now scheduled through systemd-run in its own transient unit,
# after the script has finished. This test fails if a future edit calls
# try-restart on the helper unit from anywhere else in the script.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wafproxy-self-update.sh"
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[[ -f "$script" ]] || fail "missing $script"

start="$(awk '/^schedule_helper_refresh\(\) \{/ { print NR; exit }' "$script")"
[[ -n "$start" ]] || fail "schedule_helper_refresh() is missing"
end="$(awk -v start="$start" 'NR >= start && /^}/ { print NR; exit }' "$script")"
[[ -n "$end" ]] || fail "schedule_helper_refresh() has no closing brace"
body="$(sed -n "${start},${end}p" "$script")"
grep -q 'systemd-run' <<<"$body" || fail "schedule_helper_refresh() does not use systemd-run"
grep -q -- '--on-active=' <<<"$body" || fail "the helper restart is not delayed until the script exits"
grep -q 'try-restart wafproxy-updates.service' <<<"$body" || fail "schedule_helper_refresh() does not restart the helper"

outside="$(awk -v start="$start" -v end="$end" '
  /try-restart wafproxy-updates.service/ && (NR < start || NR > end) { print NR ": " $0 }
' "$script")"
if [[ -n "$outside" ]]; then
  fail "the updater restarts its own unit while running (it will kill itself):
$outside"
fi

echo "PASS: the updater schedules the helper restart outside its own cgroup"
