#!/bin/sh
# keepalived -> WAF-Proxy role notification. Install as
# /usr/local/bin/wafproxy-ha-notify, owned root:wafproxy, mode 0750.
#
# A refused transition exits non-zero on purpose: keepalived then shows the
# instance as FAULT instead of believing this node is serving.
set -eu

case "${1:-}" in
  MASTER|BACKUP|FAULT) ;;
  *) echo "usage: $0 MASTER|BACKUP|FAULT" >&2; exit 2 ;;
esac

# The service's data directory, so the CLI finds the same control socket.
DATADIR="${WAFPROXY_DATA_DIR:-/var/lib/wafproxy}"

exec sudo -u wafproxy env WAFPROXY_DATA_DIR="$DATADIR" \
  /usr/local/bin/wafproxy ha notify "$1"
