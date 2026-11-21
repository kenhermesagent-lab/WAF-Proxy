#!/usr/bin/env bash
# Install or upgrade the native (systemd) deployment. The Docker Compose path
# in docs/INSTALL.md does not use this script.
#
#   make build
#   sudo ./deploy/install.sh [path-to-binary]
#
# The script is idempotent: it keeps an existing /etc/wafproxy/wafproxy.env and
# /var/lib/wafproxy on upgrade.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $EUID -ne 0 ]]; then
  echo "install.sh: run as root (sudo ./deploy/install.sh)" >&2
  exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
  echo "install.sh: systemd is not running here; use the Docker Compose deployment" >&2
  exit 1
fi

binary="${1:-bin/wafproxy}"
if [[ ! -x "$binary" ]]; then
  echo "install.sh: $binary not found or not executable; build it first with 'make build'" >&2
  exit 1
fi

if ! getent group wafproxy >/dev/null; then
  groupadd --system wafproxy
fi
if ! id -u wafproxy >/dev/null 2>&1; then
  nologin="$(command -v nologin || echo /bin/false)"
  useradd --system --gid wafproxy --home-dir /var/lib/wafproxy --no-create-home --shell "$nologin" wafproxy
fi

install -d -m 0750 -o wafproxy -g wafproxy /var/lib/wafproxy /var/log/wafproxy
install -d -m 0750 -o root -g wafproxy /etc/wafproxy
install -m 0755 "$binary" /usr/local/bin/wafproxy
if [[ ! -e /etc/wafproxy/wafproxy.env ]]; then
  install -m 0640 -o root -g wafproxy deploy/wafproxy.env.example /etc/wafproxy/wafproxy.env
  echo "installed /etc/wafproxy/wafproxy.env"
fi
install -m 0644 deploy/wafproxy.service /etc/systemd/system/wafproxy.service

if ! command -v nft >/dev/null; then
  echo "warning: nft not found; install the nftables package to enable kernel-mode bans" >&2
fi

systemctl daemon-reload
systemctl enable wafproxy.service
systemctl restart wafproxy.service

cat <<'EOF'

WAF-Proxy is running under systemd.

First boot (console on loopback):
  ssh -L 8080:127.0.0.1:8080 <this-host>
  open http://127.0.0.1:8080

Or set WAFPROXY_LISTEN_GUI=<LAN-IP>:8080 in /etc/wafproxy/wafproxy.env and run
`systemctl restart wafproxy` before completing the wizard.

Logs:  journalctl -u wafproxy -f
Unit:  systemctl status wafproxy
EOF
