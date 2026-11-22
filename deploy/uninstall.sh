#!/usr/bin/env bash
# Remove a native (systemd) WAF-Proxy installation.
#
# This script is intentionally limited to the paths and systemd units that
# deploy/install.sh creates. It never removes shared packages (nftables,
# ca-certificates, tzdata), Tailscale, CrowdSec, Docker, Go, or the checkout.
#
#   sudo ./deploy/uninstall.sh
#   sudo ./deploy/uninstall.sh --yes
#   sudo ./deploy/uninstall.sh --keep-data
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./deploy/uninstall.sh [--yes] [--keep-data]

Removes the native WAF-Proxy installation:
  - wafproxy.service and wafproxy-updates.service
  - /var/lib/waf-proxy (bin, lib, src and data), /usr/local/waf-proxy and the
    /usr/local/bin and /usr/local/lib/wafproxy links
  - the app-owned nftables table inet wafproxy
  - /etc/wafproxy and /var/log/wafproxy
  - the wafproxy system user and group

Options:
  --yes         Skip the confirmation prompt (for automation).
  --keep-data   Keep /var/lib/waf-proxy/data, /etc/wafproxy, /var/log/wafproxy
                and the wafproxy user/group so a later reinstall can reuse them.
  -h, --help    Show this help.

Not touched: OS packages, host firewall/router rules, Tailscale, CrowdSec,
Docker, the Go toolchain, or this repository checkout.
EOF
}

assume_yes=0
keep_data=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) assume_yes=1 ;;
    --keep-data) keep_data=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "uninstall.sh: unknown option $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  echo "uninstall.sh: run as root (sudo ./deploy/uninstall.sh)" >&2
  exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
  echo "uninstall.sh: systemd is not running here; this script is for the native systemd install" >&2
  exit 1
fi

warn() { echo "uninstall.sh: $*" >&2; }
remove_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    echo "removing $path"
    rm -rf -- "$path"
  fi
}

cat <<'EOF'
This permanently removes the native WAF-Proxy installation.

The repository checkout is not removed. Shared OS packages, Tailscale,
CrowdSec and Docker are not removed.
EOF
if ((keep_data)); then
  echo "Keeping /var/lib/waf-proxy/data, /etc/wafproxy, /var/log/wafproxy and the wafproxy user/group."
fi

if (( !assume_yes )); then
  if [[ ! -t 0 ]]; then
    echo "uninstall.sh: no terminal for confirmation; pass --yes to run unattended" >&2
    exit 1
  fi
  read -r -p "Type 'uninstall' to continue: " answer
  if [[ "$answer" != "uninstall" ]]; then
    echo "uninstall.sh: aborted" >&2
    exit 1
  fi
fi

# Stop the console before the helper so no new package operation can start.
for unit in wafproxy.service wafproxy-updates.service wafproxy-docker-updates.service; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  systemctl stop "$unit" >/dev/null 2>&1 || true
done

# The ban engine owns this table. Remove it so leftover bans do not survive an
# uninstall, but leave the nftables package and the host's own tables alone.
if command -v nft >/dev/null 2>&1; then
  if nft list table inet wafproxy >/dev/null 2>&1; then
    if ! nft delete table inet wafproxy; then
      warn "could not delete nftables table inet wafproxy"
    fi
  fi
else
  warn "nft is not installed; skipping the app-owned nftables table"
fi

remove_path /etc/systemd/system/wafproxy.service
remove_path /etc/systemd/system/wafproxy-updates.service
remove_path /etc/systemd/system/wafproxy-docker-updates.service
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed wafproxy.service wafproxy-updates.service wafproxy-docker-updates.service >/dev/null 2>&1 || true

remove_path /usr/local/bin/wafproxy
remove_path /usr/local/bin/wafproxy-updated
remove_path /usr/local/lib/wafproxy
remove_path /usr/local/waf-proxy
remove_path /run/wafproxy-updates

if ((keep_data)); then
  echo "kept /var/lib/waf-proxy/data, /etc/wafproxy and /var/log/wafproxy"
else
  remove_path /etc/wafproxy
  remove_path /var/log/wafproxy
fi

# The install root holds the binaries, helper scripts and the update checkout;
# the state lives in its data/ subdirectory.
remove_path /var/lib/waf-proxy/src
remove_path /var/lib/waf-proxy/bin
remove_path /var/lib/waf-proxy/lib
if ((keep_data)); then
  echo "kept /var/lib/waf-proxy/data"
else
  remove_path /var/lib/waf-proxy/data
  rmdir /var/lib/waf-proxy 2>/dev/null || true
  # State and program files from releases before 1.14.
  remove_path /var/lib/wafproxy
  remove_path /var/lib/wafproxy.pre-1.14

  if getent passwd wafproxy >/dev/null 2>&1; then
    if ! userdel wafproxy; then
      warn "could not remove the wafproxy user"
    fi
  fi
  if getent group wafproxy >/dev/null 2>&1; then
    if ! groupdel wafproxy; then
      warn "could not remove the wafproxy group"
    fi
  fi
fi

echo
echo "WAF-Proxy native installation removed."
echo "The repository checkout, OS packages, host firewall/router rules and optional"
echo "Tailscale/CrowdSec/Docker installations were left untouched."
if (( !keep_data )); then
  echo "System journal entries for the removed units may still be present."
fi
