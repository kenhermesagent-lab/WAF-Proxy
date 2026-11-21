#!/usr/bin/env bash
# Install or upgrade the native (systemd) deployment. The Docker Compose path
# in docs/INSTALL.md does not use this script.
#
#   make build
#   sudo ./deploy/install.sh
#
# The installer asks which interface is WAN and which is LAN, then binds the
# proxy to the WAN address and the admin GUI to the LAN address only. It also
# enables the admin listener's RFC1918-only client check. On upgrade it keeps
# the existing database and optional settings in /etc/wafproxy/wafproxy.env.
#
# Non-interactive use (for image builds and tests):
#   sudo ./deploy/install.sh --wan-iface eth0 --lan-iface eth1
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./deploy/install.sh [options] [path-to-binary]

Options:
  --wan-iface NAME   WAN interface (prompted when omitted)
  --lan-iface NAME   LAN interface (prompted when omitted)
  --wan-port PORT    WAN proxy port (default 443)
  --gui-port PORT    Admin GUI port on the LAN (default 8443)
  --yes              never prompt; requires --wan-iface and --lan-iface
  -h, --help         show this help

The LAN address must be RFC1918 because WAFPROXY_GUI_PRIVATE_ONLY is enabled:
the admin console refuses clients outside 10/8, 172.16/12, 192.168/16 and
loopback. Loopback remains allowed for local health checks and manual tunnels.
EOF
}

cd "$(dirname "$0")/.."

binary="bin/wafproxy"
wan_iface="${WAFPROXY_INSTALL_WAN_IFACE:-}"
lan_iface="${WAFPROXY_INSTALL_LAN_IFACE:-}"
wan_port="${WAFPROXY_INSTALL_WAN_PORT:-443}"
gui_port="${WAFPROXY_INSTALL_GUI_PORT:-8443}"
wan_port_set=0
gui_port_set=0
[[ -n "${WAFPROXY_INSTALL_WAN_PORT:-}" ]] && wan_port_set=1
[[ -n "${WAFPROXY_INSTALL_GUI_PORT:-}" ]] && gui_port_set=1
assume_yes=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --wan-iface) wan_iface="${2:?--wan-iface needs a value}"; shift 2 ;;
    --lan-iface) lan_iface="${2:?--lan-iface needs a value}"; shift 2 ;;
    --wan-port) wan_port="${2:?--wan-port needs a value}"; wan_port_set=1; shift 2 ;;
    --gui-port) gui_port="${2:?--gui-port needs a value}"; gui_port_set=1; shift 2 ;;
    --yes) assume_yes=1; shift ;;
    -*) echo "install.sh: unknown option $1" >&2; usage >&2; exit 2 ;;
    *) binary="$1"; shift ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "install.sh: run as root (sudo ./deploy/install.sh)" >&2
  exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
  echo "install.sh: systemd is not running here; use the Docker Compose deployment" >&2
  exit 1
fi
if [[ ! -x "$binary" ]]; then
  echo "install.sh: $binary not found or not executable; build it first with 'make build'" >&2
  exit 1
fi
if ! command -v ip >/dev/null; then
  echo "install.sh: the 'ip' command is required (install iproute2)" >&2
  exit 1
fi

die() { echo "install.sh: $*" >&2; exit 1; }

valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

valid_port "$wan_port" || die "WAN port must be 1-65535"
valid_port "$gui_port" || die "GUI port must be 1-65535"

# One row per global IPv4 address. Interface names become part of the env file,
# so keep the accepted character set narrow.
mapfile -t rows < <(
  ip -4 -o addr show scope global 2>/dev/null |
    awk '$2 != "lo" && $4 != "" && !seen[$2]++ {
      split($4, a, "/");
      if ($2 ~ /^[A-Za-z0-9_.:-]+$/) print $2 " " a[1] " " $4
    }'
)
[[ ${#rows[@]} -gt 0 ]] || die "no interface has a global IPv4 address; assign the WAN and LAN addresses first"

iface_ip() {
  local name="$1"
  local addr=""
  local row
  for row in "${rows[@]}"; do
    read -r row_iface row_ip _ <<<"$row"
    if [[ "$row_iface" == "$name" ]]; then
      addr="$row_ip"
      break
    fi
  done
  [[ -n "$addr" ]] || die "interface $name has no global IPv4 address"
  printf '%s\n' "$addr"
}

is_rfc1918() {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]}))
  local c=$((10#${BASH_REMATCH[3]})) d=$((10#${BASH_REMATCH[4]}))
  ((a <= 255 && b <= 255 && c <= 255 && d <= 255)) || return 1
  ((a == 10)) || ((a == 172 && b >= 16 && b <= 31)) || ((a == 192 && b == 168))
}

prompt() {
  local label="$1" answer=""
  if ! read -r -p "$label: " answer; then
    die "no input; pass --wan-iface and --lan-iface for non-interactive use"
  fi
  printf '%s\n' "$answer"
}

print_rows() {
  local i
  for i in "${!rows[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${rows[$i]}"
  done
}

default_wan_index() {
  local default_iface route idx=""
  route="$(ip route show default 2>/dev/null | head -n 1)"
  default_iface="$(awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}' <<<"$route")"
  for idx in "${!rows[@]}"; do
    read -r row_iface _ _ <<<"${rows[$idx]}"
    if [[ -n "$default_iface" && "$row_iface" == "$default_iface" ]]; then
      printf '%s\n' "$idx"
      return
    fi
  done
  printf '0\n'
}

default_lan_index() {
  local wan="$1" idx row_iface
  for idx in "${!rows[@]}"; do
    read -r row_iface _ _ <<<"${rows[$idx]}"
    if [[ "$row_iface" != "$wan" ]]; then
      printf '%s\n' "$idx"
      return
    fi
  done
  printf '0\n'
}

choose_index() {
  local label="$1" default_idx="$2" answer idx
  while true; do
    {
      echo "Available IPv4 interfaces:"
      print_rows
      echo "Select the $label interface [default $((default_idx + 1))]:"
    } >&2
    answer="$(prompt "Number")"
    answer="${answer:-$((default_idx + 1))}"
    if [[ "$answer" =~ ^[0-9]+$ ]]; then
      idx=$((10#$answer - 1))
      if ((idx >= 0 && idx < ${#rows[@]})); then
        printf '%s\n' "$idx"
        return
      fi
    fi
    echo "Enter a number between 1 and ${#rows[@]}." >&2
  done
}

if [[ -z "$wan_iface" ]]; then
  if ((assume_yes)) || [[ ! -t 0 ]]; then
    die "--yes requires --wan-iface and --lan-iface (no prompt is possible)"
  fi
  idx="$(choose_index "WAN" "$(default_wan_index)")"
  read -r wan_iface _ _ <<<"${rows[$idx]}"
fi

if [[ -z "$lan_iface" ]]; then
  if ((assume_yes)) || [[ ! -t 0 ]]; then
    die "--yes requires --wan-iface and --lan-iface (no prompt is possible)"
  fi
  idx="$(choose_index "LAN" "$(default_lan_index "$wan_iface")")"
  read -r lan_iface _ _ <<<"${rows[$idx]}"
fi

wan_ip="$(iface_ip "$wan_iface")"
lan_ip="$(iface_ip "$lan_iface")"
is_rfc1918 "$lan_ip" || die "LAN address $lan_ip is not RFC1918; the admin console would reject every client"
if [[ "$wan_iface" == "$lan_iface" && "$wan_port" == "$gui_port" ]]; then
  die "WAN and GUI ports cannot be the same when both bind the same interface"
fi

if (( !wan_port_set && !assume_yes )) && [[ -t 0 ]]; then
  answer="$(prompt "WAN proxy port [$wan_port]")"
  wan_port="${answer:-$wan_port}"
  valid_port "$wan_port" || die "WAN port must be 1-65535"
fi
if (( !gui_port_set && !assume_yes )) && [[ -t 0 ]]; then
  answer="$(prompt "Admin GUI port on the LAN [$gui_port]")"
  gui_port="${answer:-$gui_port}"
  valid_port "$gui_port" || die "GUI port must be 1-65535"
fi
if [[ "$wan_iface" == "$lan_iface" && "$wan_port" == "$gui_port" ]]; then
  die "WAN and GUI ports cannot be the same when both bind the same interface"
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

# The Updates page uses a separate root helper instead of sudo: the main unit
# has NoNewPrivileges=yes, so a setuid sudo could not elevate it. The helper
# owns a Unix socket and accepts only its compiled package allowlist.
helper_binary="bin/wafproxy-updated"
helper_installed=0
if [[ -x "$helper_binary" ]]; then
  install -m 0755 "$helper_binary" /usr/local/bin/wafproxy-updated
  install -m 0644 deploy/wafproxy-updates.service /etc/systemd/system/wafproxy-updates.service
  helper_installed=1
else
  echo "warning: $helper_binary not found; the Updates page will be read-only" >&2
fi

# The helper can rebuild the checked-out repository on request. Record the
# checkout and its owner once, as root, so a private fork's existing git
# credentials work; the public repository needs none. The browser never
# supplies a URL or command.
self_update_installed=0
update_source="$(pwd)"
update_user="$(stat -c '%U' "$update_source" 2>/dev/null || true)"
if [[ "$update_user" == "root" || "$update_user" == "" ]]; then
  update_user=""
fi
update_remote=""
update_branch="main"
if command -v git >/dev/null 2>&1; then
  update_remote="$(git -C "$update_source" config --get remote.origin.url 2>/dev/null || true)"
  update_branch="$(git -C "$update_source" symbolic-ref --short HEAD 2>/dev/null || echo main)"
fi
if [[ -n "$update_remote" && -d "$update_source/.git" && -f deploy/wafproxy-self-update.sh ]]; then
  install -d -m 0755 /usr/local/lib/wafproxy
  install -m 0755 deploy/wafproxy-self-update.sh /usr/local/lib/wafproxy/self-update
  install -m 0755 deploy/wafproxy-self-update-check.sh /usr/local/lib/wafproxy/self-update-check
  {
    printf 'WAFPROXY_UPDATE_SOURCE_DIR=%q\n' "$update_source"
    printf 'WAFPROXY_UPDATE_USER=%q\n' "$update_user"
    printf 'WAFPROXY_UPDATE_BRANCH=%q\n' "$update_branch"
    printf 'WAFPROXY_UPDATE_MODE=%q\n' "native"
  } >/etc/wafproxy/self-update.conf
  chmod 0644 /etc/wafproxy/self-update.conf
  self_update_installed=1
else
  echo "warning: no git checkout origin found; the Updates page can check but not apply application updates" >&2
fi

# The CrowdSec page installs the Security Engine on this host through the same
# root helper. The script is fixed and takes no argument from the browser.
install -d -m 0755 /usr/local/lib/wafproxy
if [[ -f deploy/crowdsec-install.sh ]]; then
  install -m 0755 deploy/crowdsec-install.sh /usr/local/lib/wafproxy/crowdsec-install
else
  echo "warning: deploy/crowdsec-install.sh missing; the CrowdSec page cannot install the engine" >&2
fi

if [[ ! -e /etc/wafproxy/wafproxy.env ]]; then
  install -m 0640 -o root -g wafproxy deploy/wafproxy.env.example /etc/wafproxy/wafproxy.env
  echo "installed /etc/wafproxy/wafproxy.env"
fi
install -m 0644 deploy/wafproxy.service /etc/systemd/system/wafproxy.service

# Update a single key without disturbing comments, optional secrets or values
# added by the operator. Rewriting in place keeps the root:wafproxy 0640 mode.
set_env() {
  local key="$1" value="$2" file="/etc/wafproxy/wafproxy.env" tmp
  tmp="$(mktemp)"
  if grep -q "^${key}=" "$file"; then
    awk -v key="$key" -v value="$value" '
      $0 ~ "^" key "=" && !seen { print key "=" value; seen = 1; next }
      { print }
    ' "$file" >"$tmp"
    cat "$tmp" >"$file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
  rm -f "$tmp"
}

set_env WAFPROXY_LISTEN_WAN "${wan_ip}:${wan_port}"
set_env WAFPROXY_LISTEN_GUI "${lan_ip}:${gui_port}"
set_env WAFPROXY_WAN_IFACE "$wan_iface"
set_env WAFPROXY_LAN_IFACE "$lan_iface"
set_env WAFPROXY_GUI_PRIVATE_ONLY "true"

if ! command -v nft >/dev/null; then
  echo "warning: nft not found; install the nftables package to enable kernel-mode bans" >&2
fi

systemctl daemon-reload
if ((helper_installed)); then
  if ! systemctl enable wafproxy-updates.service >/dev/null 2>&1; then
    echo "warning: could not enable wafproxy-updates.service at boot" >&2
  fi
  if ! systemctl restart wafproxy-updates.service; then
    echo "warning: wafproxy-updates.service did not start; host updates will be read-only" >&2
    journalctl -u wafproxy-updates.service -n 20 --no-pager >&2 || true
  fi
fi
systemctl enable wafproxy.service
if ! systemctl restart wafproxy.service; then
  journalctl -u wafproxy.service -n 30 --no-pager >&2 || true
  die "wafproxy.service failed to start"
fi

# `systemctl restart` returns when the process is launched, not when the
# listener is accepting connections. Wait briefly so the printed URL is usable
# immediately and an early crash is reported as a failed install.
ready=0
for _ in $(seq 1 20); do
  if ! systemctl is-active --quiet wafproxy.service; then
    break
  fi
  if command -v ss >/dev/null 2>&1 && ss -ltnH "sport = :$gui_port" 2>/dev/null | grep -q "$lan_ip:$gui_port"; then
    ready=1
    break
  fi
  if ! command -v ss >/dev/null 2>&1 && (exec 3<>"/dev/tcp/$lan_ip/$gui_port") 2>/dev/null; then
    exec 3>&-
    ready=1
    break
  fi
  sleep 0.5
done
if ((!ready)); then
  systemctl --no-pager status wafproxy.service >&2 || true
  journalctl -u wafproxy.service -n 30 --no-pager >&2 || true
  die "wafproxy.service is running but did not open $lan_ip:$gui_port"
fi

tailscale_status="not installed (optional; see docs/INSTALL.md section 12)"
if command -v tailscale >/dev/null 2>&1; then
  tailscale_ip="$(ip -4 -o addr show dev tailscale0 2>/dev/null | awk '$3 == "inet" { split($4, a, "/"); print a[1]; exit }' || true)"
  if [[ -n "$tailscale_ip" ]]; then
    tailscale_status="connected at $tailscale_ip"
  else
    tailscale_status="installed but not connected (run: sudo tailscale up)"
  fi
fi

cat <<EOF

WAF-Proxy is running under systemd.

WAN interface:  $wan_iface ($wan_ip:$wan_port)
LAN interface:  $lan_iface ($lan_ip:$gui_port, admin GUI only)
Admin access:   http://$lan_ip:$gui_port
                Only RFC1918 clients are accepted (loopback remains allowed for local checks).
WAN proxy:      https://$wan_ip:$wan_port
App updates:    $([[ $self_update_installed == 1 ]] && echo "enabled from $update_source" || echo "check-only; no git checkout")
Tailscale:      $tailscale_status
                Enable admin/proxy access on the Tailscale page after setup.
                Tailnet clients must be granted tcp:$wan_port, tcp:$gui_port and DNS 53 by ACL.

Open the admin GUI, complete the wizard (its addresses are prefilled), then run
\`systemctl restart wafproxy\` so the stored settings are used. On an existing install, addresses already
stored in SQLite take precedence over this env file; change them in Settings
if the interfaces moved.

Logs:  journalctl -u wafproxy -f
Unit:  systemctl status wafproxy
EOF
