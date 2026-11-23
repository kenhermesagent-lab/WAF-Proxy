#!/usr/bin/env bash
# Root-owned installer for the Cloudflare Tunnel connector, run by
# wafproxy-updated when an administrator clicks Install on the Cloudflare page.
# It is fixed: it reads no argument from the browser and installs one package.
#
# The systemd unit the package ships is disabled: the console owns the process,
# because it starts and stops it as the tunnel token and the Enable switch
# change.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

die() { echo "cloudflared-install: $*" >&2; exit 1; }
step() { echo "cloudflared-install: $*" >&2; }

[[ $EUID -eq 0 ]] || die "must run as root"
command -v apt-get >/dev/null || die "apt-get is required; this installer supports Debian and Ubuntu"
command -v systemctl >/dev/null || die "systemd is required"

if ! command -v cloudflared >/dev/null; then
  command -v curl >/dev/null || die "curl is required to add the Cloudflare repository"
  step "adding Cloudflare's package repository"
  install -d -m 0755 /usr/share/keyrings
  keyring=/usr/share/keyrings/cloudflare-main.gpg
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o "$tmp" || die "cannot download Cloudflare's signing key"
  install -m 0644 "$tmp" "$keyring"
  echo "deb [signed-by=$keyring] https://pkg.cloudflare.com/cloudflared any main" \
    >/etc/apt/sources.list.d/cloudflared.list
  step "installing the connector package"
  apt-get update -qq >&2
  apt-get install -y --no-install-recommends cloudflared >&2 || die "cannot install the cloudflared package"
fi

# The console starts cloudflared with the tunnel token, so the package's unit
# must stay out of the way. Disabling an absent unit is not an error.
systemctl disable --now cloudflared >/dev/null 2>&1 || true

step "installed $(cloudflared version 2>/dev/null | head -n 1 || echo cloudflared)"
