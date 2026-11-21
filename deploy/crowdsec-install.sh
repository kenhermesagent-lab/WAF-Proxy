#!/usr/bin/env bash
# Root-owned CrowdSec installer, run by wafproxy-updated when an administrator
# clicks Install on the CrowdSec page. It is fixed: it reads no argument from
# the browser and installs only what this file names.
#
# It installs the Security Engine from the official CrowdSec repository, adds
# the nginx collection, points acquisition at the WAF access log (which is
# written in nginx combined format), creates the bouncer key, and prints:
#
#   WAFPROXY_LAPI=http://127.0.0.1:8080
#   WAFPROXY_KEY=<bouncer key>
#
# The console seals that key in its database and enables the bouncer, so there
# is nothing to copy: the installer fills in the LAPI URL and the key itself.
# The only thing left for the operator is linking the engine to their CrowdSec
# account (`cscli console enroll <key>`), offered on the same page.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

die() { echo "crowdsec-install: $*" >&2; exit 1; }
step() { echo "crowdsec-install: $*" >&2; }

[[ $EUID -eq 0 ]] || die "must run as root"
command -v apt-get >/dev/null || die "apt-get is required; this installer supports Debian and Ubuntu"
command -v systemctl >/dev/null || die "systemd is required"

# The native unit writes the access log here (deploy/wafproxy.service).
log=/var/log/wafproxy/access.log

if ! command -v cscli >/dev/null; then
  step "adding the CrowdSec package repository"
  command -v curl >/dev/null || die "curl is required to add the CrowdSec repository"
  installer="$(mktemp)"
  trap 'rm -f "$installer"' EXIT
  # Downloaded first so a failed fetch is reported instead of piped into a shell.
  curl -fsSL https://install.crowdsec.net -o "$installer" || die "cannot download the CrowdSec repository installer"
  sh "$installer" >&2
fi

step "installing the engine package"
apt-get update -qq >&2
apt-get install -y --no-install-recommends crowdsec >&2 || die "cannot install the crowdsec package"

step "installing the nginx collection"
cscli collections install crowdsecurity/nginx >&2 || die "cannot install the crowdsecurity/nginx collection"

# Acquisition: one file in acquis.d, which the engine loads automatically.
install -d -m 0755 /etc/crowdsec/acquis.d
cat >/etc/crowdsec/acquis.d/wafproxy.yaml <<EOF
# Managed by WAF-Proxy: the console writes its access log in nginx combined
# format so the stock crowdsecurity/nginx parser can read it.
filenames:
  - $log
labels:
  type: nginx
EOF

# The engine runs as the crowdsec user and must read a log the wafproxy group
# owns. Membership is additive and matched by name.
if id -u crowdsec >/dev/null 2>&1 && getent group wafproxy >/dev/null; then
  if ! id -nG crowdsec | tr ' ' '\n' | grep -qx wafproxy; then
    usermod -aG wafproxy crowdsec
  fi
fi

step "starting the engine"
systemctl enable crowdsec >/dev/null 2>&1 || true
systemctl restart crowdsec || die "the CrowdSec service did not start"

# Creating a bouncer needs a responsive Local API.
for _ in $(seq 1 30); do
  cscli lapi status >/dev/null 2>&1 && break
  sleep 1
done

step "creating the bouncer key"
cscli bouncers delete wafproxy >/dev/null 2>&1 || true

# Choose the key here and hand it to cscli, instead of reading it back from the
# command's output: the printed format changes between releases and may be
# empty, which used to abort the whole install after the engine was ready.
key=""
if command -v openssl >/dev/null 2>&1; then
  key="$(openssl rand -hex 16)"
else
  key="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi
[[ $key =~ ^[A-Za-z0-9_-]{16,128}$ ]] || die "cannot generate a bouncer key"

if ! create_out="$(cscli bouncers add wafproxy --key "$key" 2>&1)"; then
  # Releases without --key print the key instead; read it as a fallback.
  step "cscli did not accept a supplied key, reading its generated one"
  cscli bouncers delete wafproxy >/dev/null 2>&1 || true
  create_out="$(cscli bouncers add wafproxy -o raw 2>&1 || true)"
  key="$(printf '%s\n' "$create_out" | tail -n 1 | tr -d '[:space:]')"
  if [[ ! $key =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
    key="$(printf '%s\n' "$create_out" \
      | sed -n "s/.*Api key for '[^']*': *//p" \
      | tail -n 1 | tr -d '[:space:]')"
  fi
  [[ $key =~ ^[A-Za-z0-9_-]{16,128}$ ]] || die "cannot create a bouncer key: $create_out"
fi

# Report the listen address the engine actually uses, so a customised LAPI is
# still written back to the console correctly.
lapi="$(sed -n 's/^[[:space:]]*listen_uri:[[:space:]]*//p' /etc/crowdsec/config.yaml 2>/dev/null | head -n 1 | tr -d '"' | tr -d "'" || true)"
lapi="${lapi#http://}"
lapi="${lapi#https://}"
[[ -n "$lapi" ]] || lapi="127.0.0.1:8080"
[[ "$lapi" == *:* ]] || lapi="$lapi:8080"
[[ "$lapi" == 0.0.0.0:* ]] && lapi="127.0.0.1:${lapi##*:}"

# Prove the key works before the console stores it: /v1/decisions with a valid
# bouncer key answers 200, and anything else (403 for a bad key) is a failure.
step "verifying the bouncer key against the Local API"
if ! command -v curl >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends curl >&2 || die "curl is required to verify the bouncer key"
fi
base="http://$lapi"
code=""
for _ in $(seq 1 10); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "X-Api-Key: $key" "$base/v1/decisions?limit=1" 2>/dev/null || true)"
  [[ "$code" == "200" ]] && break
  sleep 1
done
[[ "$code" == "200" ]] || die "the new bouncer key was rejected by $base/v1/decisions (HTTP ${code:-no response})"
step "bouncer key verified"

printf 'WAFPROXY_LAPI=http://%s\n' "$lapi"
printf 'WAFPROXY_KEY=%s\n' "$key"
step "done; the bouncer key was verified and written to the console"
