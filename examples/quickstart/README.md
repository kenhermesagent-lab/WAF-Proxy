# Quickstart demo

One site, one upstream, loopback only: a normal request passes, a SQL injection is blocked. No DNS,
no certificate authority, no backend of your own, nothing exposed to your network.

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
./demo.sh
```

Once the published image is pullable, the first line is just `docker compose up -d`; the overlay only
swaps the image for one built from this checkout.

Expected output:

```
1/2  An ordinary request
GET /                     -> HTTP 200

2/2  A SQL injection
GET /?id=1' OR '1'='1    -> HTTP 403
```

## What it starts

| Service | Image | Why |
| --- | --- | --- |
| `wafproxy` | `ghcr.io/kenhermesagent-lab/wafproxy:${WAFPROXY_VERSION:-1.65.0}` | the proxy and console, listening on `127.0.0.1:8080` (console) and `127.0.0.1:8443` (TLS) |
| `echo` | `hashicorp/http-echo:1.0` | a stand-in backend answering `hello from the upstream` on `127.0.0.1:9000` |

Host networking is deliberate: the proxy binds the addresses it is given and manages nftables
directly, exactly as in [`deploy/docker-compose.yml`](../../deploy/docker-compose.yml).

## What `demo.sh` does

1. Waits for the console.
2. Creates the administrator with `wafproxy setup` — **without** an authenticator, because this is a
   throwaway install. A real deployment chooses TOTP in the wizard.
3. Imports [`demo.yaml`](demo.yaml): one proxy for `demo.local`, `waf_mode: block`, WAF profile
   `Generic Web`, upstream `http://127.0.0.1:9000`.
4. Sends `GET /` (expects `200`) and `GET /?id=1' OR '1'='1` (expects `403`).

The second request is caught by rule **942100** at stage `waf`. **Logs** in the console shows it with
the request, the stage, the rule id and the anomaly score, and **Why?** replays the same request
against the current rules without touching the echo service.

## Poking at it

```bash
# TLS is a throwaway self-signed certificate here; -k skips verification
curl -k --resolve demo.local:8443:127.0.0.1 https://demo.local:8443/

# block page back, nothing forwarded
curl -k -i --resolve demo.local:8443:127.0.0.1 "https://demo.local:8443/?id=1%27%20OR%20%271%27%3D%271"

# XSS and path traversal are caught by the same ruleset
curl -k -o /dev/null -w '%{http_code}\n' --resolve demo.local:8443:127.0.0.1 \
  "https://demo.local:8443/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

Sign in at <http://127.0.0.1:8080> as `admin` / `demo-password-123`, and the dashboard shows the
allowed request, the block, and the rule behind it.

## Options

| Variable | Default | Use |
| --- | --- | --- |
| `WAFPROXY_VERSION` | `1.65.0` | image tag to pull |
| `WAFPROXY_DEMO_PASSWORD` | `demo-password-123` | administrator password |
| `WAFPROXY_DEMO_HOST` | `demo.local` | hostname the demo proxy serves |
| `WAFPROXY_GUI` | `http://127.0.0.1:8080` | console address the script talks to |

Pin a different tag with `WAFPROXY_VERSION=1.66.0 docker compose ... up -d`.

## Clean up

```bash
docker compose down -v
```

The demo database lives in the `wafproxy-quickstart_data` volume and nowhere else.
