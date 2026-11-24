# Optional integrations

Part of [Installation](../INSTALL.md).

## 7. Optional CrowdSec

The bouncer needs a CrowdSec Security Engine and its Local API. On a native install the console
installs and configures it for you (section 11.4); containers use the included sidecar:

```bash
docker compose -f deploy/docker-compose.yml --profile crowdsec up -d crowdsec
docker exec crowdsec cscli bouncers add wafproxy
```

Open **CrowdSec** in the console, enter `http://127.0.0.1:8081` and the printed key, then click
**Save and apply**. The page can test the key, enable/disable the bouncer without a restart and
shows last poll, applied decisions and the last error. The access log written to
`/logs/access.log` is tailed by the sidecar with the stock nginx parser; decisions arrive over
the LAPI stream and are applied as `source=crowdsec` bans. The legacy
`WAFPROXY_CROWDSEC_URL` / `WAFPROXY_CROWDSEC_KEY` variables remain first-boot defaults.

## 8. Optional streaming (Plex, Jellyfin and game servers)

Media players validate the server's own certificates (Plex clients check the `*.plex.direct`
names that encode its address), which this gateway cannot mint, and a game server does not
speak HTTP at all. The **Streaming** page therefore runs one **transparent relay per
application** on its own WAN port instead of an HTTP reverse proxy: a TCP stream passes TLS
through untouched, a UDP datagram is carried to a connected upstream socket, and either way the
server sees every client as coming from the proxy's LAN address. That single address is what
goes in the server's trusted list, so “allow only this, refuse everything else” stays intact.

The shipped catalog has a section each for **Plex** (`32400/tcp`) and **Jellyfin**
(`8096/tcp`), a **Custom** card that forwards any port on either protocol, and the game presets
below.

### Game server presets

A game card seeds a protocol, a port range and a one-line note. **Every value stays editable**:
the preset is a starting point, not a contract, and published ports change between game builds,
so check the game's current documentation. A listen range maps 1:1 onto the server address you
enter, so Valheim's `2456-2458` forwards to `2456-2458` on that host.

| Service | ID | Protocol | Ports | Notes |
| --- | --- | --- | --- | --- |
| Minecraft (Java) | `minecraft-java` | tcp | 25565 | TCP only; Bedrock is its own card. |
| Minecraft (Bedrock) | `minecraft-bedrock` | udp | 19132 | IPv6 clients use 19133; add it as a second card if you need it. |
| Source engine (TF2, CS, Garry's Mod) | `source` | both | 27015 | UDP carries the game; some server tools use TCP. |
| Valheim | `valheim` | udp | 2456-2458 | Three ports in one card, mapped 1:1 onto the server. |
| Palworld | `palworld` | udp | 8211 | One UDP port for game and query. |
| FiveM | `fivem` | both | 30120 | The same number on both protocols. |
| Factorio | `factorio` | both | 34197 | UDP carries the game; some tools use TCP. |
| ARK: Survival Evolved | `ark` | udp | 7777-7778 | The query port is a separate card. |
| ARK query port | `ark-query` | udp | 27015 | Only needed when clients query a separate port. |
| Rust | `rust` | both | 28015 | Game traffic; RCON is a separate card. |
| Rust RCON | `rust-rcon` | tcp | 28016 | TCP only, and only when RCON is enabled on the server. |
| 7 Days to Die | `7dtd` | both | 26900-26903 | Some servers use only two of them, so trim the count. |

A few of these overlap on purpose — ARK's query port `27015` is the Source engine's game port —
so enable the cards a particular server needs rather than the whole group.

### Ports and router rules

| Card | Protocol | Ports | Router rules |
| --- | --- | --- | --- |
| Plex | tcp | 32400 | one TCP rule |
| Jellyfin | tcp | 8096 | one TCP rule |
| a game card | as seeded, editable | its range | one rule per protocol the card lists |

Forward **TCP and UDP** for a card whose protocol is `both`: many routers need that as two rules
on the same number, and a range needs a port-range rule (`2456-2458`), not a single port. Forward
DNAT only, without SNAT, so the game server sees the proxy's LAN address and can trust it (step 5
below). Routers without NAT loopback (hairpin) cannot reach the WAN address from inside the LAN;
the client should connect to the server directly there — that is a router limit, not a relay
fault.

### UDP is spoofable

A UDP source address can be forged, so an allow list decides who is answered but cannot prove who
sent. What protects the box is the rest of the settings: the amplification ports (`53`, `123`,
`161`, `389`, `1900`, `5353`, `11211`) refuse UDP outright, a UDP port below `1024` needs **Refuse
sources that are not on an allow list** and at least one allowed source, `max_datagram` drops
oversized datagrams instead of truncating them, and the total, per-source and new-session rate caps
bound what one address can start. Tick that switch on a friends-only server: with no list attached
it refuses everyone, which is safer than answering anyone.

1. GUI → **Streaming** → the application's tab in the strip under the page tabs → enable.
2. **Listen address** = an address assigned to this host (`192.168.1.20` in the two-NIC
   reference; on a single-NIC host the LAN address the router forwards to), **port** = the
   port clients will use (any free port works, defaults are 32400 and 8096), **server** =
   the LAN address and port of that application (`192.168.2.10:32400`,
   `192.168.2.11:8096`). On a game card check **protocol** (`tcp`, `udp` or `both`), **port
   count** and **upstream port** first: the card forwards its listen range 1:1 onto the server,
   so a Valheim card with port `2456` and count `3` listens on 2456–2458 and forwards to
   2456–2458.
3. **Allowed sources** is optional: empty accepts any client the firewall lets through; a
   CIDR restricts further. **Max connections** caps concurrent TCP streams or UDP sessions (and
   **Max sessions per source** the sessions one address may hold). **Blocklists and
   whitelists** attach any list from **Policies** to this port: a blocklist refuses its addresses
   and countries first, a whitelist makes the port reachable only from what it holds plus the
   allow list, and a blocklist wins when both name the same address. Country entries need the
   GeoIP database; without it they match nothing.
4. **Save and apply** binds the port immediately and opens it on the host firewall when firewalld
   or ufw is running: firewalld gets a permanent `--add-port` for the range plus a reload, ufw gets
   `allow <range>/<proto>`. The Status card lists the ports the console opened; moving the card to
   another port or switching it off closes exactly those. When neither tool is reachable the save
   still applies and the page says which range to open yourself. There is no Docker restart to do
   while the stack uses `network_mode: host`. A port already used by the GUI, the HTTP proxy or
   another streaming section is refused with a clear message.
5. On the Firewalla: WAN `32400/tcp` → `192.168.1.20:32400` (and the same for 8096),
   **DNAT only, no SNAT**. A `udp` or `both` card needs the matching UDP rule (or the range),
   and a game card needs one rule per protocol it lists. The listener address must not appear
   as the source, or the server cannot trust it.
6. In the application:
   - **Plex**: Settings → Network → *List of IP addresses and networks that are allowed
     without auth* → add `192.168.1.10/32`, and keep the list strict.
   - **Jellyfin**: Settings → Networking → *Known proxies* → add `192.168.1.10`. Jellyfin has
     no IP whitelist of its own; use the allow list above when only some clients should
     connect.

Everything the relay carries is encrypted end to end, so the WAF and access gate cannot
inspect it. The source allowlist, the connection cap and the ban engine do apply: a banned
address is refused on accept, a stream that is already running is cut when the ban lands, and
both show up in **Logs** as `stream` events (rule `stream-ban`). A retrying banned host
produces at most one event a minute per application, with the number of attempts it folded
in, so a loop cannot flood the log. Keep HTTP apps on their own hostnames for inspection.

### File descriptors

A UDP session owns one connected upstream socket, so a game card uses one descriptor per client:
the default cap of 256 sessions is at most 256 sockets for that card, plus one listen socket per
card and one per TCP listener in a `both` card. The shipped systemd unit sets
`LimitNOFILE=8192`, which leaves room for several cards at the default cap. After replacing the
unit file, confirm the running process inherited it (`ulimit -n` in its shell, or
`cat /proc/$(pidof wafproxy)/limits`). `ss -u -a` lists the UDP sockets: the count should flatten
when the served game is idle instead of climbing, which is the session table leaking.

### High availability

Forwarders bind only on the node that is serving; a standby holds no game port. A failover drops
every live game session — the new active starts with an empty session table and each client
reconnects on its own, which is better than both nodes answering on one port. See the failover
checklist in [docs/HA.md](../HA.md).

`deploy/.env` is not mounted into the container by default, so the GUI cannot rewrite it in
the shipped stack. To let it mirror `PLEX_*` values there, mount the file and point the
container at it (the file must already exist):

```yaml
    environment:
      WAFPROXY_ENV_FILE: /config/.env
    volumes:
      - ./.env:/config/.env
```

The Streaming page can also restart the container (`POST /api/system/restart`), which is only
needed when the port is published by Docker rather than with host networking.
