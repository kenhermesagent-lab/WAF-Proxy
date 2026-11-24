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

## 8. Optional streaming (Plex, Jellyfin)

Media players validate the server's own certificates (Plex clients check the `*.plex.direct`
names that encode its address), which this gateway cannot mint. The **Streaming** page
therefore runs one **transparent TCP relay per application** on its own WAN port instead of an
HTTP reverse proxy: TLS passes through untouched and the server sees every client as coming
from the proxy's LAN address. That single address is what goes in the server's trusted list,
so “allow only this, refuse everything else” stays intact.

The shipped catalog has a section each for **Plex** (`32400`) and **Jellyfin** (`8096`), a
**Custom** card that forwards any port on either protocol, and the game presets below.

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

1. GUI → **Streaming** → the application's section → enable.
2. **Listen address** = an address assigned to this host (`192.168.1.20` in the two-NIC
   reference; on a single-NIC host the LAN address the router forwards to), **port** = the
   port clients will use (any free port works, defaults are 32400 and 8096), **server** =
   the LAN address and port of that application (`192.168.2.10:32400`,
   `192.168.2.11:8096`).
3. **Allowed sources** is optional: empty accepts any client the firewall lets through; a
   CIDR restricts further. **Max connections** caps concurrent streams. **Blocklists and
   whitelists** attach any list from **Policies** to this port: a blocklist refuses its addresses
   and countries first, a whitelist makes the port reachable only from what it holds plus the
   allow list, and a blocklist wins when both name the same address. Country entries need the
   GeoIP database; without it they match nothing.
4. **Save and apply** binds the port immediately. There is no Docker restart to do while the
   stack uses `network_mode: host`. A port already used by the GUI, the HTTP proxy or another
   streaming section is refused with a clear message.
5. On the Firewalla: WAN `32400/tcp` → `192.168.1.20:32400` (and the same for 8096),
   **DNAT only, no SNAT**. The listener address must not appear as the source, or the server
   cannot trust it.
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
