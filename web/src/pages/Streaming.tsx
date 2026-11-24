import { ReactNode, useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Field, errText, fmtBytes, PageHead } from "../ui";
import type { AccessList, StreamingService } from "../types";

type Form = {
  enabled: boolean;
  protocol: string;
  listen_ip: string;
  port: number;
  port_count: number;
  upstream: string;
  allow: string;
  max_conns: number;
  max_per_source: number;
  idle_seconds: number;
  max_datagram: number;
  require_allow: boolean;
  list_ids: number[];
};

type Loaded = { services: StreamingService[]; env: { path: string; error: string } };

// Groups come from the catalog; the headings only order them on the page.
const GROUPS: { id: string; title: string; sub: string }[] = [
  {
    id: "media",
    title: "Media",
    sub: "TLS passes through untouched, so the server's own certificates and clients keep working. Every client appears to come from this host's address.",
  },
  {
    id: "game",
    title: "Game servers",
    sub: "A preset seeds the protocol and the ports and nothing more. Published game ports change between builds, so check the game's current documentation and edit the card when it does.",
  },
  {
    id: "custom",
    title: "Custom",
    sub: "Any port on either protocol, for an application without a preset.",
  },
];

const PROTOCOLS: { id: string; label: string }[] = [
  { id: "tcp", label: "TCP" },
  { id: "udp", label: "UDP" },
  { id: "both", label: "TCP + UDP" },
];

const protocolLabel = (p: string) => (p === "both" ? "TCP+UDP" : p.toUpperCase());
const usesUDP = (p: string) => p === "udp" || p === "both";

// rangeText is what the listener binds: one port, or base to last.
const rangeText = (port: number, count: number) => (count > 1 ? `${port}-${port + count - 1}` : `${port}`);

// liveText reads the saved protocol, not the form, because the counters describe
// what is running right now.
function liveText(svc: StreamingService): string {
  const connections = `${svc.active.toLocaleString()} connection${svc.active === 1 ? "" : "s"}`;
  const sessions = `${svc.active_sessions.toLocaleString()} session${svc.active_sessions === 1 ? "" : "s"}`;
  if (svc.protocol === "udp") return sessions;
  if (svc.protocol === "both") return `${connections} · ${sessions}`;
  return connections;
}

const formFrom = (s: StreamingService): Form => ({
  enabled: s.enabled,
  protocol: s.protocol || s.default.protocol || "tcp",
  listen_ip: s.listen_ip || s.default.listen_ip || "",
  port: s.port || s.default.port,
  port_count: s.port_count || s.default.port_count || 1,
  upstream: s.upstream || s.default.upstream || "",
  allow: (s.allow || []).join(", "),
  max_conns: s.max_conns || s.default.max_conns,
  max_per_source: s.max_per_source || s.default.max_per_source,
  idle_seconds: s.idle_seconds || s.default.idle_seconds,
  max_datagram: s.max_datagram || s.default.max_datagram,
  require_allow: s.require_allow,
  list_ids: s.list_ids || [],
});

// Steps are per application because the "trust this address" setting lives in a
// different place in each server. An unknown catalog entry still gets the
// firewall steps and a pointer to its own documentation.
function guideSteps(svc: StreamingService, f: Form): ReactNode[] {
  const label = svc.label;
  const ports = rangeText(f.port, f.port_count);
  const target = (
    <code>
      {f.listen_ip || "<host address>"}:{ports}
    </code>
  );
  const server = (
    <>
      The <em>server</em> field is the machine running {label} — its LAN address and base port. The gateway relays to
      it; clients never connect to it directly.
    </>
  );
  const listen = (
    <>
      The <em>listen address</em> must be an IP configured on this host: the listener binds it and the router forwards
      the port to it. A single-NIC host uses the same address here as its LAN address.
    </>
  );
  const firewall = (
    <>
      On the router or firewall, forward <code>{ports}/{protocolLabel(f.protocol)}</code> to {target} with{" "}
      <strong>no SNAT</strong>. {label} then sees every client as coming from this host's address, which is what its
      allow list needs.
    </>
  );

  switch (svc.id) {
    case "plex":
      return [
        server,
        listen,
        firewall,
        <>
          In Plex: <em>Settings → Network → List of IP addresses and networks that are allowed without auth</em> → add
          this host's address, and keep the list strict: everything else is refused by Plex itself.
        </>,
        <>
          Plex clients validate the <code>*.plex.direct</code> certificates that encode the server address, so the
          relay passes TLS through untouched. The payload stays encrypted and is therefore not inspected by the WAF.
        </>,
      ];
    case "jellyfin":
      return [
        server,
        listen,
        firewall,
        <>
          In Jellyfin: <em>Settings → Networking → Known proxies</em> → add this host's address so Jellyfin treats the
          hop as trusted. Jellyfin has no IP whitelist of its own; use the allow list above if only some clients should
          reach it.
        </>,
        <>
          The relay is protocol agnostic: Jellyfin's plain HTTP port (<code>8096</code>) and its HTTPS port (
          <code>8920</code>) both pass through unchanged. Point the field above at whichever one you serve.
        </>,
      ];
    default:
      if (svc.group === "game") {
        return [
          server,
          listen,
          firewall,
          <>
            Start the server, then compare the card with its own manual. The preset is a seed: if the game changed its
            ports, edit the card rather than adding a second forwarder.
          </>,
          <>
            A game that opens several ports needs every port in the range forwarded, and some routers take one rule per
            port. A range maps 1:1 onto the server, so <code>{ports}</code> forwards to <code>{ports}</code> there.
          </>,
        ];
      }
      return [
        server,
        listen,
        firewall,
        <>
          Add this host's address to the application's trusted-proxy or whitelist setting — see its documentation for
          where that lives.
        </>,
      ];
  }
}

export default function Streaming({ onError, onOK, head = true }: { onError: (m: string) => void; onOK: (m: string) => void; head?: boolean }) {
  const [services, setServices] = useState<StreamingService[]>([]);
  const [lists, setLists] = useState<AccessList[]>([]);
  const [forms, setForms] = useState<Record<string, Form>>({});
  const [env, setEnv] = useState<{ path: string; error: string }>({ path: "", error: "" });
  const [saving, setSaving] = useState("");
  const [restarting, setRestarting] = useState(false);

  const load = (resetForms: boolean) =>
    api
      .get<Loaded>("/api/streaming")
      .then((r) => {
        setServices(r.services);
        setEnv(r.env || { path: "", error: "" });
        if (resetForms) {
          setForms(Object.fromEntries(r.services.map((s) => [s.id, formFrom(s)])));
        }
      })
      .catch((e) => onError(errText(e)));

  // Refresh counters without clobbering a form that is being edited.
  const refresh = () =>
    api
      .get<Loaded>("/api/streaming")
      .then((r) => {
        setServices(r.services);
        setEnv(r.env || { path: "", error: "" });
      })
      .catch(() => undefined);

  useEffect(() => {
    load(true);
    api
      .get<AccessList[]>("/api/lists")
      .then(setLists)
      .catch((e) => onError(errText(e)));
    // Only a visible tab polls: a hidden one asking for counters every three
    // seconds buys nothing.
    const t = setInterval(() => {
      if (document.visibilityState === "visible") refresh();
    }, 3000);
    return () => clearInterval(t);
  }, []);

  const setField = <K extends keyof Form>(id: string, key: K, value: Form[K]) =>
    setForms((prev) => ({ ...prev, [id]: { ...prev[id], [key]: value } }));

  // A list is attached or detached as a whole, exactly as an access profile
  // does it, so the same named list means the same thing everywhere.
  const toggleList = (id: string, listID: number, on: boolean) =>
    setForms((prev) => {
      const current = prev[id].list_ids.filter((x) => x !== listID);
      return { ...prev, [id]: { ...prev[id], list_ids: on ? [...current, listID] : current } };
    });

  const listSummary = (l: AccessList) => {
    const ips = l.ips ? l.ips.split(",").filter(Boolean).length : 0;
    const countries = l.countries ? l.countries.split(",").filter(Boolean).length : 0;
    return [ips ? `${ips} address${ips === 1 ? "" : "es"}` : "", countries ? `${countries} countr${countries === 1 ? "y" : "ies"}` : ""]
      .filter(Boolean)
      .join(" · ");
  };

  const save = async (svc: StreamingService) => {
    setSaving(svc.id);
    try {
      const r = await api.put<{ applied: boolean; error: string; env: { path: string; error: string } }>(
        `/api/streaming/${svc.id}`,
        forms[svc.id],
      );
      setEnv(r.env || { path: "", error: "" });
      if (r.applied) onOK(`${svc.label} forwarder saved and applied`);
      else onError(`Saved, but the ${svc.label} listener did not start: ${r.error}`);
      // Re-read this service only, so edits in another section survive.
      const fresh = await api.get<Loaded>("/api/streaming");
      setServices(fresh.services);
      const updated = fresh.services.find((s) => s.id === svc.id);
      if (updated) setForms((prev) => ({ ...prev, [svc.id]: formFrom(updated) }));
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving("");
    }
  };

  const restart = async () => {
    if (!(await confirmDialog("Restart WAF-Proxy? The admin session is kept, but the UI disconnects for a few seconds."))) return;
    try {
      await api.post("/api/system/restart");
      setRestarting(true);
    } catch (e) {
      onError(errText(e));
    }
  };

  const card = (svc: StreamingService) => {
    const f = forms[svc.id];
    if (!f) return null;
    const enabled = svc.enabled;
    const openToAnyone =
      usesUDP(f.protocol) &&
      !f.require_allow &&
      !f.allow.trim() &&
      !lists.some((l) => l.kind === "whitelist" && f.list_ids.includes(l.id));
    const busiest = svc.sessions[0];
    return (
      <div key={svc.id} className="grid" style={{ gap: 14 }}>
        <div className="split" style={{ alignItems: "start" }}>
          <Card
            title={`${svc.label} forwarding`}
            sub={svc.notes || undefined}
            actions={
              <>
                <Badge tone={enabled ? (svc.bound ? "ok" : "warn") : ""}>
                  {enabled ? (svc.bound ? "listening" : "enabled, not bound") : "off"}
                </Badge>
                <button className="small primary" onClick={() => save(svc)} disabled={saving === svc.id}>
                  {saving === svc.id ? "Saving…" : "Save"}
                </button>
              </>
            }
          >
            <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 14, textTransform: "none", letterSpacing: 0 }}>
              <input
                type="checkbox"
                style={{ width: "auto" }}
                checked={f.enabled}
                onChange={(e) => setField(svc.id, "enabled", e.target.checked)}
              />
              Forward {svc.label} traffic through this gateway
            </label>

            <div className="row grow">
              <Field label="Protocol">
                <select
                  aria-label={`${svc.label} protocol`}
                  value={f.protocol}
                  onChange={(e) => setField(svc.id, "protocol", e.target.value)}
                >
                  {PROTOCOLS.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Listen address (this host)">
                <input
                  aria-label={`${svc.label} listen address`}
                  value={f.listen_ip}
                  onChange={(e) => setField(svc.id, "listen_ip", e.target.value)}
                  placeholder="192.168.1.10"
                />
              </Field>
            </div>

            <div className="row grow">
              <Field label="Listen port">
                <input
                  type="number"
                  aria-label={`${svc.label} listen port`}
                  min={1}
                  max={65535}
                  value={f.port}
                  onChange={(e) => setField(svc.id, "port", Number(e.target.value))}
                />
              </Field>
              <Field label="Port count" hint="1 disables the range">
                <input
                  type="number"
                  aria-label={`${svc.label} port count`}
                  min={1}
                  max={16}
                  value={f.port_count}
                  onChange={(e) => setField(svc.id, "port_count", Number(e.target.value))}
                />
              </Field>
            </div>

            <p className="muted" style={{ fontSize: 12, margin: "-2px 0 12px" }}>
              An IP assigned to this host. With one NIC that is the LAN address your router forwards to, and the WAN
              and LAN fields in Settings hold the same value.
            </p>

            {f.port_count > 1 && (
              <p className="muted" style={{ fontSize: 12, margin: "-2px 0 12px" }}>
                Listens on {rangeText(f.port, f.port_count)} and forwards each port to the same range on the server.
              </p>
            )}

            <Field label="Server (host or host:port)" hint="The base port: a range forwards each port to the same range on this host.">
              <input
                aria-label={`${svc.label} server`}
                value={f.upstream}
                onChange={(e) => setField(svc.id, "upstream", e.target.value)}
                placeholder={svc.default_port ? `10.0.0.10:${svc.default_port}` : "10.0.0.10:25565"}
              />
            </Field>

            <div className="row grow">
              <Field label="Allowed sources (IP / CIDR, comma separated, empty = any)">
                <input
                  aria-label={`${svc.label} allowed sources`}
                  value={f.allow}
                  onChange={(e) => setField(svc.id, "allow", e.target.value)}
                  placeholder="203.0.113.7, 10.0.0.0/8, 2001:db8::/32"
                />
              </Field>
              <Field label={usesUDP(f.protocol) ? "Max sessions" : "Max connections"}>
                <input
                  type="number"
                  aria-label={`${svc.label} max sessions`}
                  min={1}
                  max={4096}
                  value={f.max_conns}
                  onChange={(e) => setField(svc.id, "max_conns", Number(e.target.value))}
                />
              </Field>
            </div>

            <p className="muted" style={{ fontSize: 12, margin: "-2px 0 12px" }}>
              One or more addresses are accepted: a single IPv4/IPv6 address, a CIDR block, or a comma-separated mix of
              both. An empty list means any source; the session cap and active bans still apply.
            </p>

            {usesUDP(f.protocol) && (
              <>
                <div className="row grow">
                  <Field label="Max sessions per source" hint="A spoofed source spray hits this cap before it fills the session table.">
                    <input
                      type="number"
                      aria-label={`${svc.label} max sessions per source`}
                      min={1}
                      max={4096}
                      value={f.max_per_source}
                      onChange={(e) => setField(svc.id, "max_per_source", Number(e.target.value))}
                    />
                  </Field>
                  <Field label="Idle session timeout (seconds)" hint="Games keepalive continuously; a session silent this long is reclaimed.">
                    <input
                      type="number"
                      aria-label={`${svc.label} idle seconds`}
                      min={10}
                      max={3600}
                      value={f.idle_seconds}
                      onChange={(e) => setField(svc.id, "idle_seconds", Number(e.target.value))}
                    />
                  </Field>
                </div>
                <Field label="Largest datagram (bytes)" hint="Bigger datagrams are dropped and counted, never truncated and forwarded.">
                  <input
                    type="number"
                    aria-label={`${svc.label} max datagram`}
                    min={576}
                    max={8192}
                    value={f.max_datagram}
                    onChange={(e) => setField(svc.id, "max_datagram", Number(e.target.value))}
                  />
                </Field>
                <label
                  style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}
                >
                  <input
                    type="checkbox"
                    style={{ width: "auto" }}
                    aria-label={`${svc.label} require an allow list`}
                    checked={f.require_allow}
                    onChange={(e) => setField(svc.id, "require_allow", e.target.checked)}
                  />
                  Refuse sources that are not on an allow list
                </label>
                <p className="muted" style={{ fontSize: 12, margin: "4px 0 12px" }}>
                  With no allow list or whitelist attached, every new session is refused — closing the port is safer
                  than answering anyone.
                </p>
              </>
            )}

            {openToAnyone && (
              <div
                role="note"
                style={{ borderLeft: "4px solid var(--warn, #d08b2e)", padding: "8px 0 8px 12px", margin: "4px 0 14px", fontSize: 13 }}
              >
                <strong>This port answers any source.</strong> Add an allow list, attach a whitelist, or tick “Refuse
                sources that are not on an allow list”. A UDP source address can be forged, so a list decides who is
                answered but cannot prove who sent; the amplification ports are refused outright and the session caps
                bound everything else.
              </div>
            )}

            <div className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 }}>
              Blocklists and whitelists
            </div>
            {lists.length === 0 ? (
              <p className="muted" style={{ fontSize: 12, margin: "0 0 12px" }}>
                No lists yet. Create them under Policies → Lists, then attach them here.
              </p>
            ) : (
              <>
                <div style={{ display: "grid", gap: 6, marginBottom: 8 }}>
                  {lists.map((l) => (
                    <label
                      key={l.id}
                      style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}
                    >
                      <input
                        type="checkbox"
                        style={{ width: "auto" }}
                        checked={f.list_ids.includes(l.id)}
                        onChange={(e) => toggleList(svc.id, l.id, e.target.checked)}
                      />
                      <Badge tone={l.kind === "blocklist" ? "bad" : "ok"}>{l.kind === "blocklist" ? "block" : "allow"}</Badge>
                      {l.name}
                      <span className="muted" style={{ fontSize: 12 }}>{listSummary(l)}</span>
                    </label>
                  ))}
                </div>
                <p className="muted" style={{ fontSize: 12, margin: "0 0 12px" }}>
                  A whitelist makes this port reachable only from what it holds, plus the allow list above; a blocklist
                  refuses its entries first and wins when both name the same address. Countries use the same GeoIP
                  database as the HTTP proxy, so without it country entries match nothing.
                </p>
              </>
            )}
          </Card>

          <Card title="Status">
            <div style={{ maxWidth: 520 }}>
              <div className="bar-row">
                <div>Listener</div>
                <div>
                  {svc.bound ? (
                    <Badge tone="ok">{svc.listen_addr}</Badge>
                  ) : enabled ? (
                    <Badge tone="warn">not bound</Badge>
                  ) : (
                    <Badge>disabled</Badge>
                  )}
                </div>
              </div>
              <div className="bar-row">
                <div>Protocol</div>
                <div>
                  {protocolLabel(svc.protocol || "tcp")}
                  {svc.port_count > 1 ? ` · ${svc.port_count} ports` : ""}
                </div>
              </div>
              <div className="bar-row">
                <div>Server</div>
                <div className="mono">{svc.upstream || "—"}</div>
              </div>
              <div className="bar-row">
                <div>Active</div>
                <div>{liveText(svc)}</div>
              </div>
              <div className="bar-row">
                <div>Transferred</div>
                <div>
                  ↓ {fmtBytes(svc.bytes_in)} · ↑ {fmtBytes(svc.bytes_out)}
                </div>
              </div>
              <div className="bar-row">
                <div>Busiest source</div>
                <div className="mono">{busiest ? `${busiest.addr} · ${fmtBytes(busiest.bytes_in + busiest.bytes_out)}` : "—"}</div>
              </div>
              <div className="bar-row">
                <div>Accepted since start</div>
                <div>{svc.total.toLocaleString()}</div>
              </div>
              <div className="bar-row">
                <div>Lists</div>
                <div className="muted">
                  {(svc.list_ids || []).map((id) => lists.find((l) => l.id === id)?.name || `#${id}`).join(", ") || "none"}
                </div>
              </div>
              <div className="bar-row">
                <div>Refused (lists, allow list or cap)</div>
                <div>{svc.blocked.toLocaleString()}</div>
              </div>
              <div className="bar-row">
                <div>Refused (active ban)</div>
                <div>{svc.banned.toLocaleString()}</div>
              </div>
              {svc.oversize > 0 && (
                <div className="bar-row">
                  <div>Dropped (oversize)</div>
                  <div>{svc.oversize.toLocaleString()}</div>
                </div>
              )}
              <div className="bar-row" style={{ borderBottom: svc.last_error ? undefined : 0 }}>
                <div>Streams cut by ban</div>
                <div>{svc.dropped.toLocaleString()}</div>
              </div>
              {svc.last_error && (
                <div className="bar-row" style={{ borderBottom: 0 }}>
                  <div>Last error</div>
                  <div className="err-text" style={{ margin: 0 }}>
                    {svc.last_error}
                  </div>
                </div>
              )}
            </div>
          </Card>
        </div>

        <Card title={`Connecting ${svc.label}`}>
          <ol className="muted" style={{ margin: 0, paddingLeft: 18, fontSize: 13, lineHeight: 1.7, maxWidth: "88ch" }}>
            {guideSteps(svc, f).map((node, i) => (
              <li key={i}>{node}</li>
            ))}
          </ol>
        </Card>
      </div>
    );
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      {head && <PageHead sub="One front door for media servers and game servers, with the same source policy and bans as your web sites." />}
      <Card title="How forwarding works">
        <p className="muted" style={{ margin: 0, fontSize: 13, lineHeight: 1.7, maxWidth: "88ch" }}>
          Each enabled service gets its own listener on a port on this host, relaying bytes unchanged over TCP, UDP or
          both. TLS stays end to end, so an application's own certificates and clients keep working, and every client
          appears to come from this host's address — the one entry its allow list needs. This is relay-grade: the WAF
          and access gate cannot inspect the traffic and no game protocol is parsed, so there are no player counts or
          server queries. The source allow list, the named blocklists and whitelists, the session caps and the ban
          engine do apply: a banned or blocked address is refused, and a session that is already running is cut when
          the ban lands.
        </p>
      </Card>

      {GROUPS.map((g) => {
        const group = services.filter((s) => s.group === g.id);
        if (group.length === 0) return null;
        return (
          <section key={g.id} className="grid" style={{ gap: 14 }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 16 }}>{g.title}</h2>
              <p className="muted" style={{ margin: "4px 0 0", fontSize: 12, lineHeight: 1.6, maxWidth: "88ch" }}>
                {g.sub}
              </p>
            </div>
            {group.map(card)}
          </section>
        );
      })}

      <Card title="Restart WAF-Proxy">
        <p className="muted" style={{ fontSize: 13, marginTop: 0, maxWidth: "88ch" }}>
          Saving a forwarder rebinds its ports immediately, which is all that is needed with the shipped{" "}
          <code>network_mode: host</code> compose file: the container shares the host's network, so Docker publishes no
          ports. Restart only after changing the bind addresses in Settings, or when the host's own IP changed and the
          listener needs the new one.
        </p>
        <div style={{ marginTop: 14 }}>
          <div className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: ".06em" }}>
            Compose env file
          </div>
          <div className="muted" style={{ fontSize: 12, marginTop: 4, overflowWrap: "anywhere" }}>
            {env.path ? <span className="mono">{env.path}</span> : "not mounted — settings are kept in the database"}
          </div>
          {env.error ? <div className="err-text" style={{ margin: 0 }}>{env.error}</div> : null}
        </div>
        <div className="row mt">
          <button className="danger" onClick={restart} disabled={restarting}>
            {restarting ? "Restarting…" : "Restart service"}
          </button>
          {restarting && <span className="muted">Waiting for WAF-Proxy to come back — reload in a few seconds.</span>}
        </div>
      </Card>
    </div>
  );
}
