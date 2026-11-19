import { ReactNode, useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Badge, Card, Field, errText } from "../ui";
import type { StreamingService } from "../types";

type Form = {
  enabled: boolean;
  listen_ip: string;
  port: number;
  upstream: string;
  allow: string;
  max_conns: number;
};

type Loaded = { services: StreamingService[]; env: { path: string; error: string } };

const formFrom = (s: StreamingService): Form => ({
  enabled: s.enabled,
  listen_ip: s.listen_ip || s.default.listen_ip || "",
  port: s.port || s.default.port,
  upstream: s.upstream || s.default.upstream || "",
  allow: (s.allow || []).join(","),
  max_conns: s.max_conns || s.default.max_conns,
});

// Steps are per application because the "trust this address" setting lives in a
// different place in each server. An unknown catalog entry still gets the
// firewall steps and a pointer to its own documentation.
function guideSteps(id: string, f: Form): ReactNode[] {
  const target = (
    <>
      <code>
        {f.listen_ip || "<WAN address>"}:{f.port}
      </code>
    </>
  );
  const firewall = (
    <>
      On the firewall, forward WAN <code>{f.port}/tcp</code> to {target} with <strong>no SNAT</strong>. The server
      then sees every client as coming from this proxy's LAN address, which is what its allow-list needs.
    </>
  );
  const server = (
    <>
      Set the server address above to the box running the application. The listener binds the WAN address so the
      firewall rule has a target.
    </>
  );

  switch (id) {
    case "plex":
      return [
        server,
        firewall,
        <>
          In Plex: <em>Settings → Network → List of IP addresses and networks that are allowed without auth</em> →
          add this proxy's LAN address, and keep the list strict: everything else is refused by Plex itself.
        </>,
        <>
          Plex clients validate the <code>*.plex.direct</code> certificates that encode the server address, so the
          relay passes TLS through untouched. The payload stays encrypted and is therefore not inspected by the WAF.
        </>,
      ];
    case "jellyfin":
      return [
        server,
        firewall,
        <>
          In Jellyfin: <em>Settings → Networking → Known proxies</em> → add this proxy's LAN address so Jellyfin treats
          the hop as trusted. Jellyfin has no IP whitelist of its own; use the allow list above if only some clients
          should reach it.
        </>,
        <>
          The relay is protocol agnostic: Jellyfin's plain HTTP port (<code>8096</code>) and its HTTPS port (
          <code>8920</code>) both pass through unchanged. Point the field above at whichever one you serve.
        </>,
      ];
    default:
      return [
        server,
        firewall,
        <>
          Add this proxy's LAN address to the application's trusted-proxy or whitelist setting — see its documentation
          for where that lives.
        </>,
      ];
  }
}

export default function Streaming({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [services, setServices] = useState<StreamingService[]>([]);
  const [forms, setForms] = useState<Record<string, Form>>({});
  const [env, setEnv] = useState<{ path: string; error: string }>({ path: "", error: "" });
  const [saving, setSaving] = useState("");
  const [restarting, setRestarting] = useState(false);
  const loaded = useRef(false);

  const load = (resetForms: boolean) =>
    api
      .get<Loaded>("/api/streaming")
      .then((r) => {
        setServices(r.services);
        setEnv(r.env || { path: "", error: "" });
        if (resetForms) {
          loaded.current = true;
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
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  const setField = <K extends keyof Form>(id: string, key: K, value: Form[K]) =>
    setForms((prev) => ({ ...prev, [id]: { ...prev[id], [key]: value } }));

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
    if (!confirm("Restart the proxy container? The admin session is kept, but the UI disconnects for a few seconds.")) return;
    try {
      await api.post("/api/system/restart");
      setRestarting(true);
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="How forwarding works">
        <p className="muted" style={{ margin: 0, fontSize: 13, lineHeight: 1.7 }}>
          Each enabled application gets its own listener on the WAN address, relaying TCP byte for byte. TLS stays
          end to end, so the application's own certificates and clients keep working, and every client appears to come
          from this proxy's LAN address — the one entry its whitelist needs. The WAF and access gate cannot inspect
          this traffic, but the source allow list, the connection cap and the ban engine do: a banned address is
          refused, and a stream that is already running is cut when the ban lands.
        </p>
      </Card>

      {services.map((svc) => {
        const f = forms[svc.id];
        if (!f) return null;
        const saved = svc.enabled;
        return (
          <div key={svc.id} className="grid" style={{ gap: 14 }}>
            <div className="split" style={{ alignItems: "start" }}>
              <Card
                title={`${svc.label} forwarding`}
                actions={
                  <Badge tone={saved ? (svc.bound ? "ok" : "warn") : ""}>
                    {saved ? (svc.bound ? "listening" : "enabled, not bound") : "off"}
                  </Badge>
                }
              >
                <label
                  style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 14, textTransform: "none", letterSpacing: 0 }}
                >
                  <input
                    type="checkbox"
                    style={{ width: "auto" }}
                    checked={f.enabled}
                    onChange={(e) => setField(svc.id, "enabled", e.target.checked)}
                  />
                  Forward {svc.label} traffic through this gateway
                </label>

                <div className="row grow">
                  <Field label="Listen address (WAN)">
                    <input value={f.listen_ip} onChange={(e) => setField(svc.id, "listen_ip", e.target.value)} placeholder="192.168.191.2" />
                  </Field>
                  <Field label="Listen port">
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={f.port}
                      onChange={(e) => setField(svc.id, "port", Number(e.target.value))}
                    />
                  </Field>
                </div>

                <Field label={`${svc.label} server (host or host:port)`}>
                  <input value={f.upstream} onChange={(e) => setField(svc.id, "upstream", e.target.value)} placeholder={`192.168.101.10:${svc.default_port}`} />
                </Field>

                <div className="row grow">
                  <Field label="Allowed sources (CIDR, empty = any)">
                    <input value={f.allow} onChange={(e) => setField(svc.id, "allow", e.target.value)} placeholder="203.0.113.0/24" />
                  </Field>
                  <Field label="Max connections">
                    <input
                      type="number"
                      min={1}
                      max={4096}
                      value={f.max_conns}
                      onChange={(e) => setField(svc.id, "max_conns", Number(e.target.value))}
                    />
                  </Field>
                </div>

                <button className="primary mt" onClick={() => save(svc)} disabled={saving === svc.id}>
                  {saving === svc.id ? "Saving…" : "Save and apply"}
                </button>
              </Card>

              <Card title="Status">
                <div style={{ maxWidth: 520 }}>
                  <div className="bar-row">
                    <div>Listener</div>
                    <div>
                      {svc.bound ? (
                        <Badge tone="ok">{svc.listen_addr}</Badge>
                      ) : (
                        <Badge tone="warn">{saved ? "not bound" : "disabled"}</Badge>
                      )}
                    </div>
                  </div>
                  <div className="bar-row">
                    <div>Server</div>
                    <div className="mono">{svc.upstream || "—"}</div>
                  </div>
                  <div className="bar-row">
                    <div>Active connections</div>
                    <div>{svc.active.toLocaleString()}</div>
                  </div>
                  <div className="bar-row">
                    <div>Accepted since start</div>
                    <div>{svc.total.toLocaleString()}</div>
                  </div>
                  <div className="bar-row">
                    <div>Refused (allow list / cap)</div>
                    <div>{svc.blocked.toLocaleString()}</div>
                  </div>
                  <div className="bar-row">
                    <div>Refused (active ban)</div>
                    <div>{svc.banned.toLocaleString()}</div>
                  </div>
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
              <ol className="muted" style={{ margin: 0, paddingLeft: 18, fontSize: 13, lineHeight: 1.7 }}>
                {guideSteps(svc.id, f).map((node, i) => (
                  <li key={i}>{node}</li>
                ))}
              </ol>
            </Card>
          </div>
        );
      })}

      <Card title="Container restart">
        <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
          Saving a forwarder rebinds its port immediately, which is enough with the shipped{" "}
          <code>network_mode: host</code> compose file. A restart is only needed when the port is published by Docker
          and the container has to be recreated, or after changing the WAN/GUI bind addresses.
        </p>
        <div className="bar-row">
          <div>Compose env file</div>
          <div className="muted" style={{ fontSize: 12 }}>
            {env.path ? <span className="mono">{env.path}</span> : "not mounted (host networking needs no port publishing)"}
            {env.error ? <div className="err-text" style={{ margin: 0 }}>{env.error}</div> : null}
          </div>
        </div>
        <div className="row mt">
          <button className="danger" onClick={restart} disabled={restarting}>
            {restarting ? "Restarting…" : "Restart container"}
          </button>
          {restarting && <span className="muted">Waiting for the container to come back — reload in a few seconds.</span>}
        </div>
      </Card>
    </div>
  );
}
