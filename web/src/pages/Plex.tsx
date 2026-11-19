import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Badge, Card, Field, errText } from "../ui";
import type { PlexStatus } from "../types";

type Form = {
  enabled: boolean;
  listen_ip: string;
  port: number;
  upstream: string;
  allow: string;
  max_conns: number;
};

const EMPTY_FORM: Form = { enabled: false, listen_ip: "", port: 32400, upstream: "", allow: "", max_conns: 256 };

export default function Plex({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [status, setStatus] = useState<PlexStatus | null>(null);
  const [form, setForm] = useState<Form>(EMPTY_FORM);
  const [env, setEnv] = useState<{ path: string; error: string }>({ path: "", error: "" });
  const [saving, setSaving] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const loaded = useRef(false);

  const applyResponse = (r: {
    status: PlexStatus;
    defaults: { listen_ip: string; port: number; upstream: string; max_conns: number };
    env: { path: string; error: string };
  }) => {
    setStatus(r.status);
    setEnv(r.env || { path: "", error: "" });
    if (!loaded.current) {
      loaded.current = true;
      setForm({
        enabled: r.status.enabled,
        listen_ip: r.status.listen_ip || r.defaults.listen_ip || "",
        port: r.status.port || r.defaults.port || 32400,
        upstream: r.status.upstream || r.defaults.upstream || "",
        allow: (r.status.allow || []).join(","),
        max_conns: r.status.max_conns || r.defaults.max_conns || 256,
      });
    }
  };

  const load = () =>
    api
      .get<Parameters<typeof applyResponse>[0]>("/api/plex")
      .then(applyResponse)
      .catch((e) => onError(errText(e)));

  // Refresh the live counters without clobbering a form that is being edited.
  const refresh = () =>
    api
      .get<Parameters<typeof applyResponse>[0]>("/api/plex")
      .then((r) => setStatus(r.status))
      .catch(() => undefined);

  useEffect(() => {
    load();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.put<{ applied: boolean; error: string; env: { path: string; error: string } }>("/api/plex", form);
      setEnv(r.env || { path: "", error: "" });
      if (r.applied) onOK("Plex forwarder saved and applied");
      else onError(`Saved, but the listener did not start: ${r.error}`);
      loaded.current = false;
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
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

  const bound = status?.bound ?? false;

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="grid cols-2">
        <Card
          title="Plex forwarding"
          actions={<Badge tone={form.enabled ? (bound ? "ok" : "warn") : ""}>{form.enabled ? (bound ? "listening" : "enabled, not bound") : "off"}</Badge>}
        >
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 14, textTransform: "none", letterSpacing: 0 }}>
            <input
              type="checkbox"
              style={{ width: "auto" }}
              checked={form.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
            />
            Forward Plex traffic through this gateway
          </label>

          <div className="row grow">
            <Field label="Listen address (WAN)">
              <input value={form.listen_ip} onChange={(e) => set("listen_ip", e.target.value)} placeholder="192.168.191.2" />
            </Field>
            <Field label="Listen port">
              <input
                type="number"
                min={1}
                max={65535}
                value={form.port}
                onChange={(e) => set("port", Number(e.target.value))}
              />
            </Field>
          </div>

          <Field label="Plex server (host or host:port)">
            <input
              value={form.upstream}
              onChange={(e) => set("upstream", e.target.value)}
              placeholder="192.168.101.10:32400"
            />
          </Field>

          <div className="row grow">
            <Field label="Allowed sources (CIDR, empty = any)">
              <input value={form.allow} onChange={(e) => set("allow", e.target.value)} placeholder="203.0.113.0/24" />
            </Field>
            <Field label="Max connections">
              <input
                type="number"
                min={1}
                max={4096}
                value={form.max_conns}
                onChange={(e) => set("max_conns", Number(e.target.value))}
              />
            </Field>
          </div>

          <button className="primary mt" onClick={save} disabled={saving}>
            {saving ? "Saving…" : "Save and apply"}
          </button>
        </Card>

        <Card title="Status">
          <div className="bar-row">
            <div>Listener</div>
            <div>
              {bound ? (
                <Badge tone="ok">{status?.listen_addr}</Badge>
              ) : (
                <Badge tone="warn">{form.enabled ? "not bound" : "disabled"}</Badge>
              )}
            </div>
          </div>
          <div className="bar-row">
            <div>Plex server</div>
            <div className="mono">{status?.upstream || "—"}</div>
          </div>
          <div className="bar-row">
            <div>Active connections</div>
            <div>{status?.active ?? 0}</div>
          </div>
          <div className="bar-row">
            <div>Accepted since start</div>
            <div>{(status?.total ?? 0).toLocaleString()}</div>
          </div>
          <div className="bar-row">
            <div>Refused (allow list / limit)</div>
            <div>{(status?.blocked ?? 0).toLocaleString()}</div>
          </div>
          <div className="bar-row">
            <div>Refused (active ban)</div>
            <div>{(status?.banned ?? 0).toLocaleString()}</div>
          </div>
          {status?.last_error && (
            <div className="bar-row" style={{ borderBottom: 0 }}>
              <div>Last error</div>
              <div className="err-text" style={{ margin: 0 }}>
                {status.last_error}
              </div>
            </div>
          )}
        </Card>
      </div>

      <Card title="How to put Plex behind the gateway">
        <ol className="muted" style={{ margin: 0, paddingLeft: 18, fontSize: 13, lineHeight: 1.7 }}>
          <li>
            Set the <strong>Plex server</strong> field to the box running Plex, for example{" "}
            <code>192.168.101.10:32400</code>. The forwarding listener is bound to the WAN address above so the
            firewall has a target.
          </li>
          <li>
            On the firewall, forward WAN <code>{form.port || 32400}/tcp</code> to{" "}
            <code>
              {form.listen_ip || "<WAN address>"}:{form.port || 32400}
            </code>{" "}
            with <strong>no SNAT</strong>. Plex then sees every client as coming from this proxy's LAN address, which
            is the only entry its whitelist needs.
          </li>
          <li>
            In Plex, add that LAN address to <em>Settings → Network → List of IP addresses and networks that are
            allowed without auth</em>, and keep the whitelist strict: everything else is refused by Plex itself.
          </li>
          <li>
            The relay is a transparent TCP forward, so Plex's own TLS certificates and <code>*.plex.direct</code>{" "}
            names keep working. The payload stays encrypted and is therefore <strong>not</strong> inspected by the
            WAF; keep HTTP proxies on their own hostnames for inspection.
          </li>
        </ol>
      </Card>

      <Card title="Container restart">
        <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
          Saving the forwarder rebinds the port immediately, which is enough with the shipped{" "}
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
