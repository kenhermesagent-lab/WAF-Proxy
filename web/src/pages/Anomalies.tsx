import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Drawer, Empty, Field, confirmDialog, errText, fmtAgo, PageHead } from "../ui";
import type { AnomalyConfig, AnomalyDestination, AnomalyEvent, AnomalyMute } from "../types";

const LABELS: Record<string, string> = {
  egress_spike: "Outbound spike",
  rate_spike: "Request-rate spike",
  auth_burst: "Login-failure burst",
};

function fmtBytes(v: number): string {
  if (v >= 1 << 30) return `${(v / (1 << 30)).toFixed(1)} GB`;
  if (v >= 1 << 20) return `${(v / (1 << 20)).toFixed(1)} MB`;
  if (v >= 1 << 10) return `${(v / (1 << 10)).toFixed(1)} KB`;
  return `${Math.round(v)} B`;
}

// The value column carries a byte count for egress and a rate for the others,
// so it is formatted per kind rather than as a bare number.
function fmtValue(kind: string, v: number): string {
  if (kind === "egress_spike") return fmtBytes(v);
  if (kind === "rate_spike") return `${v.toFixed(0)} req/s`;
  return `${v.toFixed(0)} failures/min`;
}

const TONE: Record<string, "bad" | "warn" | "info"> = {
  egress_spike: "bad",
  rate_spike: "warn",
  auth_burst: "info",
};

export default function Anomalies({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [events, setEvents] = useState<AnomalyEvent[]>([]);
  const [mutes, setMutes] = useState<AnomalyMute[]>([]);
  const [cfg, setCfg] = useState<AnomalyConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [selected, setSelected] = useState<AnomalyEvent | null>(null);
  const [dests, setDests] = useState<AnomalyDestination[] | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    api
      .get<{ events: AnomalyEvent[]; config: AnomalyConfig; mutes?: AnomalyMute[] }>("/api/anomaly")
      .then((r) => {
        setEvents(r.events || []);
        setMutes(r.mutes || []);
        setCfg(r.config);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const set = (patch: Partial<AnomalyConfig>) => setCfg((c) => (c ? { ...c, ...patch } : c));

  const save = async () => {
    if (!cfg) return;
    setSaving(true);
    try {
      await api.put("/api/anomaly/settings", cfg);
      onOK("Detection thresholds saved");
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const ack = async (e: AnomalyEvent) => {
    try {
      await api.post(`/api/anomaly/events/${e.id}/ack`);
      load();
    } catch (err) {
      onError(errText(err));
    }
  };

  const inspect = async (e: AnomalyEvent) => {
    setSelected(e);
    setDests(null);
    try {
      const r = await api.get<{ event: AnomalyEvent; destinations: AnomalyDestination[] }>(`/api/anomaly/events/${e.id}`);
      setSelected(r.event);
      setDests(r.destinations || []);
    } catch (err) {
      onError(errText(err));
      setDests([]);
    }
  };

  const mute = async (d: AnomalyDestination) => {
    if (!selected) return;
    const ok = await confirmDialog(
      `Traffic from ${selected.proxy_host || `#${selected.proxy_id}`} to ${d.address} is expected. ` +
        "Muting stops outbound-spike detections for this site while its upstreams are muted, and acknowledges the open ones.",
      { title: "Mute destination", confirmLabel: "Mute" },
    );
    if (!ok) return;
    setBusy(true);
    try {
      await api.post(`/api/anomaly/events/${selected.id}/mute`, { address: d.address });
      onOK(`Muted outbound traffic to ${d.address}`);
      await inspect(selected);
      load();
    } catch (err) {
      onError(errText(err));
    } finally {
      setBusy(false);
    }
  };

  const unmute = async (proxyID: number, address: string) => {
    setBusy(true);
    try {
      await api.del(`/api/anomaly/mutes?proxy_id=${proxyID}&address=${encodeURIComponent(address)}`);
      onOK(`Detecting outbound spikes to ${address} again`);
      if (selected) await inspect(selected);
      load();
    } catch (err) {
      onError(errText(err));
    } finally {
      setBusy(false);
    }
  };

  const hostOf = (proxyID: number) => events.find((e) => e.proxy_id === proxyID)?.proxy_host || `#${proxyID}`;
  const open = events.filter((e) => e.state === "open").length;

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead sub="Behavioural detections with the thresholds that open them." />
      <Card
        title="Detection"
        actions={<button className="small primary" onClick={save} disabled={saving || !cfg}>{saving ? "Saving…" : "Save"}</button>}
      >
        {!cfg ? (
          <p className="muted">Loading…</p>
        ) : (
          <>
            <div className="row grow">
              <label style={{ margin: "18px 0 0", display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
                <input type="checkbox" style={{ width: "auto" }} checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
                detect anomalies
              </label>
              <Field label="Egress floor (MB / min)">
                <input type="number" min={1} value={cfg.egress_mb} onChange={(e) => set({ egress_mb: Number(e.target.value) })} />
              </Field>
              <Field label="Egress factor (× baseline)">
                <input type="number" step="0.1" value={cfg.egress_factor} onChange={(e) => set({ egress_factor: Number(e.target.value) })} />
              </Field>
            </div>
            <div className="row grow">
              <Field label="Request-rate threshold (rps)">
                <input type="number" min={1} value={cfg.rate_rps} onChange={(e) => set({ rate_rps: Number(e.target.value) })} />
              </Field>
              <Field label="Rate factor (× baseline)">
                <input type="number" step="0.1" value={cfg.rate_factor} onChange={(e) => set({ rate_factor: Number(e.target.value) })} />
              </Field>
              <Field label="Login-failure burst (/ min)">
                <input type="number" min={1} value={cfg.auth_burst} onChange={(e) => set({ auth_burst: Number(e.target.value) })} />
              </Field>
            </div>
            <p className="muted" style={{ fontSize: 12 }}>
              Counters are compared once a minute against the same proxy's median over the last hour. A detection
              opens one event per condition per proxy, refreshes it while it lasts, and sends a notification you can
              mute per class under <strong>Notifications</strong>. Baselines are in memory, so the first minute after
              a restart only takes a sample.
            </p>
          </>
        )}
      </Card>

      <Card title={`Events (${open} open)`}>
        {events.length === 0 ? (
          <Empty>Nothing detected yet. Events appear after a minute of traffic above a threshold.</Empty>
        ) : (
          <div className="table-wrap"><table>
            <thead>
              <tr>
                <th>When</th>
                <th>Detection</th>
                <th>Proxy</th>
                <th>Value</th>
                <th>Baseline</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="clickable" onClick={() => inspect(e)}>
                  <td className="muted">{fmtAgo(e.last_seen)}</td>
                  <td><Badge tone={TONE[e.kind] || "info"}>{LABELS[e.kind] || e.kind}</Badge></td>
                  <td className="mono">{e.proxy_host || `#${e.proxy_id}`}</td>
                  <td>{e.detail}</td>
                  <td className="muted">{e.baseline > 0 ? fmtValue(e.kind, e.baseline) : "—"}</td>
                  <td>
                    {e.state === "open" ? (
                      <Badge tone="bad">open</Badge>
                    ) : (
                      <Badge tone="ok">{e.acknowledged_by ? `ack · ${e.acknowledged_by}` : "acknowledged"}</Badge>
                    )}
                  </td>
                  <td>
                    {e.state === "open" && (
                      <button
                        className="small"
                        onClick={(ev) => {
                          ev.stopPropagation();
                          ack(e);
                        }}
                      >
                        Acknowledge
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>

      {mutes.length > 0 && (
        <Card title={`Muted destinations (${mutes.length})`}>
          <p className="faint small-text" style={{ marginTop: 0 }}>
            Outbound spikes toward these addresses are expected and raise no event. Unmute to detect them again.
          </p>
          {mutes.map((m) => (
            <div className="bar-row" key={`${m.proxy_id}-${m.address}`}>
              <div>
                <span className="mono">{m.address}</span>
                <div className="faint small-text">{hostOf(m.proxy_id)} · muted {fmtAgo(m.at)}</div>
              </div>
              <button className="small" onClick={() => unmute(m.proxy_id, m.address)} disabled={busy}>Unmute</button>
            </div>
          ))}
        </Card>
      )}

      {selected && (
        <Drawer
          title={<span className="mono">{selected.proxy_host || `#${selected.proxy_id}`}</span>}
          sub={`${LABELS[selected.kind] || selected.kind} · ${fmtAgo(selected.last_seen)} · ${selected.detail}`}
          onClose={() => setSelected(null)}
          footer={<button className="small" onClick={() => setSelected(null)}>Close</button>}
        >
          <div className="bar-row">
            <div>Value</div>
            <div className="mono">{fmtValue(selected.kind, selected.value)}</div>
          </div>
          <div className="bar-row">
            <div>
              Baseline
              <div className="faint small-text">this site's median over the last hour</div>
            </div>
            <div className="mono">{selected.baseline > 0 ? fmtValue(selected.kind, selected.baseline) : "—"}</div>
          </div>
          <div className="bar-row">
            <div>
              Window
              <div className="faint small-text">{new Date(selected.window_start).toLocaleString()}</div>
            </div>
            <div className="mono">{selected.window_seconds}s</div>
          </div>
          <div className="bar-row">
            <div>State</div>
            <div>
              {selected.state === "open" ? (
                <Badge tone="bad">open</Badge>
              ) : (
                <Badge tone="ok">acknowledged{selected.acknowledged_by ? ` · ${selected.acknowledged_by}` : ""}</Badge>
              )}
            </div>
          </div>

          <h3 style={{ margin: "18px 0 4px", fontSize: 13 }}>Where the outbound traffic goes</h3>
          <p className="faint small-text" style={{ marginTop: 0 }}>
            Every request to this site is forwarded to its configured upstreams, so this is where the bytes left for.
          </p>
          {dests === null ? (
            <p className="muted">Loading…</p>
          ) : dests.length === 0 ? (
            <Empty>This site has no upstreams configured, so there is no destination to show.</Empty>
          ) : (
            dests.map((d) => (
              <div className="bar-row" key={d.url}>
                <div>
                  <span className="mono">{d.address}{d.port ? `:${d.port}` : ""}</span>
                  <div className="faint small-text">
                    {d.resolved && d.resolved.length > 0 ? d.resolved.join(", ") : "the name did not resolve"} · {d.url}
                  </div>
                  <div style={{ marginTop: 4 }}>
                    {d.whitelist ? (
                      <Badge tone="ok">whitelisted · {d.whitelist}</Badge>
                    ) : (
                      <span className="faint small-text">not covered by an IP whitelist</span>
                    )}
                    {d.muted && <span style={{ marginLeft: 8 }}><Badge tone="info">muted</Badge></span>}
                  </div>
                </div>
                {d.muted ? (
                  <button className="small" onClick={() => unmute(selected.proxy_id, d.address)} disabled={busy}>
                    Unmute
                  </button>
                ) : (
                  <button className="small" onClick={() => mute(d)} disabled={busy}>
                    Mute destination
                  </button>
                )}
              </div>
            ))
          )}
          <p className="faint small-text">
            A site whose every upstream is muted raises no outbound spikes. Requests, rate spikes and login failures
            are detected as before, and the notification class can still be muted separately under{" "}
            <strong>Notifications</strong>.
          </p>
        </Drawer>
      )}
    </div>
  );
}
