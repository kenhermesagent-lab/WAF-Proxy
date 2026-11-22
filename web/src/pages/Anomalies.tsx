import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo } from "../ui";
import type { AnomalyConfig, AnomalyEvent } from "../types";

const LABELS: Record<string, string> = {
  egress_spike: "Outbound spike",
  rate_spike: "Request-rate spike",
  auth_burst: "Login-failure burst",
};

const TONE: Record<string, "bad" | "warn" | "info"> = {
  egress_spike: "bad",
  rate_spike: "warn",
  auth_burst: "info",
};

export default function Anomalies({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [events, setEvents] = useState<AnomalyEvent[]>([]);
  const [cfg, setCfg] = useState<AnomalyConfig | null>(null);
  const [saving, setSaving] = useState(false);

  const load = () =>
    api
      .get<{ events: AnomalyEvent[]; config: AnomalyConfig }>("/api/anomaly")
      .then((r) => {
        setEvents(r.events || []);
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

  const open = events.filter((e) => e.state === "open").length;

  return (
    <div className="grid" style={{ gap: 14 }}>
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
                <tr key={e.id}>
                  <td className="muted">{fmtAgo(e.last_seen)}</td>
                  <td><Badge tone={TONE[e.kind] || "info"}>{LABELS[e.kind] || e.kind}</Badge></td>
                  <td className="mono">{e.proxy_host || `#${e.proxy_id}`}</td>
                  <td>{e.detail}</td>
                  <td className="muted">{e.baseline > 0 ? e.baseline.toFixed(1) : "—"}</td>
                  <td>
                    {e.state === "open" ? (
                      <Badge tone="bad">open</Badge>
                    ) : (
                      <Badge tone="ok">{e.acknowledged_by ? `ack · ${e.acknowledged_by}` : "acknowledged"}</Badge>
                    )}
                  </td>
                  <td>
                    {e.state === "open" && (
                      <button className="small" onClick={() => ack(e)}>Acknowledge</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
    </div>
  );
}
