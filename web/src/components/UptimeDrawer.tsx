import { useEffect, useState } from "react";
import { api } from "../api";
import type { UptimeHistory } from "../types";
import { Badge, Drawer, Empty, errText, fmtTime } from "../ui";
import Chart from "./Chart";

function span(from: string, to?: string | null): string {
  const a = new Date(from).getTime();
  const b = to ? new Date(to).getTime() : Date.now();
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return "—";
  const s = Math.round((b - a) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function stateBadge(state: string) {
  if (state === "up") return <Badge tone="ok">up</Badge>;
  if (state === "down") return <Badge tone="bad">down</Badge>;
  if (state === "disabled") return <Badge tone="warn">disabled</Badge>;
  return <Badge tone="">unknown</Badge>;
}

function Facts({ t }: { t: UptimeHistory }) {
  const s = t.stats;
  const rows: [string, string][] = [
    ["24h uptime", t.checks_24 ? `${t.uptime_24.toFixed(1)}%` : "—"],
    ["Probes", `${s.checks}`],
    ["State since", t.last_change ? `${fmtTime(t.last_change)} (${span(t.last_change)})` : "—"],
    ["Latency p50 / p95", `${s.p50_ms} / ${s.p95_ms} ms`],
    ["p99 / max", `${s.p99_ms} / ${s.max_ms} ms`],
    ["Average", `${s.avg_ms} ms`],
  ];
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "max-content 1fr max-content 1fr",
        gap: "3px 14px",
        fontSize: 12,
      }}
    >
      {rows.map(([k, v]) => (
        <span key={k} style={{ display: "contents" }}>
          <span className="faint">{k}</span>
          <span>{v}</span>
        </span>
      ))}
    </div>
  );
}

/**
 * The history behind one uptime row: the latency every 30 seconds, the outages
 * with when they started and ended, and the stretches that were merely slow.
 * A failing probe is drawn at 0 ms so an outage reads as a gap to the floor.
 */
export default function UptimeDrawer({
  proxyId,
  proxyHost,
  onClose,
  onError,
}: {
  proxyId: number;
  proxyHost: string;
  onClose: () => void;
  onError: (m: string) => void;
}) {
  const [targets, setTargets] = useState<UptimeHistory[] | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .get<{ targets: UptimeHistory[] }>(`/api/uptime/history?proxy_id=${proxyId}`)
        .then((r) => alive && setTargets(r.targets ?? []))
        .catch((e) => {
          if (!alive) return;
          onError(errText(e));
          setTargets([]);
        });
    load();
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [proxyId]);

  return (
    <Drawer title={`Uptime · ${proxyHost}`} sub="Probes every 30 seconds, kept for 24 hours" onClose={onClose} wide>
      {targets === null ? (
        <p className="muted">Loading…</p>
      ) : targets.length === 0 ? (
        <Empty title="No probe history yet" icon="chart">
          The monitor records its first sample on the next check, within 30 seconds.
        </Empty>
      ) : (
        <div className="grid" style={{ gap: 16 }}>
          {targets.map((t) => {
            const labels = t.samples.map((s) =>
              new Date(s.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
            );
            const values = t.samples.map((s) => (s.ok ? s.ms : 0));
            return (
              <div key={t.id} className="grid" style={{ gap: 10 }}>
                <div className="row" style={{ gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
                  {stateBadge(t.state)}
                  <span className="mono" style={{ fontSize: 12 }}>{t.url || "no enabled upstream"}</span>
                  {t.status_code ? <span className="faint">HTTP {t.status_code}</span> : null}
                  {t.error && <span className="faint">{t.error}</span>}
                </div>
                <Facts t={t} />
                <Chart
                  series={[{ label: "Latency (ms)", color: "#5b9dff", values, area: true }]}
                  labels={labels}
                  height={170}
                  format={(n) => `${Math.round(n)} ms`}
                />
                <p className="muted" style={{ fontSize: 11.5, margin: 0 }}>
                  A failed probe is drawn at 0 ms; the outages below name what it returned.
                </p>

                <div>
                  <div className="faint" style={{ fontSize: 11.5, marginBottom: 4 }}>
                    Outages ({t.incidents.length})
                  </div>
                  {t.incidents.length === 0 ? (
                    <p className="muted" style={{ fontSize: 12, margin: 0 }}>No outage in the last 24 hours.</p>
                  ) : (
                    <div className="table-wrap"><table className="table-compact">
                      <thead>
                        <tr><th>Down</th><th>Back</th><th>Lasted</th><th className="num">Probes</th><th>Error</th></tr>
                      </thead>
                      <tbody>
                        {t.incidents.map((inc) => (
                          <tr key={inc.start}>
                            <td className="muted">{fmtTime(inc.start)}</td>
                            <td className="muted">{inc.end ? fmtTime(inc.end) : <Badge tone="bad">ongoing</Badge>}</td>
                            <td>{span(inc.start, inc.end)}</td>
                            <td className="num">{inc.checks}</td>
                            <td className="muted" title={inc.error}>{inc.error || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table></div>
                  )}
                </div>

                <div>
                  <div className="faint" style={{ fontSize: 11.5, marginBottom: 4 }}>
                    Slow stretches ({t.slow.length})
                  </div>
                  {t.slow.length === 0 ? (
                    <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                      Nothing above 250 ms or twice the median for two probes in a row.
                    </p>
                  ) : (
                    <div className="table-wrap"><table className="table-compact">
                      <thead>
                        <tr><th>Started</th><th>Ended</th><th>Lasted</th><th className="num">Probes</th><th className="num">Average</th><th className="num">Peak</th></tr>
                      </thead>
                      <tbody>
                        {t.slow.map((s) => (
                          <tr key={s.start}>
                            <td className="muted">{fmtTime(s.start)}</td>
                            <td className="muted">{fmtTime(s.end)}</td>
                            <td>{span(s.start, s.end)}</td>
                            <td className="num">{s.checks}</td>
                            <td className="num">{s.avg_ms} ms</td>
                            <td className="num">{s.max_ms} ms</td>
                          </tr>
                        ))}
                      </tbody>
                    </table></div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Drawer>
  );
}
