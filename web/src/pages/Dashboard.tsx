import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import Globe from "../components/Globe";
import { Card, Empty, fmtAgo, fmtBps, fmtBytes } from "../ui";
import { Event, GlobePoint, Metrics } from "../types";

function Spark({ values, color }: { values: number[]; color: string }) {
  const max = Math.max(1, ...values);
  const pts = values
    .map((v, i) => {
      const x = (i / Math.max(1, values.length - 1)) * 100;
      const y = 28 - (v / max) * 26;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" style={{ width: "100%", height: 36 }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export default function Dashboard({ onError, home }: { onError: (m: string) => void; home: { lat: number; lon: number } }) {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [points, setPoints] = useState<GlobePoint[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const es = new EventSource("/api/stream");
    es.addEventListener("open", () => setConnected(true));
    es.addEventListener("error", () => setConnected(false));
    es.addEventListener("metrics", (ev) => {
      try {
        setMetrics(JSON.parse((ev as MessageEvent).data));
        setConnected(true);
      } catch {
        /* ignore malformed frame */
      }
    });
    es.addEventListener("globe", (ev) => {
      try {
        setPoints(JSON.parse((ev as MessageEvent).data));
      } catch {
        /* ignore */
      }
    });
    return () => es.close();
  }, []);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .get<{ events: Event[]; total: number }>("/api/events?limit=40&blocked=1")
        .then((r) => alive && setEvents(r.events))
        .catch((e) => alive && onError(e.message));
    load();
    const t = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [onError]);

  const totals = useMemo(() => {
    const t = { requests: 0, blocked: 0, bytesIn: 0, bytesOut: 0 };
    if (metrics) {
      for (const c of Object.values(metrics.proxies)) {
        t.requests += c.requests;
        t.blocked += c.blocked;
        t.bytesIn += c.bytes_in;
        t.bytesOut += c.bytes_out;
      }
    }
    return t;
  }, [metrics]);

  const wanRx = metrics?.history.map((h) => h.wan_rx) ?? [];
  const wanTx = metrics?.history.map((h) => h.wan_tx) ?? [];

  const topSources = useMemo(() => {
    const map = new Map<string, { count: number; country: string }>();
    for (const e of events) {
      const cur = map.get(e.src_ip) ?? { count: 0, country: e.country };
      cur.count++;
      map.set(e.src_ip, cur);
    }
    return [...map.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 8);
  }, [events]);

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="grid cols-4">
        <Card>
          <div className="stat">
            <div className="k">WAN inbound</div>
            <div className="v">{fmtBps(metrics?.wan.rx_bps ?? 0)}</div>
            <div className="sub">{fmtBytes(metrics?.wan.rx_total ?? 0)} total · {Math.round(metrics?.wan.rx_pps ?? 0)} pps</div>
            <Spark values={wanRx} color="#3b82f6" />
          </div>
        </Card>
        <Card>
          <div className="stat">
            <div className="k">WAN outbound</div>
            <div className="v">{fmtBps(metrics?.wan.tx_bps ?? 0)}</div>
            <div className="sub">{fmtBytes(metrics?.wan.tx_total ?? 0)} total · {Math.round(metrics?.wan.tx_pps ?? 0)} pps</div>
            <Spark values={wanTx} color="#22c55e" />
          </div>
        </Card>
        <Card>
          <div className="stat">
            <div className="k">Sessions</div>
            <div className="v">{metrics?.sessions.active ?? 0}</div>
            <div className="sub">
              {metrics?.sessions.available
                ? `${metrics.sessions.established} established · ${metrics.sessions.time_wait} time-wait`
                : "conntrack unavailable"}
            </div>
          </div>
        </Card>
        <Card>
          <div className="stat">
            <div className="k">Requests</div>
            <div className="v">{totals.requests.toLocaleString()}</div>
            <div className="sub">{totals.blocked.toLocaleString()} blocked · {fmtBytes(totals.bytesOut)} out</div>
          </div>
        </Card>
      </div>

      <div className="split">
        <Card title="Live attacks" actions={<span className={`badge ${connected ? "ok" : "warn"}`}>{connected ? "live" : "reconnecting"}</span>}>
          <Globe points={points} home={home} />
          <div className="grid cols-2 mt">
            <div>
              <div className="k muted" style={{ fontSize: 11, letterSpacing: ".07em", textTransform: "uppercase" }}>LAN</div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="mono">↓ {fmtBps(metrics?.lan.rx_bps ?? 0)}</span>
                <span className="mono">↑ {fmtBps(metrics?.lan.tx_bps ?? 0)}</span>
              </div>
            </div>
            <div>
              <div className="muted" style={{ fontSize: 11, letterSpacing: ".07em", textTransform: "uppercase" }}>Dual NIC</div>
              <div>{metrics?.dual_nic ? <span className="badge ok">WAN + LAN separated</span> : <span className="badge warn">single interface</span>}</div>
            </div>
          </div>
        </Card>

        <Card title="Top blocked sources">
          {topSources.length === 0 && <Empty>No blocked traffic yet.</Empty>}
          {topSources.map(([ip, info]) => (
            <div className="bar-row" key={ip}>
              <div>
                <span className="mono">{ip}</span>
                <div className="bar-track">
                  <div className="bar-fill" style={{ width: `${(info.count / topSources[0][1].count) * 100}%` }} />
                </div>
              </div>
              <div className="right">
                <div>{info.count}</div>
                <div className="faint" style={{ fontSize: 11 }}>{info.country || "—"}</div>
              </div>
            </div>
          ))}
        </Card>
      </div>

      <Card title="Recent blocked requests">
        {events.length === 0 ? (
          <Empty>Nothing blocked yet. Traffic that trips a policy will appear here.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Host</th>
                <th>Request</th>
                <th>Stage</th>
                <th>Rule</th>
                <th className="num">Status</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 12).map((e) => (
                <tr key={e.id}>
                  <td className="muted">{fmtAgo(e.ts)}</td>
                  <td><span className="mono">{e.src_ip}</span><div className="faint" style={{ fontSize: 11 }}>{e.country || "—"} · AS{e.asn || "?"}</div></td>
                  <td className="muted">{e.host}</td>
                  <td className="mono" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.method} {e.path}</td>
                  <td><span className="badge bad">{e.stage}</span></td>
                  <td className="muted" style={{ maxWidth: 240 }}>{e.rule_msg || e.rule_id || "—"}</td>
                  <td className="num">{e.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
