import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import Globe from "../components/Globe";
import { Badge, Card, Empty, fmtAgo, fmtBps, fmtBytes } from "../ui";
import { Event, GlobePoint, Metrics, Proxy } from "../types";

type Rate = { requests: number; bytesIn: number; bytesOut: number };

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
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [rates, setRates] = useState<Record<string, Rate>>({});
  const [hours, setHours] = useState(1);
  const [connected, setConnected] = useState(false);
  const previous = useRef<{ at: number; proxies: Metrics["proxies"] } | null>(null);
  const hoursRef = useRef(hours);
  hoursRef.current = hours;

  // Rates are derived from the cumulative counters that arrive every second.
  // Keeping the previous frame in a ref avoids a second server-side counter.
  const applyMetrics = useCallback((m: Metrics) => {
    const at = Date.now();
    const prev = previous.current;
    if (prev) {
      const dt = (at - prev.at) / 1000;
      if (dt >= 0.2 && dt <= 30) {
        const next: Record<string, Rate> = {};
        for (const [id, c] of Object.entries(m.proxies || {})) {
          const before = prev.proxies[id];
          next[id] = {
            requests: before ? Math.max(0, (c.requests - before.requests) / dt) : 0,
            bytesIn: before ? Math.max(0, (c.bytes_in - before.bytes_in) / dt) : 0,
            bytesOut: before ? Math.max(0, (c.bytes_out - before.bytes_out) / dt) : 0,
          };
        }
        setRates(next);
      }
    }
    previous.current = { at, proxies: m.proxies || {} };
    setMetrics(m);
    setConnected(true);
  }, []);

  useEffect(() => {
    const es = new EventSource("/api/stream");
    es.addEventListener("open", () => setConnected(true));
    es.addEventListener("error", () => setConnected(false));
    es.addEventListener("metrics", (ev) => {
      try {
        applyMetrics(JSON.parse((ev as MessageEvent).data));
      } catch {
        /* ignore malformed frame */
      }
    });
    es.addEventListener("globe", (ev) => {
      if (hoursRef.current !== 1) return;
      try {
        setPoints(JSON.parse((ev as MessageEvent).data));
      } catch {
        /* ignore */
      }
    });
    return () => es.close();
  }, [applyMetrics]);

  // Paint once from the REST endpoints: the first SSE frame is up to a second
  // away, and a blocked EventSource (an extension or proxy) would otherwise
  // leave the page empty forever.
  useEffect(() => {
    api
      .get<Metrics>("/api/metrics")
      .then((m) => {
        if (!previous.current) applyMetrics(m);
      })
      .catch(() => undefined);
    api.get<Proxy[]>("/api/proxies").then(setProxies).catch(() => undefined);
  }, [applyMetrics]);

  // The SSE globe feed is one hour; longer ranges are fetched on a slower poll
  // so the database query stays cheap while the user explores the history.
  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .get<GlobePoint[]>(`/api/globe?hours=${hours}`)
        .then((p) => alive && setPoints(p || []))
        .catch(() => undefined);
    load();
    if (hours === 1) return () => { alive = false; };
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [hours]);

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

  const proxyRows = useMemo(() => {
    const names = new Map(proxies.map((p) => [String(p.id), p.hostname]));
    return Object.entries(metrics?.proxies ?? {})
      .map(([id, c]) => ({ id, host: names.get(id) || `proxy #${id}`, ...c, rate: rates[id] }))
      .sort((a, b) => b.requests - a.requests);
  }, [metrics, proxies, rates]);

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

      <Card
        title="Proxy traffic"
        actions={<span className="muted" style={{ fontSize: 11 }}>live rates over the last second</span>}
      >
        {proxyRows.length === 0 ? (
          <Empty>No requests since the service started.</Empty>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Proxy</th>
                  <th className="num">Requests</th>
                  <th className="num">Req/s</th>
                  <th className="num">Inbound</th>
                  <th className="num">Outbound</th>
                  <th className="num">Blocked</th>
                  <th className="num">Total traffic</th>
                </tr>
              </thead>
              <tbody>
                {proxyRows.map((p, i) => (
                  <tr key={p.id}>
                    <td>
                      <span>{p.host}</span>{" "}
                      {i === 0 && <Badge tone="info">most used</Badge>}
                    </td>
                    <td className="num">{p.requests.toLocaleString()}</td>
                    <td className="num">{p.rate ? p.rate.requests.toFixed(1) : "—"}</td>
                    <td className="num">{p.rate ? fmtBps(p.rate.bytesIn) : "—"}</td>
                    <td className="num">{p.rate ? fmtBps(p.rate.bytesOut) : "—"}</td>
                    <td className="num">{p.blocked.toLocaleString()}</td>
                    <td className="num">{fmtBytes(p.bytes_in + p.bytes_out)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="split">
        <Card
          title="Live attacks"
          actions={
            <div className="row" style={{ gap: 6 }}>
              {[1, 6, 24].map((h) => (
                <button
                  key={h}
                  className={`small ${hours === h ? "primary" : ""}`}
                  onClick={() => setHours(h)}
                  aria-pressed={hours === h}
                >
                  {h}h
                </button>
              ))}
              <span className={`badge ${connected ? "ok" : "warn"}`}>{connected ? "live" : "reconnecting"}</span>
            </div>
          }
        >
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
              <div className="muted" style={{ fontSize: 11, letterSpacing: ".07em", textTransform: "uppercase" }}>WAN → LAN</div>
              <div className="mono" style={{ fontSize: 12 }}>
                {metrics?.wan.name || "—"} <span className="muted">→</span> {metrics?.lan.name || "—"}
              </div>
              <div className="muted" style={{ fontSize: 11 }}>
                {metrics?.dual_nic ? "separate counters" : "same interface"}
              </div>
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
          <div style={{ overflowX: "auto" }}>
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
                  <td className="muted" title={e.rule_msg || e.rule_id} style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.rule_msg || e.rule_id || "—"}</td>
                  <td className="num">{e.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </Card>
    </div>
  );
}
