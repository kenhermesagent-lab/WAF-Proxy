import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import Globe from "../components/Globe";
import AttackMap from "../components/AttackMap";
import Chart from "../components/Chart";
import Icon from "../components/Icon";
import { countryFlag, countryName } from "../countries";
import { Badge, Card, Empty, Info, Skeleton, TableWrap, fmtAgo, fmtBps, fmtBytes, fmtTime } from "../ui";
import { AnomalyEvent, Cert, Event, Feed, GlobeHit, GlobePoint, Metrics, Proxy, UpdatesSnapshot, Uptime } from "../types";

type Rate = { requests: number; bytesIn: number; bytesOut: number };

function compactBps(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB/s`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB/s`;
  if (n >= 1e3) return `${Math.round(n / 1e3)} KB/s`;
  return `${Math.round(n)} B/s`;
}

function historyLabel(ts: number, index: number, total: number): string {
  const ms = ts > 1e12 ? ts : Date.now() - (total - 1 - index) * 1000;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function Dashboard({
  onError,
  home,
  onOpenSource,
}: {
  onError: (m: string) => void;
  home: { lat: number; lon: number };
  onOpenSource: (ip: string) => void;
}) {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [points, setPoints] = useState<GlobePoint[]>([]);
  const [hits, setHits] = useState<GlobeHit[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [uptime, setUptime] = useState<Uptime | null>(null);
  const [certs, setCerts] = useState<Cert[]>([]);
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyEvent[]>([]);
  const [updates, setUpdates] = useState<UpdatesSnapshot | null>(null);
  const [rates, setRates] = useState<Record<string, Rate>>({});
  const [hours, setHours] = useState(1);
  const [connected, setConnected] = useState(false);
  const [mapOpen, setMapOpen] = useState(false);
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
  // away, and a blocked EventSource would otherwise leave the page empty.
  useEffect(() => {
    api
      .get<Metrics>("/api/metrics")
      .then((m) => {
        if (!previous.current) applyMetrics(m);
      })
      .catch(() => undefined);
    api.get<Proxy[]>("/api/proxies").then(setProxies).catch(() => undefined);
  }, [applyMetrics]);

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
    if (hours !== 1) {
      setHits([]);
      return;
    }
    let alive = true;
    let since = new Date(Date.now() - 60000).toISOString();
    const load = () =>
      api
        .get<GlobeHit[]>(`/api/globe/hits?since=${encodeURIComponent(since)}`)
        .then((rows) => {
          if (!alive || !rows || rows.length === 0) return;
          since = rows[0].ts;
          setHits((prev) => {
            const known = new Set(prev.map((h) => h.id));
            const add = rows.filter((h) => !known.has(h.id));
            if (add.length === 0) return prev;
            const cutoff = Date.now() - 60000;
            return [...add, ...prev].filter((h) => Date.parse(h.ts) >= cutoff).slice(0, 240);
          });
        })
        .catch(() => undefined);
    load();
    const t = setInterval(load, 2000);
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
        .then((r) => alive && setEvents(r.events ?? []))
        .catch((e) => alive && onError(e.message));
    load();
    const t = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [onError]);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .get<Uptime>("/api/uptime")
        .then((u) => alive && setUptime(u))
        .catch(() => undefined);
    load();
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // Everything the attention queue reads. Each source is optional: a role
  // without the permission, or a node with no detector, simply has none.
  useEffect(() => {
    let alive = true;
    const load = () => {
      Promise.all([
        api.get<{ certs: Cert[] }>("/api/certs").catch(() => ({ certs: [] })),
        api.get<{ feeds: Feed[] }>("/api/feeds").catch(() => ({ feeds: [] })),
        api.get<{ events: AnomalyEvent[] }>("/api/anomaly").catch(() => ({ events: [] })),
        api.get<UpdatesSnapshot>("/api/updates").catch(() => null),
      ]).then(([c, f, a, u]) => {
        if (!alive) return;
        setCerts(c?.certs ?? []);
        setFeeds(f?.feeds ?? []);
        setAnomalies(a?.events ?? []);
        setUpdates(u);
      });
    };
    load();
    const t = setInterval(load, 60000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

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

  const history = metrics?.history ?? [];
  const hasTraffic = history.some((h) => h.proxy_rx > 0 || h.proxy_tx > 0);
  const chartLabels = history.map((h, i) => historyLabel(h.ts, i, history.length));

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
    return [...map.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 6);
  }, [events]);

  const regions = useMemo(() => {
    const map = new Map<string, number>();
    for (const p of points) map.set(p.country, (map.get(p.country) ?? 0) + p.count);
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  }, [points]);

  const blockedShare = totals.requests ? (totals.blocked / totals.requests) * 100 : 0;

  // The attention queue has no dismiss state: an item stays until its cause
  // clears, so the list can never disagree with the resources it summarises.
  const attention = useMemo(() => {
    const items: { id: string; tone: "bad" | "warn"; title: string; detail: string; href: string; action: string }[] = [];
    const now = Date.now();
    const downTargets = (uptime?.targets ?? []).filter((t) => t.state === "down");
    if (downTargets.length > 0) {
      items.push({
        id: "backends",
        tone: "bad",
        title: `${downTargets.length} backend${downTargets.length === 1 ? "" : "s"} down`,
        detail: downTargets.slice(0, 3).map((t) => t.proxy_host).join(", ") + (downTargets.length > 3 ? ` +${downTargets.length - 3} more` : ""),
        href: "#/statistics",
        action: "View uptime",
      });
    }
    const failedCerts = certs.filter((c) => !!c.last_error);
    if (failedCerts.length > 0) {
      items.push({
        id: "certs-failed",
        tone: "bad",
        title: `${failedCerts.length} certificate renewal${failedCerts.length === 1 ? " has" : "s have"} failed`,
        detail: failedCerts.slice(0, 2).map((c) => `${c.domains}: ${c.last_error}`).join(" · "),
        href: "#/proxies/certs",
        action: "Open certificates",
      });
    }
    const expiring = certs.filter((c) => {
      const at = Date.parse(c.expires_at || "");
      return Number.isFinite(at) && at - now < 21 * 86400000 && !c.last_error;
    });
    if (expiring.length > 0) {
      items.push({
        id: "certs-expiring",
        tone: "warn",
        title: `${expiring.length} certificate${expiring.length === 1 ? " expires" : "s expire"} within 21 days`,
        detail: expiring.slice(0, 3).map((c) => c.domains).join(", "),
        href: "#/proxies/certs",
        action: "Review renewals",
      });
    }
    const badFeeds = feeds.filter((f) => f.enabled && (f.state === "error" || f.state === "frozen"));
    if (badFeeds.length > 0) {
      items.push({
        id: "feeds",
        tone: "warn",
        title: `${badFeeds.length} threat feed${badFeeds.length === 1 ? "" : "s"} need attention`,
        detail: badFeeds.slice(0, 3).map((f) => `${f.name} (${f.state})`).join(", "),
        href: "#/intel/feeds",
        action: "Open threat intel",
      });
    }
    const openAnomalies = anomalies.filter((a) => a.state === "open" && Date.parse(a.created_at) > now - 86400000);
    if (openAnomalies.length > 0) {
      items.push({
        id: "anomalies",
        tone: "warn",
        title: `${openAnomalies.length} unexplained anomal${openAnomalies.length === 1 ? "y" : "ies"} in the last 24h`,
        detail: openAnomalies.slice(0, 3).map((a) => `${a.proxy_host}: ${a.kind}`).join(", "),
        href: "#/anomalies",
        action: "Review anomalies",
      });
    }
    const securityUpdates = updates?.packages?.filter((p) => p.security && p.can_update) ?? [];
    if (securityUpdates.length > 0) {
      items.push({
        id: "security-updates",
        tone: "warn",
        title: `${securityUpdates.length} security package update${securityUpdates.length === 1 ? "" : "s"} pending`,
        detail: securityUpdates.slice(0, 3).map((p) => p.name).join(", "),
        href: "#/settings/updates",
        action: "Open updates",
      });
    }
    if (updates?.app_update_available) {
      items.push({
        id: "app-update",
        tone: "warn",
        title: `Console update available${updates.app_remote_version ? `: v${updates.app_remote_version}` : ""}`,
        detail: "Apply it from Updates when the node has a quiet moment.",
        href: "#/settings/updates",
        action: "Open updates",
      });
    }
    return items;
  }, [anomalies, certs, feeds, updates, uptime]);

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="page-head">
        <div>
          <p>Live traffic, blocked requests and upstream health across every proxy on this node.</p>
        </div>
        <div className="actions">
          <span className={`badge ${connected ? "ok" : "warn"}`}>
            <span className="dot" aria-hidden="true" />
            {connected ? "Streaming live" : "Reconnecting"}
          </span>
          <a className="small" href="#/statistics" style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--muted)", fontSize: 12 }}>
            <Icon name="chart" size={14} /> Analytics
          </a>
        </div>
      </div>

      <Card
        title="Needs attention"
        actions={
          attention.length ? (
            <Badge tone={attention.some((a) => a.tone === "bad") ? "bad" : "warn"}>{attention.length} open</Badge>
          ) : (
            <span className="faint small-text">checked every minute</span>
          )
        }
      >
        {attention.length === 0 ? (
          <Empty title="Nothing needs you" icon="check">
            Backends, certificates, threat feeds and updates are all healthy.
          </Empty>
        ) : (
          <div className="grid" style={{ gap: 8 }}>
            {attention.map((a) => (
              <div className={`banner ${a.tone}`} role="status" key={a.id}>
                <Icon name="alert" size={16} />
                <span>
                  <b>{a.title}</b>
                  {a.detail ? ` · ${a.detail}` : ""}
                </span>
                <span className="banner-actions">
                  <a className="small" href={a.href}>{a.action}</a>
                </span>
              </div>
            ))}
          </div>
        )}
      </Card>

      <div className="kpi-grid">
        {!metrics ? (
          Array.from({ length: 6 }).map((_, i) => <div className="skeleton kpi" key={i} />)
        ) : (
          <>
            <div className="kpi">
              <div className="kpi-label">
                Proxy traffic
                <Info label="How byte accounting works">
                  Every byte on the HTTPS listener, headers and TLS included, so it matches what the WAN interface
                  sees for proxied hosts. “Server &amp; other” is the rest of the interface: SSH, this console, OS
                  updates and upstream legs.
                </Info>
              </div>
              <div className="kpi-pair">
                <div>
                  <div className="kpi-dir"><span className="in">↓</span>Inbound</div>
                  <div className="kpi-value">{fmtBps(metrics.proxy.in_bps)}</div>
                  <div className="kpi-sub">{fmtBytes(metrics.proxy.in_total)} total</div>
                </div>
                <div>
                  <div className="kpi-dir"><span className="out">↑</span>Outbound</div>
                  <div className="kpi-value">{fmtBps(metrics.proxy.out_bps)}</div>
                  <div className="kpi-sub">{fmtBytes(metrics.proxy.out_total)} total</div>
                </div>
              </div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Requests</div>
              <div className="kpi-value">{totals.requests.toLocaleString()}</div>
              <div className="kpi-sub">{blockedShare.toFixed(2)}% blocked · {fmtBytes(totals.bytesOut)} delivered</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Blocked</div>
              <div className="kpi-value">{totals.blocked.toLocaleString()}</div>
              <div className="kpi-sub">{metrics.inflight} in flight · {metrics.shed.toLocaleString()} shed at capacity</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Sessions</div>
              <div className="kpi-value">{metrics.sessions.active.toLocaleString()}</div>
              <div className="kpi-sub">
                {metrics.sessions.available
                  ? `${metrics.sessions.established.toLocaleString()} established · ${metrics.sessions.time_wait} time-wait`
                  : "conntrack unavailable"}
              </div>
              <div className="facts" style={{ marginTop: 10 }}>
                <span><b>{metrics.wan.name || "—"}</b> WAN</span>
                <span><b>{metrics.lan.name || "—"}</b> LAN</span>
                <span>{metrics.dual_nic ? "dual NIC" : "single NIC"}</span>
              </div>
            </div>
            <div className="kpi">
              <div className="kpi-label">
                Server &amp; other
                <Info label="What server traffic means">
                  Actual host traffic outside the proxy listeners: SSH, this console, OS updates and the upstream legs
                  of proxied requests. It is not proxy traffic.
                </Info>
              </div>
              <div className="kpi-pair">
                <div>
                  <div className="kpi-dir"><span className="other-in">↓</span>Inbound</div>
                  <div className="kpi-value">{fmtBps(metrics.host.in_bps)}</div>
                  <div className="kpi-sub">{fmtBytes(metrics.host.in_total)} total</div>
                </div>
                <div>
                  <div className="kpi-dir"><span>↑</span>Outbound</div>
                  <div className="kpi-value">{fmtBps(metrics.host.out_bps)}</div>
                  <div className="kpi-sub">{fmtBytes(metrics.host.out_total)} total</div>
                </div>
              </div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Request budget</div>
              <div className="kpi-value">
                {metrics.inflight}
                <small> / {metrics.max_inflight}</small>
              </div>
              <div className="kpi-meter" aria-hidden="true">
                <span style={{ width: `${metrics.max_inflight ? Math.min(100, (metrics.inflight / metrics.max_inflight) * 100) : 0}%` }} />
              </div>
              <div className="kpi-sub">
                {metrics.max_inflight ? `${Math.round((metrics.inflight / metrics.max_inflight) * 100)}% of max` : "no limit"} ·{" "}
                {metrics.shed.toLocaleString()} refused while full
              </div>
            </div>
          </>
        )}
      </div>

      <Card
        title="Network throughput"
        sub="WAN-facing proxy traffic sampled every second. Rates update live."
        actions={<span className="faint small-text">{history.length ? `last ${history.length}s` : ""}</span>}
      >
        {!metrics ? (
          <Skeleton kind="block" />
        ) : !hasTraffic ? (
          <Empty title="No proxy traffic yet" icon="chart">
            Rates appear here once a proxy serves a request.
          </Empty>
        ) : (
          <Chart
            series={[
              { label: "Proxy inbound", color: "#4f8cff", values: history.map((h) => h.proxy_rx), area: true },
              { label: "Proxy outbound", color: "#3ecf8e", values: history.map((h) => h.proxy_tx), area: true },
            ]}
            labels={chartLabels}
            height={200}
            format={compactBps}
            tooltipTitle={(label) => `Sample ${label}`}
          />
        )}
      </Card>

      <div className="split">
        <Card
          title="Live attacks"
          actions={
            <>
              <div className="btn-group">
                {[1, 6, 24].map((h) => (
                  <button
                    key={h}
                    className={`xsmall ${hours === h ? "primary" : ""}`}
                    onClick={() => setHours(h)}
                    aria-pressed={hours === h}
                  >
                    {h}h
                  </button>
                ))}
              </div>
              <button className="small" onClick={() => setMapOpen(true)}>
                <Icon name="expand" size={13} /> Open map
              </button>
            </>
          }
        >
          <Globe points={points} hits={hits} home={home} hours={hours} variant="compact" />
          <div className="facts" style={{ marginTop: 10 }}>
            <span>Source regions ranked by blocked requests</span>
            <span style={{ marginLeft: "auto" }}>{regions.reduce((n, [, c]) => n + c, 0).toLocaleString()} blocked</span>
          </div>
        </Card>

        <Card
          title="Top regions"
          actions={<button className="xsmall ghost" onClick={() => setMapOpen(true)}>Drill in</button>}
        >
          {regions.length === 0 ? (
            <Empty title="No blocked traffic yet" icon="globe">Regions appear here as blocked requests arrive.</Empty>
          ) : (
            <div className="region-list">
              {regions.slice(0, 7).map(([country, count], i) => (
                <button key={country} className="region-row" onClick={() => setMapOpen(true)}>
                  <span className="flag">{countryFlag(country) || "•"}</span>
                  <span className="region-name">{countryName(country) || "Unknown"}</span>
                  <span className="region-count">{count.toLocaleString()}</span>
                  <span className="region-bar">
                    <i style={{ width: `${Math.max(3, (count / regions[0][1]) * 100)}%`, opacity: 1 - i * 0.08 }} />
                  </span>
                </button>
              ))}
            </div>
          )}
          <div className="mt">
            <div className="row between small-text faint">
              <span>Attacks in window</span>
              <span style={{ color: "var(--muted)" }}>{regions.length} regions</span>
            </div>
          </div>
        </Card>
      </div>

      <div className="split">
        <Card title="Proxy traffic" actions={<a className="xsmall" href="#/proxies/sites" style={{ color: "var(--muted)", fontSize: 11.5 }}>Manage proxies</a>}>
          {proxyRows.length === 0 ? (
            <Empty title="No requests since start" icon="server">Traffic appears as soon as a proxy accepts a request.</Empty>
          ) : (
            <TableWrap>
              <table>
                <thead>
                  <tr>
                    <th>Proxy</th>
                    <th className="num">Requests</th>
                    <th className="num">Req/s</th>
                    <th className="num">Inbound</th>
                    <th className="num">Outbound</th>
                    <th className="num">Blocked</th>
                    <th className="num">Total</th>
                  </tr>
                </thead>
                <tbody>
                  {proxyRows.map((p) => (
                    <tr key={p.id}>
                      <td>
                        <div className="mono" style={{ fontSize: 12 }}>{p.host}</div>
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
            </TableWrap>
          )}
        </Card>

        <Card title="Top blocked sources" actions={<span className="faint small-text">last {events.length} events</span>}>
          {topSources.length === 0 ? (
            <Empty title="Nothing blocked yet" icon="shield">Traffic that trips a policy will appear here.</Empty>
          ) : (
            topSources.map(([ip, info]) => (
              <div className="bar-row" key={ip}>
                <div style={{ minWidth: 0 }}>
                  <div className="row between">
                    <button className="link-cell mono" style={{ fontSize: 11.5 }} onClick={() => onOpenSource(ip)} title={`Investigate ${ip}`}>{ip}</button>
                    <span className="faint small-text">{countryFlag(info.country)} {countryName(info.country) || "—"}</span>
                  </div>
                  <div className="bar-track">
                    <div className="bar-fill" style={{ width: `${(info.count / topSources[0][1].count) * 100}%` }} />
                  </div>
                </div>
                <div className="right" style={{ fontVariantNumeric: "tabular-nums" }}>{info.count}</div>
              </div>
            ))
          )}
        </Card>
      </div>

      <Card
        title="Recent blocked requests"
        actions={<a className="xsmall" href="#/logs?blocked=1" style={{ color: "var(--muted)", fontSize: 11.5 }}>Open log</a>}
      >
        {events.length === 0 ? (
          <Empty title="No blocked requests" icon="shield">The most recent policy blocks will show up here.</Empty>
        ) : (
          <TableWrap>
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
                    <td className="muted" title={fmtTime(e.ts)} style={{ whiteSpace: "nowrap" }}>{fmtAgo(e.ts)}</td>
                    <td>
                      <button className="link-cell mono" style={{ fontSize: 11.5 }} onClick={() => onOpenSource(e.src_ip)} title={`Investigate ${e.src_ip}`}>{e.src_ip}</button>
                      <div className="faint small-text">{countryName(e.country) || e.country || "—"} · AS{e.asn || "?"}</div>
                    </td>
                    <td className="muted">{e.host}</td>
                    <td className="mono" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.method} {e.path}</td>
                    <td><Badge tone="bad">{e.stage}</Badge></td>
                    <td className="muted" title={e.rule_msg || e.rule_id} style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.rule_msg || e.rule_id || "—"}</td>
                    <td className="num">{e.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      {mapOpen && (
        <AttackMap
          points={points}
          hits={hits}
          home={home}
          hours={hours}
          onHours={setHours}
          onClose={() => setMapOpen(false)}
          onError={onError}
          onOpenSource={onOpenSource}
        />
      )}
    </div>
  );
}
