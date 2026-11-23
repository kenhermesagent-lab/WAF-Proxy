import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { countryFlag, countryName } from "../countries";
import { Analytics, GateFailure, Uptime, UptimeTarget } from "../types";
import Chart from "../components/Chart";
import { Badge, Card, Empty, PageHead, PageTabs, errText, fmtAgo, fmtBytes, fmtTime } from "../ui";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "traffic", label: "Traffic" },
  { id: "uptime", label: "Uptime" },
  { id: "gate", label: "Access gate logins" },
];

const day = (offset: number) => {
  const d = new Date();
  d.setDate(d.getDate() + offset);
  return d.toISOString().slice(0, 10);
};

function duration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

function pct(part: number, total: number): string {
  return total ? `${((part / total) * 100).toFixed(1)}%` : "0%";
}

function stateBadge(state: string) {
  if (state === "up") return <Badge tone="ok">up</Badge>;
  if (state === "down") return <Badge tone="bad">down</Badge>;
  if (state === "disabled") return <Badge tone="warn">disabled</Badge>;
  return <Badge tone="">unknown</Badge>;
}

function UptimeRow({ t }: { t: UptimeTarget }) {
  return (
    <tr>
      <td className="proxy-cell">
        <div>{t.proxy_host}</div>
        <div className="mono faint" style={{ fontSize: 11 }}>{t.url || "no enabled upstream"}</div>
      </td>
      <td>{stateBadge(t.state)}</td>
      <td className="num">{t.checks_24 ? `${t.uptime_24.toFixed(1)}%` : "—"}</td>
      <td className="num hide-tablet">{t.state === "up" ? `${t.latency_ms} ms` : "—"}</td>
      <td className="num hide-tablet">{t.status_code || "—"}</td>
      <td className="muted hide-tablet">{t.last_check ? fmtTime(t.last_check) : "—"}</td>
      <td className="muted hide-tablet" title={t.error}>{t.error || "—"}</td>
    </tr>
  );
}

export default function Statistics({
  onError,
  tab = "overview",
  tabs = TABS,
  onTab,
}: {
  onError: (m: string) => void;
  tab?: string;
  tabs?: { id: string; label: string }[];
  onTab?: (id: string) => void;
}) {
  const [from, setFrom] = useState(day(-6));
  const [to, setTo] = useState(day(0));
  const [stats, setStats] = useState<Analytics | null>(null);
  const [uptime, setUptime] = useState<Uptime | null>(null);
  const [failures, setFailures] = useState<GateFailure[]>([]);
  const [loading, setLoading] = useState(false);

  const loadStats = () => {
    setLoading(true);
    api
      .get<Analytics>(`/api/analytics?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`)
      .then(setStats)
      .catch((e) => onError(errText(e)))
      .finally(() => setLoading(false));
  };

  const loadFailures = () =>
    api
      .get<{ failures: GateFailure[] }>(
        `/api/gate-failures?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
      )
      .then((r) => setFailures(r.failures || []))
      .catch((e) => onError(errText(e)));

  const block = async (f: GateFailure) => {
    try {
      await api.post("/api/bans", {
        cidr: f.ip,
        reason: `access gate: ${f.attempts} failed logins${f.username ? ` as ${f.username}` : ""}`,
        permanent: true,
      });
      loadFailures();
    } catch (e) {
      onError(errText(e));
    }
  };

  useEffect(() => {
    loadStats();
  }, [from, to]);

  // The failures table is one click away and costs a query, so it is only
  // fetched while its tab is open.
  useEffect(() => {
    if (tab === "gate") loadFailures();
  }, [tab, from, to]);

  useEffect(() => {
    let alive = true;
    const refresh = () =>
      api
        .get<Uptime>("/api/uptime")
        .then((u) => alive && setUptime(u))
        .catch(() => undefined);
    refresh();
    const t = setInterval(refresh, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const series = stats?.series ?? [];
  const errors = stats?.totals.blocked ?? 0;
  const requests = stats?.totals.requests ?? 0;
  const success = Math.max(0, requests - errors);
  const topCountries = useMemo(() => (stats?.countries ?? []).slice(0, 24), [stats]);
  const countryTotal = Math.max(1, ...(stats?.countries ?? []).map((c) => c.count));
  const down = (uptime?.targets ?? []).filter((t) => t.state === "down").length;
  const live = tab === "uptime";

  const labels = series.map((b) => {
    const d = new Date(b.bucket);
    if (Number.isNaN(d.getTime())) return "";
    return series.length <= 48
      ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : d.toLocaleDateString([], { month: "short", day: "numeric" });
  });
  const compact = (n: number) =>
    n >= 1e9 ? `${(n / 1e9).toFixed(1)}B` : n >= 1e6 ? `${(n / 1e6).toFixed(n % 1e6 === 0 ? 0 : 1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(n % 1e3 === 0 ? 0 : 1)}k` : `${Math.round(n)}`;

  const rangeStrip = (
    <>
      <Card>
        <form
          className="filter-row"
          onSubmit={(e) => {
            e.preventDefault();
            loadStats();
            if (tab === "gate") loadFailures();
          }}
        >
          <label className="field" style={{ flex: "0 0 165px", marginBottom: 0 }}>
            <span>From</span>
            <input type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)} />
          </label>
          <label className="field" style={{ flex: "0 0 165px", marginBottom: 0 }}>
            <span>To</span>
            <input type="date" value={to} min={from} onChange={(e) => setTo(e.target.value)} />
          </label>
          <button className="primary" disabled={loading}>{loading ? "Loading…" : "Search"}</button>
          <div className="quick-ranges">
            <button type="button" className="small" onClick={() => { setFrom(day(0)); setTo(day(0)); }}>Today</button>
            <button type="button" className="small" onClick={() => { setFrom(day(-6)); setTo(day(0)); }}>Last 7 days</button>
          </div>
        </form>
        <p className="faint small-text" style={{ marginBottom: 0 }}>
          Event totals for the selected dates. Allowed requests above the sampling threshold are sampled, so counts
          are approximate at very high traffic.
        </p>
      </Card>
    </>
  );

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead sub="Request outcomes, policy stages and backend uptime for the selected period." />
      {!live && rangeStrip}

      {!live && (
        <Card title="Requests over time" sub="Hourly buckets; blocked traffic is overlaid on total requests.">
          {series.length === 0 ? (
            <Empty title="No events in this range" icon="chart">Choose a different date range to see traffic.</Empty>
          ) : (
            <Chart
              series={[
                { label: "Requests", color: "#4f8cff", values: series.map((b) => b.requests), area: true },
                { label: "Blocked", color: "#f0616d", values: series.map((b) => b.errors) },
              ]}
              labels={labels}
              height={240}
              format={compact}
              tooltipTitle={(l) => l}
            />
          )}
        </Card>
      )}

      <PageTabs tabs={tabs} active={tab} onSelect={(id) => onTab?.(id)} />

      {tab === "overview" && (
        <>
          <div className="kpi-grid">
            <div className="kpi">
              <div className="kpi-label">Total requests</div>
              <div className="kpi-value">{requests.toLocaleString()}</div>
              <div className="kpi-sub">{stats?.totals.src_ips.toLocaleString() ?? 0} unique source IPs</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Successful</div>
              <div className="kpi-value" style={{ color: "var(--ok)" }}>{success.toLocaleString()}</div>
              <div className="kpi-sub">{pct(success, requests)} of traffic</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Error / blocked</div>
              <div className="kpi-value" style={{ color: "var(--danger)" }}>{errors.toLocaleString()}</div>
              <div className="kpi-sub">{pct(errors, requests)} of traffic</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Process uptime</div>
              <div className="kpi-value">{duration(uptime?.process_uptime_s ?? 0)}</div>
              <div className="kpi-sub">{uptime?.targets.length ?? 0} backend probes</div>
            </div>
          </div>

          <Card title="Request outcome by stage">
            {(stats?.stages ?? []).length === 0 ? (
              <Empty>No stage data in this range.</Empty>
            ) : (
              <div className="country-chips">
                {stats?.stages.map((s) => (
                  <span className="country-chip" key={s.name}>
                    <span className="mono">{s.name}</span>
                    <b>{s.count.toLocaleString()}</b>
                  </span>
                ))}
              </div>
            )}
          </Card>
        </>
      )}

      {tab === "traffic" && (
        <div className="split">
          <Card title="Forward types / proxies">
            {(stats?.proxies ?? []).length === 0 ? (
              <Empty>No routed traffic in this range.</Empty>
            ) : (
              <div className="table-wrap"><table>
                <thead>
                  <tr><th>Proxy</th><th className="num">Requests</th><th className="num hide-phone">Success</th><th className="num hide-phone">Errors</th><th className="num hide-phone">Traffic</th></tr>
                </thead>
                <tbody>
                  {stats?.proxies.map((p) => (
                    <tr key={p.proxy_id}>
                      <td>{p.host || `proxy #${p.proxy_id}`}</td>
                      <td className="num">{p.requests.toLocaleString()}</td>
                      <td className="num hide-phone">{p.success.toLocaleString()}</td>
                      <td className="num hide-phone">{p.errors.toLocaleString()}</td>
                      <td className="num hide-phone">{fmtBytes(p.bytes_in + p.bytes_out)}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            )}
          </Card>

          <Card title="Visitors by country">
            {topCountries.length === 0 ? (
              <Empty>No country data. Install a GeoIP database in Settings.</Empty>
            ) : (
              <div className="country-chips">
                {topCountries.map((c) => (
                  <span className="country-chip" key={c.name} title={`${countryName(c.name)} — ${c.count.toLocaleString()} requests`}>
                    <span>{countryFlag(c.name)} {countryName(c.name)}</span>
                    <b>{c.count.toLocaleString()}</b>
                    <i style={{ width: `${Math.max(4, (c.count / countryTotal) * 100)}%` }} />
                  </span>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "uptime" && (
        <Card
          title="Uptime monitor"
          actions={
            <span className="row" style={{ gap: 8 }}>
              {down > 0
                ? <Badge tone="bad">{down} backend down</Badge>
                : <Badge tone="ok">all probes healthy</Badge>}
              <span className="muted" style={{ fontSize: 11 }}>
                {uptime?.checked_at ? `checked ${fmtTime(uptime.checked_at)}` : "waiting for the first probe"}
              </span>
            </span>
          }
        >
          <div className="grid cols-3" style={{ marginBottom: 12 }}>
            {(uptime?.proxies ?? []).map((p) => (
              <div className="bar-row" key={p.proxy_id}>
                <div>
                  <div>{p.host}</div>
                  <div className="faint" style={{ fontSize: 11 }}>{p.up}/{p.targets} upstreams up</div>
                </div>
                <div>{stateBadge(p.state)}</div>
              </div>
            ))}
            {(uptime?.proxies ?? []).length === 0 && <Empty>No proxies configured.</Empty>}
          </div>
          {(uptime?.targets ?? []).length > 0 && (
            <div className="table-wrap"><table>
              <thead>
                <tr><th>Proxy / backend</th><th>State</th><th className="num">24h uptime</th><th className="num hide-tablet">Latency</th><th className="num hide-tablet">HTTP</th><th className="hide-tablet">Last check</th><th className="hide-tablet">Detail</th></tr>
              </thead>
              <tbody>
                {uptime?.targets.map((t) => <UptimeRow key={t.id} t={t} />)}
              </tbody>
            </table></div>
          )}
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            Every enabled upstream is checked with an HTTP HEAD request every 30 seconds. A backend returning 5xx or
            timing out is marked down, and the transition is sent to the notification channels that have
            <code> Backend up/down</code> enabled.
          </p>
        </Card>
      )}

      {tab === "gate" && (
        <Card
          title="Failed access-gate logins"
          actions={<span className="muted" style={{ fontSize: 11 }}>usernames and addresses the gate rejected</span>}
        >
          {failures.length === 0 ? (
            <Empty>No failed logins in this range.</Empty>
          ) : (
            <div className="table-wrap"><table>
              <thead>
                <tr><th>Address / proxy</th><th className="hide-phone">Username tried</th><th className="num">Attempts</th><th className="hide-tablet">Last attempt</th><th>State</th></tr>
              </thead>
              <tbody>
                {failures.map((f) => (
                  <tr key={`${f.ip}:${f.username}:${f.proxy_id}`}>
                    <td>
                      <div className="mono">{f.ip}</div>
                      <div className="faint gate-proxy" style={{ fontSize: 11 }}>{f.proxy_host || `proxy #${f.proxy_id}`}</div>
                    </td>
                    <td className="hide-phone">{f.username || <span className="faint">passphrase</span>}</td>
                    <td className="num">{f.attempts.toLocaleString()}</td>
                    <td className="muted hide-tablet" title={fmtTime(f.last)}>{fmtAgo(f.last)}</td>
                    <td>
                      {!f.blocked ? (
                        <Badge tone="warn">not blocked</Badge>
                      ) : f.blocked_permanent ? (
                        <Badge tone="bad">permanent ban</Badge>
                      ) : (
                        <Badge tone="info">temp ban</Badge>
                      )}
                      {f.blocked && f.blocked_reason ? (
                        <div className="faint" style={{ fontSize: 11 }}>{f.blocked_reason}</div>
                      ) : null}
                      {!f.blocked && (
                        <div style={{ marginTop: 4 }}>
                          <button
                            className="small danger"
                            title="Block this address permanently; it is added to Policies"
                            onClick={() => block(f)}
                          >
                            Block
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            The gate already bans by itself: three failures in ten minutes earns 15 minutes, ten in a day earns 24 hours.
            A permanent ban here also covers the whole address at the proxy and in nftables, and is listed under Policies.
          </p>
        </Card>
      )}
    </div>
  );
}
