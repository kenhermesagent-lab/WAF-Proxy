import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { countryFlag, countryName } from "../countries";
import { Analytics, GateFailure, Uptime, UptimeTarget } from "../types";
import { Badge, Card, Empty, errText, fmtBytes, fmtTime } from "../ui";

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
      <td>
        <div>{t.proxy_host}</div>
        <div className="mono faint" style={{ fontSize: 11 }}>{t.url || "no enabled upstream"}</div>
      </td>
      <td>{stateBadge(t.state)}</td>
      <td className="num">{t.checks_24 ? `${t.uptime_24.toFixed(1)}%` : "—"}</td>
      <td className="num">{t.state === "up" ? `${t.latency_ms} ms` : "—"}</td>
      <td className="num">{t.status_code || "—"}</td>
      <td className="muted">{t.last_check ? fmtTime(t.last_check) : "—"}</td>
      <td className="muted" title={t.error}>{t.error || "—"}</td>
    </tr>
  );
}

export default function Statistics({ onError }: { onError: (m: string) => void }) {
  const [from, setFrom] = useState(day(-6));
  const [to, setTo] = useState(day(0));
  const [stats, setStats] = useState<Analytics | null>(null);
  const [uptime, setUptime] = useState<Uptime | null>(null);
  const [failures, setFailures] = useState<GateFailure[]>([]);
  const [loading, setLoading] = useState(false);

  const loadFailures = () =>
    api
      .get<{ failures: GateFailure[] }>(
        `/api/gate-failures?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
      )
      .then((r) => setFailures(r.failures || []))
      .catch((e) => onError(errText(e)));

  const load = () => {
    setLoading(true);
    api
      .get<Analytics>(`/api/analytics?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`)
      .then(setStats)
      .catch((e) => onError(errText(e)))
      .finally(() => setLoading(false));
    loadFailures();
  };

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
    load();
  }, [from, to]);

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
  const maxTraffic = Math.max(1, ...series.map((b) => b.bytes_in + b.bytes_out));
  const errors = stats?.totals.blocked ?? 0;
  const requests = stats?.totals.requests ?? 0;
  const success = Math.max(0, requests - errors);
  const topCountries = useMemo(() => (stats?.countries ?? []).slice(0, 24), [stats]);
  const countryTotal = Math.max(1, ...(stats?.countries ?? []).map((c) => c.count));
  const down = (uptime?.targets ?? []).filter((t) => t.state === "down").length;

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="Requests and uptime">
        <form
          className="row grow"
          onSubmit={(e) => {
            e.preventDefault();
            load();
          }}
        >
          <label className="field">
            <span>From</span>
            <input type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)} />
          </label>
          <label className="field">
            <span>To</span>
            <input type="date" value={to} min={from} onChange={(e) => setTo(e.target.value)} />
          </label>
          <button className="primary" style={{ marginTop: 18 }} disabled={loading}>
            {loading ? "Loading…" : "Search"}
          </button>
          <button
            type="button"
            style={{ marginTop: 18 }}
            onClick={() => {
              setFrom(day(0));
              setTo(day(0));
            }}
          >
            Today
          </button>
          <button
            type="button"
            style={{ marginTop: 18 }}
            onClick={() => {
              setFrom(day(-6));
              setTo(day(0));
            }}
          >
            Last 7 days
          </button>
          <div style={{ margin: "18px 0 0 auto" }}>
            {down > 0 ? <Badge tone="bad">{down} backend down</Badge> : <Badge tone="ok">all probes healthy</Badge>}
          </div>
        </form>
        <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
          Event totals for the selected dates. Allowed requests above the sampling threshold are sampled, so counts
          are approximate at very high traffic.
        </p>
      </Card>

      <div className="grid cols-4">
        <Card>
          <div className="stat">
            <div className="k">Total requests</div>
            <div className="v">{requests.toLocaleString()}</div>
            <div className="sub">{stats?.totals.src_ips.toLocaleString() ?? 0} unique source IPs</div>
          </div>
        </Card>
        <Card>
          <div className="stat">
            <div className="k">Successful requests</div>
            <div className="v" style={{ color: "var(--ok)" }}>{success.toLocaleString()}</div>
            <div className="sub">{pct(success, requests)} of traffic</div>
          </div>
        </Card>
        <Card>
          <div className="stat">
            <div className="k">Error / blocked requests</div>
            <div className="v" style={{ color: "var(--bad)" }}>{errors.toLocaleString()}</div>
            <div className="sub">{pct(errors, requests)} of traffic</div>
          </div>
        </Card>
        <Card>
          <div className="stat">
            <div className="k">Proxy uptime</div>
            <div className="v">{duration(uptime?.process_uptime_s ?? 0)}</div>
            <div className="sub">{uptime?.targets.length ?? 0} backend probes</div>
          </div>
        </Card>
      </div>

      <Card
        title="Failed access-gate logins"
        actions={<span className="muted" style={{ fontSize: 11 }}>usernames and addresses the gate rejected</span>}
      >
        {failures.length === 0 ? (
          <Empty>No failed logins in this range.</Empty>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr><th>Address</th><th>Username tried</th><th>Proxy</th><th className="num">Attempts</th><th>Last attempt</th><th>State</th><th /></tr>
              </thead>
              <tbody>
                {failures.map((f) => (
                  <tr key={`${f.ip}:${f.username}:${f.proxy_id}`}>
                    <td className="mono">{f.ip}</td>
                    <td>{f.username || <span className="faint">passphrase</span>}</td>
                    <td>{f.proxy_host || `proxy #${f.proxy_id}`}</td>
                    <td className="num">{f.attempts.toLocaleString()}</td>
                    <td className="muted">{fmtTime(f.last)}</td>
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
                    </td>
                    <td className="right">
                      {!f.blocked && (
                        <button className="small danger" onClick={() => block(f)}>
                          Block permanently
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
          The gate already bans by itself: three failures in ten minutes earns 15 minutes, ten in a day earns 24 hours.
          A permanent ban here also covers the whole address at the proxy and in nftables, and is listed under Policies.
        </p>
      </Card>

      <Card title="Traffic by hour">
        {series.length === 0 ? (
          <Empty>No events in this range.</Empty>
        ) : (
          <>
            <div className="stats-bars" aria-label="Traffic per hour">
              {series.map((b) => (
                <div
                  key={b.bucket}
                  className="stats-bar"
                  title={`${fmtTime(b.bucket)} · ${b.requests.toLocaleString()} requests · ${fmtBytes(b.bytes_in + b.bytes_out)}`}
                >
                  <div
                    className="stats-bar-fill"
                    style={{ height: `${Math.max(3, ((b.bytes_in + b.bytes_out) / maxTraffic) * 100)}%` }}
                  >
                    {b.errors > 0 && (
                      <i style={{ height: `${(b.errors / Math.max(1, b.requests)) * 100}%` }} />
                    )}
                  </div>
                </div>
              ))}
            </div>
            <div className="row" style={{ justifyContent: "space-between", fontSize: 11 }}>
              <span className="muted">{fmtTime(series[0]?.bucket)}</span>
              <span className="muted">
                <i className="legend-dot ok" /> allowed <i className="legend-dot bad" /> blocked
              </span>
              <span className="muted">{fmtTime(series[series.length - 1]?.bucket)}</span>
            </div>
          </>
        )}
      </Card>

      <div className="split">
        <Card title="Forward types / proxies">
          {(stats?.proxies ?? []).length === 0 ? (
            <Empty>No routed traffic in this range.</Empty>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table>
                <thead>
                  <tr><th>Proxy</th><th className="num">Requests</th><th className="num">Success</th><th className="num">Errors</th><th className="num">Traffic</th></tr>
                </thead>
                <tbody>
                  {stats?.proxies.map((p) => (
                    <tr key={p.proxy_id}>
                      <td>{p.host || `proxy #${p.proxy_id}`}</td>
                      <td className="num">{p.requests.toLocaleString()}</td>
                      <td className="num">{p.success.toLocaleString()}</td>
                      <td className="num">{p.errors.toLocaleString()}</td>
                      <td className="num">{fmtBytes(p.bytes_in + p.bytes_out)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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

      <Card
        title="Uptime monitor"
        actions={
          <span className="muted" style={{ fontSize: 11 }}>
            {uptime?.checked_at ? `checked ${fmtTime(uptime.checked_at)}` : "waiting for the first probe"}
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
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr><th>Proxy / backend</th><th>State</th><th className="num">24h uptime</th><th className="num">Latency</th><th className="num">HTTP</th><th>Last check</th><th>Detail</th></tr>
              </thead>
              <tbody>
                {uptime?.targets.map((t) => <UptimeRow key={t.id} t={t} />)}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
          Every enabled upstream is checked with an HTTP HEAD request every 30 seconds. A backend returning 5xx or
          timing out is marked down, and the transition is sent to the notification channels that have
          <code> Backend up/down</code> enabled.
        </p>
      </Card>

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
    </div>
  );
}
