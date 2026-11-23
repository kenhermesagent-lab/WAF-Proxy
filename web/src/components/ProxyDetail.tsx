import { useEffect, useState } from "react";
import { api } from "../api";
import type { Cert, Metrics, ProtectionProfile, Proxy, UptimeTarget } from "../types";
import { Badge, Drawer, Empty, Skeleton, fmtAgo, fmtBytes, fmtTime } from "../ui";

const GATE_LABELS: Record<string, string> = {
  off: "Off",
  passphrase: "Shared passphrase",
  accounts: "Accounts",
  accounts_totp: "Accounts + TOTP",
  forward_auth: "Identity provider",
};

/**
 * One proxy in one place: configuration, measured traffic, upstream health,
 * certificate and routes. Read-only; editing stays in the proxy drawer.
 */
export default function ProxyDetail({
  proxy,
  protection,
  cert,
  onEdit,
  onClose,
}: {
  proxy: Proxy;
  protection?: ProtectionProfile;
  cert?: Cert;
  onEdit: () => void;
  onClose: () => void;
}) {
  const [counters, setCounters] = useState<Metrics["proxies"][string] | null>(null);
  const [targets, setTargets] = useState<UptimeTarget[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    // Both feeds are optional: a role without metrics still sees the config.
    Promise.all([
      api.get<Metrics>("/api/metrics").catch(() => null),
      api.get<{ targets: UptimeTarget[] }>("/api/uptime").catch(() => ({ targets: [] })),
    ])
      .then(([m, u]) => {
        if (!alive) return;
        setCounters(m?.proxies?.[String(proxy.id)] ?? null);
        setTargets((u?.targets ?? []).filter((t) => t.proxy_id === proxy.id));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [proxy.id]);

  const blockedShare = counters?.requests ? (counters.blocked / counters.requests) * 100 : 0;
  // A rounded 100 hides a real outage, so only a perfect score prints as 100.
  const uptime = (pct: number) => (pct >= 99.95 ? "100" : pct.toFixed(1));

  return (
    <Drawer
      title={proxy.hostname}
      sub={`Proxy #${proxy.id} · ${proxy.upstreams.length} upstream${proxy.upstreams.length === 1 ? "" : "s"}`}
      onClose={onClose}
      footer={
        <>
          <a className="small" href={`#/logs?host=${encodeURIComponent(proxy.hostname)}`} onClick={onClose} style={{ marginRight: "auto" }}>
            Open log for this host
          </a>
          <button onClick={onEdit}>Edit proxy</button>
          <button className="primary" onClick={onClose}>Close</button>
        </>
      }
    >
      <div className="row" style={{ gap: 6, marginBottom: 14 }}>
        <Badge tone={!proxy.enabled ? "" : proxy.maintenance ? "warn" : "ok"}>
          {!proxy.enabled ? "Disabled" : proxy.maintenance ? "Maintenance" : "Enabled"}
        </Badge>
        <Badge tone={proxy.waf_mode === "off" ? "warn" : "info"}>WAF {proxy.waf_mode}</Badge>
        <Badge>Bots {proxy.bot_level}</Badge>
        <Badge tone={proxy.gate_mode === "off" ? "" : "ok"}>Gate {GATE_LABELS[proxy.gate_mode] ?? proxy.gate_mode}</Badge>
      </div>

      {loading ? (
        <>
          <Skeleton kind="line" count={2} />
          <Skeleton kind="block" />
        </>
      ) : (
        <>
          <div className="grid cols-4 mb">
            <div className="stat">
              <div className="k">Requests</div>
              <div className="v">{counters ? counters.requests.toLocaleString() : "—"}</div>
              <div className="sub">since start</div>
            </div>
            <div className="stat">
              <div className="k">Blocked</div>
              <div className="v">{counters ? counters.blocked.toLocaleString() : "—"}</div>
              <div className="sub">{counters?.requests ? `${blockedShare.toFixed(1)}% of requests` : "—"}</div>
            </div>
            <div className="stat">
              <div className="k">Inbound</div>
              <div className="v" style={{ fontSize: 16 }}>{counters ? fmtBytes(counters.bytes_in) : "—"}</div>
              <div className="sub">delivered to upstreams</div>
            </div>
            <div className="stat">
              <div className="k">Outbound</div>
              <div className="v" style={{ fontSize: 16 }}>{counters ? fmtBytes(counters.bytes_out) : "—"}</div>
              <div className="sub">returned to clients</div>
            </div>
          </div>

          <h3 style={{ fontSize: 13, margin: "4px 0 8px" }}>Upstream health</h3>
          {targets.length === 0 ? (
            <Empty title="No health check yet" icon="server">
              A target appears after the first probe of this proxy's upstreams.
            </Empty>
          ) : (
            <div className="table-wrap mb">
              <table>
                <thead>
                  <tr><th>Upstream</th><th>State</th><th className="num">Latency</th><th className="num">24h up</th><th>Checked</th></tr>
                </thead>
                <tbody>
                  {targets.map((t) => (
                    <tr key={t.id}>
                      <td className="mono" style={{ fontSize: 11.5 }} title={t.url}>{t.url}</td>
                      <td><Badge tone={t.state === "up" ? "ok" : t.state === "down" ? "bad" : "warn"}>{t.state}</Badge></td>
                      <td className="num">{t.latency_ms ? `${t.latency_ms} ms` : "—"}</td>
                      <td className="num">{t.checks_24 ? `${uptime(t.uptime_24)}%` : "—"}</td>
                      <td className="muted" title={fmtTime(t.last_check)}>{fmtAgo(t.last_check)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h3 style={{ fontSize: 13, margin: "4px 0 8px" }}>Configuration</h3>
          <div className="facts mb">
            <span>Protection profile <b>{protection?.name ?? "default"}</b></span>
            <span>Certificate <b>{cert ? cert.domains : "auto"}</b></span>
            <span>Fingerprint <b>{proxy.fingerprint || "strict"}</b></span>
            <span>Gate mode <b>{GATE_LABELS[proxy.gate_mode] ?? proxy.gate_mode}</b></span>
            {cert ? <span>Expires <b>{fmtTime(cert.expires_at)}</b></span> : null}
            {proxy.gate_users?.length ? <span>Gate accounts <b>{proxy.gate_users.join(", ")}</b></span> : null}
          </div>

          <h3 style={{ fontSize: 13, margin: "4px 0 8px" }}>Upstreams</h3>
          <div className="table-wrap mb">
            <table>
              <thead>
                <tr><th>URL</th><th className="num">Weight</th><th>State</th></tr>
              </thead>
              <tbody>
                {proxy.upstreams.map((u, i) => (
                  <tr key={`${u.url}-${i}`}>
                    <td className="mono" style={{ fontSize: 11.5 }}>{u.url || "—"}</td>
                    <td className="num">{u.weight}</td>
                    <td>{u.enabled ? <Badge tone="ok">enabled</Badge> : <Badge tone="warn">disabled</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h3 style={{ fontSize: 13, margin: "4px 0 8px" }}>Routes</h3>
          {proxy.routes?.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Kind</th><th>Match</th><th>Target</th></tr>
                </thead>
                <tbody>
                  {proxy.routes.map((rt, i) => (
                    <tr key={`${rt.match}-${i}`}>
                      <td><Badge>{rt.kind}</Badge></td>
                      <td className="mono">{rt.match}</td>
                      <td className="mono" style={{ fontSize: 11.5 }}>{rt.target}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted" style={{ fontSize: 12 }}>No redirects or aliases on this hostname.</p>
          )}
        </>
      )}
    </Drawer>
  );
}
