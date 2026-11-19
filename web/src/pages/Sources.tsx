import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo, fmtTime } from "../ui";
import type { IPDetail, IPSummary } from "../types";

export default function Sources({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [q, setQ] = useState("");
  const [hours, setHours] = useState("24");
  const [list, setList] = useState<IPSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState<IPDetail | null>(null);

  const load = async () => {
    setLoading(true);
    const p = new URLSearchParams();
    p.set("hours", hours);
    p.set("limit", "100");
    if (q.trim()) p.set("q", q.trim());
    try {
      const r = await api.get<{ ips: IPSummary[] }>(`/api/ips?${p.toString()}`);
      setList(r.ips || []);
    } catch (e) {
      onError(errText(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const open = async (ip: string) => {
    try {
      const p = new URLSearchParams();
      p.set("hours", hours);
      const r = await api.get<IPDetail>(`/api/ips/${encodeURIComponent(ip)}?${p.toString()}`);
      setDetail(r);
    } catch (e) {
      onError(errText(e));
    }
  };

  const ban = async (ip: string) => {
    const reason = prompt(`Reason for banning ${ip}?`, "manual from source explorer");
    if (!reason) return;
    try {
      await api.post("/api/bans", { cidr: ip, reason, permanent: false, ttl_seconds: 86400 });
      onOK(`${ip} banned for 24 hours`);
      await load();
      if (detail?.summary.ip === ip) open(ip);
    } catch (e) {
      onError(errText(e));
    }
  };

  const unban = async (row: IPSummary) => {
    if (!row.ban_id) {
      onError("Ban id is unavailable; remove it from the Policies page");
      return;
    }
    if (!confirm(`Unban ${row.ip}?`)) return;
    try {
      await api.del(`/api/bans/${row.ban_id}`);
      onOK(`${row.ip} unbanned`);
      await load();
      if (detail?.summary.ip === row.ip) open(row.ip);
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="Source IP explorer">
        <div className="row grow">
          <Field label="IP prefix">
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="203.0.113 or 2001:db8" />
          </Field>
          <Field label="Window">
            <select value={hours} onChange={(e) => setHours(e.target.value)}>
              <option value="1">1 hour</option>
              <option value="24">24 hours</option>
              <option value="168">7 days</option>
              <option value="720">30 days</option>
            </select>
          </Field>
          <button className="primary" style={{ marginTop: 18 }} onClick={load} disabled={loading}>
            {loading ? "Searching…" : "Search"}
          </button>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          Aggregates requests, blocks, distinct hosts and ban state per source address. Click a row
          for the recent requests from that address.
        </p>
      </Card>

      <Card title={`Sources (${list.length})`}>
        {list.length === 0 ? <Empty>No requests match this window.</Empty> : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr><th>Source</th><th>Location</th><th className="num">Requests</th><th className="num">Blocked</th><th className="num">Hosts</th><th>Last seen</th><th>State</th><th /></tr>
              </thead>
              <tbody>
                {list.map((r) => (
                  <tr key={r.ip} style={{ cursor: "pointer" }} onClick={() => open(r.ip)}>
                    <td className="mono">{r.ip}</td>
                    <td className="muted">{r.country || "—"} · AS{r.asn || "?"}</td>
                    <td className="num">{r.requests.toLocaleString()}</td>
                    <td className="num">{r.blocked.toLocaleString()}</td>
                    <td className="num">{r.hosts}</td>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtAgo(r.last_seen)}</td>
                    <td>
                      {r.banned
                        ? <Badge tone="bad">{r.permanent ? "permanent ban" : "banned"}</Badge>
                        : <Badge tone="">clean</Badge>}
                    </td>
                    <td className="right" style={{ whiteSpace: "nowrap" }} onClick={(e) => e.stopPropagation()}>
                      {r.banned
                        ? <button className="small" onClick={() => unban(r)}>Unban</button>
                        : <button className="small danger" onClick={() => ban(r.ip)}>Ban 24h</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {detail && (
        <Card
          title={`${detail.summary.ip} — ${detail.summary.requests.toLocaleString()} requests`}
          actions={<button className="small" onClick={() => setDetail(null)}>Close</button>}
        >
          <div className="grid cols-4 mb">
            <div className="stat"><div className="k">Blocked</div><div className="v">{detail.summary.blocked.toLocaleString()}</div></div>
            <div className="stat"><div className="k">Hosts</div><div className="v">{detail.summary.hosts}</div></div>
            <div className="stat"><div className="k">First seen</div><div className="sub">{detail.summary.requests ? fmtTime(detail.summary.first_seen) : "—"}</div></div>
            <div className="stat"><div className="k">Ban</div><div className="sub">
              {detail.summary.banned
                ? `${detail.summary.permanent ? "permanent" : "temporary"} — ${detail.summary.ban_reason || "no reason"}`
                : "none"}
            </div></div>
          </div>
          {detail.events.length === 0 ? <Empty>No events stored for this address in the window.</Empty> : (
            <table>
              <thead><tr><th>Time</th><th>Host</th><th>Request</th><th>Stage</th><th>Action</th><th className="num">Status</th></tr></thead>
              <tbody>
                {detail.events.map((e) => (
                  <tr key={e.id}>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(e.ts)}</td>
                    <td className="muted">{e.host}</td>
                    <td className="mono" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.method} {e.path}</td>
                    <td><Badge tone={e.action === "allow" ? "" : "bad"}>{e.stage || "—"}</Badge></td>
                    <td>{e.action}</td>
                    <td className="num">{e.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="muted" style={{ fontSize: 12 }}>
            Showing the newest {detail.events.length} of {detail.total.toLocaleString()} matching events.
          </p>
        </Card>
      )}
    </div>
  );
}
