import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, errText, fmtTime } from "../ui";
import { Event } from "../types";

const PAGE = 50;

export default function Logs({ onError }: { onError: (m: string) => void }) {
  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState({ ip: "", host: "", stage: "", action: "", blocked: false });
  const [loading, setLoading] = useState(false);

  const load = async (nextOffset = offset) => {
    setLoading(true);
    const q = new URLSearchParams();
    q.set("limit", String(PAGE));
    q.set("offset", String(nextOffset));
    if (filters.ip) q.set("ip", filters.ip);
    if (filters.host) q.set("host", filters.host);
    if (filters.stage) q.set("stage", filters.stage);
    if (filters.action) q.set("action", filters.action);
    if (filters.blocked) q.set("blocked", "1");
    try {
      const r = await api.get<{ events: Event[]; total: number }>(`/api/events?${q.toString()}`);
      setEvents(r.events || []);
      setTotal(r.total || 0);
      setOffset(nextOffset);
    } catch (e) {
      onError(errText(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(0);
  }, []);

  const exportHref = () => {
    const q = new URLSearchParams();
    q.set("limit", "50000");
    if (filters.ip) q.set("ip", filters.ip);
    if (filters.host) q.set("host", filters.host);
    if (filters.stage) q.set("stage", filters.stage);
    if (filters.action) q.set("action", filters.action);
    if (filters.blocked) q.set("blocked", "1");
    return `/api/events/export.csv?${q.toString()}`;
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="Filters">
        <div className="row grow">
          <div className="field"><label>Source IP</label><input value={filters.ip} onChange={(e) => setFilters({ ...filters, ip: e.target.value })} placeholder="203.0.113.7" /></div>
          <div className="field"><label>Host</label><input value={filters.host} onChange={(e) => setFilters({ ...filters, host: e.target.value })} placeholder="app.example.com" /></div>
          <div className="field"><label>Stage</label>
            <select value={filters.stage} onChange={(e) => setFilters({ ...filters, stage: e.target.value })}>
              <option value="">any</option>
              <option value="waf">waf</option>
              <option value="feed">feed</option>
              <option value="country-block">country-block</option>
              <option value="asn-block">asn-block</option>
              <option value="decoy">decoy</option>
              <option value="decoy-host">decoy-host</option>
              <option value="dos">dos</option>
              <option value="temp-ban">temp-ban</option>
              <option value="permanent-ban">permanent-ban</option>
              <option value="access-gate">access-gate</option>
              <option value="unknown-host">unknown-host</option>
            </select>
          </div>
          <div className="field"><label>Action</label>
            <select value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })}>
              <option value="">any</option>
              <option value="allow">allow</option>
              <option value="block">block</option>
              <option value="ban">ban</option>
              <option value="challenge">challenge</option>
              <option value="log">log</option>
            </select>
          </div>
          <label style={{ marginTop: 18, display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={filters.blocked} onChange={(e) => setFilters({ ...filters, blocked: e.target.checked })} /> blocked only
          </label>
          <button className="primary" style={{ marginTop: 18 }} onClick={() => load(0)} disabled={loading}>{loading ? "Loading…" : "Search"}</button>
        </div>
      </Card>

      <Card
        title={`Events (${total.toLocaleString()})`}
        actions={
          <div className="row">
            <a href={exportHref()}><button className="small">Export CSV</button></a>
            <button className="small" disabled={offset === 0} onClick={() => load(Math.max(0, offset - PAGE))}>Newer</button>
            <button className="small" disabled={offset + PAGE >= total} onClick={() => load(offset + PAGE)}>Older</button>
          </div>
        }
      >
        {events.length === 0 ? <Empty>No events match these filters.</Empty> : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr><th>Time</th><th>Source</th><th>Host</th><th>Request</th><th>Stage</th><th>Rule</th><th className="num">Status</th><th className="num">Latency</th><th className="num">Out</th></tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(e.ts)}</td>
                    <td>
                      <div className="mono">{e.src_ip}</div>
                      <div className="faint" style={{ fontSize: 11 }}>{e.country || "—"} · AS{e.asn || "?"}</div>
                    </td>
                    <td className="muted">{e.host}</td>
                    <td className="mono" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.method} {e.path}</td>
                    <td><Badge tone={e.action === "allow" ? "" : e.action === "log" ? "info" : "bad"}>{e.stage || "—"}</Badge></td>
                    <td className="muted" style={{ maxWidth: 240 }}>{e.rule_msg || e.rule_id || "—"}</td>
                    <td className="num">{e.status}</td>
                    <td className="num">{e.latency_ms} ms</td>
                    <td className="num">{e.bytes_out}</td>
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
