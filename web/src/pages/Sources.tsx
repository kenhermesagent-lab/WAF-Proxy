import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo, fmtTime, PageHead } from "../ui";
import type { IPSummary } from "../types";

export default function Sources({
  onError,
  onOpenSource,
  head = true,
}: {
  onError: (m: string) => void;
  onOpenSource: (ip: string) => void;
  head?: boolean;
}) {
  const [q, setQ] = useState("");
  const [hours, setHours] = useState("24");
  const [list, setList] = useState<IPSummary[]>([]);
  const [loading, setLoading] = useState(false);

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

  return (
    <div className="grid" style={{ gap: 14 }}>
      {head && <PageHead sub="Source addresses ranked by request volume, with block counts and a link to their events." />}
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
          Aggregates requests, blocks, distinct hosts and ban state per source address. Click a row to
          investigate the address: recent requests, intel matches and the ban controls.
        </p>
      </Card>

      <Card title={`Sources (${list.length})`}>
        {list.length === 0 ? <Empty>No requests match this window.</Empty> : (
          <div style={{ overflowX: "auto" }}>
            <div className="table-wrap"><table>
              <thead>
                <tr><th>Source</th><th className="hide-compact">Location</th><th className="num hide-narrow">Requests</th><th className="num hide-narrow">Blocked</th><th className="num hide-tablet">Hosts</th><th>Last seen</th><th>State</th><th /></tr>
              </thead>
              <tbody>
                {list.map((r) => (
                  <tr key={r.ip} className="clickable" onClick={() => onOpenSource(r.ip)}>
                    <td className="mono">{r.ip}</td>
                    <td className="muted hide-compact">{r.country || "—"} · AS{r.asn || "?"}</td>
                    <td className="num hide-narrow">{r.requests.toLocaleString()}</td>
                    <td className="num hide-narrow">{r.blocked.toLocaleString()}</td>
                    <td className="num hide-tablet">{r.hosts}</td>
                    <td className="muted" style={{ whiteSpace: "nowrap" }} title={fmtTime(r.last_seen)}>{fmtAgo(r.last_seen)}</td>
                    <td>
                      {r.banned
                        ? <Badge tone="bad">{r.permanent ? "permanent ban" : "banned"}</Badge>
                        : <Badge tone="">clean</Badge>}
                    </td>
                    <td className="right" style={{ whiteSpace: "nowrap" }} onClick={(e) => e.stopPropagation()}>
                      <button className="small" onClick={() => onOpenSource(r.ip)}>Investigate</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          </div>
        )}
      </Card>
    </div>
  );
}
