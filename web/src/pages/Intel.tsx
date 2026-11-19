import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo } from "../ui";
import { Feed } from "../types";

export default function Intel({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [total, setTotal] = useState(0);
  const [form, setForm] = useState({ name: "", url: "", action: "block", interval_s: 900 });

  const load = () =>
    api
      .get<{ feeds: Feed[]; total: number }>("/api/feeds")
      .then((r) => {
        setFeeds(r.feeds || []);
        setTotal(r.total || 0);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const toggle = async (f: Feed) => {
    try {
      await api.put(`/api/feeds/${f.id}`, { ...f, enabled: !f.enabled });
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const refresh = async (f: Feed) => {
    try {
      await api.post(`/api/feeds/${f.id}/refresh`);
      onOK(`Refreshing ${f.name}`);
      setTimeout(load, 1500);
    } catch (e) {
      onError(errText(e));
    }
  };

  const add = async () => {
    try {
      await api.post("/api/feeds", form);
      setForm({ name: "", url: "", action: "block", interval_s: 900 });
      onOK("Feed added");
      setTimeout(load, 1200);
    } catch (e) {
      onError(errText(e));
    }
  };

  const remove = async (f: Feed) => {
    if (!confirm(`Delete feed ${f.name}?`)) return;
    try {
      await api.del(`/api/feeds/${f.id}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="grid cols-3">
        <Card>
          <div className="stat"><div className="k">Merged entries</div><div className="v">{total.toLocaleString()}</div><div className="sub">deduplicated CIDRs in memory</div></div>
        </Card>
        <Card>
          <div className="stat"><div className="k">Enabled feeds</div><div className="v">{feeds.filter((f) => f.enabled).length}</div><div className="sub">of {feeds.length} configured</div></div>
        </Card>
        <Card>
          <div className="stat"><div className="k">Frozen</div><div className="v">{feeds.filter((f) => f.state === "frozen").length}</div><div className="sub">guardrails held a suspicious list</div></div>
        </Card>
      </div>

      <Card title="Add custom feed">
        <div className="row grow">
          <Field label="Name"><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="My blocklist" /></Field>
          <Field label="URL"><input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="https://example.com/blocklist.txt" /></Field>
          <Field label="Action">
            <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}>
              <option value="block">block</option>
              <option value="challenge">challenge</option>
              <option value="log">log only</option>
            </select>
          </Field>
          <Field label="Interval (s)"><input type="number" value={form.interval_s} onChange={(e) => setForm({ ...form, interval_s: Number(e.target.value) })} /></Field>
          <button className="primary" style={{ marginTop: 18 }} onClick={add}>Add feed</button>
        </div>
      </Card>

      <Card title="Feeds">
        {feeds.length === 0 ? <Empty>No feeds configured.</Empty> : (
          <table>
            <thead>
              <tr><th>Feed</th><th>Action</th><th className="num">Entries</th><th>Last refresh</th><th>State</th><th /></tr>
            </thead>
            <tbody>
              {feeds.map((f) => (
                <tr key={f.id}>
                  <td>
                    <div>{f.name}</div>
                    <div className="faint mono" style={{ fontSize: 11, maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.url}</div>
                  </td>
                  <td><Badge tone={f.action === "block" ? "bad" : "info"}>{f.action}</Badge></td>
                  <td className="num">{f.last_count.toLocaleString()}</td>
                  <td className="muted">{fmtAgo(f.last_fetch)}</td>
                  <td>
                    <Badge tone={f.state === "ok" ? "ok" : f.state === "frozen" ? "bad" : f.state === "error" ? "warn" : "info"}>{f.state}</Badge>
                    {f.last_error ? <div className="faint" style={{ fontSize: 11, maxWidth: 260 }}>{f.last_error}</div> : null}
                  </td>
                  <td className="right" style={{ whiteSpace: "nowrap" }}>
                    <button className="small" onClick={() => toggle(f)}>{f.enabled ? "Disable" : "Enable"}</button>{" "}
                    <button className="small" onClick={() => refresh(f)}>Refresh</button>{" "}
                    {!f.builtin && <button className="small danger" onClick={() => remove(f)}>Delete</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted mt" style={{ fontSize: 12 }}>
          Feeds are fetched with ETag/If-Modified-Since caching, deduplicated and merged into one in-memory table. A list that grows
          more than five times in a single refresh is frozen instead of applied.
        </p>
      </Card>
    </div>
  );
}
