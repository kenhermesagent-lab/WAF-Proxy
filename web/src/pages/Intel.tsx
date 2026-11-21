import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo } from "../ui";
import { CrowdSecBlocklists, Feed } from "../types";

export default function Intel({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [total, setTotal] = useState(0);
  const [form, setForm] = useState({ name: "", url: "", action: "block", interval_s: 900 });
  const [uploadName, setUploadName] = useState("");
  const [uploading, setUploading] = useState(false);
  const [consoleLists, setConsoleLists] = useState<CrowdSecBlocklists | null>(null);
  const file = useRef<HTMLInputElement>(null);

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

  useEffect(() => {
    let alive = true;
    const refresh = () =>
      api
        .get<CrowdSecBlocklists>("/api/crowdsec/blocklists")
        .then((r) => alive && setConsoleLists(r))
        .catch(() => undefined);
    refresh();
    const t = setInterval(refresh, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
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

  const upload = async () => {
    const chosen = file.current?.files?.[0];
    if (!chosen) {
      onError("Choose a .txt or .csv file first");
      return;
    }
    setUploading(true);
    try {
      const body = new FormData();
      body.append("file", chosen);
      if (uploadName.trim()) body.append("name", uploadName.trim());
      const r = await api.upload<{ id: number; entries: number }>("/api/feeds/upload", body);
      onOK(`Uploaded ${r.entries.toLocaleString()} entries as a local feed`);
      setUploadName("");
      if (file.current) file.current.value = "";
      setTimeout(load, 1200);
    } catch (e) {
      onError(errText(e));
    } finally {
      setUploading(false);
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

      <Card title="Upload local blocklist">
        <div className="row grow">
          <Field label="Name (optional)">
            <input value={uploadName} onChange={(e) => setUploadName(e.target.value)} placeholder="Defaults to the file name" />
          </Field>
          <Field label="File (.txt or .csv, max 10 MB)">
            <input ref={file} type="file" accept=".txt,.csv,text/plain,text/csv" />
          </Field>
          <button className="primary" style={{ marginTop: 18 }} onClick={upload} disabled={uploading}>
            {uploading ? "Uploading…" : "Upload and enable"}
          </button>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          The file is stored locally and appears in Feeds as a local list. Its action is always
          <strong> block</strong>, so every address is dropped globally. CSV files may have the IP in any column.
        </p>
      </Card>

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

      <Card
        title="CrowdSec console blocklists"
        actions={
          consoleLists?.available ? (
            <Badge>{consoleLists.total.toLocaleString()} decisions</Badge>
          ) : (
            <Badge tone="warn">not reported</Badge>
          )
        }
      >
        {!consoleLists ? (
          <Empty>Loading…</Empty>
        ) : !consoleLists.available ? (
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            {consoleLists.reason || "The Security Engine did not report its decisions."}
          </p>
        ) : consoleLists.rows.length === 0 ? (
          <Empty>No console-pushed decisions are active on this engine.</Empty>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr><th>Reason</th><th>Origin</th><th>Action</th><th className="num">Decisions</th></tr>
              </thead>
              <tbody>
                {consoleLists.rows.map((r) => (
                  <tr key={`${r.origin}:${r.reason}:${r.action}`}>
                    <td className="mono">{r.reason}</td>
                    <td>
                      <Badge tone={r.origin === "console" ? "bad" : "info"}>{r.origin}</Badge>
                    </td>
                    <td>{r.action}</td>
                    <td className="num">{r.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {consoleLists?.raw && (
          <pre className="mono" style={{ fontSize: 11, maxHeight: 220, overflow: "auto" }}>{consoleLists.raw}</pre>
        )}
        <p className="muted mt" style={{ fontSize: 12, marginBottom: 0 }}>
          Reported by the Security Engine (<code>cscli metrics show decisions</code>) and enforced by the bouncer, so
          every row is a decision that is actually in force. Origins <code>lists</code> (subscribed blocklists),
          <code> CAPI</code> (community blocklist) and <code>console</code> (pushed from the console) are managed at
          app.crowdsec.net and cannot be edited here.
        </p>
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
                    <div className="faint mono" style={{ fontSize: 11, maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {f.local ? `Local upload · ${f.filename || "file"}` : f.url}
                    </div>
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
