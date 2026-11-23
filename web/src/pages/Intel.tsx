import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, Field, errText, fmtAgo } from "../ui";
import { modeBadges } from "../bundles";
import { BundleHit, BundlesSnapshot, CrowdSecBlocklists, Feed, IntelLookup } from "../types";

export default function Intel({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [total, setTotal] = useState(0);
  const [form, setForm] = useState({ name: "", url: "", action: "block", interval_s: 900 });
  const [uploadName, setUploadName] = useState("");
  const [uploading, setUploading] = useState(false);
  const [consoleLists, setConsoleLists] = useState<CrowdSecBlocklists | null>(null);
  const [probe, setProbe] = useState("");
  const [lookup, setLookup] = useState<IntelLookup | null>(null);
  const [checking, setChecking] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const [bundles, setBundles] = useState<BundlesSnapshot | null>(null);
  const [bundleHits, setBundleHits] = useState<BundleHit[]>([]);
  const [checkingBundles, setCheckingBundles] = useState(false);

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

  const loadBundles = () => {
    api.get<BundlesSnapshot>("/api/bundles").then(setBundles).catch(() => undefined);
    api
      .get<{ hours: number; rules: BundleHit[] }>("/api/bundles/hits?hours=24")
      .then((r) => setBundleHits(r.rules || []))
      .catch(() => undefined);
  };

  useEffect(() => {
    loadBundles();
    const t = setInterval(loadBundles, 30000);
    return () => clearInterval(t);
  }, []);

  const checkBundles = async () => {
    setCheckingBundles(true);
    try {
      const snap = await api.post<BundlesSnapshot>("/api/bundles/check");
      setBundles(snap);
      if (snap.error) onError(snap.error);
      else onOK("Bundle channel checked");
      loadBundles();
    } catch (e) {
      onError(errText(e));
    } finally {
      setCheckingBundles(false);
    }
  };

  const toggle = async (f: Feed) => {
    try {
      await api.put(`/api/feeds/${f.id}`, { ...f, enabled: !f.enabled });
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const setAction = async (f: Feed, action: string) => {
    try {
      await api.put(`/api/feeds/${f.id}`, { ...f, action });
      onOK(`${f.name} now ${action === "log" ? "logs only" : action + "s"}`);
    } catch (e) {
      onError(errText(e));
    }
    load();
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
    if (!(await confirmDialog(`Delete feed ${f.name}?`))) return;
    try {
      await api.del(`/api/feeds/${f.id}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const checkIP = async () => {
    setChecking(true);
    try {
      setLookup(await api.get<IntelLookup>(`/api/intel/lookup?ip=${encodeURIComponent(probe.trim())}`));
    } catch (e) {
      setLookup(null);
      onError(errText(e));
    } finally {
      setChecking(false);
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

      <Card
        title="Signature bundles"
        actions={
          <>
            <Badge tone={bundles?.configured ? "ok" : "warn"}>
              {bundles?.configured ? "signed channel" : "not configured"}
            </Badge>
            <button className="small" onClick={checkBundles} disabled={checkingBundles || !bundles?.configured}>
              {checkingBundles ? "Checking…" : "Check now"}
            </button>
          </>
        }
      >
        {!bundles ? (
          <Empty>Loading…</Empty>
        ) : !bundles.configured ? (
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            No signed bundle channel is configured. Set <code>WAFPROXY_BUNDLE_URL</code> and
            <code> WAFPROXY_BUNDLE_PUBKEY</code> to receive attack-signature packs. A pack carries rules only, never
            addresses, so it can add signatures but never ban an IP.
          </p>
        ) : bundles.bundles.length === 0 ? (
          <Empty>No bundles installed yet.</Empty>
        ) : (
          <>
            <div className="facts" style={{ marginBottom: 10 }}>
              <span><b>Channel</b> <code>{bundles.url}</code></span>
              <span><b>Publisher</b> <code>{bundles.key_id}</code></span>
              <span><b>Checked</b> {fmtAgo(bundles.last_check)} · next {fmtAgo(bundles.next_check)}</span>
            </div>
            {bundles.error ? (
              <div className="banner warn" style={{ marginBottom: 10 }} role="status">{bundles.error}</div>
            ) : null}
            <div style={{ overflowX: "auto" }}>
              <div className="table-wrap"><table>
                <thead>
                  <tr><th>Bundle</th><th>Version</th><th className="num">Rules</th><th>Installed</th><th>Profile modes</th></tr>
                </thead>
                <tbody>
                  {bundles.bundles.map((b) => (
                    <tr key={b.name}>
                      <td>{b.name}</td>
                      <td className="mono">{b.version}</td>
                      <td className="num">{b.rules}</td>
                      <td className="muted">{fmtAgo(b.installed_at)}</td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          {modeBadges(b.modes).map((m) => <Badge key={m.label} tone={m.tone}>{m.label}</Badge>)}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            </div>
            <p className="muted mt" style={{ fontSize: 12, marginBottom: 0 }}>
              Checks read the signed manifest hourly and download a pack only when its version changes. Each rule
              runs in log only until a profile allows it to block; the mode is per profile, so one site can refuse
              these matches while another only records them.
            </p>
          </>
        )}
      </Card>

      <Card
        title="Bundle hits"
        actions={<span className="faint" style={{ fontSize: 11.5 }}>last 24 hours</span>}
      >
        {bundleHits.length === 0 ? (
          <Empty>No bundle rule has matched in the last 24 hours.</Empty>
        ) : (
          <>
            {bundleHits.every((h) => (h.modes?.block ?? 0) === 0) ? (
              <div className="banner warn" style={{ marginBottom: 10 }} role="status">
                <span>These requests were served: every profile runs these bundles in log only.</span>
                <div className="banner-actions">
                  <button className="small" onClick={() => { window.location.hash = "#/policies?tab=profiles"; }}>
                    Set bundle mode →
                  </button>
                </div>
              </div>
            ) : null}
            <div style={{ overflowX: "auto" }}>
              <div className="table-wrap"><table>
                <thead>
                  <tr><th>Rule</th><th>Bundle</th><th>What it matched</th><th className="num">Hits</th><th className="num">Addresses</th><th>Last seen</th><th>Today</th></tr>
                </thead>
                <tbody>
                  {bundleHits.map((h) => (
                    <tr key={h.rule_id}>
                      <td className="mono">{h.rule_id}</td>
                      <td>
                        {h.bundle || <span className="faint">removed</span>}{" "}
                        {h.version ? <span className="faint" style={{ fontSize: 11 }}>{h.version}</span> : null}
                      </td>
                      <td className="muted" style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={h.message}>{h.message}</td>
                      <td className="num">{h.hits.toLocaleString()}</td>
                      <td className="num">{h.addresses.toLocaleString()}</td>
                      <td className="muted">{fmtAgo(h.last_seen)}</td>
                      <td>
                        {(h.modes?.block ?? 0) > 0
                          ? <Badge tone="bad">blocked</Badge>
                          : (h.modes?.log ?? 0) > 0
                            ? <Badge tone="warn">logged</Badge>
                            : <Badge>off</Badge>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            </div>
            <p className="muted mt" style={{ fontSize: 12, marginBottom: 0 }}>
              A hit proves a rule matched, not that the request was hostile. The counts come from the request log, so
              they follow the retention window and the sampling setting.
            </p>
          </>
        )}
      </Card>

      <Card title="Check an address">
        <div className="row grow">
          <Field label="IP address">
            <input value={probe} onChange={(e) => setProbe(e.target.value)} placeholder="203.0.113.10" />
          </Field>
          <button className="primary" style={{ marginTop: 18 }} disabled={checking || !probe.trim()} onClick={checkIP}>
            {checking ? "Checking…" : "Check"}
          </button>
        </div>
        {lookup && (
          <>
            <div className="bar-row">
              <div>Threat feed</div>
              <div>
                {lookup.feed ? (
                  <>
                    <Badge tone={lookup.feed.action === "block" ? "bad" : "warn"}>{lookup.feed.action}</Badge>{" "}
                    {lookup.feed.name}
                  </>
                ) : (
                  <span className="muted">not listed</span>
                )}
              </div>
            </div>
            <div className="bar-row" style={{ borderBottom: 0 }}>
              <div>Ban</div>
              <div>
                {lookup.ban ? (
                  <>
                    <Badge tone={lookup.ban.permanent ? "bad" : "warn"}>
                      {lookup.ban.permanent ? "permanent" : "temporary"}
                    </Badge>{" "}
                    {lookup.ban.cidr} — {lookup.ban.reason} (source: {lookup.ban.source})
                    {lookup.ban.expires_at && (
                      <span className="muted"> · until {lookup.ban.expires_at.slice(0, 16).replace("T", " ")}Z</span>
                    )}
                  </>
                ) : (
                  <span className="muted">not banned</span>
                )}
              </div>
            </div>
          </>
        )}
      </Card>

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
          ) : consoleLists ? (
            <Badge tone="warn">not reported</Badge>
          ) : undefined
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
            <div className="table-wrap"><table>
              <thead>
                <tr><th>Reason</th><th>Origin</th><th>Action</th><th className="num">Decisions</th></tr>
              </thead>
              <tbody>
                {consoleLists.rows.map((r) => (
                  <tr key={`${r.origin}:${r.reason}:${r.action}`}>
                    <td className="mono" style={{ overflowWrap: "anywhere" }}>{r.reason}</td>
                    <td>
                      <Badge tone={r.origin === "console" ? "bad" : "info"}>{r.origin}</Badge>
                    </td>
                    <td>{r.action}</td>
                    <td className="num">{r.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          </div>
        )}
        {consoleLists?.raw && (
          <pre className="mono" style={{ fontSize: 11, maxHeight: 220, overflow: "auto" }}>{consoleLists.raw}</pre>
        )}
        {consoleLists?.available && (
          <p className="muted mt" style={{ fontSize: 12, marginBottom: 0 }}>
            Reported by the Security Engine (<code>cscli metrics show decisions</code>) and enforced by the bouncer, so
            every row is a decision that is actually in force. Origins <code>lists</code> (subscribed blocklists),
            <code> CAPI</code> (community blocklist) and <code>console</code> (pushed from the console) are managed at
            app.crowdsec.net and cannot be edited here.
          </p>
        )}
      </Card>

      <Card title="Feeds">
        {feeds.length === 0 ? <Empty>No feeds configured.</Empty> : (
          <div style={{ overflowX: "auto" }}>
            <div className="table-wrap"><table>
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
                    <td>
                      {f.local ? (
                        <Badge tone="bad">block</Badge>
                      ) : (
                        <select
                          value={f.action}
                          aria-label={`Action for ${f.name}`}
                          style={{ width: 118 }}
                          onChange={(e) => setAction(f, e.target.value)}
                        >
                          <option value="block">block</option>
                          <option value="challenge">challenge</option>
                          <option value="log">log only</option>
                        </select>
                      )}
                    </td>
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
            </table></div>
          </div>
        )}
        <p className="muted mt" style={{ fontSize: 12 }}>
          Feeds are fetched with ETag/If-Modified-Since caching, deduplicated and merged into one in-memory table. A list that grows
          more than five times in a single refresh is frozen instead of applied.
        </p>
      </Card>
    </div>
  );
}
