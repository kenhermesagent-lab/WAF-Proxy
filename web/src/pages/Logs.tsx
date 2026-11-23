import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import Simulator from "../components/Simulator";
import { Badge, Card, Empty, Field, confirmDialog, errText, fmtTime } from "../ui";
import { Event } from "../types";

const PAGE = 50;
const LIVE_MS = 2000;
const VIEWS_KEY = "waf.logs.views";

type SavedView = { name: string; query: string };

function clockTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function filtersFromQuery(query?: string) {
  const q = new URLSearchParams(query ?? "");
  return {
    ip: q.get("ip") ?? "",
    host: q.get("host") ?? "",
    stage: q.get("stage") ?? "",
    action: q.get("action") ?? "",
    blocked: q.get("blocked") === "1",
  };
}

type Filters = ReturnType<typeof filtersFromQuery>;

function queryOf(f: Filters): URLSearchParams {
  const q = new URLSearchParams();
  if (f.ip) q.set("ip", f.ip);
  if (f.host) q.set("host", f.host);
  if (f.stage) q.set("stage", f.stage);
  if (f.action) q.set("action", f.action);
  if (f.blocked) q.set("blocked", "1");
  return q;
}

// A corrupt or hand-edited preference is ignored rather than breaking the page.
function readViews(): SavedView[] {
  try {
    const raw = JSON.parse(localStorage.getItem(VIEWS_KEY) ?? "[]") as unknown;
    if (!Array.isArray(raw)) return [];
    return raw.filter(
      (v): v is SavedView => !!v && typeof v === "object" && typeof (v as SavedView).name === "string" && typeof (v as SavedView).query === "string",
    );
  } catch {
    return [];
  }
}

function writeViews(views: SavedView[]) {
  try {
    localStorage.setItem(VIEWS_KEY, JSON.stringify(views));
  } catch {
    /* a full or blocked storage keeps the in-memory list */
  }
}

export default function Logs({
  onError,
  onOK,
  query,
  onOpenSource,
  canWrite,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  query?: string;
  onOpenSource: (ip: string) => void;
  canWrite: boolean;
}) {
  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState(() => filtersFromQuery(query));
  const [loading, setLoading] = useState(false);
  const [live, setLive] = useState(false);
  const [picked, setPicked] = useState<Event | null>(null);
  const [views, setViews] = useState<SavedView[]>(readViews);
  const [viewName, setViewName] = useState("");
  const [viewSel, setViewSel] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [bulkBusy, setBulkBusy] = useState(false);
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  // Only the newest request may paint the table, and a background poll never
  // races a search the operator is waiting on.
  const seq = useRef(0);
  const busy = useRef(false);

  const load = async (nextOffset = offset, active = filters, quiet = false) => {
    if (quiet && busy.current) return;
    const mine = ++seq.current;
    if (!quiet) {
      busy.current = true;
      setLoading(true);
      // Selection is per visible page, so a new search starts with none.
      setSelected([]);
    }
    const q = queryOf(active);
    q.set("limit", String(PAGE));
    q.set("offset", String(nextOffset));
    try {
      const r = await api.get<{ events: Event[]; total: number }>(`/api/events?${q.toString()}`);
      if (mine !== seq.current) return;
      setEvents(r.events || []);
      setTotal(r.total || 0);
      setOffset(nextOffset);
    } catch (e) {
      // A poll that fails is retried in two seconds; do not stack toasts for it.
      if (mine === seq.current && !quiet) onError(errText(e));
    } finally {
      if (!quiet) {
        busy.current = false;
        if (mine === seq.current) setLoading(false);
      }
    }
  };

  useEffect(() => {
    load(0);
  }, []);

  // A command-palette result opens the log with a prefilled filter.
  useEffect(() => {
    if (!query) return;
    const f = filtersFromQuery(query);
    setFilters(f);
    load(0, f);
  }, [query]);

  // Live tail: refresh the newest page while the tab is visible, and catch up
  // immediately when the operator comes back to it.
  useEffect(() => {
    if (!live) return;
    const poll = () => {
      if (document.hidden) return;
      load(0, filtersRef.current, true);
    };
    const t = window.setInterval(poll, LIVE_MS);
    document.addEventListener("visibilitychange", poll);
    return () => {
      window.clearInterval(t);
      document.removeEventListener("visibilitychange", poll);
    };
  }, [live]);

  const toggleLive = () => {
    const next = !live;
    setLive(next);
    if (next) load(0, filtersRef.current, true);
  };

  const applyView = (name: string) => {
    setViewSel(name);
    const view = views.find((v) => v.name === name);
    if (!view) return;
    const f = filtersFromQuery(view.query);
    setFilters(f);
    load(0, f);
  };

  const saveView = () => {
    const name = viewName.trim();
    if (!name) return;
    const next = [...views.filter((v) => v.name !== name), { name, query: queryOf(filters).toString() }];
    setViews(next);
    writeViews(next);
    setViewName("");
    setViewSel(name);
    onOK(`View “${name}” saved`);
  };

  const removeView = () => {
    if (!viewSel) return;
    const next = views.filter((v) => v.name !== viewSel);
    setViews(next);
    writeViews(next);
    setViewSel("");
  };

  const copyLink = async () => {
    const view = views.find((v) => v.name === viewSel);
    if (!view) return;
    const link = `${window.location.origin}${window.location.pathname}#/logs?${view.query}`;
    try {
      await navigator.clipboard.writeText(link);
      onOK("Link copied");
    } catch {
      onError("The clipboard is unavailable here; copy the address bar instead");
    }
  };

  const toggleSelected = (ip: string) =>
    setSelected((list) => (list.includes(ip) ? list.filter((x) => x !== ip) : [...list, ip]));

  const pageIps = [...new Set(events.map((e) => e.src_ip))];
  const allSelected = pageIps.length > 0 && pageIps.every((ip) => selected.includes(ip));

  const bulkBan = async () => {
    const ok = await confirmDialog(
      `Ban ${selected.length} source${selected.length === 1 ? "" : "s"} for 24 hours? Every address is audited and can be released later.`,
      { title: "Ban selected sources", confirmLabel: "Ban 24h" },
    );
    if (!ok) return;
    setBulkBusy(true);
    try {
      const results = await Promise.allSettled(
        selected.map((ip) =>
          api.post("/api/bans", { cidr: ip, reason: "bulk ban from log", permanent: false, ttl_seconds: 86400 }),
        ),
      );
      const failed = results.filter((r) => r.status === "rejected").length;
      const done = selected.length - failed;
      if (failed > 0) onError(`${done} banned, ${failed} failed`);
      else onOK(`${done} source${done === 1 ? "" : "s"} banned for 24 hours`);
      await load(0);
    } catch (e) {
      onError(errText(e));
    } finally {
      setBulkBusy(false);
    }
  };

  const copyIps = async () => {
    try {
      await navigator.clipboard.writeText(selected.join(","));
      onOK(`${selected.length} address${selected.length === 1 ? "" : "es"} copied`);
    } catch {
      onError("The clipboard is unavailable here");
    }
  };

  const exportHref = () => {
    const q = queryOf(filters);
    q.set("limit", "50000");
    return `/api/events/export.csv?${q.toString()}`;
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="Filters">
        <div className="row grow" style={{ marginBottom: 6 }}>
          <Field label="Saved views">
            <select value={viewSel} onChange={(e) => applyView(e.target.value)}>
              <option value="">Choose a view…</option>
              {views.map((v) => <option key={v.name} value={v.name}>{v.name}</option>)}
            </select>
          </Field>
          <Field label="Name">
            <input
              value={viewName}
              onChange={(e) => setViewName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && saveView()}
              placeholder="Port scans"
            />
          </Field>
          <button style={{ marginTop: 18 }} onClick={saveView} disabled={!viewName.trim()}>Save view</button>
          <button style={{ marginTop: 18 }} onClick={copyLink} disabled={!viewSel}>Copy link</button>
          <button style={{ marginTop: 18 }} onClick={removeView} disabled={!viewSel}>Delete view</button>
        </div>
        <div className="row grow">
          <div className="field"><label>Source IP</label><input value={filters.ip} onChange={(e) => setFilters({ ...filters, ip: e.target.value })} placeholder="203.0.113.7" /></div>
          <div className="field"><label>Host</label><input value={filters.host} onChange={(e) => setFilters({ ...filters, host: e.target.value })} placeholder="app.example.com" /></div>
          <div className="field"><label>Stage</label>
            <select value={filters.stage} onChange={(e) => setFilters({ ...filters, stage: e.target.value })}>
              <option value="">any</option>
              <option value="waf">waf</option>
              <option value="response-waf">response-waf</option>
              <option value="response-skipped">response-skipped</option>
              <option value="whitelist">whitelist</option>
              <option value="method">method</option>
              <option value="protocol">protocol</option>
              <option value="route">route</option>
              <option value="stream">stream</option>
              <option value="feed">feed</option>
              <option value="list-block">list-block</option>
              <option value="list-allow">list-allow</option>
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
            <button
              className={`small ${live ? "primary" : "ghost"}`}
              onClick={toggleLive}
              aria-pressed={live}
              title={live ? "Pause the live tail" : "Follow new events every 2 seconds"}
            >
              {live ? "● Live" : "Live tail"}
            </button>
            <a href={exportHref()}><button className="small">Export CSV</button></a>
            <button className="small" disabled={live || offset === 0} onClick={() => load(Math.max(0, offset - PAGE))}>Newer</button>
            <button className="small" disabled={live || offset + PAGE >= total} onClick={() => load(offset + PAGE)}>Older</button>
          </div>
        }
      >
        {selected.length > 0 && (
          <div className="banner" role="status" style={{ marginBottom: 10 }}>
            <span>
              <b>{selected.length}</b> source{selected.length === 1 ? "" : "s"} selected
            </span>
            <span className="banner-actions">
              {canWrite && (
                <button className="small danger" onClick={bulkBan} disabled={bulkBusy}>
                  {bulkBusy ? "Banning…" : "Ban 24h"}
                </button>
              )}
              <button className="small" onClick={copyIps}>Copy IPs</button>
              <button className="small ghost" onClick={() => setSelected([])}>Clear</button>
            </span>
          </div>
        )}
        {events.length === 0 ? <Empty>No events match these filters.</Empty> : (
          <div className="table-wrap"><table>
              <thead>
                <tr>
                  <th style={{ width: 28 }}>
                    <input
                      type="checkbox"
                      style={{ width: "auto" }}
                      checked={allSelected}
                      aria-label="Select every source on this page"
                      onChange={() => setSelected(allSelected ? [] : pageIps)}
                    />
                  </th>
                  <th>Time</th><th>Source</th><th className="hide-tablet">Host</th><th>Request</th><th className="hide-tablet">Stage</th><th className="hide-tablet">Rule</th><th className="num">Status</th><th className="num hide-tablet">Latency</th><th className="num hide-tablet">Out</th><th /></tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td>
                      <input
                        type="checkbox"
                        style={{ width: "auto" }}
                        checked={selected.includes(e.src_ip)}
                        aria-label={`Select ${e.src_ip}`}
                        onChange={() => toggleSelected(e.src_ip)}
                      />
                    </td>
                    <td className="muted log-time" title={fmtTime(e.ts)}>
                      <span className="log-time-full">{fmtTime(e.ts)}</span>
                      <span className="log-time-clock">{clockTime(e.ts)}</span>
                    </td>
                    <td>
                      <button className="link-cell mono" onClick={() => onOpenSource(e.src_ip)} title={`Investigate ${e.src_ip}`}>
                        {e.src_ip}
                      </button>
                      <div className="faint log-source-meta" style={{ fontSize: 11 }}>{e.country || "—"} · AS{e.asn || "?"}</div>
                    </td>
                    <td className="muted hide-tablet">{e.host}</td>
                    <td className="mono"><span className="log-request">{e.method} {e.path}</span></td>
                    <td className="hide-tablet"><Badge tone={e.action === "allow" ? "" : e.action === "log" ? "info" : "bad"}>{e.stage || "—"}</Badge></td>
                    <td className="muted hide-tablet" title={e.rule_msg || e.rule_id} style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.rule_msg || e.rule_id || "—"}</td>
                    <td className="num">{e.status}</td>
                    <td className="num hide-tablet">{e.latency_ms} ms</td>
                    <td className="num hide-tablet">{e.bytes_out}</td>
                    <td><button className="small" onClick={() => setPicked(e)}>Why?</button></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
        )}
        <p className="faint small-text" style={{ marginBottom: 0 }}>
          Selection covers this page only and clears on a new search or page.
        </p>
      </Card>

      {picked && (
        <Simulator event={picked} onClose={() => setPicked(null)} onError={onError} />
      )}
    </div>
  );
}
