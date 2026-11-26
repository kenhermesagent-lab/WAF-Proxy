import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import {
  Badge, Card, Empty, Field, Modal, PageHead, PageTabs, SaveBar, Switch, TableWrap, errText, fmtAgo, fmtBytes, fmtTime,
} from "../ui";
import { can, type Me } from "../types";

type Tone = "ok" | "warn" | "bad" | "info" | "";

type Finding = {
  key: string;
  target?: string;
  stage: string;
  class: string;
  title: string;
  severity: string;
  cvss?: number;
  exploitation?: string;
  cve_ids?: string[];
  product?: string;
  version?: string;
  	recommendation: string;
	note?: string;
	reason?: string;
	state?: string;
  first_seen?: string;
};

type Run = {
  id: number;
  target: string;
  trigger: string;
  actor: string;
  path: string;
  started_at: string;
  ended_at?: string;
  	verdicts?: string;
	skipped_reason?: string;
	abandoned?: boolean;
};

type Evidence = {
  seq: number;
  stage: string;
  class: string;
  method: string;
  path: string;
  verdict: string;
  wan_status: number;
  upstream_status: number;
  similarity?: number;
  detail?: string;
  note?: string;
};

type FeedSource = {
  source: string;
  last_ok?: string;
  last_error?: string;
  age_seconds?: number;
  stale: boolean;
  bytes: number;
  records: number;
  sha256?: string;
};

type Schedule = {
  site_id: number;
  cadence: string;
  hour: number;
  day: number;
  enabled: boolean;
  triggers?: string[];
  updated_by?: string;
};

type Limits = { paused: boolean; probes_per_second: number };

type Overview = {
  posture: "covered" | "exposed" | "unknown";
  open_findings: number;
  severities: Record<string, number>;
  findings: Finding[];
  runs: Run[];
  sources: FeedSource[];
};

type Target = { id: number; hostname: string; enabled: boolean };

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "scans", label: "Scans" },
  { id: "findings", label: "Findings" },
  { id: "feed", label: "Vulnerability feed" },
  { id: "schedule", label: "Schedule" },
];

const SEVERITY_TONE: Record<string, Tone> = { critical: "bad", high: "bad", medium: "warn", low: "info" };
const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// Every verdict is a state, and the ones that did not prove a block say so in
// words: not run and inconclusive are never shown as clean.
const VERDICT: Record<string, { label: string; tone: Tone }> = {
  "blocked-waf": { label: "Blocked by the WAF", tone: "ok" },
  "blocked-gate": { label: "Stopped by the gate", tone: "ok" },
  "reached-backend": { label: "Reached the backend", tone: "bad" },
  "not-blocked": { label: "Not blocked", tone: "bad" },
  inconclusive: { label: "Inconclusive — not clean", tone: "warn" },
  "not-run": { label: "Not run — not clean", tone: "warn" },
  unknown: { label: "Unknown — not clean", tone: "warn" },
  passed: { label: "Control passed", tone: "ok" },
  "not-applicable": { label: "Not applicable", tone: "" },
};

const POSTURE: Record<string, { label: string; tone: Tone; text: string }> = {
  covered: {
    label: "Covered",
    tone: "ok",
    text: "The last run found nothing reachable and every vulnerability feed is current.",
  },
  exposed: {
    label: "Exposed",
    tone: "bad",
    text: "A reachable issue was found. Treat the site as exposed until the finding is fixed or accepted.",
  },
  unknown: {
    label: "Unknown",
    tone: "warn",
    text: "Nothing has run, or a vulnerability feed is stale, so the state is unknown — not clean.",
  },
};

const TRIGGERS = [
  { id: "config", label: "After a configuration change" },
  { id: "upgrade", label: "After an upgrade" },
  { id: "kev", label: "When a new KEV entry matches a watched component" },
];

function verdictBadge(verdict: string) {
  const v = VERDICT[verdict];
  return <Badge tone={v?.tone ?? "info"}>{v?.label ?? verdict}</Badge>;
}

function parseVerdicts(raw?: string): [string, number][] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as Record<string, number>;
    return Object.entries(parsed).sort((a, b) => b[1] - a[1]);
  } catch {
    return [];
  }
}

function duration(run: Run): string {
  if (!run.ended_at) return run.abandoned ? "abandoned" : "running";
  const ms = new Date(run.ended_at).getTime() - new Date(run.started_at).getTime();
  return ms < 1000 ? `${ms} ms` : `${Math.round(ms / 1000)} s`;
}

// The Security page reads the site's scan state and offers the four writes the
// server also checks: a run, a finding decision, a schedule and the limits.
// A role without the token sees the same page with the action disabled and the
// reason in its title, so the page never pretends a button would work.
export default function SecurityPage({
  me, tab = "overview", tabs = TABS, onTab, onError, onOK,
}: {
  me?: Me | null;
  tab?: string;
  tabs?: { id: string; label: string }[];
  onTab?: (id: string) => void;
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const active = TABS.some((t) => t.id === tab) ? tab : "overview";
  const perms = me?.permissions;
  const canRun = can(perms, "security.run");
  const canWrite = can(perms, "security.write");

  const [overview, setOverview] = useState<Overview | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [feed, setFeed] = useState<{ sources: FeedSource[]; storage_cap_bytes: number } | null>(null);
  const [schedule, setSchedule] = useState<Schedule | null>(null);
  const [limits, setLimits] = useState<Limits>({ paused: false, probes_per_second: 12 });
  const [targets, setTargets] = useState<Target[]>([]);
  const [detail, setDetail] = useState<{ run: Run; evidence: Evidence[] } | null>(null);
  const [stateFilter, setStateFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [accepting, setAccepting] = useState<Finding | null>(null);
  const [note, setNote] = useState("");
  const [selected, setSelected] = useState<number[]>([]);

  const load = () => {
    api.get<Overview>("/api/security/overview").then(setOverview).catch((e) => onError(errText(e)));
    api.get<{ runs: Run[] }>("/api/security/runs").then((r) => setRuns(r.runs ?? [])).catch(() => undefined);
    api.get<{ findings: Finding[] }>("/api/security/findings").then((r) => setFindings(r.findings ?? [])).catch(() => undefined);
    api.get<{ sources: FeedSource[]; storage_cap_bytes: number }>("/api/security/feed").then(setFeed).catch(() => undefined);
    api.get<{ schedule: Schedule }>("/api/security/schedule").then((r) => setSchedule(r.schedule)).catch(() => undefined);
    api.get<Limits>("/api/security/limits").then(setLimits).catch(() => undefined);
    // /api/proxies answers with a bare array, not a wrapper object.
    api.get<Target[]>("/api/proxies").then((r) => setTargets(Array.isArray(r) ? r : [])).catch(() => undefined);
  };

  	// Refetch per tab, not once per mount: a scheduled run or a decision made
	// in another window changes the findings, and a tab switch is the natural
	// moment to show it rather than the stale list from first load.
	useEffect(() => {
		load();
	}, [active]);

  const openDetail = async (id: number) => {
    try {
      const r = await api.get<{ run: Run; evidence: Evidence[] }>(`/api/security/runs/${id}`);
      setDetail(r);
    } catch (e) {
      onError(errText(e));
    }
  };

  const startRun = async () => {
    if (selected.length === 0) {
      onError("Choose at least one hostname to scan.");
      return;
    }
    setBusy("run");
    try {
      const r = await api.post<{ runs: Run[] }>("/api/security/runs", { targets: selected });
      onOK(`Scan finished on ${r.runs.map((x) => x.target).join(", ")}`);
      setSelected([]);
      load();
      if (r.runs[0]) await openDetail(r.runs[0].id);
      onTab?.("scans");
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(null);
    }
  };

  const decide = async (finding: Finding, state: string, reason: string) => {
    setBusy(finding.key);
    try {
      		// The scan's note is the server's; only the acceptance reason is ours.
		await api.patch(`/api/security/findings/${encodeURIComponent(finding.key)}`, { state, reason: reason || undefined });
      onOK(state === "accepted" ? "Finding accepted" : "Finding reopened for the next run");
      setAccepting(null);
      setNote("");
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(null);
    }
  };

  const syncFeed = async () => {
    setBusy("feed");
    try {
      const r = await api.post<{ changed: boolean; records: number }>("/api/security/feed/sync", { source: "kev" });
      onOK(r.changed ? `The KEV snapshot updated (${r.records} entries)` : "The KEV snapshot was already current");
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(null);
    }
  };

  const saveSchedule = async () => {
    if (!schedule) return;
    setBusy("schedule");
    try {
      const r = await api.put<{ schedule: Schedule }>("/api/security/schedule", {
        cadence: schedule.cadence, hour: schedule.hour, day: schedule.day,
        enabled: schedule.enabled, triggers: schedule.triggers ?? [],
      });
      setSchedule(r.schedule);
      onOK("Scan schedule saved");
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(null);
    }
  };

  const saveLimits = async () => {
    setBusy("limits");
    try {
      setLimits(await api.put<Limits>("/api/security/limits", limits));
      onOK("Scan limits saved");
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(null);
    }
  };

  const visible = useMemo(
    () =>
      findings
        .filter((f) => (stateFilter ? (f.state || "open") === stateFilter : true))
        .filter((f) => (severityFilter ? f.severity === severityFilter : true))
        .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)),
    [findings, stateFilter, severityFilter],
  );
  const attention = useMemo(
    () => findings.filter((f) => !f.state || f.state === "open").sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)).slice(0, 5),
    [findings],
  );
  const watched = useMemo(() => {
    const byProduct = new Map<string, string>();
    for (const f of findings) {
      if (f.product && (!f.state || f.state === "open")) byProduct.set(f.product, f.version ?? "");
    }
    return [...byProduct.entries()];
  }, [findings]);
  const posture = POSTURE[overview?.posture ?? "unknown"];

  const runButton = (
    <button className="primary" onClick={startRun} disabled={!canRun || busy === "run"} title={canRun ? undefined : "Your role cannot start scans."}>
      {busy === "run" ? "Scanning…" : "Run scan"}
    </button>
  );

  return (
    <>
      <PageHead
        sub="Scan this node's own published hostnames the way a stranger would, then join what the WAF missed to public vulnerability data."
        actions={runButton}
      />
      <PageTabs tabs={tabs} active={active} onSelect={(id) => onTab?.(id)} />

      {active === "overview" && (
        <>
          <Card
            title="Posture"
            actions={<Badge tone={posture.tone}>{posture.label}</Badge>}
          >
            <p className="muted">{posture.text}</p>
            <p className="muted">
              {overview
                ? `${overview.open_findings} open finding${overview.open_findings === 1 ? "" : "s"} · last run ${
                    overview.runs[0] ? fmtAgo(overview.runs[0].started_at) : "never"
                  }`
                : "Reading the last runs and feed state…"}
            </p>
            {overview && Object.keys(overview.severities).length > 0 && (
              <p>
                {["critical", "high", "medium", "low"].map((sev) =>
                  overview.severities[sev] ? (
                    <span key={sev} style={{ marginRight: 8 }}>
                      <Badge tone={SEVERITY_TONE[sev]}>{`${overview.severities[sev]} ${sev}`}</Badge>
                    </span>
                  ) : null,
                )}
              </p>
            )}
          </Card>

          <Card title="Needs attention" sub="Ordered by severity; a KEV hit means it is being exploited in the wild.">
            {attention.length === 0 ? (
              <Empty title="Nothing open">A run that found nothing is not the same as a run that did not happen; the posture above says which one this is.</Empty>
            ) : (
              <TableWrap>
                <table>
                  <thead>
                    <tr>
                      <th>Finding</th>
                      <th>Hostname</th>
                      <th>Severity</th>
                      <th>Exploitation</th>
                      <th>What to do</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attention.map((f) => (
                      <tr key={f.key}>
                        <td>{f.title}</td>
                        <td>{f.target || "—"}</td>
                        <td><Badge tone={SEVERITY_TONE[f.severity]}>{f.severity}</Badge></td>
                        <td>{f.exploitation ? <Badge tone="bad">{f.exploitation}</Badge> : <span className="muted">none known</span>}</td>
                        <td>{f.recommendation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </Card>

          <Card title="Scan a hostname" sub="A target is a proxy record this site may read; the scan never accepts a URL.">
            {targets.length === 0 ? (
              <p className="muted">This site has no hostnames yet.</p>
            ) : (
              <div>
                {targets.map((t) => (
                  <label key={t.id} style={{ display: "block" }}>
                    <input
                      type="checkbox"
                      checked={selected.includes(t.id)}
                      disabled={!canRun}
                      onChange={(e) =>
                        setSelected((list) => (e.target.checked ? [...list, t.id] : list.filter((id) => id !== t.id)))
                      }
                    />
                    <span>{t.hostname}</span>
                  </label>
                ))}
              </div>
            )}
            <p className="muted">At most four hostnames per run. A paused scanner refuses every run, manual or scheduled.</p>
          </Card>

          <Card title="Recent runs">
            {runs.length === 0 ? (
              <p className="muted">No run has happened on this site yet.</p>
            ) : (
              <TableWrap>
                <table>
                  <thead>
                    <tr><th>Hostname</th><th>Trigger</th><th>Started</th><th>Duration</th><th>Path</th><th>Verdicts</th><th /></tr>
                  </thead>
                  <tbody>
                    {runs.slice(0, 5).map((r) => (
                      <tr key={r.id}>
                        <td>{r.target}</td>
                        <td>{r.trigger}</td>
                        <td>{fmtTime(r.started_at)}</td>
                        <td>{r.abandoned ? <Badge tone="warn">abandoned</Badge> : duration(r)}</td>
                        <td>{r.skipped_reason ? <Badge tone="warn">{`skipped: ${r.skipped_reason}`}</Badge> : r.path || "—"}</td>
                        <td>{parseVerdicts(r.verdicts).map(([v, n]) => `${VERDICT[v]?.label ?? v} ${n}`).join(", ") || "—"}</td>
                        <td><button onClick={() => { onTab?.("scans"); openDetail(r.id); }}>Detail</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </Card>

          <Card title="Feed freshness" sub="A stale source makes every dependent claim unknown rather than clean.">
            <FeedTable sources={overview?.sources ?? feed?.sources ?? []} />
          </Card>

          <Card title="Authorization" sub="Fixed rules on the server, not settings.">
            <ul>
              <li>Read-only toward the backend: GET, HEAD, OPTIONS and TRACE, plus two POSTs it cannot choose.</li>
              <li>Only proxy records this site may read; a foreign target is a 404 and is audited.</li>
              <li>Evidence keeps hashes, status and header names, never a credential or a response body.</li>
              <li>Starting a scan needs security.run; changing findings and the schedule needs security.write.</li>
            </ul>
          </Card>
        </>
      )}

      {active === "scans" && (
        <>
          <Card title="Run history">
            {runs.length === 0 ? (
              <p className="muted">No run has happened on this site yet.</p>
            ) : (
              <TableWrap>
                <table>
                  <thead>
                    <tr><th>Hostname</th><th>Trigger</th><th>Actor</th><th>Started</th><th>Duration</th><th>Path</th><th /></tr>
                  </thead>
                  <tbody>
                    {runs.map((r) => (
                      <tr key={r.id}>
                        <td>{r.target}</td>
                        <td>{r.trigger}</td>
                        <td>{r.actor || "—"}</td>
                        <td>{fmtTime(r.started_at)}</td>
                        <td>{r.abandoned ? <Badge tone="warn">abandoned</Badge> : duration(r)}</td>
                        <td>{r.skipped_reason ? <Badge tone="warn">{`skipped: ${r.skipped_reason}`}</Badge> : r.path || "—"}</td>
                        <td><button onClick={() => openDetail(r.id)}>Evidence</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </Card>

          {detail && (
            <Card
              title={`Run #${detail.run.id} · ${detail.run.target}`}
              actions={<button onClick={() => setDetail(null)}>Close</button>}
              sub="Each row is one probe. A local path means the request never left this node, so its findings are this node's WAF, not the operator's edge."
            >
              {detail.run.abandoned ? (
                <p><Badge tone="warn">This run never finished: the process died before it could close the run. Its evidence below is what it recorded, and it is not a clean result.</Badge></p>
              ) : null}
              {detail.run.skipped_reason ? (
                <p><Badge tone="warn">{`This run stopped early: ${detail.run.skipped_reason}`}</Badge></p>
              ) : null}
              <p>
                <Badge tone={detail.run.path === "edge" ? "ok" : "info"}>Path: {detail.run.path || "unknown"}</Badge>{" "}
                <span className="muted">
                  {parseVerdicts(detail.run.verdicts).map(([v, n]) => `${VERDICT[v]?.label ?? v} ${n}`).join(" · ")}
                </span>
              </p>
              <TableWrap>
                <table>
                  <thead>
                    <tr><th>#</th><th>Stage</th><th>Class</th><th>Request</th><th>Verdict</th><th>WAN</th><th>Upstream</th><th>Detail</th></tr>
                  </thead>
                  <tbody>
                    {detail.evidence.map((ev) => (
                      <tr key={ev.seq}>
                        <td>{ev.seq}</td>
                        <td>{ev.stage}</td>
                        <td>{ev.class}</td>
                        <td><code>{ev.method} {ev.path}</code></td>
                        <td>{verdictBadge(ev.verdict)}</td>
                        <td>{ev.wan_status || "—"}</td>
                        <td>{ev.upstream_status || "—"}</td>
                        <td>{ev.detail || ev.note || ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </Card>
          )}
        </>
      )}

      {active === "findings" && (
        <Card
          title="Findings"
          actions={
            <span className="actions">
              <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)} aria-label="Filter by state">
                <option value="">All states</option>
                <option value="open">Open</option>
                <option value="accepted">Accepted</option>
                <option value="resolved">Resolved</option>
              </select>
              <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} aria-label="Filter by severity">
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </span>
          }
          sub="Accepting a finding records who and why; it stays accepted across runs until it is reopened."
        >
          {visible.length === 0 ? (
            <Empty title="No findings match">Nothing is proven open with these filters. A stale feed still makes the state unknown, not clean.</Empty>
          ) : (
            <TableWrap>
              <table>
                <thead>
                  <tr><th>Finding</th><th>Hostname</th><th>Severity</th><th>Component</th><th>State</th><th>First seen</th><th /></tr>
                </thead>
                <tbody>
                  {visible.map((f) => (
                    <tr key={f.key}>
                      <td>
                        <div>{f.title}</div>
                        <div className="muted">{f.recommendation}</div>
                        {f.reason ? <div className="muted">Accepted reason: {f.reason}</div> : null}
                        {f.note ? <div className="muted">Scan note: {f.note}</div> : null}
                        {f.cve_ids?.length ? <div className="muted">{f.cve_ids.join(", ")}</div> : null}
                      </td>
                      <td>{f.target || "—"}</td>
                      <td>
                        <Badge tone={SEVERITY_TONE[f.severity]}>{f.severity}</Badge>
                        {f.exploitation ? <div><Badge tone="bad">{f.exploitation}</Badge></div> : null}
                      </td>
                      <td>{f.product ? `${f.product} ${f.version ?? ""}` : "—"}</td>
                      <td><Badge tone={(f.state || "open") === "open" ? "warn" : (f.state === "accepted" ? "info" : "ok")}>{f.state || "open"}</Badge></td>
                      <td>{f.first_seen ? fmtAgo(f.first_seen) : "—"}</td>
                      <td>
                        <span className="actions">
                          <button
                            disabled={!canWrite || busy === f.key || f.state === "accepted"}
                            title={canWrite ? undefined : "Your role cannot change findings."}
                            onClick={() => { setAccepting(f); setNote(f.reason ?? ""); }}
                          >
                            Accept…
                          </button>
                          <button
                            disabled={!canWrite || busy === f.key || (f.state || "open") === "open"}
                            title={canWrite ? undefined : "Your role cannot change findings."}
                            							onClick={() => decide(f, "open", "")}
                          >
                            Reopen
                          </button>
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>
      )}

      {active === "feed" && (
        <>
          <Card
            title="Sources"
            actions={
              <button onClick={syncFeed} disabled={!canWrite || busy === "feed"} title={canWrite ? undefined : "Your role cannot sync feeds."}>
                {busy === "feed" ? "Syncing…" : "Sync KEV now"}
              </button>
            }
            sub="Three times the source's cadence counts as stale. OSV is queried per component and cached, so it has no bulk sync."
          >
            <FeedTable sources={feed?.sources ?? []} />
          </Card>
          <Card title="Storage" sub="The feature's whole budget, not just this snapshot.">
            {feed ? (
              <p>
                {fmtBytes(feed.sources.reduce((n, s) => n + s.bytes, 0))} of {fmtBytes(feed.storage_cap_bytes)} used
              </p>
            ) : (
              <p className="muted">Reading storage…</p>
            )}
          </Card>
          <Card title="Components watched" sub="A component is watched because an open finding names it; a version is only as good as the evidence that produced it.">
            {watched.length === 0 ? (
              <p className="muted">No open finding names a component yet.</p>
            ) : (
              <ul>
                {watched.map(([product, version]) => (
                  <li key={product}>{product} {version || "(version unknown — never reported as clean)"}</li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}

      {active === "schedule" && (
        <>
          <Card
            title="Scan cadence"
            sub="Per site, with jitter, and skipped when the proxy configuration and fingerprints are unchanged."
          >
            {!schedule ? (
              <p className="muted">Reading the schedule…</p>
            ) : (
              <>
                <Switch
                  label="Enabled"
                  help="The scheduler runs on the active node only."
                  checked={schedule.enabled}
                  disabled={!canWrite}
                  onChange={(v) => setSchedule({ ...schedule, enabled: v })}
                />
                <Field label="Cadence">
                  <select
                    value={schedule.cadence}
                    disabled={!canWrite}
                    onChange={(e) => setSchedule({ ...schedule, cadence: e.target.value })}
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </Field>
                {schedule.cadence !== "daily" && (
                  <Field
                    label={schedule.cadence === "weekly" ? "Weekday (0 = Sunday)" : "Day of month"}
                    hint={schedule.cadence === "monthly" ? "1–28, so every month has the day." : undefined}
                  >
                    <input
                      type="number"
                      min={schedule.cadence === "monthly" ? 1 : 0}
                      max={schedule.cadence === "monthly" ? 28 : 6}
                      value={schedule.day}
                      disabled={!canWrite}
                      onChange={(e) => setSchedule({ ...schedule, day: Number(e.target.value) })}
                    />
                  </Field>
                )}
                <Field label="Hour (UTC)" hint="Jitter stays inside this hour.">
                  <input
                    type="number"
                    min={0}
                    max={23}
                    value={schedule.hour}
                    disabled={!canWrite}
                    onChange={(e) => setSchedule({ ...schedule, hour: Number(e.target.value) })}
                  />
                </Field>
                <Field label="Triggers" hint="On top of the schedule.">
                  <div>
                    {TRIGGERS.map((t) => (
                      <label key={t.id} style={{ display: "block" }}>
                        <input
                          type="checkbox"
                          checked={(schedule.triggers ?? []).includes(t.id)}
                          disabled={!canWrite}
                          onChange={(e) =>
                            setSchedule({
                              ...schedule,
                              triggers: e.target.checked
                                ? [...(schedule.triggers ?? []), t.id]
                                : (schedule.triggers ?? []).filter((x) => x !== t.id),
                            })
                          }
                        />
                        <span>{t.label}</span>
                      </label>
                    ))}
                  </div>
                </Field>
                <SaveBar
                  note={schedule.updated_by ? `Last saved by ${schedule.updated_by}` : "Not saved yet"}
                  saving={busy === "schedule"}
                  disabled={!canWrite}
                  onSave={saveSchedule}
                />
              </>
            )}
          </Card>

          <Card title="Engine and safety limits" sub="Conservative by default: 12 requests a second and at most four hostnames per run.">
            <Switch
              label="Pause all scanning"
              help="Manual and scheduled runs are both refused while this is on."
              checked={limits.paused}
              disabled={!canWrite}
              onChange={(v) => setLimits({ ...limits, paused: v })}
            />
            <Field label="Probes per second" hint="1–50. The runner also aborts a run on a sustained 429.">
              <input
                type="number"
                min={1}
                max={50}
                value={limits.probes_per_second}
                disabled={!canWrite}
                onChange={(e) => setLimits({ ...limits, probes_per_second: Number(e.target.value) })}
              />
            </Field>
            <button onClick={saveLimits} disabled={!canWrite || busy === "limits"} title={canWrite ? undefined : "Your role cannot change limits."}>
              {busy === "limits" ? "Saving…" : "Save limits"}
            </button>
          </Card>

          <Card title="Alerting" sub="Findings use the channels already set up under Notifications.">
            <p className="muted">
              A new finding sends security_new, a resolved one sends security_resolved, and a KEV match sends
              security_kev. Alerts dedupe by finding key, so a nightly run does not repeat what is already open.
            </p>
          </Card>
        </>
      )}

      {accepting && (
        <Modal
          title={`Accept “${accepting.title}”`}
          onClose={() => setAccepting(null)}
          footer={
            <>
              <button onClick={() => setAccepting(null)}>Cancel</button>
              <button
                className="primary"
                disabled={busy === accepting.key || note.trim() === ""}
                onClick={() => decide(accepting, "accepted", note.trim())}
              >
                Accept with reason
              </button>
            </>
          }
        >
          			<p className="muted">The reason is stored apart from the scan's own note, so it survives a reopen and is shown next to it.</p>
          <Field label="Why is this acceptable?">
            <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={4} />
          </Field>
        </Modal>
      )}
    </>
  );
}

function FeedTable({ sources }: { sources: FeedSource[] }) {
  if (sources.length === 0) return <p className="muted">Reading feed state…</p>;
  return (
    <TableWrap>
      <table>
        <thead>
          <tr><th>Source</th><th>Last success</th><th>Age</th><th>State</th><th>Records</th><th>Size</th></tr>
        </thead>
        <tbody>
          {sources.map((s) => (
            <tr key={s.source}>
              <td>{s.source.toUpperCase()}</td>
              <td>{s.last_ok ? fmtTime(s.last_ok) : "never"}</td>
              <td>{s.last_ok ? fmtAgo(s.last_ok) : "—"}</td>
              <td>
                {s.stale ? <Badge tone="warn">stale — claims unknown</Badge> : <Badge tone="ok">current</Badge>}
                {s.last_error ? <div className="muted">{s.last_error}</div> : null}
              </td>
              <td>{s.records}</td>
              <td>{fmtBytes(s.bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
