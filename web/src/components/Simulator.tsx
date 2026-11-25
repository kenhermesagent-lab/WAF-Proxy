import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Modal, errText } from "../ui";
import { Event, Profile, Proxy, SimException, SimResult } from "../types";

// Simulator replays one logged event through the policy pipeline without
// touching the upstream, so an operator can see which stage refused it.
export default function Simulator({ event, onClose, onError }: {
  event: Event;
  onClose: () => void;
  onError: (m: string) => void;
}) {
  const [proxy, setProxy] = useState<Proxy | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [form, setForm] = useState({
    method: event.method,
    path: event.path,
    query: event.query ?? "",
    body: "",
    client_ip: event.src_ip,
    headers: event.ua ? { "User-Agent": event.ua } : {},
  });
  const [result, setResult] = useState<SimResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<SimException | null>(null);
  const [saved, setSaved] = useState("");

  useEffect(() => {
    let live = true;
    api.get<Proxy[]>("/api/proxies")
      .then((list) => {
        if (!live) return;
        setProxy((list ?? []).find((p) => p.hostname === event.host) ?? null);
        setLoaded(true);
      })
      .catch((e) => {
        if (!live) return;
        setLoaded(true);
        onError(errText(e));
      });
    return () => { live = false; };
  }, [event.host]);

  const run = async () => {
    if (!proxy) return;
    setBusy(true);
    setResult(null);
    setConfirming(null);
    setSaved("");
    try {
      setResult(await api.post<SimResult>("/api/simulate", { proxy_id: proxy.id, ...form }));
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const except = async (ex: SimException) => {
    try {
      const profiles = await api.get<Profile[]>("/api/profiles");
      const prof = (profiles ?? []).find((p) => p.id === ex.profile_id);
      if (!prof) {
        onError("That protection profile no longer exists.");
        return;
      }
      const ids = prof.exceptions.split(",").map((s) => s.trim()).filter(Boolean);
      if (!ids.includes(String(ex.rule_id))) ids.push(String(ex.rule_id));
      await api.put(`/api/profiles/${ex.profile_id}`, { ...prof, exceptions: ids.join(",") });
      setConfirming(null);
      setResult((prev) => (prev ? { ...prev, exception: undefined } : prev));
      setSaved(`Rule ${ex.rule_id} is now excepted in ${ex.profile}.`);
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <Modal title={`Why was this request handled this way? · ${event.host}`} onClose={onClose}>
      <div className="grid" style={{ gap: 12 }}>
        <p className="muted" style={{ margin: 0 }}>
          Replays the request through the policy pipeline in this process. Nothing is sent to the
          upstream and no rate limit is spent.
        </p>
        <div className="grid" style={{ gap: 6 }}>
          <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
            <Badge tone={event.action === "allow" ? "ok" : "bad"}>{event.action || "allow"}</Badge>
            <span className="muted">{event.status} · {event.stage || "—"}</span>
            {event.rule_id && <span className="mono">rule {event.rule_id}</span>}
            <span className="faint">{event.latency_ms} ms · {new Date(event.ts).toLocaleString()}</span>
          </div>
          {event.rule_msg && <div className="muted">{event.rule_msg}</div>}
          {event.request_id && <div className="faint mono">request {event.request_id}</div>}
          <div className="faint">
            Recorded when the request was served, above; the replay below is what the current
            configuration would do to the same request.
          </div>
        </div>
        {proxy && (
          <div className="faint" style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
            <span>site #{proxy.id}</span>
            <span>WAF {proxy.waf_mode || "inherit"}</span>
            <span>profile {proxy.profile_id ?? "default"}</span>
            <span>access profile {proxy.access_profile_id ?? "—"}</span>
            <span>gate {proxy.gate_mode || "off"}</span>
            <span>body-skip {proxy.body_skip?.length ?? 0}</span>
            <span>ceiling {proxy.max_body ? `${Math.round(proxy.max_body / (1 << 20))} MiB` : "host default"}</span>
          </div>
        )}
        <div className="row grow">
          <div className="field">
            <label>Method</label>
            <input value={form.method} onChange={(e) => setForm({ ...form, method: e.target.value })} />
          </div>
          <div className="field">
            <label>Path</label>
            <input value={form.path} onChange={(e) => setForm({ ...form, path: e.target.value })} />
          </div>
          <div className="field">
            <label>Client IP</label>
            <input value={form.client_ip} onChange={(e) => setForm({ ...form, client_ip: e.target.value })} />
          </div>
        </div>
        <div className="field">
          <label>Query</label>
          <input value={form.query} placeholder="id=1" onChange={(e) => setForm({ ...form, query: e.target.value })} />
        </div>
        <div className="field">
          <label>Body</label>
          <textarea rows={3} value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} />
          <div className="faint">
            The body is not recorded, so it starts empty. The query and user agent are filled from
            the event; no other headers were recorded.
          </div>
        </div>
        <div className="row">
          <button className="primary" onClick={run} disabled={busy || !proxy}>
            {busy ? "Simulating…" : "Simulate"}
          </button>
          {!loaded && <span className="muted">Looking up the proxy…</span>}
          {loaded && !proxy && <Badge tone="bad">No proxy is configured for {event.host}</Badge>}
          {saved && <span className="muted">{saved}</span>}
        </div>

        {result && (
          <div className="grid" style={{ gap: 10 }}>
            <div className="row">
              <Badge tone={result.verdict.action === "allow" ? "ok" : "bad"}>{result.verdict.action}</Badge>
              <span className="muted">{result.verdict.reason || result.verdict.stage}</span>
            </div>
            <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Stage</th><th>Verdict</th><th>Reason</th><th>Rules</th></tr>
              </thead>
              <tbody>
                {result.stages.map((s, i) => (
                  <tr key={i}>
                    <td><Badge tone={s.stage === result.verdict.stage && s.verdict !== "allow" ? "bad" : ""}>{s.stage}</Badge></td>
                    <td>{s.verdict}</td>
                    <td className="muted">{s.skipped || s.reason || "—"}</td>
                    <td className="mono">{(s.rule_ids ?? []).join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            {result.matches.length > 0 && (
              <div>
                <div className="muted">Matched rules</div>
                <ul style={{ margin: "4px 0 0 18px" }}>
                  {result.matches.map((m) => (
                    <li key={m.rule_id} className="mono">{m.rule_id} · {m.message}</li>
                  ))}
                </ul>
              </div>
            )}
            <div className="muted">
              {result.verdict.action === "block" || result.verdict.action === "ban"
                ? "blocked before the request was routed"
                : result.route
                  ? result.route
                  : result.upstream
                    ? `served by ${result.upstream}`
                    : "no route or upstream would serve this request"}
            </div>
            {result.truncated && <div><Badge tone="warn">Body truncated at the profile limit</Badge></div>}
            {result.notes.length > 0 && (
              <ul className="faint" style={{ margin: 0, paddingLeft: 18 }}>
                {result.notes.map((n) => <li key={n}>{n}</li>)}
              </ul>
            )}
            {result.exception && (
              <div className="grid" style={{ gap: 8 }}>
                {confirming ? (
                  <>
                    <div>
                      {confirming.other_hosts.length > 0
                        ? <>This also stops rule <strong>{confirming.rule_id}</strong> for <strong>{confirming.other_hosts.join(", ")}</strong>.</>
                        : <>No other site uses the <strong>{confirming.profile}</strong> profile, so only this site is affected.</>}
                    </div>
                    <div className="row">
                      <button className="primary" onClick={() => except(confirming)}>Confirm exception</button>
                      <button onClick={() => setConfirming(null)}>Cancel</button>
                    </div>
                  </>
                ) : (
                  <button onClick={() => setConfirming(result.exception!)}>
                    Except rule {result.exception.rule_id} in {result.exception.profile}
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
