import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Field, PageHead, TableWrap, errText, fmtAgo, fmtTime } from "../ui";
import type { HADiagnostics, HAEventItem, HAStatus, Me } from "../types";

type Action = "sync" | "failover" | "failback" | "unpair";

const ROLE_TONE: Record<string, "ok" | "warn" | "bad" | "info" | ""> = {
  active: "ok",
  standby: "info",
  standalone: "",
};

const ACTION_LABEL: Record<Action, string> = {
  sync: "Sync now",
  failover: "Fail over",
  failback: "Fail back",
  unpair: "Unpair",
};

// The page is read-only apart from the four buttons below; every one of them
// re-authenticates, and failover/unpair need the cluster id typed again.
export default function HAPage({
  me, version = "", onError, onOK,
}: {
  me?: Me | null;
  version?: string;
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [st, setSt] = useState<HAStatus | null>(null);
  const [diag, setDiag] = useState<HADiagnostics | null>(null);
  const [events, setEvents] = useState<HAEventItem[]>([]);
  const [pairCode, setPairCode] = useState<{ code: string; expires_at: string } | null>(null);
  const [join, setJoin] = useState({ address: "", fingerprint: "", code: "" });
  const [pending, setPending] = useState<Action | null>(null);
  const [confirm, setConfirm] = useState({ password: "", totp: "", cluster: "", dryRun: true, force: false });
  const [busy, setBusy] = useState(false);

  const load = () => {
    api.get<HAStatus>("/api/ha").then(setSt).catch(() => undefined);
    api.get<HADiagnostics>("/api/ha/diagnostics").then(setDiag).catch(() => undefined);
    api.get<{ events: HAEventItem[] }>("/api/ha/events").then((r) => setEvents(r.events ?? [])).catch(() => undefined);
  };

  useEffect(() => {
    load();
    const tick = () => {
      if (document.visibilityState === "visible") load();
    };
    const timer = window.setInterval(tick, 5000);
    document.addEventListener("visibilitychange", tick);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", tick);
    };
  }, []);

  const createPair = async () => {
    try {
      const r = await api.post<{ code: string; expires_at: string }>("/api/ha/pair", {
        password: confirm.password, totp: confirm.totp,
      });
      setPairCode(r);
      onOK("Pairing code created; it expires in 10 minutes");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const joinPair = async () => {
    try {
      await api.post("/api/ha/join", {
        address: join.address, fingerprint: join.fingerprint, code: join.code,
        password: confirm.password, totp: confirm.totp,
      });
      onOK("Joined the pair; restart this node to bring up its HA role");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const run = async () => {
    if (!pending) return;
    setBusy(true);
    try {
      await api.post(`/api/ha/${pending}`, {
        password: confirm.password, totp: confirm.totp,
        cluster_id: pending === "failover" || pending === "unpair" ? confirm.cluster : undefined,
        dry_run: pending === "failover" || pending === "failback" ? confirm.dryRun : undefined,
        force: pending === "failover" || pending === "failback" ? confirm.force : undefined,
      });
      onOK(`${ACTION_LABEL[pending]} finished`);
      setPending(null);
      setConfirm({ password: "", totp: "", cluster: "", dryRun: true, force: false });
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const copy = async (label: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      onOK(`${label} copied`);
    } catch {
      onError("The clipboard is not available in this browser");
    }
  };

  if (!st) {
    return (
      <>
        <PageHead sub="Two nodes, one service address." />
        <div className="card"><p className="faint">Reading this node's role…</p></div>
      </>
    );
  }

  if (st && !st.enabled) {
    return (
      <>
        <PageHead sub="Two nodes, one service address." />
        <div className="card">
          <div className="section-head">
            <h2>High availability is turned off</h2>
            <p>{st.reason || "Enable it in Settings → High availability to pair this node."}</p>
          </div>
          <a className="button primary" href="#/settings">Open Settings</a>
        </div>
      </>
    );
  }

  const role = st?.role ?? "standalone";
  const state = st?.state ?? "standalone";
  const canWrite = !!st?.can_write;
  const paired = !!st?.paired;
  const readOnlyReason = !canWrite ? "Your role cannot run HA actions." : !paired ? "Pair this node first." : "";
  const standby = paired && role === "standby";
  const actionDisabled = (action: Action) => {
    if (!canWrite) return "Your role cannot run HA actions.";
    if (!paired) return "Pair this node first.";
    if (action === "failover" && role !== "active") return "Only the active node can fail over.";
    if (action === "failback" && role !== "standby") return "Only a standby can fail back.";
    return "";
  };

  return (
    <>
      <PageHead
        sub={
          <>
            Cluster {st?.cluster_id ? <code>{st.cluster_id}</code> : "not paired"} · epoch {st?.epoch ?? 0} ·{" "}
            {paired ? (st?.serving ? "serving" : "not serving") : "unpaired"} · app {version}
          </>
        }
        actions={
          <>
            <button
              className="secondary"
              disabled={!diag}
              title={diag ? "Copy the diagnostics JSON" : "Diagnostics are still loading."}
              onClick={() => diag && copy("Diagnostics", JSON.stringify(diag, null, 2))}
            >
              Copy diagnostics
            </button>
            <button
              className="secondary"
              disabled={!!actionDisabled("sync")}
              title={actionDisabled("sync") || undefined}
              onClick={() => setPending("sync")}
            >
              Sync now
            </button>
          </>
        }
      />

      <div aria-live="polite" className="faint small-text" style={{ marginBottom: 10 }}>
        {role.toUpperCase()} — {state}. {st?.reason ?? ""}
      </div>

      {standby && (
        <div className="card" style={{ borderLeft: "4px solid var(--warn, #d08b2e)" }}>
          <strong>STANDBY — READ ONLY.</strong> This node follows the active; configuration changes are refused
          here until it is promoted. Sync now, Copy diagnostics and the read-only cards still work.
        </div>
      )}

      {!paired ? (
        <section className="card">
          <div className="section-head">
            <h2>Pair this node</h2>
            <p>Create a pair here and join it from the other node with the code it shows, or join an existing pair.</p>
          </div>
          <div className="field-grid">
            <Field label="Your administrator password">
              <input type="password" value={confirm.password} onChange={(e) => setConfirm({ ...confirm, password: e.target.value })} />
            </Field>
            <Field label="Authenticator code (when enrolled)">
              <input value={confirm.totp} onChange={(e) => setConfirm({ ...confirm, totp: e.target.value })} placeholder="123456" />
            </Field>
          </div>
          <div className="bar-row">
            <div>
              <strong>Create a pair</strong>
              <p className="faint small-text">Shows a 26-character code once, valid for 10 minutes.</p>
            </div>
            <button className="primary" onClick={createPair}>Create a pair</button>
          </div>
          {pairCode && (
            <div className="card" aria-live="polite">
              <p>Give this code to the other node. It expires {fmtAgo(pairCode.expires_at)}.</p>
              <p><code style={{ fontSize: 16, letterSpacing: 2 }}>{pairCode.code}</code></p>
              <button className="secondary" onClick={() => copy("Pairing code", pairCode.code)}>Copy code</button>
            </div>
          )}
          <div className="section-head" style={{ marginTop: 16 }}>
            <h3>Join a pair</h3>
            <p>Run <code>wafproxy ha pair</code> on the other node, then paste its address, fingerprint and code.</p>
          </div>
          <div className="field-grid">
            <Field label="Peer HA address"><input value={join.address} onChange={(e) => setJoin({ ...join, address: e.target.value })} placeholder="10.0.0.10:9443" /></Field>
            <Field label="Peer fingerprint"><input value={join.fingerprint} onChange={(e) => setJoin({ ...join, fingerprint: e.target.value })} /></Field>
            <Field label="Pairing code"><input value={join.code} onChange={(e) => setJoin({ ...join, code: e.target.value })} /></Field>
          </div>
          <button className="primary" onClick={joinPair}>Join the pair</button>
          <p className="faint small-text">
            Both nodes need certificates, the same master key, a reachable HA address, firewall rules for 9443,
            clock sync and keepalived. See section 5 of the HA runbook.
          </p>
        </section>
      ) : (
        <>
          <section className="card">
            <div className="section-head">
              <h2>Role and state</h2>
              <p>What this node is doing right now.</p>
            </div>
            <div className="bar-row"><div>Role</div><div><Badge tone={ROLE_TONE[role] ?? "info"}>{role.toUpperCase()}</Badge></div></div>
            <div className="bar-row"><div>State</div><div>{state}</div></div>
            <div className="bar-row"><div>Epoch</div><div>{st?.epoch ?? 0}</div></div>
            <div className="bar-row"><div>Serving traffic</div><div>{st?.serving ? "yes" : "no"}</div></div>
            <div className="bar-row"><div>In role since</div><div>{fmtAgo(st?.updated_at)}</div></div>
            {st?.reason ? <div className="bar-row"><div>Reason</div><div>{st.reason}</div></div> : null}
          </section>

          <section className="card">
            <div className="section-head">
              <h2>Peer</h2>
              <p>The other node in this pair.</p>
            </div>
            <div className="bar-row"><div>Address</div><div>{st?.peer || "not reported"}</div></div>
            <div className="bar-row"><div>Fingerprint</div><div><code>{st?.peer_fingerprint ?? "—"}</code></div></div>
            <div className="bar-row"><div>Cluster id</div><div><code>{st?.cluster_id ?? "—"}</code></div></div>
            <p className="faint small-text">Heartbeat, RTT and clock skew are reported by <code>wafproxy ha status</code>.</p>
          </section>

          <section className="card">
            <div className="section-head">
              <h2>Replication</h2>
              <p>What has not reached the other node yet.</p>
            </div>
            <div className="bar-row"><div>Outbox depth</div><div>{diag?.outbox?.depth ?? 0}</div></div>
            <div className="bar-row"><div>Outbox size</div><div>{Math.round((diag?.outbox?.bytes ?? 0) / 1024)} KiB</div></div>
            <div className="bar-row"><div>Last acknowledged sequence</div><div>{diag?.ack?.seq ?? 0}</div></div>
            <div className="bar-row"><div>Acknowledged</div><div>{fmtAgo(diag?.ack?.at)}</div></div>
            {diag?.outbox?.pending_by_kind && Object.keys(diag.outbox.pending_by_kind).length > 0 && (
              <TableWrap>
                <table>
                  <thead><tr><th>Kind</th><th>Pending</th></tr></thead>
                  <tbody>
                    {Object.entries(diag.outbox.pending_by_kind).map(([kind, n]) => (
                      <tr key={kind}><td>{kind}</td><td>{n}</td></tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </section>

          <section className="card">
            <div className="section-head">
              <h2>Actions from this console</h2>
              <p>The last 20 HA actions taken here; the durable record is the audit log.</p>
            </div>
            {events.length === 0 ? (
              <p className="faint">No HA actions from this process yet.</p>
            ) : (
              <TableWrap>
                <table>
                  <thead><tr><th>Time</th><th>Action</th><th>Result</th><th>Epoch</th><th>Duration</th></tr></thead>
                  <tbody>
                    {events.slice(0, 20).map((e, i) => (
                      <tr key={`${e.at}-${i}`}>
                        <td>{fmtTime(e.at)}</td>
                        <td>{e.action}</td>
                        <td>{e.ok ? "ok" : e.error || "failed"}</td>
                        <td>{e.epoch ?? "—"}</td>
                        <td>{e.duration_ms ? `${e.duration_ms} ms` : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </section>

          <section className="card">
            <div className="section-head">
              <h2>Maintenance</h2>
              <p>Every action re-authenticates. Moves can be dry-run first.</p>
            </div>
            <div className="bar-row">
              <div>Flap budget</div>
              <div>{st?.max_failovers_per_hour ?? "—"} automatic moves per hour</div>
            </div>
            <div className="bar-row">
              <div>
                <strong>Fail over</strong>
                <p className="faint small-text">Move the service to the peer, if it is healthy.</p>
              </div>
              <button disabled={!!actionDisabled("failover")} title={actionDisabled("failover") || undefined} onClick={() => setPending("failover")}>Fail over</button>
            </div>
            <div className="bar-row">
              <div>
                <strong>Fail back</strong>
                <p className="faint small-text">Take the service back after a failover.</p>
              </div>
              <button disabled={!!actionDisabled("failback")} title={actionDisabled("failback") || undefined} onClick={() => setPending("failback")}>Fail back</button>
            </div>
            <div className="bar-row">
              <div>
                <strong>Unpair</strong>
                <p className="faint small-text">Leave the pair. Unpair the other node too; the peer keeps its frozen copy.</p>
              </div>
              <button disabled={!!actionDisabled("unpair")} title={actionDisabled("unpair") || undefined} onClick={() => setPending("unpair")}>Unpair</button>
            </div>
            {readOnlyReason && <p className="faint small-text">{readOnlyReason}</p>}
          </section>
        </>
      )}

      {pending && (
        <div className="card" role="dialog" aria-label={`Confirm ${ACTION_LABEL[pending]}`}>
          <div className="section-head">
            <h2>{ACTION_LABEL[pending]}</h2>
            <p>
              {pending === "sync"
                ? "Reconciles configuration with the other node immediately."
                : pending === "unpair"
                  ? "This node leaves the pair and stops replicating."
                  : "Moves the service address between the two nodes."}
            </p>
          </div>
          <div className="field-grid">
            <Field label="Administrator password">
              <input type="password" value={confirm.password} onChange={(e) => setConfirm({ ...confirm, password: e.target.value })} />
            </Field>
            <Field label="Authenticator code (when enrolled)">
              <input value={confirm.totp} onChange={(e) => setConfirm({ ...confirm, totp: e.target.value })} placeholder="123456" />
            </Field>
            {(pending === "failover" || pending === "unpair") && (
              <Field label="Cluster id" hint={`Type ${st?.cluster_id ?? "the cluster id"} to confirm.`}>
                <input value={confirm.cluster} onChange={(e) => setConfirm({ ...confirm, cluster: e.target.value })} />
              </Field>
            )}
            {(pending === "failover" || pending === "failback") && (
              <Field label="Dry run" hint="Checks every precondition without moving the service.">
                <input type="checkbox" checked={confirm.dryRun} onChange={(e) => setConfirm({ ...confirm, dryRun: e.target.checked })} />
              </Field>
            )}
          </div>
          <button className="primary" disabled={busy} onClick={run}>{busy ? "Running…" : ACTION_LABEL[pending]}</button>{" "}
          <button className="secondary" disabled={busy} onClick={() => setPending(null)}>Cancel</button>
        </div>
      )}
    </>
  );
}
