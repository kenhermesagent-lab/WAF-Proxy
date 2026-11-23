import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo, PageHead } from "../ui";
import type { CrowdSecBlocklists, CrowdSecInstall, CrowdSecStatus } from "../types";

// ConsoleConnection shows the rows `cscli console status` reports, so the plan
// and decision management state are visible instead of inferred.
function ConsoleConnection({ inst }: { inst: CrowdSecInstall }) {
  if (!inst.console_plan && !inst.console_capi && !inst.console_decision && !inst.console_papi) return null;
  return (
    <div style={{ marginTop: 12 }}>
      <div className="table-wrap"><table>
        <tbody>
          <tr><td className="muted">Plan</td><td>{inst.console_plan || "—"}</td></tr>
          <tr><td className="muted">Central API</td><td>{inst.console_capi || "—"}</td></tr>
          <tr>
            <td className="muted">Decision management</td>
            <td>
              {inst.console_decision_active ? (
                <Badge tone="ok">{inst.console_decision || "active"}</Badge>
              ) : (
                <Badge tone="warn">{inst.console_decision || "not available"}</Badge>
              )}
            </td>
          </tr>
          <tr><td className="muted">PAPI subscriptions</td><td>{inst.console_papi || "—"}</td></tr>
        </tbody>
      </table></div>
      <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
        {inst.console_decision_active
          ? "The console can push decisions and blocklists to this engine; what it is currently enforcing is listed, read-only, further down this page."
          : "Console-pushed decisions and blocklists will not reach this engine until Decision management is active, which needs a plan that includes it."}
      </p>
    </div>
  );
}

export default function CrowdSecPage({ onError, onOK, head = true }: { onError: (m: string) => void; onOK: (m: string) => void; head?: boolean }) {
  const [status, setStatus] = useState<CrowdSecStatus | null>(null);
  const [inst, setInst] = useState<CrowdSecInstall | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [url, setUrl] = useState("");
  const [key, setKey] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [enrollKey, setEnrollKey] = useState("");
  const [enrolling, setEnrolling] = useState(false);
  const [installKey, setInstallKey] = useState("");
  const [restarting, setRestarting] = useState(false);
  const [blocklists, setBlocklists] = useState<CrowdSecBlocklists | null>(null);

  const applyStatus = (s: CrowdSecStatus) => {
    setStatus(s);
    setEnabled(s.config?.enabled ?? s.configured);
    setUrl(s.config?.url ?? s.lapi ?? "");
  };

  const load = () =>
    api
      .get<CrowdSecStatus>("/api/crowdsec")
      .then(applyStatus)
      .catch((e) => onError(errText(e)));

  const loadInstall = () =>
    api
      .get<CrowdSecInstall>("/api/crowdsec/install")
      .then(setInst)
      .catch(() => undefined);

  useEffect(() => {
    load();
    loadInstall();
    const t = setInterval(() => {
      api.get<CrowdSecStatus>("/api/crowdsec").then(setStatus).catch(() => undefined);
    }, 15000);
    return () => clearInterval(t);
  }, []);

  // What the engine is enforcing right now, which also proves the bouncer is
  // reading decisions rather than merely configured.
  useEffect(() => {
    let alive = true;
    const refresh = () =>
      api
        .get<CrowdSecBlocklists>("/api/crowdsec/blocklists")
        .then((r) => alive && setBlocklists(r))
        .catch(() => undefined);
    refresh();
    const t = setInterval(refresh, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // A host install runs in the background: adding the CrowdSec repository and
  // installing the engine takes minutes, so poll instead of one long request.
  useEffect(() => {
    if (!inst?.running) return;
    const t = setInterval(() => {
      api
        .get<CrowdSecInstall>("/api/crowdsec/install")
        .then((next) => {
          setInst(next);
          if (!next.running) load();
        })
        .catch(() => undefined);
    }, 2000);
    return () => clearInterval(t);
  }, [inst?.running]);

  const save = async () => {
    setSaving(true);
    try {
      const next = await api.put<CrowdSecStatus>("/api/crowdsec", {
        enabled,
        url,
        key,
        clear_key: clearKey,
      });
      applyStatus(next);
      setKey("");
      setClearKey(false);
      onOK(enabled ? "CrowdSec bouncer enabled" : "CrowdSec bouncer disabled");
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    setTesting(true);
    try {
      await api.post("/api/crowdsec/test", { url, key });
      onOK("CrowdSec LAPI accepted the connection and bouncer key");
    } catch (e) {
      onError(errText(e));
    } finally {
      setTesting(false);
    }
  };

  const install = async (consoleKey = "") => {
    try {
      await api.post("/api/crowdsec/install", { console_key: consoleKey });
      onOK(
        consoleKey
          ? "Installing and linking to your CrowdSec console — approve the engine there when it appears"
          : "Installing CrowdSec — this page updates when it finishes",
      );
      loadInstall();
    } catch (e) {
      onError(errText(e));
    }
  };

  const restart = async () => {
    setRestarting(true);
    try {
      await api.post("/api/crowdsec/restart");
      onOK("CrowdSec restarted");
      setTimeout(loadInstall, 1500);
      loadInstall();
    } catch (e) {
      onError(errText(e));
    } finally {
      setRestarting(false);
    }
  };

  const enroll = async () => {
    setEnrolling(true);
    try {
      await api.post("/api/crowdsec/console", { key: enrollKey });
      setEnrollKey("");
      onOK("Enrollment sent — accept the engine in your CrowdSec console");
      loadInstall();
    } catch (e) {
      onError(errText(e));
    } finally {
      setEnrolling(false);
    }
  };

  const keySet = status?.config?.key_set || false;
  const configured = status?.configured || false;

  return (
    <div className="grid" style={{ gap: 14 }}>
      {head && <PageHead sub="The bouncer that applies community decisions to proxy and stream traffic." />}
      <Card
        title="Security engine and bouncer"
        actions={<button className="small" onClick={load}>Refresh</button>}
      >
        <div className="bar-row">
          <div>Bouncer</div>
          <div>
            {configured ? (
              <Badge tone="ok">streaming decisions</Badge>
            ) : enabled ? (
              <Badge tone="warn">enabled, waiting for configuration</Badge>
            ) : (
              <Badge>disabled</Badge>
            )}
          </div>
        </div>
        <div className="bar-row">
          <div>LAPI</div>
          <div className="mono" style={{ fontSize: 12 }}>{status?.lapi || "not configured"}</div>
        </div>
        <div className="bar-row">
          <div>Last successful poll</div>
          <div className="muted" style={{ fontSize: 12 }}>{status?.last_poll ? fmtAgo(status.last_poll) : "never"}</div>
        </div>
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>Decisions applied</div>
          <div className="mono">{status?.applied ?? 0}</div>
        </div>
        {status?.last_error && <p className="err-text">{status.last_error}</p>}
        <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
          The bouncer is an outbound client: it polls the CrowdSec Security Engine's Local API for ban
          decisions and applies them to the local ban engine. The Security Engine (and its LAPI) must be
          installed and running separately. No CrowdSec port is exposed to the WAN.
        </p>
      </Card>

      <Card
        title="CrowdSec console blocklists"
        actions={
          blocklists?.available ? (
            <Badge>{blocklists.total.toLocaleString()} decisions</Badge>
          ) : blocklists ? (
            <Badge tone="warn">not reported</Badge>
          ) : undefined
        }
      >
        {!blocklists ? (
          <Empty>Loading…</Empty>
        ) : !blocklists.available ? (
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            {blocklists.reason || "The Security Engine did not report its decisions."}
          </p>
        ) : blocklists.rows.length === 0 ? (
          <Empty>No console-pushed decisions are active on this engine.</Empty>
        ) : (
          <div className="table-wrap"><table>
            <thead>
              <tr><th>Reason</th><th>Origin</th><th>Action</th><th className="num">Decisions</th></tr>
            </thead>
            <tbody>
              {blocklists.rows.map((r) => (
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
        )}
        {blocklists?.raw && (
          <pre className="mono" style={{ fontSize: 11, maxHeight: 220, overflow: "auto" }}>{blocklists.raw}</pre>
        )}
        {blocklists?.available && (
          <p className="muted mt" style={{ fontSize: 12, marginBottom: 0 }}>
            Reported by the Security Engine (<code>cscli metrics show decisions</code>) and enforced by the bouncer, so
            every row is a decision that is actually in force. Origins <code>lists</code> (subscribed blocklists),
            <code> CAPI</code> (community blocklist) and <code>console</code> (pushed from the console) are managed at
            app.crowdsec.net and cannot be edited here.
          </p>
        )}
      </Card>

      {inst && !inst.container && (
        <Card title="Automatic install (native Linux)">
          {inst.supported ? (
            <>
              <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
                Installs the Security Engine from the CrowdSec repository, adds the nginx collection, points
                its acquisition at the WAF access log, then writes the LAPI URL and a fresh bouncer key into
                this page and enables the bouncer. Paste an enrollment key and the installer links the engine
                to your account in the same run.
              </p>
              <ol className="muted" style={{ fontSize: 12, lineHeight: 1.8, paddingLeft: 18 }}>
                <li>Open app.crowdsec.net and sign in, or create a free account.</li>
                <li>Go to <strong>Security Engines</strong> → <strong>Add security engine</strong>.</li>
                <li>Copy the enrollment key it shows, paste it below, and start the install.</li>
                <li>Approve the pending engine in the portal, then restart CrowdSec from this page.</li>
              </ol>
              <div className="row grow">
                <Field label="CrowdSec console enrollment key (optional)">
                  <input
                    type="password"
                    value={installKey}
                    onChange={(e) => setInstallKey(e.target.value)}
                    placeholder="paste the key from app.crowdsec.net"
                    autoComplete="off"
                  />
                </Field>
              </div>
              <div className="row" style={{ gap: 8 }}>
                <button
                  className="primary"
                  onClick={() => install(installKey.trim())}
                  disabled={inst.running}
                >
                  {inst.running
                    ? "Installing…"
                    : inst.installed
                      ? "Re-run installer and enroll"
                      : "Install and enroll"}
                </button>
                <button onClick={() => install("")} disabled={inst.running}>
                  Install without linking
                </button>
                {inst.running && (
                  <span className="muted" style={{ fontSize: 12 }}>
                    This page refreshes itself while the host installs.
                  </span>
                )}
              </div>
              {inst.installed && (
                <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
                  Engine {inst.version ? `v${inst.version}` : "installed"} ·{" "}
                  {inst.engine_running ? "running" : "not running"}
                  {inst.console_enrolled ? " · enrolled in your CrowdSec console" : ""}
                </p>
              )}
            </>
          ) : (
            <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>{inst.reason}</p>
          )}
          {inst.error && <p className="err-text">{inst.error}</p>}
          {inst.output && (
            <pre
              className="mono"
              style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 11.5, maxHeight: 260, overflowY: "auto", marginBottom: 0 }}
            >
              {inst.output}
            </pre>
          )}
        </Card>
      )}

      {inst?.installed && !inst.container && (
        <Card
          title="CrowdSec Cloud (optional)"
          actions={
            inst.console_state === "enrolled" ? (
              <Badge tone="ok">accepted by console</Badge>
            ) : inst.console_state === "pending" || inst.console_enrolled ? (
              <Badge tone="warn">pending acceptance</Badge>
            ) : (
              <Badge>not linked</Badge>
            )
          }
        >
          {inst.console_state === "enrolled" ? (
            <>
              <p className="muted" style={{ fontSize: 12, lineHeight: 1.7, marginTop: 0 }}>
                The console accepted this engine. Its alerts appear under app.crowdsec.net → Security
                Engines; Console-pushed blocklists additionally need a plan with decision management.
              </p>
              {inst.console_detail && (
                <p className="mono muted" style={{ fontSize: 11.5, marginBottom: 0 }}>{inst.console_detail}</p>
              )}
              <ConsoleConnection inst={inst} />
            </>
          ) : inst.console_state === "pending" || inst.console_enrolled ? (
            <>
              <p className="muted" style={{ fontSize: 12, lineHeight: 1.7, marginTop: 0 }}>
                The enrollment request was sent, but the console has not accepted this engine yet — until
                it is accepted, no events reach your account. This is the step people miss.
              </p>
              <ol className="muted" style={{ fontSize: 12, lineHeight: 1.8, paddingLeft: 18, marginTop: 0 }}>
                <li>Open app.crowdsec.net → <strong>Security Engines</strong>.</li>
                <li>Select the engine waiting there and click <strong>Accept enroll</strong>.</li>
                <li>Restart the engine here so it picks up the console settings.</li>
              </ol>
              <div className="row" style={{ gap: 8 }}>
                <button className="primary" onClick={restart} disabled={restarting}>
                  {restarting ? "Restarting…" : "Restart CrowdSec"}
                </button>
                <span className="muted" style={{ fontSize: 12 }}>
                  Runs <code>systemctl restart crowdsec</code> as root; the state below refreshes afterwards.
                </span>
              </div>
              {inst.console_detail && (
                <p className="mono muted" style={{ fontSize: 11.5, marginBottom: 0 }}>{inst.console_detail}</p>
              )}
              <ConsoleConnection inst={inst} />
            </>
          ) : (
            <>
              <p className="muted" style={{ fontSize: 12, lineHeight: 1.7, marginTop: 0 }}>
                Linking uploads this engine's alerts to your account and lets the console push blocklists
                back. The bouncer is already configured, so this is the only manual step.
              </p>
              <ol className="muted" style={{ fontSize: 12, lineHeight: 1.8, paddingLeft: 18, marginTop: 0 }}>
                <li>Open app.crowdsec.net and sign in, or create a free account.</li>
                <li>Go to <strong>Security Engines</strong> → <strong>Add security engine</strong>.</li>
                <li>Copy the enrollment key it shows.</li>
                <li>Paste it below and choose <strong>Enroll engine</strong>.</li>
                <li>
                  Accept the pending engine in the console, then run{" "}
                  <code>sudo systemctl restart crowdsec</code> on this host.
                </li>
              </ol>
              <div className="row grow">
                <Field label="Enrollment key">
                  <input
                    type="password"
                    value={enrollKey}
                    onChange={(e) => setEnrollKey(e.target.value)}
                    placeholder="paste the key from app.crowdsec.net"
                    autoComplete="off"
                  />
                </Field>
              </div>
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <button
                  className="primary"
                  onClick={enroll}
                  disabled={enrolling || enrollKey.trim().length < 16}
                >
                  {enrolling ? "Enrolling…" : "Enroll engine"}
                </button>
              </div>
            </>
          )}
        </Card>
      )}

      <Card
        title="Bouncer configuration"
        actions={
          <>
            <button className="small" onClick={test} disabled={testing || (!url && !status?.lapi)}>
              {testing ? "Testing…" : "Test connection"}
            </button>
            <button className="small primary" onClick={save} disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </button>
          </>
        }
      >
        <div className="row grow">
          <Field label="LAPI URL">
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://127.0.0.1:8081" />
          </Field>
          <Field label={keySet ? "Bouncer key (leave blank to keep the saved key)" : "Bouncer key"}>
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={keySet ? "•••••••• saved" : "paste the key from cscli bouncers add"}
              autoComplete="off"
            />
          </Field>
        </div>
        <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, textTransform: "none", letterSpacing: 0 }}>
          <input type="checkbox" style={{ width: "auto" }} checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enable the CrowdSec bouncer
        </label>
        {keySet && (
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={clearKey} onChange={(e) => setClearKey(e.target.checked)} />
            Remove the saved key
          </label>
        )}
        <p className="muted" style={{ fontSize: 12 }}>
          The key is encrypted with the installation master key and never returned to the browser. Changing
          the configuration takes effect within 30 seconds without restarting WAF-Proxy.
        </p>
      </Card>

      <div className="grid cols-2">
        <Card title="Docker Compose engine">
          <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
            The repository includes an optional CrowdSec sidecar that reads the WAF access log. Start it,
            create a bouncer key, then paste the key above.
          </p>
          <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, margin: 0 }}>{`cd /path/to/WAF-Proxy
docker compose -f deploy/docker-compose.yml --profile crowdsec up -d crowdsec
docker exec crowdsec cscli bouncers add wafproxy

# LAPI URL for the bouncer:
http://127.0.0.1:8081`}</pre>
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            The sidecar uses host networking and its LAPI listens on loopback only.
          </p>
        </Card>

        <Card title="Native engine by hand">
          <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
            Prefer the manual path, or the automatic install above did not fit? Install the engine from the
            CrowdSec repository, add the nginx collection, and create a bouncer key. Point its acquisition at
            the WAF access log with the nginx parser.
          </p>
          <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, margin: 0 }}>{`sudo cscli collections install crowdsecurity/nginx
sudo cscli bouncers add wafproxy

# LAPI URL for the bouncer (stock native default):
http://127.0.0.1:8080`}</pre>
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            Use the listen URI from the engine's config if it was customised. Keep the LAPI on loopback or a
            private network; the bouncer needs only outbound access to it.
          </p>
        </Card>
      </div>

      <Card title="What the bouncer applies">
        <p className="muted" style={{ fontSize: 12, lineHeight: 1.7, marginTop: 0 }}>
          IP and range ban decisions are added to the local ban table with source <code>crowdsec</code> and
          the scenario name. When CrowdSec withdraws a decision, only the matching CrowdSec-sourced ban is
          removed. Decisions with non-ban types or simulated decisions are ignored. This bouncer does not
          replace the WAF, threat feeds, or the local ban engine.
        </p>
      </Card>
    </div>
  );
}
