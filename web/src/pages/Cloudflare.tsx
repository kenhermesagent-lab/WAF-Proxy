import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Badge, Card, PageHead, PageTabs, SaveBar, Switch, confirmDialog, errText } from "../ui";
import type { CloudflareCheck, CloudflareStatus } from "../types";
import CloudflareApps from "./CloudflareApps";

type TabProps = { tab: string; tabs: { id: string; label: string }[]; onTab: (id: string) => void };

const DASHBOARD_URL = "https://one.dash.cloudflare.com/";

type Saved = { enabled: boolean; strict: boolean; tunnelID: string };
type InstallState = { running: boolean; installed: boolean; error?: string; output?: string };

export default function CloudflarePage({
  tab,
  tabs,
  onTab,
  onError,
  onOK,
}: TabProps & {
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [cf, setCf] = useState<CloudflareStatus | null>(null);
  const [saved, setSaved] = useState<Saved | null>(null);
  const [token, setToken] = useState("");
  const [saving, setSaving] = useState(false);
  const [tokenSaving, setTokenSaving] = useState(false);
  const [checking, setChecking] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [busy, setBusy] = useState(false);
  const installPoll = useRef<number | null>(null);

  const mark = (next: CloudflareStatus) => {
    setCf(next);
    setSaved({ enabled: next.enabled, strict: next.strict_origin, tunnelID: next.tunnel_id });
  };

  const load = () =>
    api
      .get<CloudflareStatus>("/api/cloudflare")
      .then(mark)
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
    return () => {
      if (installPoll.current) window.clearInterval(installPoll.current);
    };
  }, []);

  if (!cf) {
    return (
      <Card title="Cloudflare">
        <p className="muted">Loading…</p>
      </Card>
    );
  }

  const changes =
    saved && (cf.enabled !== saved.enabled || cf.strict_origin !== saved.strict || cf.tunnel_id !== saved.tunnelID)
      ? 1
      : 0;

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      onOK("Copied to clipboard");
    } catch {
      onError("The browser blocked clipboard access");
    }
  };

  const toggleEnabled = (on: boolean) => {
    if (on && !cf.token_set) {
      onError("Paste the tunnel token in step 3 first");
      return;
    }
    setCf({ ...cf, enabled: on });
  };

  const save = async () => {
    if (!cf) return;
    setSaving(true);
    try {
      await api.put("/api/cloudflare", {
        enabled: cf.enabled,
        strict_origin: cf.strict_origin,
        tunnel_id: cf.tunnel_id.trim(),
      });
      onOK(cf.enabled ? "Tunnel settings saved; the connector is starting" : "Tunnel settings saved");
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const saveToken = async () => {
    const value = token.trim();
    if (!value) {
      onError("Paste the tunnel token first");
      return;
    }
    setTokenSaving(true);
    try {
      await api.put("/api/cloudflare", { token: value });
      setToken("");
      onOK("Tunnel token saved and sealed");
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setTokenSaving(false);
    }
  };

  const removeToken = async () => {
    if (!(await confirmDialog("Remove the saved tunnel token? The connector cannot start until a new one is saved."))) return;
    setTokenSaving(true);
    try {
      await api.put("/api/cloudflare", { token: "" });
      onOK("Tunnel token removed");
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setTokenSaving(false);
    }
  };

  const install = async () => {
    setInstalling(true);
    try {
      await api.post("/api/cloudflare/install");
      installPoll.current = window.setInterval(async () => {
        try {
          const st = await api.get<InstallState>("/api/cloudflare/install");
          if (st.running) return;
          if (installPoll.current) window.clearInterval(installPoll.current);
          installPoll.current = null;
          setInstalling(false);
          if (st.error) onError(st.error);
          else onOK("Connector installed");
          await load();
        } catch (e) {
          if (installPoll.current) window.clearInterval(installPoll.current);
          installPoll.current = null;
          setInstalling(false);
          onError(errText(e));
        }
      }, 3000);
    } catch (e) {
      setInstalling(false);
      onError(errText(e));
    }
  };

  const connector = async (action: "start" | "stop" | "restart") => {
    setBusy(true);
    try {
      await api.post("/api/cloudflare/connector", { action });
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const check = async () => {
    setChecking(true);
    try {
      const res = await api.post<{ checks: CloudflareCheck[] }>("/api/cloudflare/check", {
        hostnames: [cf.console_host],
      });
      setCf((prev) => (prev ? { ...prev, checks: res.checks, checks_at: new Date().toISOString() } : prev));
      const failed = res.checks.filter((c) => !c.ok).length;
      if (failed === 0) onOK("All tunnel checks passed");
      else onError(`${failed} check${failed === 1 ? "" : "s"} need attention`);
    } catch (e) {
      onError(errText(e));
    } finally {
      setChecking(false);
    }
  };

  const service = `${cf.gui_tls ? "https" : "http"}://127.0.0.1:${cf.gui_port}`;
  const manualCommands = [
    "curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg",
    'echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | sudo tee /etc/apt/sources.list.d/cloudflared.list',
    "sudo apt-get update && sudo apt-get install -y cloudflared",
    "sudo systemctl disable --now cloudflared",
  ];

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead sub="Publish this console and its sites through Cloudflare Tunnel, with Access in front of them." />
      <PageTabs tabs={tabs} active={tab} onSelect={onTab} />
      {tab === "apps" && <CloudflareApps onError={onError} onOK={onOK} />}

      <Card title="Connector">
        <div className="bar-row">
          <div>Status</div>
          <div>
            {cf.state === "running" ? (
              <Badge tone="ok">connected</Badge>
            ) : cf.state === "starting" ? (
              <Badge tone="warn">starting</Badge>
            ) : cf.state === "error" ? (
              <Badge tone="bad">error</Badge>
            ) : (
              <Badge>stopped</Badge>
            )}
            {cf.state === "running" && (
              <span className="muted" style={{ marginLeft: 8 }}>
                {cf.connections > 1 ? `${cf.connections} connections` : cf.connections === 1 ? "1 connection" : "registered"}
              </span>
            )}
          </div>
        </div>
        <div className="bar-row">
          <div>cloudflared</div>
          <div>
            {cf.installed ? (
              <span className="mono">{cf.version || "installed"}</span>
            ) : (
              <Badge tone="warn">not installed</Badge>
            )}
          </div>
        </div>
        <div className="bar-row">
          <div>Tunnel</div>
          <div className="mono" style={{ overflowWrap: "anywhere" }}>
            {cf.tunnel_id || "not set (managed in the dashboard)"}
          </div>
        </div>
        <div className="bar-row">
          <div>Metrics</div>
          <div className="mono">{cf.metrics_addr}</div>
        </div>
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>Connector service</div>
          <div className="row">
            <button disabled={busy || !cf.token_set} onClick={() => connector("start")}>
              Start
            </button>
            <button disabled={busy || cf.state === "stopped"} onClick={() => connector("stop")}>
              Stop
            </button>
            <button disabled={busy || !cf.token_set} onClick={() => connector("restart")}>
              Restart
            </button>
          </div>
        </div>
        {cf.error && <p className="err-text">{cf.error}</p>}
        <div style={{ marginTop: 10 }}>
          <Switch
            label="Enable Cloudflare Tunnel"
            help="Runs the connector with the saved token. Off stops it and leaves the settings in place."
            checked={cf.enabled}
            onChange={toggleEnabled}
          />
          <Switch
            label="Trust CF-Connecting-IP from the connector"
            help="Lets the WAF filter, log and ban the Cloudflare client address instead of the loopback peer. Turn it off when another proxy in front of the tunnel sets its own X-Forwarded-For."
            checked={cf.strict_origin}
            onChange={(v) => setCf({ ...cf, strict_origin: v })}
          />
        </div>
        {cf.restart_required && (
          <p className="err-text">
            The installed cloudflared ({cf.version}) is newer than the running connector. Restart it to use the update.
          </p>
        )}
        {cf.log.length > 0 && (
          <details style={{ marginTop: 10 }}>
            <summary className="muted" style={{ cursor: "pointer", fontSize: 12 }}>
              Connector output (last {cf.log.length} lines)
            </summary>
            <pre style={{ fontSize: 11.5, overflowX: "auto", maxHeight: 220 }}>{cf.log.join("\n")}</pre>
          </details>
        )}
        {cf.helper_ready && !cf.container && (
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            The Updates page upgrades cloudflared with the other host packages; the connector restart above applies it.
          </p>
        )}
      </Card>

      {tab !== "apps" && (
        <>
      <Card title="1 · Install the connector">
        {cf.installed ? (
          <p className="muted" style={{ marginTop: 0 }}>
            cloudflared {cf.version || ""} is installed on this host. The console runs it directly; the package's
            systemd unit stays disabled so there is only one connector.
          </p>
        ) : cf.container ? (
          <>
            <p className="muted" style={{ marginTop: 0 }}>
              This console runs in a container, so it cannot install host packages. Install cloudflared on the host and
              start it there with the tunnel token; the tunnel does not need to run inside the container, and the checks
              below still reach it.
            </p>
            <code style={{ overflowWrap: "anywhere" }}>cloudflared tunnel run --token &lt;token&gt;</code>
          </>
        ) : (
          <>
            <p className="muted" style={{ marginTop: 0 }}>
              {cf.install_reason || "Install the connector from Cloudflare's package repository."}
            </p>
            {installing ? (
              <p className="muted">Installing… this can take a minute while apt refreshes its index.</p>
            ) : (
              <div className="row">
                {cf.install_supported && (
                  <button className="primary" onClick={install}>
                    Install connector
                  </button>
                )}
                <a href={DASHBOARD_URL} target="_blank" rel="noreferrer">
                  <button>Open Cloudflare dashboard</button>
                </a>
              </div>
            )}
            {cf.install_error && <p className="err-text">{cf.install_error}</p>}
            {!cf.install_supported && !cf.container && (
              <>
                <p className="muted" style={{ fontSize: 12 }}>
                  Or run these on the host yourself:
                </p>
                {manualCommands.map((cmd) => (
                  <div key={cmd} className="row" style={{ marginBottom: 6 }}>
                    <code style={{ flex: 1, overflowWrap: "anywhere", fontSize: 11.5 }}>{cmd}</code>
                    <button onClick={() => copy(cmd)}>Copy</button>
                  </div>
                ))}
              </>
            )}
          </>
        )}
        {cf.install_output && (
          <details style={{ marginTop: 8 }}>
            <summary className="muted" style={{ cursor: "pointer", fontSize: 12 }}>
              Installer output
            </summary>
            <pre style={{ fontSize: 11.5, overflowX: "auto", maxHeight: 220 }}>{cf.install_output}</pre>
          </details>
        )}
      </Card>

      <Card title="2 · Create the tunnel">
        <ol className="muted" style={{ margin: "0 0 0 18px", padding: 0, fontSize: 13, lineHeight: 1.9 }}>
          <li>In the Cloudflare dashboard open Networks → Tunnels (Zero Trust uses the same page).</li>
          <li>Create a tunnel, choose cloudflared as the environment and name it, for example waf-proxy.</li>
          <li>Copy the connector token it shows; that token is the whole credential.</li>
        </ol>
        <p className="muted" style={{ fontSize: 12 }}>
          An existing tunnel works too: open its configuration and copy the token. The tunnel ID below is optional and
          only labels the page; ingress lives in the dashboard in this mode.
        </p>
        <div className="row">
          <input
            className="mono"
            style={{ flex: 1, minWidth: 240 }}
            placeholder="Tunnel ID (optional)"
            value={cf.tunnel_id}
            onChange={(e) => setCf({ ...cf, tunnel_id: e.target.value })}
          />
          <a href={DASHBOARD_URL} target="_blank" rel="noreferrer">
            <button>Cloudflare dashboard</button>
          </a>
        </div>
      </Card>

      <Card title="3 · Paste the tunnel token">
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
          The token is sealed in the console database and never shown again. To rotate it, paste the new one; an
          unchanged tunnel keeps working until you save.
        </p>
        <div className="row">
          <input
            type="password"
            autoComplete="off"
            style={{ flex: 1, minWidth: 260 }}
            placeholder={cf.token_set ? `Saved token ends in …${cf.token_tail ?? ""}` : "Paste the tunnel token"}
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <button className="primary" onClick={saveToken} disabled={tokenSaving || !token.trim()}>
            {tokenSaving ? "Saving…" : "Save token"}
          </button>
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          {cf.token_set && !cf.enabled && (
            <button className="small" onClick={removeToken} disabled={tokenSaving}>
              Remove token
            </button>
          )}
        </div>
        <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
          {cf.token_set ? (
            <>
              <Badge tone="ok">token saved</Badge> Enabling the connector restarts it with this token.
            </>
          ) : (
            "No token saved yet. The Enable switch stays off until one is."
          )}
        </p>
      </Card>

      <Card title="4 · Publish the console hostname">
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
          In the tunnel's Public Hostname tab add one entry for the console:
        </p>
        <div className="bar-row">
          <div>Hostname</div>
          <div className="mono">{cf.console_host || "set the console hostname on the Sites page"}</div>
        </div>
        <div className="bar-row">
          <div>Service</div>
          <div className="mono">{service}</div>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          {cf.gui_tls ? (
            <>
              The console listener uses TLS on loopback, so the service is <code>{service}</code>; enable
              <strong> No TLS Verify</strong> on the public hostname because the certificate is for the public name.
            </>
          ) : (
            <>
              The console listener is plain HTTP on loopback, so the service is <code>{service}</code> with no TLS
              options. If you kept the console on its default port, that value comes from Settings → Network.
            </>
          )}
        </p>
        <div className="row">
          <button onClick={() => copy(service)}>Copy service address</button>
          {cf.console_host && (
            <button onClick={() => copy(`https://${cf.console_host}`)}>Copy console URL</button>
          )}
        </div>
      </Card>

      <Card title="5 · Put Cloudflare Access in front (recommended)">
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
          A tunnel hostname is public by itself. Access adds an identity check the console cannot enforce on its own,
          and it is the only place a stolen password is stopped before the login form.
        </p>
        <ol className="muted" style={{ margin: "0 0 0 18px", padding: 0, fontSize: 13, lineHeight: 1.9 }}>
          <li>Zero Trust → Access → Applications → Add a self-hosted application for the console hostname.</li>
          <li>Add an Allow policy for your email address, or for a group, and save.</li>
          <li>
            Add a Bypass policy for <code>/api/health</code> if you want the checks below to reach the console without a
            sign-in; the origin check then proves the path end to end.
          </li>
          <li>Optionally add a service token for monitoring, and send its headers from your uptime checker.</li>
        </ol>
        <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
          With Access on you sign in twice: Cloudflare first, then the console's own password and authenticator. That is
          expected, and the console's accounts still decide what the person may do.
        </p>
      </Card>

      <Card title="6 · Verify">
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
          The checks look up the hostname, ask Cloudflare for it and confirm the response came from this console.
          {cf.checks_at ? ` Last run ${new Date(cf.checks_at).toLocaleString()}.` : ""}
        </p>
        {!cf.checks || cf.checks.length === 0 ? (
          <p className="muted" style={{ marginBottom: 0 }}>
            No checks yet. Save the token, enable the connector and run the checks.
          </p>
        ) : (
          cf.checks.map((c) => (
            <div key={c.id} className="bar-row">
              <div>
                {c.label}
                {c.detail && (
                  <div className="muted" style={{ fontSize: 11.5 }}>
                    {c.detail}
                  </div>
                )}
              </div>
              <div>{c.ok ? <Badge tone="ok">pass</Badge> : <Badge tone="warn">needs attention</Badge>}</div>
            </div>
          ))
        )}
        <div className="row" style={{ marginTop: 10 }}>
          <button onClick={check} disabled={checking}>
            {checking ? "Checking…" : "Run checks"}
          </button>
        </div>
      </Card>
        </>
      )}

      {tab !== "apps" && (changes > 0 || saving) && saved && (
        <SaveBar
          note={<><b>Unsaved changes</b> · tunnel settings apply when you save</>}
          saveLabel="Save tunnel settings"
          saving={saving}
          onDiscard={() => {
            setCf({ ...cf, enabled: saved.enabled, strict_origin: saved.strict, tunnel_id: saved.tunnelID });
            onOK("Unsaved changes discarded");
          }}
          onSave={save}
        />
      )}
    </div>
  );
}
