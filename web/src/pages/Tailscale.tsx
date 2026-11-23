import { useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, SaveBar, errText, PageHead } from "../ui";
import type { TailscaleStatus } from "../types";

export default function TailscalePage({
  onError,
  onOK,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [ts, setTs] = useState<TailscaleStatus | null>(null);
  const [saving, setSaving] = useState(false);
  const [restarting, setRestarting] = useState(false);

  const load = () =>
    api
      .get<TailscaleStatus>("/api/tailscale")
      .then(setTs)
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const change = (patch: Partial<TailscaleStatus>) =>
    setTs((prev) => (prev ? { ...prev, ...patch } : prev));

  const save = async () => {
    if (!ts) return;
    setSaving(true);
    try {
      await api.put("/api/tailscale", {
        admin_enabled: ts.admin_enabled,
        proxy_enabled: ts.proxy_enabled,
        dns_enabled: ts.dns_enabled,
      });
      onOK("Tailscale settings saved; restart to apply the listeners");
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const restart = async () => {
    if (!(await confirmDialog("Restart WAF-Proxy? The admin session is kept, but the UI disconnects for a few seconds."))) return;
    try {
      await api.post("/api/system/restart");
      setRestarting(true);
    } catch (e) {
      onError(errText(e));
    }
  };

  if (!ts) {
    return <Card title="Tailscale"><p className="muted">Loading…</p></Card>;
  }

  const adminDisabled = !ts.available && !ts.admin_enabled;
  const proxyDisabled = !ts.available && !ts.proxy_enabled;
  const dnsDisabled = !ts.available || !ts.proxy_enabled;

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead sub="Private tailnet listeners for the console and for proxied applications." />
      <Card title="Native Tailscale access">
        <div className="bar-row">
          <div>Interface</div>
          <div>
            {ts.available ? <Badge tone="ok">connected</Badge> : <Badge tone="warn">not detected</Badge>}
            {ts.ip && <span className="mono" style={{ marginLeft: 8 }}>{ts.ip}</span>}
          </div>
        </div>
        <div className="bar-row">
          <div>Admin listener</div>
          <div>
            {ts.admin_active ? <Badge tone="ok">listening</Badge> : ts.admin_enabled ? <Badge tone="warn">not listening</Badge> : <Badge>off</Badge>}
            {ts.admin_url && <span className="mono" style={{ marginLeft: 8 }}>{ts.admin_url}</span>}
          </div>
        </div>
        <div className="bar-row">
          <div>Proxy listener</div>
          <div>
            {ts.proxy_active ? <Badge tone="ok">listening</Badge> : ts.proxy_enabled ? <Badge tone="warn">not listening</Badge> : <Badge>off</Badge>}
            {ts.proxy_addr && <span className="mono" style={{ marginLeft: 8 }}>{ts.proxy_addr}</span>}
          </div>
        </div>
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>Split DNS</div>
          <div>
            {ts.dns_active ? <Badge tone="ok">answering</Badge> : ts.dns_enabled ? <Badge tone="warn">not answering</Badge> : <Badge>off</Badge>}
            {ts.dns_addr && <span className="mono" style={{ marginLeft: 8 }}>{ts.dns_addr}</span>}
          </div>
        </div>
        {!ts.available && ts.error && <p className="err-text">{ts.error}</p>}
        {ts.admin_error && <p className="err-text">Admin listener: {ts.admin_error}</p>}
        {ts.proxy_error && <p className="err-text">Proxy listener: {ts.proxy_error}</p>}
        {ts.dns_error && <p className="err-text">Split DNS: {ts.dns_error}</p>}
        <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
          Native Tailscale is detected from the <code>tailscale0</code> interface. The LAN console stays
          available; enabling the admin switch adds a second listener reachable only from the tailnet.
          Tailnet ACLs still apply, and the console keeps its password + authenticator check.
        </p>
      </Card>

      <div className="grid cols-2">
        <Card title="Admin console">
          <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
            <input
              type="checkbox"
              style={{ width: "auto" }}
              checked={ts.admin_enabled}
              disabled={adminDisabled}
              onChange={(e) => change({ admin_enabled: e.target.checked })}
            />
            Admin console over Tailscale
          </label>
          <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
            Binds the existing console to the tailnet address on port {ts.gui_port}. The URL is plain
            HTTP inside Tailscale's encrypted WireGuard transport; it is not exposed to the public
            internet or the LAN listener.
          </p>
          {ts.admin_url && (
            <p className="mono" style={{ fontSize: 12, overflowWrap: "anywhere" }}>{ts.admin_url}</p>
          )}
        </Card>

        <Card title="App traffic">
          <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
            <input
              type="checkbox"
              style={{ width: "auto" }}
              checked={ts.proxy_enabled}
              disabled={proxyDisabled}
              onChange={(e) => change({ proxy_enabled: e.target.checked, dns_enabled: e.target.checked && ts.dns_enabled })}
            />
            Proxy app traffic over Tailscale
          </label>
          <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0, marginTop: 8 }}>
            <input
              type="checkbox"
              style={{ width: "auto" }}
              checked={ts.dns_enabled}
              disabled={dnsDisabled}
              onChange={(e) => change({ dns_enabled: e.target.checked })}
            />
            Answer split DNS on the tailnet
          </label>
          <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
            Binds the normal TLS/SNI proxy to the tailnet address on port {ts.wan_port}. Remote apps
            must resolve to this address; split DNS answers only configured proxy hostnames.
          </p>
        </Card>
      </div>

      <Card title="Tailnet setup">
        <p className="muted" style={{ fontSize: 13, lineHeight: 1.7, marginTop: 0 }}>
          In the Tailscale admin console, grant tailnet devices access to this host on
          {" "}<code>tcp:{ts.wan_port}</code> and <code>tcp:{ts.gui_port}</code>, plus
          {" "}<code>udp:53</code> and <code>tcp:53</code> when split DNS is enabled.
        </p>
        <p className="muted" style={{ fontSize: 13, lineHeight: 1.7 }}>
          For app traffic, add a restricted nameserver in <strong>DNS → Nameservers</strong>:
          {" "}<code>{ts.ip || "100.x.y.z"}</code> restricted to <code>{ts.base_domain || "your base domain"}</code>.
          Then verify from a tailnet device:
        </p>
        <pre style={{ fontSize: 12, overflowX: "auto" }}>dig +short app.{ts.base_domain || "example.com"} @{ts.ip || "100.x.y.z"}</pre>
        <p className="muted" style={{ fontSize: 12 }}>
          The reply should be <code>{ts.ip || "100.x.y.z"}</code>. The app then reaches the WAF with its
          normal hostname and certificate; the WAF forwards to the LAN upstream and applies its normal
          policy. Tailscale clients appear as their <code>100.x</code> address in Logs and bans.
        </p>
      </Card>

      {ts.restart_required && (
        <div className="card" style={{ borderColor: "#8a6d1d" }}>
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <strong>Restart required</strong>
              <p className="muted" style={{ fontSize: 12, margin: "4px 0 0" }}>
                Saved listener changes take effect when WAF-Proxy restarts.
              </p>
            </div>
            <button className="primary" onClick={restart} disabled={restarting}>
              {restarting ? "Restarting…" : "Restart service"}
            </button>
          </div>
        </div>
      )}

      <SaveBar
        note="Listener changes take effect after saving; some need a restart."
        saveLabel="Save Tailscale settings"
        saving={saving}
        onSave={save}
      />
    </div>
  );
}
