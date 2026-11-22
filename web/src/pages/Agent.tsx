import { useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, Field, Modal, errText, fmtAgo, fmtTime } from "../ui";
import type { MCPStatus, MCPToken } from "../types";
import AgentLinks from "../components/AgentLinks";

const TOOLS = [
  ["get_security_overview", "Bans, kernel status, traffic totals, top sources and live sessions."],
  ["query_logs", "Read events by IP, host, action or stage."],
  ["get_ip_activity", "24h totals, ban state, recent events and sessions for one address."],
  ["list_anomalies", "Anomaly detections with the measured value and its baseline."],
  ["list_proxies", "Hostnames, gate modes and WAF modes."],
  ["block_ip", "Add an IP or CIDR ban with a required reason."],
  ["unblock_ip", "Lift an exact IP or CIDR ban."],
  ["list_blocks", "Active IP and username blocks."],
  ["list_gate_users", "Gate accounts and whether they are blocked."],
  ["block_username", "Block a gate account and revoke its sessions."],
  ["unblock_username", "Lift a gate username block."],
  ["list_sessions", "Live gate sessions with non-secret refs."],
  ["revoke_session", "Kill one session by ref."],
  ["revoke_sessions_for_ip", "Kill every session from one address."],
];

export default function AgentPage({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [status, setStatus] = useState<MCPStatus | null>(null);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("hermes-agent");
  const [scopes, setScopes] = useState<string[]>(TOOLS.map(([tool]) => tool));
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ name: string; token: string } | null>(null);

  const load = () =>
    api.get<MCPStatus>("/api/mcp").then(setStatus).catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const toggleScope = (tool: string) =>
    setScopes((cur) => (cur.includes(tool) ? cur.filter((x) => x !== tool) : [...cur, tool]));

  const create = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ name: string; token: string }>("/api/mcp/tokens", { name, scopes });
      setCreated({ name: r.name, token: r.token });
      setOpen(false);
      setName("hermes-agent");
      setScopes(TOOLS.map(([tool]) => tool));
      onOK("Agent token created");
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (t: MCPToken) => {
    if (!(await confirmDialog(`Revoke the token "${t.name}"? Any agent using it will be refused immediately.`))) return;
    try {
      await api.del(`/api/mcp/tokens/${t.id}`);
      onOK("Agent token revoked");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      onOK("Copied to clipboard");
    } catch {
      onError("Clipboard access was refused; select the token and copy it manually.");
    }
  };

  const endpoint = `${window.location.origin}${status?.endpoint ?? "/mcp"}`;
  const active = (status?.tokens ?? []).filter((t) => !t.revoked_at);

  return (
    <div className="grid" style={{ gap: 14 }}>
      <AgentLinks onError={onError} onOK={onOK} />

      <Card
        title="MCP gateway"
        actions={<button className="primary" onClick={() => setOpen(true)}>New agent token</button>}
      >
        <div className="bar-row">
          <div>Endpoint</div>
          <div className="mono">{endpoint}</div>
        </div>
        <div className="bar-row">
          <div>Authentication</div>
          <div>
            {status?.env_token && <Badge tone="info">environment token</Badge>}{" "}
            {active.length > 0 ? <Badge tone="ok">{active.length} active token{active.length === 1 ? "" : "s"}</Badge> : <Badge tone="warn">no active tokens</Badge>}
          </div>
        </div>
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>Protocols</div>
          <div className="muted mono" style={{ fontSize: 12 }}>{(status?.protocols ?? []).join(" · ") || "—"}</div>
        </div>
        <p className="muted" style={{ fontSize: 13 }}>
          This is a stateless MCP Streamable HTTP endpoint for a standalone agent. It authenticates with a bearer token, not the
          administrator's browser session, and exposes only the security tools below — never a shell or arbitrary command.
          Every call is written to the audit log as <span className="mono">mcp:&lt;token name&gt;</span>.
        </p>
        <div className="secret-box" style={{ fontSize: 12, whiteSpace: "pre-wrap" }}>
{`{
  "mcpServers": {
    "wafproxy": {
      "type": "http",
      "url": "${endpoint}",
      "headers": { "Authorization": "Bearer <agent token>" }
    }
  }
}`}
        </div>
      </Card>

      <Card title="Agent tokens">
        {!status ? (
          <p className="muted">Loading…</p>
        ) : (status.tokens ?? []).length === 0 ? (
          <Empty>No agent tokens yet. Create one and give it only to the agent that needs security operations access.</Empty>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <div className="table-wrap"><table>
              <thead><tr><th>Name</th><th>Prefix</th><th>Scopes</th><th>Created</th><th>Last used</th><th>Status</th><th /></tr></thead>
              <tbody>
                {status.tokens.map((t) => (
                  <tr key={t.id}>
                    <td>{t.name}</td>
                    <td className="mono">{t.prefix}…</td>
                    <td className="muted">{t.scopes?.length ? t.scopes.join(", ") : "all"}</td>
                    <td className="muted">{fmtTime(t.created_at)}</td>
                    <td className="muted">{t.last_used_at ? fmtAgo(t.last_used_at) : "never"}</td>
                    <td>{t.revoked_at ? <Badge tone="bad">revoked</Badge> : <Badge tone="ok">active</Badge>}</td>
                    <td className="right">
                      {!t.revoked_at && <button className="small danger" onClick={() => revoke(t)}>Revoke</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          </div>
        )}
        <p className="muted" style={{ fontSize: 12 }}>
          Tokens are stored as SHA-256 hashes and shown once. Revocation takes effect on the next request. The optional
          <span className="mono"> WAFPROXY_MCP_TOKEN </span> environment variable is for headless installs and appears here as
          “environment token”; it cannot be revoked from the console.
        </p>
      </Card>

      <Card title="Available tools">
        <div style={{ overflowX: "auto" }}>
          <div className="table-wrap"><table>
            <thead><tr><th>Tool</th><th>What the agent can do</th></tr></thead>
            <tbody>
              {TOOLS.map(([tool, description]) => (
                <tr key={tool}>
                  <td className="mono" style={{ whiteSpace: "nowrap" }}>{tool}</td>
                  <td className="muted">{description}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          Destructive tools require a reason and are audited. An agent should read <span className="mono">query_logs</span> or
          <span className="mono"> get_ip_activity </span> first, then take the narrowest action: one session, one IP, or one username.
        </p>
      </Card>

      {open && (
        <Modal title="New agent token" onClose={() => setOpen(false)}>
          <Field label="Token name">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="hermes-agent" autoFocus />
          </Field>
          <p className="muted" style={{ fontSize: 12 }}>
            Use a name that identifies the agent or host. Keep the token out of logs and shell history.
          </p>
                    <div className="row" style={{ justifyContent: "space-between", marginTop: 10 }}>
            <span className="muted" style={{ fontSize: 12 }}>Tools this token may call</span>
            <span className="actions">
              <button className="small" onClick={() => setScopes(TOOLS.map(([tool]) => tool))}>All</button>
              <button className="small" onClick={() => setScopes([])}>None</button>
            </span>
          </div>
          <div className="grid" style={{ gap: 6 }}>
            {TOOLS.map(([tool, description]) => (
              <label key={tool} className="row" style={{ gap: 8, alignItems: "flex-start" }}>
                <input type="checkbox" checked={scopes.includes(tool)} onChange={() => toggleScope(tool)} />
                <span className="mono">{tool}</span>
                <span className="muted" style={{ fontSize: 12 }}>{description}</span>
              </label>
            ))}
          </div>
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button className="primary" onClick={create} disabled={busy || !name.trim() || scopes.length === 0}>{busy ? "Creating…" : "Create token"}</button>
          </div>
        </Modal>
      )}

      {created && (
        <Modal title={`Token for ${created.name}`} onClose={() => setCreated(null)}>
          <p className="muted">Copy this now. It is shown once and cannot be recovered.</p>
          <div className="secret-box" style={{ wordBreak: "break-all" }}>{created.token}</div>
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => copy(created.token)}>Copy</button>
            <button className="primary" onClick={() => setCreated(null)}>I saved it</button>
          </div>
        </Modal>
      )}
    </div>
  );
}
