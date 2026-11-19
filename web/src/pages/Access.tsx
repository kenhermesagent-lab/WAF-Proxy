import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Modal, errText, fmtTime } from "../ui";
import { GateUser } from "../types";

export default function Access({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [users, setUsers] = useState<GateUser[]>([]);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ username: "", password: "", totp_enabled: true });
  const [secret, setSecret] = useState<{ url: string; secret: string; username: string } | null>(null);

  const load = () =>
    api.get<GateUser[]>("/api/gate-users").then(setUsers).catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const create = async () => {
    try {
      const r = await api.post<{ otpauth_url?: string; totp_secret?: string }>("/api/gate-users", form);
      setOpen(false);
      setForm({ username: "", password: "", totp_enabled: true });
      if (r.otpauth_url) setSecret({ url: r.otpauth_url, secret: r.totp_secret ?? "", username: form.username });
      onOK("Account created");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const remove = async (u: GateUser) => {
    if (!confirm(`Delete account ${u.username}?`)) return;
    try {
      await api.del(`/api/gate-users/${u.id}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card
        title="Access gate accounts"
        actions={<button className="primary" onClick={() => setOpen(true)}>New account</button>}
      >
        {users.length === 0 ? (
          <Empty>No accounts. Enable the gate on a proxy and either use a shared passphrase or create accounts here.</Empty>
        ) : (
          <table>
            <thead><tr><th>Username</th><th>TOTP</th><th>Created</th><th /></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="mono">{u.username}</td>
                  <td>{u.totp_enabled ? <Badge tone="ok">enabled</Badge> : <Badge tone="warn">off</Badge>}</td>
                  <td className="muted">{fmtTime(u.created_at)}</td>
                  <td className="right"><button className="small danger" onClick={() => remove(u)}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="How the gate behaves">
        <ul className="muted" style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
          <li>The login page is served by the proxy on the proxy's own hostname; nothing reaches the backend before sign-in.</li>
          <li>Three failures from an IP in ten minutes creates a 15 minute ban. Ten in a day extends it to 24 hours. Failure on three separate days becomes permanent.</li>
          <li>Accounts also lock out after five failures in fifteen minutes, which stops credential stuffing even when the attacker changes IP.</li>
          <li>Every ban is visible under Policies, is liftable from this LAN-only GUI, and is logged with its reason.</li>
        </ul>
      </Card>

      {open && (
        <Modal title="New gate account" onClose={() => setOpen(false)}>
          <Field label="Username"><input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>
          <Field label="Password (12+ characters)">
            <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </Field>
          <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={form.totp_enabled} onChange={(e) => setForm({ ...form, totp_enabled: e.target.checked })} />
            Require TOTP
          </label>
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button className="primary" onClick={create}>Create</button>
          </div>
        </Modal>
      )}

      {secret && (
        <Modal title={`TOTP for ${secret.username}`} onClose={() => setSecret(null)}>
          <p className="muted">Add this to an authenticator app now. It is shown once.</p>
          <div className="secret-box">{secret.secret}</div>
          <div className="secret-box" style={{ fontSize: 12 }}>{secret.url}</div>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button className="primary" onClick={() => setSecret(null)}>I saved it</button>
          </div>
        </Modal>
      )}
    </div>
  );
}
