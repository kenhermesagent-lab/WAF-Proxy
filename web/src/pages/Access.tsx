import { useEffect, useState } from "react";
import { api } from "../api";
import Icon from "../components/Icon";
import { Badge, Card, ConfirmDialog, Empty, Field, Modal, PageHead, Switch, TableWrap, errText, fmtTime } from "../ui";
import { GateUser } from "../types";

export default function Access({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [users, setUsers] = useState<GateUser[]>([]);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ username: "", password: "", totp_enabled: true });
  const [edit, setEdit] = useState<{ user: GateUser; password: string; totp_enabled: boolean } | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  const [secret, setSecret] = useState<{ url: string; secret: string; username: string } | null>(null);
  const [removeTarget, setRemoveTarget] = useState<GateUser | null>(null);
  const [removeBusy, setRemoveBusy] = useState(false);

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

  const saveEdit = async () => {
    if (!edit) return;
    setEditBusy(true);
    try {
      const r = await api.put<{ otpauth_url?: string; totp_secret?: string }>(`/api/gate-users/${edit.user.id}`, {
        password: edit.password,
        totp_enabled: edit.totp_enabled,
      });
      if (r.totp_secret) {
        setSecret({ url: r.otpauth_url ?? "", secret: r.totp_secret, username: edit.user.username });
      }
      onOK(`${edit.user.username} updated`);
      setEdit(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setEditBusy(false);
    }
  };

  const remove = async () => {
    if (!removeTarget) return;
    setRemoveBusy(true);
    try {
      await api.del(`/api/gate-users/${removeTarget.id}`);
      onOK(`${removeTarget.username} deleted`);
      setRemoveTarget(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setRemoveBusy(false);
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead
        title="Access gate"
        sub="Accounts served by the proxy login page, before any request reaches a backend."
        actions={<button className="primary" onClick={() => setOpen(true)}><Icon name="plus" size={14} /> New account</button>}
      />
      <Card title="Gate accounts">
        {users.length === 0 ? (
          <Empty title="No gate accounts" icon="lock" action={<button className="primary" onClick={() => setOpen(true)}>Create an account</button>}>
            Enable the gate on a proxy and either use a shared passphrase or create accounts here.
          </Empty>
        ) : (
          <TableWrap><table>
            <thead><tr><th>Username</th><th>TOTP</th><th>Created</th><th /></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="mono">{u.username}</td>
                  <td>{u.totp_enabled ? <Badge tone="ok">enabled</Badge> : <Badge tone="warn">off</Badge>}</td>
                  <td className="muted">{fmtTime(u.created_at)}</td>
                  <td className="right" style={{ whiteSpace: "nowrap" }}>
                    <button className="small" onClick={() => setEdit({ user: u, password: "", totp_enabled: u.totp_enabled })}>Edit</button>{" "}
                    <button className="small danger" onClick={() => setRemoveTarget(u)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></TableWrap>
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
          <Switch label="Require TOTP" checked={form.totp_enabled} onChange={(v) => setForm({ ...form, totp_enabled: v })} />
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button className="primary" onClick={create}>Create</button>
          </div>
        </Modal>
      )}

      {edit && (
        <Modal title={`Edit ${edit.user.username}`} onClose={() => setEdit(null)}>
          <Field label="New password (leave blank to keep the current one)">
            <input
              type="password"
              value={edit.password}
              onChange={(e) => setEdit({ ...edit, password: e.target.value })}
              placeholder="12+ characters"
              autoComplete="new-password"
            />
          </Field>
          <Switch label="Require TOTP" checked={edit.totp_enabled} onChange={(v) => setEdit({ ...edit, totp_enabled: v })} />
          {edit.totp_enabled && !edit.user.totp_enabled && (
            <p className="muted" style={{ fontSize: 12 }}>
              Saving creates an authenticator secret for this account and shows it once. Changing the
              password signs out the account's existing sessions.
            </p>
          )}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setEdit(null)}>Cancel</button>
            <button className="primary" onClick={saveEdit} disabled={editBusy}>
              {editBusy ? "Saving…" : "Save account"}
            </button>
          </div>
        </Modal>
      )}

      {removeTarget && (
        <ConfirmDialog
          title={`Delete ${removeTarget.username}?`}
          confirmLabel="Delete account"
          busy={removeBusy}
          onConfirm={remove}
          onClose={() => setRemoveTarget(null)}
        >
          The account is removed from the access gate and any active session for it is revoked. Bans are not affected.
        </ConfirmDialog>
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
