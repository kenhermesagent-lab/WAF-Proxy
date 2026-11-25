import { useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, Field, Modal, errText, fmtTime } from "../ui";
import { AdminUser, Me, PermissionArea, Role, can } from "../types";

// permissionLabel turns "policies.write" into "Policies, bans, lists and WAF
// profiles — change", using the server's area catalogue.
function permissionLabel(token: string, areas: PermissionArea[]): string {
  if (token === "*") return "Everything";
  const [area, action] = token.split(".");
  const label = areas.find((a) => a.key === area)?.label ?? area;
  return `${label} — ${action === "write" ? "change" : "view"}`;
}

export default function Team({
  me,
  onError,
  onOK,
  section = "all",
}: {
  me: Me | null;
  onError: (m: string) => void;
  onOK: (m: string) => void;
  // Account splits these into the Admins and Roles tabs. The combined form is
  // kept for existing embeds.
  section?: "all" | "admins" | "roles";
}) {
  const showAdmins = section !== "roles";
  const showRoles = section !== "admins";
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [areas, setAreas] = useState<PermissionArea[]>([]);
  const [draft, setDraft] = useState<Role | null>(null);
  const [invite, setInvite] = useState<{ username: string; email: string; password: string; role_id: number } | null>(null);
  const [mailInvite, setMailInvite] = useState<{ first_name: string; last_name: string; email: string; role_id: number } | null>(null);
  const [created, setCreated] = useState<{ username: string; totp_secret: string; otpauth_url: string; recovery_codes: string[] } | null>(null);
  const [busy, setBusy] = useState(false);

  const canManage = can(me?.permissions, "accounts.write");

  const load = () =>
    api
      .get<{ users: AdminUser[]; roles: Role[]; areas: PermissionArea[] }>("/api/users")
      .then((r) => {
        setUsers(r.users || []);
        setRoles(r.roles || []);
        setAreas(r.areas || []);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    if (can(me?.permissions, "accounts.read")) load();
  }, []);

  const setRole = async (user: AdminUser, roleID: number) => {
    try {
      await api.put(`/api/users/${user.id}`, { role_id: roleID });
      onOK(`${user.username} is now ${roles.find((r) => r.id === roleID)?.name ?? "in the new role"}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const setEmail = async (user: AdminUser) => {
    const email = window.prompt(`Email address for ${user.username}. Password-reset links are sent here.`, user.email || "");
    if (email === null) return;
    try {
      await api.put(`/api/users/${user.id}`, { email });
      onOK(email ? `Email saved for ${user.username}` : `Email removed from ${user.username}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const resetPassword = async (user: AdminUser) => {
    const password = window.prompt(`New password for ${user.username} (12+ characters). All their sessions end.`);
    if (!password) return;
    try {
      await api.put(`/api/users/${user.id}`, { password });
      onOK(`Password reset for ${user.username}`);
    } catch (e) {
      onError(errText(e));
    }
  };

  const removeUser = async (user: AdminUser) => {
    if (!(await confirmDialog(`Delete ${user.username}? Their sessions end immediately.`))) return;
    try {
      await api.del(`/api/users/${user.id}`);
      onOK(`${user.username} deleted`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const createUser = async () => {
    if (!invite) return;
    setBusy(true);
    try {
      const r = await api.post<{ username: string; totp_secret: string; otpauth_url: string; recovery_codes: string[] }>(
        "/api/users",
        invite,
      );
      setCreated(r);
      setInvite(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const sendInvite = async () => {
    if (!mailInvite) return;
    setBusy(true);
    try {
      await api.post("/api/users/invite", mailInvite);
      onOK(`Invitation sent to ${mailInvite.email}`);
      setMailInvite(null);
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const newRole = (): Role => ({ id: 0, name: "", description: "", builtin: false, permissions: ["dashboard.read"] });
  const togglePermission = (role: Role, token: string) => {
    const has = role.permissions.includes(token);
    const next = has ? role.permissions.filter((p) => p !== token) : [...role.permissions, token];
    // A write grant implies read on the server; mirror that here so the
    // checkbox list reflects what the role will actually allow.
    if (!has && token.endsWith(".write")) {
      const read = token.replace(/\.write$/, ".read");
      if (!next.includes(read)) next.push(read);
    }
    setDraft({ ...role, permissions: next.filter((p) => p !== "*") });
  };

  const saveRole = async () => {
    if (!draft) return;
    setBusy(true);
    try {
      if (draft.id === 0) await api.post("/api/roles", draft);
      else await api.put(`/api/roles/${draft.id}`, draft);
      onOK(draft.id === 0 ? "Role created" : `${draft.name} saved`);
      setDraft(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const removeRole = async (role: Role) => {
    if (!(await confirmDialog(`Delete the ${role.name} role?`))) return;
    try {
      await api.del(`/api/roles/${role.id}`);
      onOK("Role deleted");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <>
      {showAdmins && <Card
        title={`Administrators (${users.length})`}
        actions={
          canManage && (
            <span className="row" style={{ gap: 6 }}>
              <button className="small" onClick={() => setMailInvite({ first_name: "", last_name: "", email: "", role_id: roles[0]?.id ?? 0 })}>
                Invite by email
              </button>
              <button className="small primary" onClick={() => setInvite({ username: "", email: "", password: "", role_id: roles[0]?.id ?? 0 })}>
                Add administrator
              </button>
            </span>
          )
        }
      >
        {users.length === 0 ? (
          <Empty>No accounts yet.</Empty>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <div className="table-wrap"><table>
              <thead><tr><th>Account</th><th>Email</th><th>Role</th><th>Authenticator</th><th className="hide-compact">Created</th><th /></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <span className="mono">{u.username}</span>
                      {u.username === me?.username && <span className="faint" style={{ fontSize: 11 }}> · you</span>}
                      {u.auth_source && u.auth_source !== "local" && (
                        <span style={{ marginLeft: 6 }}>
                          <Badge tone="info">{u.auth_source === "ldap" ? "LDAP/AD" : u.auth_source.toUpperCase()}</Badge>
                        </span>
                      )}
                    </td>
                    <td>
                      {u.email ? (
                        <span className="mono">{u.email}</span>
                      ) : (
                        <Badge tone="warn">no email</Badge>
                      )}
                      {canManage && (
                        <button className="small" style={{ marginLeft: 6 }} onClick={() => setEmail(u)}>Edit</button>
                      )}
                    </td>
                    <td>
                      {canManage ? (
                        <select
                          className="table-select"
                          aria-label={`Role for ${u.username}`}
                          value={u.role_id}
                          onChange={(e) => setRole(u, Number(e.target.value))}
                        >
                          {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                        </select>
                      ) : (
                        <span className="muted">{u.role || "—"}</span>
                      )}
                    </td>
                    <td>
                      {u.auth_source && u.auth_source !== "local"
                        ? <Badge tone="info">directory</Badge>
                        : u.totp_enabled ? <Badge tone="ok">enrolled</Badge> : <Badge tone="warn">missing</Badge>}
                    </td>
                    <td className="muted hide-compact">{fmtTime(u.created_at)}</td>
                    <td className="right" style={{ whiteSpace: "nowrap" }}>
                      {canManage && (
                        <>
                          {(!u.auth_source || u.auth_source === "local") && (
                            <><button className="small" onClick={() => resetPassword(u)}>Reset password</button>{" "}</>
                          )}
                          <button className="small danger" disabled={u.username === me?.username} onClick={() => removeUser(u)}>Delete</button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          </div>
        )}
        <p className="muted" style={{ fontSize: 12 }}>
          Each account signs in with its own password and authenticator. A new account's secret and recovery codes are
          shown once, when it is created. An account without an email address cannot receive password-reset links.
        </p>
      </Card>}

      {showRoles && <Card
        title="Roles"
        actions={canManage && <button className="small" onClick={() => setDraft(newRole())}>New role</button>}
      >
        {roles.length === 0 ? (
          <Empty>No roles.</Empty>
        ) : (
          <div style={{ overflowX: "auto" }}>
          <div className="table-wrap"><table>
            <thead><tr><th>Role</th><th>Can</th><th /></tr></thead>
            <tbody>
              {roles.map((r) => (
                <tr key={r.id}>
                  <td style={{ minWidth: 220 }}>
                    <span style={{ whiteSpace: "nowrap" }}>{r.name} {r.builtin && <Badge tone="info">built-in</Badge>}</span>
                    {r.description && <div className="faint" style={{ fontSize: 11, maxWidth: 420 }}>{r.description}</div>}
                  </td>
                  <td className="muted" style={{ fontSize: 12, minWidth: 340 }}>{r.permissions.map((p) => permissionLabel(p, areas)).join(" · ") || "nothing"}</td>
                  <td className="right" style={{ whiteSpace: "nowrap" }}>
                    {canManage && !r.builtin && (
                      <>
                        <button className="small" onClick={() => setDraft({ ...r })}>Edit</button>{" "}
                        <button className="small danger" onClick={() => removeRole(r)}>Delete</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
          </div>
        )}
        <p className="muted" style={{ fontSize: 12 }}>
          A role grants view or change on each area. Built-in roles cannot be edited or deleted, so there is always a
          known-good Administrator, Operator, Read-only and Viewer to fall back on.
        </p>
      </Card>}

      {mailInvite && (
        <Modal title="Invite administrator" onClose={() => setMailInvite(null)}>
          <p className="muted" style={{ fontSize: 13 }}>
            The recipient gets a link to choose their own username and password and to enrol an
            authenticator. The invitation expires after 7 days.
          </p>
          <div className="row grow">
            <Field label="First name">
              <input value={mailInvite.first_name} onChange={(e) => setMailInvite({ ...mailInvite, first_name: e.target.value })} autoFocus />
            </Field>
            <Field label="Last name">
              <input value={mailInvite.last_name} onChange={(e) => setMailInvite({ ...mailInvite, last_name: e.target.value })} />
            </Field>
          </div>
          <Field label="Email address" hint="The invitation and password-reset links go here.">
            <input type="email" value={mailInvite.email} onChange={(e) => setMailInvite({ ...mailInvite, email: e.target.value })} autoComplete="email" placeholder="admin@your-domain.tld" />
          </Field>
          <Field label="Role">
            <select value={mailInvite.role_id} onChange={(e) => setMailInvite({ ...mailInvite, role_id: Number(e.target.value) })}>
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </Field>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setMailInvite(null)}>Cancel</button>
            <button className="primary" disabled={busy || !mailInvite.email} onClick={sendInvite}>
              {busy ? "Sending…" : "Send invitation"}
            </button>
          </div>
        </Modal>
      )}

      {invite && (
        <Modal title="Add administrator" onClose={() => setInvite(null)}>
          <Field label="Username">
            <input value={invite.username} onChange={(e) => setInvite({ ...invite, username: e.target.value })} autoFocus />
          </Field>
          <Field
            label="Email address"
            hint="Used for password-reset links and alert mail. Without one, this administrator cannot recover a forgotten password by email."
          >
            <input value={invite.email} onChange={(e) => setInvite({ ...invite, email: e.target.value })} type="email" autoComplete="email" placeholder="admin@your-domain.tld" />
          </Field>
          <Field label="Initial password (12+ characters)">
            <input type="password" value={invite.password} onChange={(e) => setInvite({ ...invite, password: e.target.value })} autoComplete="new-password" />
          </Field>
          <Field label="Role">
            <select value={invite.role_id} onChange={(e) => setInvite({ ...invite, role_id: Number(e.target.value) })}>
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </Field>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setInvite(null)}>Cancel</button>
            <button className="primary" disabled={busy || !invite.username || invite.password.length < 12} onClick={createUser}>
              {busy ? "Creating…" : "Create account"}
            </button>
          </div>
        </Modal>
      )}

      {created && (
        <Modal title={`Authenticator for ${created.username}`} onClose={() => setCreated(null)}>
          <p className="muted" style={{ fontSize: 13 }}>
            Give this secret to the account holder now; it is shown once. They should confirm it in their authenticator
            before signing in.
          </p>
          <div className="secret-box">{created.totp_secret}</div>
          <div className="secret-box" style={{ fontSize: 11 }}>{created.otpauth_url}</div>
          <label style={{ marginTop: 14 }}>Recovery codes</label>
          <div className="code-list">{created.recovery_codes.map((c) => <div key={c}>{c}</div>)}</div>
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button className="primary" onClick={() => setCreated(null)}>Done</button>
          </div>
        </Modal>
      )}

      {draft && (
        <Modal title={draft.id === 0 ? "New role" : `Edit ${draft.name}`} onClose={() => setDraft(null)}>
          <Field label="Role name">
            <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} autoFocus />
          </Field>
          <Field label="Description">
            <input value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} placeholder="What this role is for" />
          </Field>
          <div className="table-wrap"><table>
            <thead><tr><th>Area</th><th>View</th><th>Change</th></tr></thead>
            <tbody>
              {areas.map((a) => {
                const read = `${a.key}.read`;
                const write = `${a.key}.write`;
                return (
                  <tr key={a.key}>
                    <td>{a.label}</td>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`${a.label}: view`}
                        style={{ width: "auto" }}
                        checked={draft.permissions.includes(read) || draft.permissions.includes(write)}
                        disabled={draft.permissions.includes(write)}
                        onChange={() => togglePermission(draft, read)}
                      />
                    </td>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`${a.label}: change`}
                        style={{ width: "auto" }}
                        checked={draft.permissions.includes(write)}
                        onChange={() => togglePermission(draft, write)}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setDraft(null)}>Cancel</button>
            <button className="primary" disabled={busy || !draft.name.trim() || draft.permissions.length === 0} onClick={saveRole}>
              {busy ? "Saving…" : draft.id === 0 ? "Create role" : "Save role"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
