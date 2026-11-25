import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Field, Switch, errText } from "../ui";
import { ConsoleAuth, Role } from "../types";

type Draft = {
  enabled: boolean;
  host: string;
  port: number;
  secret: string;
  base_dn: string;
  bind_dn: string;
  bind_password: string;
  user_filter: string;
  group_filter: string;
  email_attr: string;
  use_tls: boolean;
  start_tls: boolean;
  skip_verify: boolean;
  timeout_seconds: number;
  default_role_id: number;
  role_map: string;
  has_secret?: boolean;
  has_bind_password?: boolean;
};

const LABELS: Record<string, { title: string; sub: string; port: number; map: string }> = {
  tacacs: {
    title: "TACACS+",
    sub: "Authenticate console administrators with a TACACS+ server and take their role from an authorization AV pair. PAP is used first, with an ASCII prompt fallback; a failed or unreachable authorization denies the sign-in.",
    port: 49,
    map: "15=Administrator\nrole=operator=Operator\nconsole-admin=Administrator",
  },
  radius: {
    title: "RADIUS",
    sub: "RADIUS answers yes or no, so every administrator it accepts receives the default role below.",
    port: 1812,
    map: "",
  },
  ldap: {
    title: "LDAP / Active Directory",
    sub: "Bind as the administrator, then read their groups to choose a console role.",
    port: 389,
    map: "WAF-Admins=Administrator\nWAF-Operators=Operator\nCN=Read Only,OU=Groups,DC=example,DC=com=Read-only",
  },
};

const empty = (kind: string): Draft => ({
  enabled: false,
  host: "",
  port: LABELS[kind].port,
  secret: "",
  base_dn: "",
  bind_dn: "",
  bind_password: "",
  user_filter: kind === "ldap" ? "(uid={username})" : "",
  group_filter: kind === "ldap" ? "(&(objectClass=group)(member={dn}))" : "",
  email_attr: "mail",
  use_tls: false,
  start_tls: kind === "ldap",
  skip_verify: false,
  timeout_seconds: 8,
  default_role_id: 0,
  role_map: LABELS[kind].map,
});

function toDraft(p: ConsoleAuth, kind: string): Draft {
  return {
    ...empty(kind),
    ...p,
    secret: "",
    bind_password: "",
    port: p.port || LABELS[kind].port,
    user_filter: p.user_filter || (kind === "ldap" ? "(uid={username})" : ""),
    group_filter: p.group_filter || (kind === "ldap" ? "(&(objectClass=group)(member={dn}))" : ""),
    email_attr: p.email_attr || "mail",
    role_map: p.role_map || LABELS[kind].map,
  };
}

// ConsoleAuthForm edits one console directory. It is deliberately separate
// from the forward-auth providers under Access: those gate proxied sites, this
// signs an administrator in to the console itself.
export default function ConsoleAuthForm({
  kind,
  canWrite,
  onError,
  onOK,
}: {
  kind: "tacacs" | "radius" | "ldap";
  canWrite: boolean;
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const label = LABELS[kind];
  const [draft, setDraft] = useState<Draft>(empty(kind));
  const [roles, setRoles] = useState<Role[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [test, setTest] = useState({ username: "", password: "" });
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; role?: string; warning?: string } | null>(null);

  useEffect(() => {
    let live = true;
    Promise.all([
      api.get<ConsoleAuth[]>("/api/console-auth"),
      api.get<{ roles: Role[] }>("/api/roles"),
    ])
      .then(([list, roleList]) => {
        if (!live) return;
        const current = (list ?? []).find((p) => p.kind === kind);
        if (current) setDraft(toDraft(current, kind));
        setRoles(roleList.roles ?? []);
        setLoaded(true);
      })
      .catch((e) => {
        if (!live) return;
        onError(errText(e));
        setLoaded(true);
      });
    return () => {
      live = false;
    };
  }, [kind]);

  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));

  const save = async () => {
    setSaving(true);
    try {
      // Send only the editable fields. The loaded provider also carries id,
      // kind, created_at and the has_* display flags, and the API rejects
      // unknown JSON fields.
      const body = {
        enabled: draft.enabled,
        host: draft.host,
        port: draft.port,
        secret: draft.secret,
        base_dn: draft.base_dn,
        bind_dn: draft.bind_dn,
        bind_password: draft.bind_password,
        user_filter: draft.user_filter,
        group_filter: draft.group_filter,
        email_attr: draft.email_attr,
        use_tls: draft.use_tls,
        start_tls: draft.start_tls,
        skip_verify: draft.skip_verify,
        timeout_seconds: draft.timeout_seconds,
        default_role_id: draft.default_role_id,
        role_map: draft.role_map,
      };
      const saved = await api.put<ConsoleAuth>(`/api/console-auth/${kind}`, body);
      setDraft(toDraft(saved, kind));
      onOK(`${label.title} settings saved`);
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const r = await api.post<{ ok: boolean; message: string; role?: string; warning?: string }>(
        `/api/console-auth/${kind}/test`,
        test,
      );
      setTestResult(r);
    } catch (e) {
      setTestResult({ ok: false, message: errText(e) });
    } finally {
      setTesting(false);
    }
  };

  if (!loaded) return <Card title={label.title}><p className="muted">Loading…</p></Card>;

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card
        title={label.title}
        actions={<Badge tone={draft.enabled ? "ok" : "info"}>{draft.enabled ? "enabled" : "disabled"}</Badge>}
        sub={label.sub}
      >
        <Switch
          label={`Sign administrators in with ${label.title}`}
          help="Local password accounts keep using their own password and are never shadowed by a directory username."
          checked={draft.enabled}
          onChange={(enabled) => set({ enabled })}
          disabled={!canWrite}
        />
        <div className="row grow">
          <Field label="Server">
            <input value={draft.host} onChange={(e) => set({ host: e.target.value })} placeholder="tacacs.example.com" disabled={!canWrite} />
          </Field>
          <Field label="Port">
            <input
              type="number"
              value={draft.port}
              onChange={(e) => set({ port: Number(e.target.value) })}
              min={1}
              max={65535}
              disabled={!canWrite}
            />
          </Field>
          <Field label="Timeout (seconds)">
            <input
              type="number"
              value={draft.timeout_seconds}
              onChange={(e) => set({ timeout_seconds: Number(e.target.value) })}
              min={1}
              max={60}
              disabled={!canWrite}
            />
          </Field>
        </div>

        {(kind === "tacacs" || kind === "radius") && (
          <Field
            label={draft.has_secret ? "Shared secret (leave blank to keep)" : "Shared secret"}
            hint="Sealed with the console key and never shown again."
          >
            <input
              type="password"
              value={draft.secret}
              onChange={(e) => set({ secret: e.target.value })}
              autoComplete="new-password"
              disabled={!canWrite}
            />
          </Field>
        )}

        {kind === "ldap" && (
          <>
            <div className="row grow">
              <Field label="Base DN">
                <input value={draft.base_dn} onChange={(e) => set({ base_dn: e.target.value })} placeholder="OU=People,DC=example,DC=com" disabled={!canWrite} />
              </Field>
              <Field label="Email attribute">
                <input value={draft.email_attr} onChange={(e) => set({ email_attr: e.target.value })} placeholder="mail" disabled={!canWrite} />
              </Field>
            </div>
            <Field label="User filter" hint="Use {username}. Active Directory commonly uses (sAMAccountName={username}).">
              <input value={draft.user_filter} onChange={(e) => set({ user_filter: e.target.value })} disabled={!canWrite} />
            </Field>
            <div className="row grow">
              <Field label="Service bind DN (optional)">
                <input value={draft.bind_dn} onChange={(e) => set({ bind_dn: e.target.value })} placeholder="CN=wafproxy,OU=Service,DC=example,DC=com" disabled={!canWrite} />
              </Field>
              <Field label={draft.has_bind_password ? "Bind password (leave blank to keep)" : "Bind password"}>
                <input type="password" value={draft.bind_password} onChange={(e) => set({ bind_password: e.target.value })} autoComplete="new-password" disabled={!canWrite} />
              </Field>
            </div>
            <Field label="Group filter (optional)" hint="Use {dn} for the signed-in user's DN and {username}. Matched group DNs and CNs feed the role map.">
              <input value={draft.group_filter} onChange={(e) => set({ group_filter: e.target.value })} disabled={!canWrite} />
            </Field>
            <div className="row grow">
              <Switch
                label="LDAPS (TLS from the first byte)"
                checked={draft.use_tls}
                onChange={(use_tls) => set({
                  use_tls,
                  start_tls: use_tls ? false : draft.start_tls,
                  port: use_tls && draft.port === 389 ? 636 : !use_tls && draft.port === 636 ? 389 : draft.port,
                })}
                disabled={!canWrite}
              />
              <Switch
                label="StartTLS"
                checked={draft.start_tls}
                onChange={(start_tls) => set({ start_tls, use_tls: start_tls ? false : draft.use_tls })}
                disabled={!canWrite}
              />
              <Switch label="Skip certificate check" checked={draft.skip_verify} onChange={(skip_verify) => set({ skip_verify })} disabled={!canWrite} />
            </div>
          </>
        )}
      </Card>

      <Card title="Role assignment">
        <Field label="Default role" hint={kind === "radius" ? "RADIUS cannot return a role, so this is the role every accepted administrator receives." : "Used when no role map line matches. Choose “Deny sign-in” to require a match."}>
          <select value={draft.default_role_id} onChange={(e) => set({ default_role_id: Number(e.target.value) })} disabled={!canWrite}>
            <option value={0}>Deny sign-in (no role)</option>
            {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </Field>
        {kind !== "radius" && (
          <>
            <Field
              label="Role map"
              hint={
                kind === "tacacs"
                  ? "One match=Role per line. Match a priv-lvl (15), a role AV pair value (role=operator) or the full argument."
                  : "One group=Role per line. A group DN or CN may be used."
              }
            >
              <textarea
                rows={5}
                value={draft.role_map}
                onChange={(e) => set({ role_map: e.target.value })}
                placeholder={label.map}
                disabled={!canWrite}
                style={{ fontFamily: "var(--mono, monospace)", fontSize: 12 }}
              />
            </Field>
            <p className="muted" style={{ fontSize: 12 }}>
              Role names must match a role under <strong>Roles</strong>. An unmatched administrator falls back to the
              default role, or is refused when no default is set.
            </p>
          </>
        )}
        {canWrite && (
          <button className="primary" onClick={save} disabled={saving || !draft.host}>
            {saving ? "Saving…" : `Save ${label.title}`}
          </button>
        )}
      </Card>

      <Card title="Test a sign-in" sub="Uses the saved settings, never the unsaved form.">
        <div className="row grow">
          <Field label="Username">
            <input value={test.username} onChange={(e) => setTest({ ...test, username: e.target.value })} autoComplete="off" disabled={!canWrite} />
          </Field>
          <Field label="Password">
            <input type="password" value={test.password} onChange={(e) => setTest({ ...test, password: e.target.value })} autoComplete="new-password" disabled={!canWrite} />
          </Field>
        </div>
        {canWrite && (
          <button onClick={runTest} disabled={testing || !draft.enabled || !test.username || !test.password}>
            {testing ? "Testing…" : "Test sign-in"}
          </button>
        )}
        {testResult && (
          <div className="mt" style={{ fontSize: 13 }}>
            <Badge tone={testResult.ok ? "ok" : "bad"}>{testResult.ok ? "accepted" : "refused"}</Badge>{" "}
            <span>{testResult.message}</span>
            {testResult.role && <div className="muted">Console role: <strong>{testResult.role}</strong></div>}
            {testResult.warning && <div className="muted">{testResult.warning}</div>}
          </div>
        )}
      </Card>
    </div>
  );
}
