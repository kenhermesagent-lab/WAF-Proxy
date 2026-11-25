import { useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, Field, errText, fmtTime, PageHead, PageTabs } from "../ui";
import Team from "../components/Team";
import AdminSessions from "../components/AdminSessions";
import ConsoleAuthForm from "../components/ConsoleAuth";
import { Me, TrustedDevice, can } from "../types";

const SOURCE_LABELS: Record<string, string> = {
  tacacs: "TACACS+",
  radius: "RADIUS",
  ldap: "LDAP/Active Directory",
};

export default function Account({
  me,
  onError,
  onOK,
  onSignedOut,
  tab = "account",
  tabs = [],
  onTab,
}: {
  me: Me | null;
  onError: (m: string) => void;
  onOK: (m: string) => void;
  onSignedOut: () => void;
  tab?: string;
  tabs?: { id: string; label: string }[];
  onTab?: (id: string) => void;
}) {
  const active =
    tabs.length === 0 ? tab || "account" : tabs.some((t) => t.id === tab) ? tab : "account";
  const source = me?.auth_source ?? "local";
  const external = source !== "local";
  const canReadAccounts = can(me?.permissions, "accounts.read");
  const canManage = can(me?.permissions, "accounts.write");

  const [pw, setPw] = useState({ current: "", next: "", confirm: "", totp: "", recovery: "" });
  const [pwBusy, setPwBusy] = useState(false);

  const [totpStep, setTotpStep] = useState<"idle" | "enrol">("idle");
  const [totpForm, setTotpForm] = useState({ current: "", totp: "", recovery: "" });
  const [pending, setPending] = useState<{ secret: string; url: string } | null>(null);
  const [newCode, setNewCode] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [totpBusy, setTotpBusy] = useState(false);

  const [email, setEmail] = useState(me?.email ?? "");
  const [devices, setDevices] = useState<TrustedDevice[]>([]);

  useEffect(() => setEmail(me?.email ?? ""), [me?.email]);

  const loadDevices = () =>
    api
      .get<{ devices: TrustedDevice[] }>("/api/account/devices")
      .then((r) => setDevices(r.devices || []))
      .catch(() => undefined);

  useEffect(() => {
    if (active === "account") loadDevices();
  }, [active]);

  const saveEmail = async () => {
    try {
      const r = await api.post<{ email: string }>("/api/account/email", { email });
      setEmail(r.email);
      onOK(r.email ? "Email address saved" : "Email address removed");
    } catch (e) {
      onError(errText(e));
    }
  };

  const revokeDevice = async (d: TrustedDevice) => {
    if (!(await confirmDialog("Revoke this remembered browser? It will need the authenticator code next time."))) return;
    try {
      await api.del(`/api/account/devices/${d.id}`);
      onOK("Remembered browser revoked");
      loadDevices();
    } catch (e) {
      onError(errText(e));
    }
  };

  const changePassword = async () => {
    if (pw.next !== pw.confirm) {
      onError("The new passwords do not match");
      return;
    }
    setPwBusy(true);
    try {
      const r = await api.post<{ other_sessions_revoked: boolean }>("/api/account/password", {
        current_password: pw.current,
        new_password: pw.next,
        totp: pw.totp,
        recovery: pw.recovery,
      });
      setPw({ current: "", next: "", confirm: "", totp: "", recovery: "" });
      onOK(r.other_sessions_revoked
        ? "Password changed; other sessions were signed out"
        : "Password changed; sign out other browsers manually");
    } catch (e) {
      onError(errText(e));
    } finally {
      setPwBusy(false);
    }
  };

  const beginTOTP = async () => {
    setTotpBusy(true);
    try {
      const r = await api.post<{ secret: string; otpauth_url: string }>("/api/account/totp", {
        current_password: totpForm.current,
        totp: totpForm.totp,
        recovery: totpForm.recovery,
      });
      setPending({ secret: r.secret, url: r.otpauth_url });
      setTotpStep("enrol");
      setCodes([]);
    } catch (e) {
      onError(errText(e));
    } finally {
      setTotpBusy(false);
    }
  };

  const confirmTOTP = async () => {
    if (!pending) return;
    setTotpBusy(true);
    try {
      const r = await api.post<{ recovery_codes: string[]; other_sessions_revoked: boolean }>("/api/account/totp/confirm", {
        secret: pending.secret,
        code: newCode,
      });
      setCodes(r.recovery_codes || []);
      setPending(null);
      setNewCode("");
      setTotpForm({ current: "", totp: "", recovery: "" });
      setTotpStep("idle");
      onOK(r.other_sessions_revoked
        ? "Authenticator rotated; save the new recovery codes"
        : "Authenticator rotated; sign out other browsers manually");
    } catch (e) {
      onError(errText(e));
    } finally {
      setTotpBusy(false);
    }
  };

  const accountTab = (
    <>
      <div className="grid cols-2">
        {external ? (
          <Card title="Directory account">
            <p style={{ marginTop: 0 }}>
              <Badge tone="info">{SOURCE_LABELS[source] ?? source}</Badge>
            </p>
            <p className="muted" style={{ fontSize: 13 }}>
              This account signs in through {SOURCE_LABELS[source] ?? "an external directory"}. Its password and
              authenticator are managed there, not in this console. Change the password in your directory and the new
              one works on your next sign-in.
            </p>
            <p className="muted" style={{ fontSize: 13 }}>
              Your console role is assigned by the directory mapping on the {SOURCE_LABELS[source] ?? "directory"} tab.
              Ask an administrator if you need a different role.
            </p>
          </Card>
        ) : (
          <>
            <Card title="Change password">
              <Field label="Current password">
                <input type="password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} autoComplete="current-password" />
              </Field>
              <Field label="New password (12+ characters)">
                <input type="password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} autoComplete="new-password" />
              </Field>
              <Field label="Repeat new password">
                <input type="password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} autoComplete="new-password" />
              </Field>
              <Field label="Authenticator code (if enrolled)">
                <input value={pw.totp} onChange={(e) => setPw({ ...pw, totp: e.target.value })} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" />
              </Field>
              <Field label="Or a recovery code">
                <input value={pw.recovery} onChange={(e) => setPw({ ...pw, recovery: e.target.value })} autoComplete="off" placeholder="AAAA-BBBB-CCCC" />
              </Field>
              <button className="primary" onClick={changePassword} disabled={pwBusy || !pw.current || !pw.next}>
                {pwBusy ? "Saving…" : "Change password"}
              </button>
              <p className="muted" style={{ fontSize: 12 }}>
                Changing the password signs out every other browser; this session stays active.
              </p>
            </Card>

            <Card title="Authenticator">
              {totpStep === "idle" && (
                <>
                  <p className="muted" style={{ fontSize: 13 }}>
                    Rotating the authenticator replaces the secret and all recovery codes. Add the new
                    secret to your app and confirm a code before the change takes effect.
                  </p>
                  <Field label="Current password">
                    <input type="password" value={totpForm.current} onChange={(e) => setTotpForm({ ...totpForm, current: e.target.value })} autoComplete="current-password" />
                  </Field>
                  <Field label="Current authenticator code">
                    <input value={totpForm.totp} onChange={(e) => setTotpForm({ ...totpForm, totp: e.target.value })} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" />
                  </Field>
                  <Field label="Or a recovery code (if the authenticator is lost)">
                    <input value={totpForm.recovery} onChange={(e) => setTotpForm({ ...totpForm, recovery: e.target.value })} autoComplete="off" placeholder="AAAA-BBBB-CCCC" />
                  </Field>
                  <button onClick={beginTOTP} disabled={totpBusy || !totpForm.current || (!totpForm.totp && !totpForm.recovery)}>
                    {totpBusy ? "Checking…" : "Start rotation"}
                  </button>
                </>
              )}

              {totpStep === "enrol" && pending && (
                <>
                  <p className="sub" style={{ color: "var(--muted)", fontSize: 13 }}>
                    Add this secret to your authenticator, then enter the six-digit code it shows.
                  </p>
                  <div className="secret-box">{pending.secret}</div>
                  <div className="secret-box" style={{ fontSize: 11 }}>{pending.url}</div>
                  <Field label="Code from the new secret">
                    <input value={newCode} onChange={(e) => setNewCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" autoFocus />
                  </Field>
                  <div className="row">
                    <button className="primary" onClick={confirmTOTP} disabled={totpBusy || newCode.length !== 6}>
                      {totpBusy ? "Confirming…" : "Confirm new authenticator"}
                    </button>
                    <button onClick={() => { setTotpStep("idle"); setPending(null); setNewCode(""); }}>Cancel</button>
                  </div>
                </>
              )}

              {codes.length > 0 && (
                <>
                  <label style={{ marginTop: 16 }}>New recovery codes — shown once</label>
                  <div className="code-list">
                    {codes.map((c) => <div key={c}>{c}</div>)}
                  </div>
                  <p className="muted" style={{ fontSize: 12 }}>Store these offline; each one works once.</p>
                </>
              )}
            </Card>
          </>
        )}
      </div>

      <div className="grid cols-2">
        <Card title="Email for alerts and password resets">
          <Field
            label="Your email address"
            hint={external
              ? "Security alerts are sent here. Your password reset is handled by your directory, not this console."
              : "Password-reset links and security alerts are sent here. Without an address, the Forgot password link cannot reach you."}
          >
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" placeholder="admin@your-domain.tld" />
          </Field>
          {!email && <p className="err-text">Add an email address or password reset by email will not work for this account.</p>}
          <button onClick={saveEmail} disabled={email === (me?.email ?? "")}>Save email</button>
        </Card>

        <Card title="Remembered devices">
          {devices.length === 0 ? (
            <Empty>No browser is trusted. Every sign-in asks for the authenticator code.</Empty>
          ) : (
            <div className="table-wrap"><table>
              <thead><tr><th>Device</th><th>Address</th><th>Trusted</th><th>Expires</th><th /></tr></thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id}>
                    <td style={{ maxWidth: 240 }}>
                      <span title={d.ua}>{d.ua || "Unknown browser"}</span>
                      {d.current && <> <Badge tone="info">this device</Badge></>}
                    </td>
                    <td className="mono">{d.ip || "—"}</td>
                    <td className="muted">{fmtTime(d.created_at)}</td>
                    <td className="muted">{fmtTime(d.expires_at)}</td>
                    <td className="right"><button className="small danger" onClick={() => revokeDevice(d)}>Revoke</button></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
          <p className="muted" style={{ fontSize: 12 }}>
            A remembered browser skips the authenticator code for 30 days. Revoking one takes effect on its next request;
            changing the password or authenticator forgets every device.
          </p>
        </Card>
      </div>
    </>
  );

  const sub =
    active === "account"
      ? "Your password, authenticator, alert email and remembered devices."
      : active === "admins"
        ? "Live sessions and the administrators allowed to sign in."
        : active === "roles"
          ? "The roles that decide what an administrator can see and change."
          : active === "tacacs"
            ? "Sign administrators in with TACACS+ and assign their role from an authorization AV pair."
            : active === "radius"
              ? "Sign administrators in with RADIUS. It answers yes or no, so a default role is assigned."
              : "Sign administrators in with LDAP or Active Directory and map their groups to console roles.";

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead sub={sub} />
      {tabs.length > 0 && onTab && <PageTabs tabs={tabs} active={active} onSelect={onTab} />}
      {active === "account" && accountTab}
      {active === "admins" && canReadAccounts && (
        <div className="grid" style={{ gap: 14 }}>
          <AdminSessions onError={onError} onOK={onOK} onSignedOut={onSignedOut} />
          <Team me={me} onError={onError} onOK={onOK} section="admins" />
        </div>
      )}
      {active === "roles" && canReadAccounts && <Team me={me} onError={onError} onOK={onOK} section="roles" />}
      {(active === "tacacs" || active === "radius" || active === "ldap") && canReadAccounts && (
        <ConsoleAuthForm
          key={active}
          kind={active}
          canWrite={canManage}
          onError={onError}
          onOK={onOK}
        />
      )}
      {active !== "account" && !canReadAccounts && (
        <Card title="Not available"><p className="muted">This tab needs permission to read administrator accounts.</p></Card>
      )}
    </div>
  );
}
