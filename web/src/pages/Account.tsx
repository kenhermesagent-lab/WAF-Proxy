import { useState } from "react";
import { api } from "../api";
import { Card, Field, errText } from "../ui";
import Team from "../components/Team";
import { Me, can } from "../types";

export default function Account({
  me,
  onError,
  onOK,
  onSignedOut,
}: {
  me: Me | null;
  onError: (m: string) => void;
  onOK: (m: string) => void;
  onSignedOut: () => void;
}) {
  const [pw, setPw] = useState({ current: "", next: "", confirm: "", totp: "", recovery: "" });
  const [pwBusy, setPwBusy] = useState(false);

  const [totpStep, setTotpStep] = useState<"idle" | "enrol">("idle");
  const [totpForm, setTotpForm] = useState({ current: "", totp: "", recovery: "" });
  const [pending, setPending] = useState<{ secret: string; url: string } | null>(null);
  const [newCode, setNewCode] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [totpBusy, setTotpBusy] = useState(false);

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

  const logoutAll = async () => {
    if (!confirm("Sign out every browser, including this one?")) return;
    try {
      await api.post("/api/account/logout-all");
      onSignedOut();
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="grid cols-2">
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
      </div>

      <Card title="Sessions">
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>
            Every administrator session, on every browser and device.
          </div>
          <button className="danger" onClick={logoutAll}>Sign out everywhere</button>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          Password and authenticator rotations already revoke other browsers. Use this when a
          device is lost or a session may be stolen.
        </p>
      </Card>

      {can(me?.permissions, "accounts.read") && <Team me={me} onError={onError} onOK={onOK} />}
    </div>
  );
}
