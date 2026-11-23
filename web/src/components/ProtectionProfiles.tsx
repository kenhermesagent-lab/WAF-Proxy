import { useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, Field, Modal, errText } from "../ui";
import type { HeaderAudit, ProtectionProfile, Proxy } from "../types";

const REFERRERS = [
  "no-referrer",
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
];

// The API names each check after the setting it enforces. Those identifiers are
// useful in logs but read poorly in a dialog, so show the header being discussed
// instead and fall back to the wire name for a check this build does not know.
const SETTING_LABELS: Record<string, string> = {
  frame_options: "Framing",
  hsts: "HSTS",
  csp: "Content-Security-Policy",
  nosniff: "Content-type sniffing",
  referrer_policy: "Referrer policy",
};

function settingLabel(setting: string, header: string): string {
  return SETTING_LABELS[setting] ?? header ?? setting;
}

function newProfile(): ProtectionProfile {
  return {
    id: 0,
    name: "",
    builtin: false,
    force_https: true,
    hsts: true,
    hsts_subdomains: true,
    frame_options: "sameorigin",
    nosniff: true,
    referrer_policy: "strict-origin-when-cross-origin",
    csp: "",
    permissions_policy: "",
    hide_server: true,
  };
}

function summary(p: ProtectionProfile): string {
  const on: string[] = [];
  if (p.force_https) on.push("HTTPS");
  if (p.hsts) on.push(p.hsts_subdomains ? "HSTS + subdomains" : "HSTS");
  if (p.frame_options !== "off") on.push(`frame ${p.frame_options}`);
  if (p.nosniff) on.push("nosniff");
  if (p.csp) on.push("CSP");
  if (p.permissions_policy) on.push("permissions");
  if (p.hide_server) on.push("banners hidden");
  return on.join(" · ") || "nothing enabled";
}

export default function ProtectionProfiles({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [list, setList] = useState<ProtectionProfile[]>([]);
  const [draft, setDraft] = useState<ProtectionProfile | null>(null);
  const [saving, setSaving] = useState(false);
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [checking, setChecking] = useState<ProtectionProfile | null>(null);
  const [proxyID, setProxyID] = useState("");
  const [audit, setAudit] = useState<HeaderAudit | null>(null);
  const [auditBusy, setAuditBusy] = useState(false);

  const runAudit = async () => {
    if (!checking || !proxyID) return;
    setAuditBusy(true);
    try {
      const r = await api.get<HeaderAudit>(`/api/protection-profiles/audit?proxy_id=${proxyID}&profile_id=${checking.id}`);
      setAudit(r);
    } catch (e) {
      onError(errText(e));
    } finally {
      setAuditBusy(false);
    }
  };

  const load = () =>
    api.get<ProtectionProfile[]>("/api/protection-profiles").then(setList).catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
    api.get<Proxy[]>("/api/proxies").then(setProxies).catch(() => undefined);
  }, []);

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      if (draft.id === 0) await api.post("/api/protection-profiles", draft);
      else await api.put(`/api/protection-profiles/${draft.id}`, draft);
      onOK(draft.id === 0 ? "Protection profile created" : `${draft.name} saved`);
      setDraft(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (p: ProtectionProfile) => {
    if (!(await confirmDialog(`Delete the ${p.name} profile?`))) return;
    try {
      await api.del(`/api/protection-profiles/${p.id}`);
      onOK("Protection profile deleted");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <Card
      title="Protection profiles"
      actions={<button className="small primary" onClick={() => setDraft(newProfile())}>New profile</button>}
    >
      {list.length === 0 ? (
        <Empty>No protection profiles.</Empty>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <div className="table-wrap"><table className="protection-table">
            <thead>
              <tr><th>Profile</th><th>Applied headers</th><th /></tr>
            </thead>
            <tbody>
              {list.map((p) => (
                <tr key={p.id}>
                  <td>
                    <div className="profile-title">{p.name}</div>
                    {p.builtin && <Badge tone="info">built-in</Badge>}
                  </td>
                  <td className="muted summary-cell">{summary(p)}</td>
                  <td className="right">
                    <div className="protection-actions">
                      <button className="small" onClick={() => { setChecking(p); setAudit(null); if (!proxyID && proxies[0]) setProxyID(String(proxies[0].id)); }}>Check a site</button>
                      <button className="small" onClick={() => setDraft({ ...p })}>Edit</button>
                      {!p.builtin && <button className="small danger" onClick={() => remove(p)}>Delete</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
      )}
      <p className="muted" style={{ fontSize: 12 }}>
        A proxy applies these headers on every response, after the upstream's own. HTTPS enforcement redirects a
        plain-HTTP request before the WAF runs, so the redirected request goes through the normal TLS path. HSTS is
        only sent over TLS. Use <strong>Check a site</strong> to compare a running application's own headers with the
        profile: turning framing protection off deletes the application's X-Frame-Options, so the check tells you when
        the profile is unnecessary or actively weakening it.
      </p>

      {checking && (
        <Modal title={`Backend headers · ${checking.name}`} onClose={() => { setChecking(null); setAudit(null); }}>
          {proxies.length === 0 ? (
            <Empty>Create a proxy first; the check fetches its upstream.</Empty>
          ) : (
            <>
              <div className="row grow">
                <Field label="Proxy to check">
                  <select value={proxyID} onChange={(e) => { setProxyID(e.target.value); setAudit(null); }}>
                    {proxies.map((p) => <option key={p.id} value={p.id}>{p.hostname}</option>)}
                  </select>
                </Field>
                <button className="primary" style={{ marginTop: 18 }} onClick={runAudit} disabled={auditBusy || !proxyID}>
                  {auditBusy ? "Checking…" : "Check headers"}
                </button>
              </div>
              {audit && (
                <>
                  <p className="muted" style={{ fontSize: 12 }}>
                    <span className="mono">{audit.upstream}</span> answered {audit.status}
                    {audit.self_signed ? " over a self-signed certificate" : ""}. The check requests the backend as
                    <span className="mono"> {audit.proxy}</span>.
                  </p>
                  <div>
                    {audit.checks.map((c) => (
                      <div key={c.setting} style={{ borderTop: "1px solid var(--border)", padding: "10px 0" }}>
                        <div className="row" style={{ justifyContent: "space-between", gap: 8, marginBottom: 6 }}>
                          <strong style={{ fontSize: 12.5 }}>{settingLabel(c.setting, c.header)}</strong>
                          <Badge tone={c.verdict === "at-risk" || c.verdict === "gap" ? "warn" : "ok"}>{c.verdict}</Badge>
                        </div>
                        <div className="grid cols-2" style={{ gap: 12 }}>
                          <div>
                            <div className="faint" style={{ fontSize: 10.5, letterSpacing: ".06em", textTransform: "uppercase" }}>Application</div>
                            <div className="mono" style={{ fontSize: 11.5, lineHeight: 1.5, overflowWrap: "anywhere" }}>{c.backend}</div>
                          </div>
                          <div>
                            <div className="faint" style={{ fontSize: 10.5, letterSpacing: ".06em", textTransform: "uppercase" }}>Profile</div>
                            <div className="mono" style={{ fontSize: 11.5, lineHeight: 1.5, overflowWrap: "anywhere" }}>{c.profile}</div>
                          </div>
                        </div>
                        <p className="muted" style={{ fontSize: 12, margin: "6px 0 0", lineHeight: 1.55 }}>{c.advice}</p>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </>
          )}
        </Modal>
      )}

      {draft && (
        <Modal title={draft.id === 0 ? "New protection profile" : `Edit ${draft.name}`} onClose={() => setDraft(null)}>
          <Field label="Profile name">
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder="Internal apps"
              autoFocus
              // The name is fixed once created so the proxies pointing at it keep
              // a label an operator recognises; showing it disabled beats
              // accepting an edit that the server would quietly drop.
              disabled={draft.id !== 0}
            />
          </Field>
          <div className="grid cols-2">
            <label className="row" style={{ margin: 0, gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={draft.force_https} onChange={(e) => setDraft({ ...draft, force_https: e.target.checked })} />
              Redirect HTTP to HTTPS
            </label>
            <label className="row" style={{ margin: 0, gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={draft.hsts} onChange={(e) => setDraft({ ...draft, hsts: e.target.checked })} />
              Send HSTS
            </label>
            <label className="row" style={{ margin: 0, gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={draft.hsts_subdomains} onChange={(e) => setDraft({ ...draft, hsts_subdomains: e.target.checked })} />
              HSTS covers subdomains
            </label>
            <label className="row" style={{ margin: 0, gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={draft.nosniff} onChange={(e) => setDraft({ ...draft, nosniff: e.target.checked })} />
              X-Content-Type-Options: nosniff
            </label>
            <label className="row" style={{ margin: 0, gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={draft.hide_server} onChange={(e) => setDraft({ ...draft, hide_server: e.target.checked })} />
              Hide server banners
            </label>
          </div>
          <div className="row grow">
            <Field label="Frame policy">
              <select value={draft.frame_options} onChange={(e) => setDraft({ ...draft, frame_options: e.target.value })}>
                <option value="sameorigin">SAMEORIGIN (allow same site)</option>
                <option value="deny">DENY (no framing)</option>
                <option value="off">Off</option>
              </select>
            </Field>
            <Field label="Referrer policy">
              <select value={draft.referrer_policy} onChange={(e) => setDraft({ ...draft, referrer_policy: e.target.value })}>
                {REFERRERS.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </Field>
          </div>
          <Field label="Content-Security-Policy (optional)">
            <textarea value={draft.csp} onChange={(e) => setDraft({ ...draft, csp: e.target.value })} placeholder="default-src 'self'" />
          </Field>
          <Field label="Permissions-Policy (optional)">
            <input
              value={draft.permissions_policy}
              onChange={(e) => setDraft({ ...draft, permissions_policy: e.target.value })}
              placeholder="camera=(), microphone=(), geolocation=()"
            />
          </Field>
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setDraft(null)}>Cancel</button>
            <button className="primary" disabled={saving || draft.name.trim() === ""} onClick={save}>
              {saving ? "Saving…" : draft.id === 0 ? "Create profile" : "Save profile"}
            </button>
          </div>
        </Modal>
      )}
    </Card>
  );
}
