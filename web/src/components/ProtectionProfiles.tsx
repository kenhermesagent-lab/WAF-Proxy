import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Modal, errText } from "../ui";
import type { ProtectionProfile } from "../types";

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

  const load = () =>
    api.get<ProtectionProfile[]>("/api/protection-profiles").then(setList).catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
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
    if (!confirm(`Delete the ${p.name} profile?`)) return;
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
          <table>
            <thead>
              <tr><th>Profile</th><th>Applied headers</th><th /></tr>
            </thead>
            <tbody>
              {list.map((p) => (
                <tr key={p.id}>
                  <td style={{ whiteSpace: "nowrap" }}>
                    {p.name} {p.builtin && <Badge tone="info">built-in</Badge>}
                  </td>
                  <td className="muted" style={{ fontSize: 12 }}>{summary(p)}</td>
                  <td className="right" style={{ whiteSpace: "nowrap" }}>
                    <button className="small" onClick={() => setDraft({ ...p })}>Edit</button>{" "}
                    {!p.builtin && <button className="small danger" onClick={() => remove(p)}>Delete</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted" style={{ fontSize: 12 }}>
        A proxy applies these headers on every response, after the upstream's own. HTTPS enforcement redirects a
        plain-HTTP request before the WAF runs, so the redirected request goes through the normal TLS path. HSTS is
        only sent over TLS.
      </p>

      {draft && (
        <Modal title={draft.id === 0 ? "New protection profile" : `Edit ${draft.name}`} onClose={() => setDraft(null)}>
          {draft.id === 0 && (
            <Field label="Profile name">
              <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Internal apps" autoFocus />
            </Field>
          )}
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
