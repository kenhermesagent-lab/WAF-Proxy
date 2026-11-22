import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Modal, errText } from "../ui";
import { AccessProfile, AuthProvider, Cert, Preset, ProtectionProfile, Proxy, Route, Upstream } from "../types";

type Draft = {
  id?: number;
  hostname: string;
  enabled: boolean;
  profile_id: number | null;
  protection_profile_id: number | null;
  access_profile_id: number | null;
  auth_provider_id: number | null;
  cert_id: number | null;
  gate_mode: string;
  gate_secret: string;
  fingerprint: string;
  bot_level: string;
  maintenance: boolean;
  waf_mode: string;
  /** Application preset, sent only when creating a proxy. */
  preset: string;
  upstreams: Upstream[];
  routes: Route[];
  gate_users: string[];
};

function emptyDraft(): Draft {
  return {
    hostname: "",
    enabled: true,
    profile_id: null,
    protection_profile_id: null,
    access_profile_id: null,
    auth_provider_id: null,
    cert_id: null,
    gate_mode: "off",
    gate_secret: "",
    fingerprint: "strict",
    bot_level: "light",
    maintenance: false,
    waf_mode: "inherit",
    preset: "",
    upstreams: [{ url: "http://192.168.101.10:8080", weight: 1, enabled: true }],
    routes: [],
    gate_users: [],
  };
}

export default function Proxies({ onError, onOK, base }: { onError: (m: string) => void; onOK: (m: string) => void; base: string }) {
  const [list, setList] = useState<Proxy[]>([]);
  const [protections, setProtections] = useState<ProtectionProfile[]>([]);
  const [accessProfiles, setAccessProfiles] = useState<AccessProfile[]>([]);
  const [providers, setProviders] = useState<AuthProvider[]>([]);
  const [certs, setCerts] = useState<Cert[]>([]);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saving, setSaving] = useState(false);

  const load = () =>
    Promise.all([
      api.get<Proxy[]>("/api/proxies"),
      api.get<ProtectionProfile[]>("/api/protection-profiles"),
      api.get<AccessProfile[]>("/api/access-profiles"),
      api.get<AuthProvider[]>("/api/auth-providers"),
      api.get<{ certs: Cert[] }>("/api/certs"),
      api.get<Preset[]>("/api/presets"),
    ])
      .then(([p, pp, ap, prov, c, pre]) => {
        setList(p);
        setProtections(pp);
        setAccessProfiles(ap);
        setProviders(prov);
        setCerts(c.certs || []);
        setPresets(pre);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  // New sites get the built-in hardening profile preselected, so HTTPS and HSTS
  // are on unless the admin unticks them by choosing None.
  const openNew = () =>
    setDraft({
      ...emptyDraft(),
      hostname: `app.${base}`,
      protection_profile_id: protections.find((p) => p.builtin)?.id ?? null,
    });
  const openEdit = (p: Proxy) =>
    setDraft({
      id: p.id,
      hostname: p.hostname,
      enabled: p.enabled,
      profile_id: p.profile_id ?? null,
      protection_profile_id: p.protection_profile_id ?? null,
      access_profile_id: p.access_profile_id ?? null,
      auth_provider_id: p.auth_provider_id ?? null,
      cert_id: p.cert_id ?? null,
      gate_mode: p.gate_mode || "off",
      gate_secret: "",
      fingerprint: p.fingerprint || "strict",
      bot_level: p.bot_level || "light",
      maintenance: p.maintenance,
      waf_mode: p.waf_mode || "inherit",
      preset: "",
      upstreams: p.upstreams?.length ? p.upstreams : [{ url: "", weight: 1, enabled: true }],
      routes: p.routes ?? [],
      gate_users: p.gate_users ?? [],
    });

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      // The preset is a one-time starting point: on create it becomes an
      // editable WAF profile, and on update the profile is what gets changed.
      const { preset, ...rest } = draft;
      if (draft.id) await api.put(`/api/proxies/${draft.id}`, rest);
      else await api.post("/api/proxies", { ...rest, preset });
      onOK(draft.id ? "Proxy updated" : "Proxy created");
      setDraft(null);
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const revokeSessions = async (p: Proxy) => {
    if (!confirm(`Sign out every visitor currently signed in to ${p.hostname}?`)) return;
    try {
      await api.post(`/api/proxies/${p.id}/gate/revoke`);
      onOK(`Gate sessions cleared for ${p.hostname}`);
    } catch (e) {
      onError(errText(e));
    }
  };

  const remove = async (p: Proxy) => {
    if (!confirm(`Delete ${p.hostname}? This removes its routes and upstreams.`)) return;
    try {
      await api.del(`/api/proxies/${p.id}`);
      onOK("Proxy deleted");
      await load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const chosenPreset = presets.find((p) => p.id === draft?.preset);

  const patch = (fn: (d: Draft) => void) =>
    setDraft((d) => {
      if (!d) return d;
      const next: Draft = { ...d, upstreams: [...d.upstreams], routes: [...d.routes], gate_users: [...d.gate_users] };
      fn(next);
      return next;
    });

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card
        title="Proxies"
        actions={
          <button className="primary" onClick={openNew}>
            New proxy
          </button>
        }
      >
        {list.length === 0 ? (
          <Empty>No proxies yet. Create one and point it at a backend on the LAN.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Upstreams</th>
                <th>WAF</th>
                <th>Bot</th>
                <th>Gate</th>
                <th className="num">Requests</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((p) => (
                <tr key={p.id}>
                  <td>
                    <div className="mono">{p.hostname}</div>
                    <div className="faint" style={{ fontSize: 11 }}>{p.maintenance ? "maintenance" : p.enabled ? "active" : "disabled"}</div>
                  </td>
                  <td className="muted">{p.upstreams.map((u) => u.url).join(", ") || "—"}</td>
                  <td><Badge tone={p.waf_mode === "off" ? "warn" : "info"}>{p.waf_mode}</Badge></td>
                  <td><Badge tone={p.bot_level === "off" ? "warn" : "info"}>{p.bot_level}</Badge></td>
                  <td><Badge tone={p.gate_mode === "off" ? "" : "ok"}>{p.gate_mode}</Badge></td>
                  <td className="num">{(p.requests ?? 0).toLocaleString()} <span className="faint">/ {p.blocked ?? 0} blocked</span></td>
                  <td>{p.enabled ? <Badge tone="ok">enabled</Badge> : <Badge tone="warn">disabled</Badge>}</td>
                  <td className="right" style={{ whiteSpace: "nowrap" }}>
                    <button className="small" onClick={() => openEdit(p)}>Edit</button>{" "}
                    {p.gate_mode !== "off" && (
                      <button className="small" onClick={() => revokeSessions(p)}>Sign out visitors</button>
                    )}{" "}
                    <button className="small danger" onClick={() => remove(p)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {draft && (
        <Modal title={draft.id ? `Edit ${draft.hostname}` : "New proxy"} onClose={() => setDraft(null)}>
          {!draft.id && (
            <Field label="Application preset">
              <select value={draft.preset} onChange={(e) => patch((d) => (d.preset = e.target.value))}>
                <option value="">No preset — default profile</option>
                {presets.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
              {chosenPreset ? (
                <div className="faint mt" style={{ fontSize: 12 }}>
                  <div>{chosenPreset.description}</div>
                  <div className="mono" style={{ fontSize: 11 }}>
                    methods {chosenPreset.methods} · body {chosenPreset.max_body.toLocaleString()} B
                    {chosenPreset.max_response ? ` · responses ${Math.round(chosenPreset.max_response / 1024)} KiB` : ""}
                    {chosenPreset.login_rps ? ` · logins ${chosenPreset.login_rps}/s on ${chosenPreset.login_paths}` : ""}
                  </div>
                  {chosenPreset.exceptions && (
                    <div className="mono" style={{ fontSize: 11 }}>suppresses CRS {chosenPreset.exceptions}</div>
                  )}
                  <div>
                    Creates the WAF profile “{chosenPreset.name}
                    {draft.hostname ? ` (${draft.hostname})` : ""}”, editable under Policies → WAF profiles.
                  </div>
                </div>
              ) : (
                <div className="faint mt" style={{ fontSize: 12 }}>
                  A preset fills in the WAF profile for this site; it is not applied automatically.
                </div>
              )}
            </Field>
          )}
          <div className="row grow">
            <Field label="Hostname">
              <input value={draft.hostname} onChange={(e) => patch((d) => (d.hostname = e.target.value))} placeholder={`app.${base}`} />
            </Field>
            <Field label="Access profile">
              <select
                value={draft.access_profile_id ?? ""}
                onChange={(e) =>
                  patch((d) => {
                    d.access_profile_id = e.target.value ? Number(e.target.value) : null;
                    // The profile supplies the lists and both protection profiles,
                    // so clear any inherited choice from an earlier selection.
                    d.profile_id = null;
                    d.protection_profile_id = null;
                  })
                }
              >
                <option value="">Default settings</option>
                {accessProfiles.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </Field>
            <Field label="Certificate">
              <select value={draft.cert_id ?? ""} onChange={(e) => patch((d) => (d.cert_id = e.target.value ? Number(e.target.value) : null))}>
                <option value="">Auto / default</option>
                {certs.map((c) => (
                  <option key={c.id} value={c.id}>{c.domains}</option>
                ))}
              </select>
            </Field>
          </div>

          <Card title="Upstreams">
            {draft.upstreams.map((u, i) => (
              <div className="row grow" key={i} style={{ marginBottom: 8 }}>
                <div className="field" style={{ flex: "1 1 300px" }}>
                  <input
                    value={u.url}
                    placeholder="http://192.168.101.10:8080"
                    onChange={(e) => patch((d) => { d.upstreams[i] = { ...d.upstreams[i], url: e.target.value }; })}
                  />
                </div>
                <div className="field" style={{ flex: "0 0 90px" }}>
                  <input
                    type="number"
                    min={1}
                    value={u.weight}
                    onChange={(e) => patch((d) => { d.upstreams[i] = { ...d.upstreams[i], weight: Number(e.target.value) }; })}
                  />
                </div>
                <button className="small danger" onClick={() => patch((d) => { d.upstreams.splice(i, 1); })}>Remove</button>
              </div>
            ))}
            <button className="small" onClick={() => patch((d) => { d.upstreams.push({ url: "", weight: 1, enabled: true }); })}>Add upstream</button>
          </Card>

          <div className="grid cols-2 mt">
            <Card title="Protection">
              <Field label="WAF mode">
                <select value={draft.waf_mode} onChange={(e) => patch((d) => (d.waf_mode = e.target.value))}>
                  <option value="inherit">Inherit profile</option>
                  <option value="off">Off</option>
                  <option value="detect">Detect only</option>
                  <option value="block">Block</option>
                </select>
              </Field>
              <Field label="Bot protection">
                <select value={draft.bot_level} onChange={(e) => patch((d) => (d.bot_level = e.target.value))}>
                  <option value="off">Off</option>
                  <option value="light">Light</option>
                  <option value="standard">Standard</option>
                  <option value="aggressive">Aggressive</option>
                </select>
              </Field>
              <Field label="Fingerprint mode">
                <select value={draft.fingerprint} onChange={(e) => patch((d) => (d.fingerprint = e.target.value))}>
                  <option value="strict">Strict</option>
                  <option value="minimal">Minimal</option>
                </select>
              </Field>
            </Card>
            <Card title="Access gate">
              <Field label="Mode">
                <select value={draft.gate_mode} onChange={(e) => patch((d) => (d.gate_mode = e.target.value))}>
                  <option value="off">Off</option>
                  <option value="passphrase">Shared passphrase</option>
                  <option value="accounts">Accounts</option>
                  <option value="accounts_totp">Accounts + TOTP</option>
                  <option value="forward_auth">Identity provider (forward-auth)</option>
                </select>
              </Field>
              {draft.gate_mode === "forward_auth" && (
                <Field label="Provider">
                  <select
                    value={draft.auth_provider_id ?? ""}
                    onChange={(e) => patch((d) => (d.auth_provider_id = e.target.value ? Number(e.target.value) : null))}
                  >
                    <option value="">Choose a provider…</option>
                    {providers.map((p) => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                  </select>
                </Field>
              )}
              {draft.gate_mode === "passphrase" && (
                <Field label="Passphrase (leave blank to keep)">
                  <input type="password" value={draft.gate_secret} onChange={(e) => patch((d) => (d.gate_secret = e.target.value))} />
                </Field>
              )}
              {(draft.gate_mode === "accounts" || draft.gate_mode === "accounts_totp") && (
                <Field label="Allowed accounts (comma separated, empty = all)">
                  <input
                    value={draft.gate_users.join(",")}
                    placeholder="alice,bob"
                    onChange={(e) => patch((d) => (d.gate_users = e.target.value.split(",").map((s) => s.trim()).filter(Boolean)))}
                  />
                </Field>
              )}
            </Card>
          </div>

          <Card title="Routes (redirect / alias)">
            {draft.routes.map((rt, i) => (
              <div className="row grow" key={i} style={{ marginBottom: 8 }}>
                <div className="field" style={{ flex: "0 0 130px" }}>
                  <select value={rt.kind} onChange={(e) => patch((d) => { d.routes[i] = { ...d.routes[i], kind: e.target.value }; })}>
                    <option value="redirect">redirect</option>
                    <option value="alias">alias</option>
                  </select>
                </div>
                <div className="field" style={{ flex: "1 1 160px" }}>
                  <input placeholder="/old" value={rt.match} onChange={(e) => patch((d) => { d.routes[i] = { ...d.routes[i], match: e.target.value }; })} />
                </div>
                <div className="field" style={{ flex: "1 1 220px" }}>
                  <input placeholder="https://example.com/new" value={rt.target} onChange={(e) => patch((d) => { d.routes[i] = { ...d.routes[i], target: e.target.value }; })} />
                </div>
                <button className="small danger" onClick={() => patch((d) => { d.routes.splice(i, 1); })}>Remove</button>
              </div>
            ))}
            <button className="small" onClick={() => patch((d) => { d.routes.push({ kind: "redirect", match: "/", target: "", strip_prefix: false, priority: 0 }); })}>Add route</button>
          </Card>

          <div className="row mt" style={{ justifyContent: "space-between" }}>
            <div className="row">
              <label style={{ margin: 0, display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
                <input type="checkbox" style={{ width: "auto" }} checked={draft.enabled} onChange={(e) => patch((d) => (d.enabled = e.target.checked))} /> Enabled
              </label>
              <label style={{ margin: 0, display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
                <input type="checkbox" style={{ width: "auto" }} checked={draft.maintenance} onChange={(e) => patch((d) => (d.maintenance = e.target.checked))} /> Maintenance
              </label>
            </div>
            <div className="row">
              <button onClick={() => setDraft(null)}>Cancel</button>
              <button className="primary" disabled={saving} onClick={save}>{saving ? "Saving…" : "Save proxy"}</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
