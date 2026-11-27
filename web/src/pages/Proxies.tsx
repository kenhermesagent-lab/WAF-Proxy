import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import Icon from "../components/Icon";
import ProxyDetail from "../components/ProxyDetail";
import { AccessList, AccessProfile, AuthProvider, BodySkip, Cert, Preset, Profile, ProtectionProfile, Proxy, Route, Upstream } from "../types";
import { Badge, ConfirmDialog, Drawer, Empty, Field, PageHead, PageTabs, Switch, TableWrap, errText } from "../ui";
import type { NavTab } from "../nav";
import Certs from "./Certs";
import Streaming from "./Streaming";

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
  max_body: number;
  body_skip: BodySkip[];
  deny_paths: string[];
  preset: string;
  upstreams: Upstream[];
  routes: Route[];
  gate_users: string[];
};

const GATE_LABELS: Record<string, string> = {
  off: "Off",
  passphrase: "Shared passphrase",
  accounts: "Accounts",
  accounts_totp: "Accounts + TOTP",
  forward_auth: "Identity provider",
};
const WAF_LABELS: Record<string, string> = { inherit: "Inherit", off: "Off", detect: "Detect", block: "Block" };
const BOT_LABELS: Record<string, string> = { off: "Off", light: "Light", standard: "Standard", aggressive: "Aggressive" };
const FP_LABELS: Record<string, string> = { strict: "Strict", minimal: "Minimal" };

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
    max_body: 0,
    body_skip: [],
    deny_paths: [],
    preset: "",
    upstreams: [{ url: "http://10.0.0.10:8080", weight: 1, enabled: true }],
    routes: [],
    gate_users: [],
  };
}

type Tab = "overview" | "routing" | "protection" | "access" | "routes";

export default function Proxies({
  onError,
  onOK,
  base,
  tab,
  tabs,
  onTab,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  base: string;
  tab: string;
  tabs: NavTab[];
  onTab: (id: string) => void;
}) {
  const [list, setList] = useState<Proxy[]>([]);
  const [protections, setProtections] = useState<ProtectionProfile[]>([]);
  const [accessProfiles, setAccessProfiles] = useState<AccessProfile[]>([]);
  const [providers, setProviders] = useState<AuthProvider[]>([]);
  const [certs, setCerts] = useState<Cert[]>([]);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [lists, setLists] = useState<AccessList[]>([]);
  // Whether the operator has a gate account: a preset may only preselect its
  // suggested gate when one exists, or the new site would lock everyone out.
  const [gateAccounts, setGateAccounts] = useState(0);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [drawerTab, setDrawerTab] = useState<Tab>("overview");
  const [saving, setSaving] = useState(false);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [sort, setSort] = useState<{ key: "hostname" | "requests" | "blocked"; dir: 1 | -1 }>({ key: "hostname", dir: 1 });
  const [confirm, setConfirm] = useState<null | { kind: "delete" | "revoke"; proxy: Proxy }>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [inspect, setInspect] = useState<Proxy | null>(null);

  const load = () =>
    Promise.all([
      api.get<Proxy[]>("/api/proxies"),
      api.get<ProtectionProfile[]>("/api/protection-profiles"),
      api.get<AccessProfile[]>("/api/access-profiles"),
      api.get<AuthProvider[]>("/api/auth-providers"),
      api.get<{ certs: Cert[] }>("/api/certs"),
      api.get<Preset[]>("/api/presets"),
      api.get<Profile[]>("/api/profiles"),
      api.get<{ id: number }[]>("/api/gate-users"),
      api.get<AccessList[]>("/api/lists"),
    ])
      .then(([p, pp, ap, prov, c, pre, prof, gu, li]) => {
        setList(p);
        setProtections(pp);
        setAccessProfiles(ap);
        setProviders(prov);
        setCerts(c.certs || []);
        setPresets(pre);
        setProfiles(prof);
        setGateAccounts(gu.length);
        setLists(li);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  // A host with a trusted-source exemption on its access profile is marked in
  // the list, so the exemption is visible without opening the profile.
  const wafSkipProfile = (p: Proxy) => {
    if (p.waf_mode === "off") return undefined;
    const ap = accessProfiles.find((a) => a.id === p.access_profile_id);
    return ap && (ap.waf_skip_list_ids ?? []).length > 0 ? ap : undefined;
  };

  const openNew = () => {
    setDrawerTab("overview");
    setDraft({
      ...emptyDraft(),
      hostname: `app.${base}`,
      protection_profile_id: protections.find((p) => p.builtin)?.id ?? null,
    });
  };

  const openEdit = (p: Proxy) => {
    setDrawerTab("overview");
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
      max_body: p.max_body ?? 0,
      body_skip: p.body_skip ?? [],
      deny_paths: p.deny_paths ?? [],
      preset: "",
      upstreams: p.upstreams?.length ? p.upstreams : [{ url: "", weight: 1, enabled: true }],
      routes: p.routes ?? [],
      gate_users: p.gate_users ?? [],
    });
  };

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      const { preset, ...rest } = draft;
      // An empty row is not a path; the API validates each entry, so drop it
      // rather than refusing the whole save.
      const payload = { ...rest, deny_paths: rest.deny_paths.map((p) => p.trim()).filter(Boolean) };
      if (draft.id) await api.put(`/api/proxies/${draft.id}`, payload);
      else await api.post("/api/proxies", { ...payload, preset });
      onOK(draft.id ? `${draft.hostname} updated` : `${draft.hostname} created`);
      setDraft(null);
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const runConfirm = async () => {
    if (!confirm) return;
    setConfirmBusy(true);
    try {
      if (confirm.kind === "delete") {
        await api.del(`/api/proxies/${confirm.proxy.id}`);
        onOK(`${confirm.proxy.hostname} deleted`);
        setDraft(null);
        await load();
      } else {
        await api.post(`/api/proxies/${confirm.proxy.id}/gate/revoke`);
        onOK(`Gate sessions cleared for ${confirm.proxy.hostname}`);
      }
      setConfirm(null);
    } catch (e) {
      onError(errText(e));
    } finally {
      setConfirmBusy(false);
    }
  };

  const chosenPreset = presets.find((p) => p.id === draft?.preset);

  const patch = (fn: (d: Draft) => void) =>
    setDraft((d) => {
      if (!d) return d;
      const next: Draft = { ...d, upstreams: [...d.upstreams], routes: [...d.routes], gate_users: [...d.gate_users], body_skip: [...d.body_skip], deny_paths: [...d.deny_paths] };
      fn(next);
      return next;
    });

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    const rows = list.filter((p) => {
      if (q && !p.hostname.toLowerCase().includes(q) && !(p.upstreams ?? []).some((u) => u.url.toLowerCase().includes(q))) return false;
      if (status === "enabled" && !p.enabled) return false;
      if (status === "disabled" && p.enabled) return false;
      if (status === "maintenance" && !p.maintenance) return false;
      return true;
    });
    return rows.sort((a, b) => {
      if (sort.key === "hostname") return a.hostname.localeCompare(b.hostname) * sort.dir;
      const av = sort.key === "requests" ? a.requests ?? 0 : a.blocked ?? 0;
      const bv = sort.key === "requests" ? b.requests ?? 0 : b.blocked ?? 0;
      return (av - bv) * sort.dir;
    });
  }, [list, search, status, sort]);

  const sortBy = (key: "hostname" | "requests" | "blocked") =>
    setSort((s) => ({ key, dir: s.key === key ? (s.dir === 1 ? -1 : 1) : key === "hostname" ? 1 : -1 }));

  const arrow = (key: string) => (sort.key === key ? (sort.dir === 1 ? "↑" : "↓") : "");

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead
        sub="Hostnames served by this node, with their certificates and streaming forwards."
        actions={tab === "sites" ? <button className="primary" onClick={openNew}><Icon name="plus" size={14} /> New proxy</button> : undefined}
      />
      <PageTabs tabs={tabs} active={tab} onSelect={onTab} />

      {tab === "certs" && <Certs head={false} base={base} onError={onError} onOK={onOK} />}
      {tab === "streaming" && <Streaming head={false} onError={onError} onOK={onOK} />}

      {tab === "sites" && (
            <>
          <div className="card">
            <div className="table-toolbar">
              <div className="search">
                <Icon name="search" size={14} />
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter by hostname or upstream" aria-label="Filter proxies" />
              </div>
              <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
                <option value="all">All states</option>
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
                <option value="maintenance">Maintenance</option>
              </select>
              <span className="table-count">{visible.length} of {list.length}</span>
            </div>

            {visible.length === 0 ? (
              <Empty
                title={list.length === 0 ? "No proxies yet" : "No proxies match"}
                icon="server"
                action={list.length === 0 ? <button className="primary" onClick={openNew}>Create the first proxy</button> : <button onClick={() => { setSearch(""); setStatus("all"); }}>Clear filters</button>}
              >
                {list.length === 0
                  ? "A hostname points a subdomain of your base domain at a backend on the LAN, and the WAF checks every request on the way through."
                  : "Try a different hostname or state."}
              </Empty>
            ) : (
              <TableWrap>
                <table className="proxies-table">
                  <thead>
                    <tr>
                      <th className="sortable" onClick={() => sortBy("hostname")}>Hostname {arrow("hostname")}</th>
                      <th>Upstreams</th>
                      <th>Protection</th>
                      <th>Gate</th>
                      <th className="num sortable" onClick={() => sortBy("requests")}>Requests {arrow("requests")}</th>
                      <th className="num sortable" onClick={() => sortBy("blocked")}>Blocked {arrow("blocked")}</th>
                      <th>State</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((p) => {
                      const skip = wafSkipProfile(p);
                      return (
                        <tr key={p.id} className="clickable" onClick={() => openEdit(p)}>
                          <td>
                            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                              <span className={`env-dot ${p.enabled && !p.maintenance ? "" : "warn"}`} style={p.enabled && !p.maintenance ? undefined : { background: p.maintenance ? "var(--warn)" : "var(--faint)" }} />
                              <span className="mono" style={{ color: "var(--text)", fontSize: 12 }}>{p.hostname}</span>
                              {skip && (
                                <Badge
                                  tone="warn"
                                  title={`Trusted-source WAF skip: the ${skip.name} access profile skips the WAF stage for ${skip.waf_skip_list_ids.length} trust list${skip.waf_skip_list_ids.length === 1 ? "" : "s"}`}
                                >
                                  WAF skip
                                </Badge>
                              )}
                            </div>
                            <div className="faint small-text">{p.upstreams.length} upstream{p.upstreams.length === 1 ? "" : "s"}{p.maintenance ? " · maintenance" : ""}</div>
                          </td>
                          <td className="muted mono" style={{ fontSize: 11.5 }}>
                            {p.upstreams[0]?.url ?? "—"}
                            {p.upstreams.length > 1 ? <div className="faint">+{p.upstreams.length - 1} more</div> : null}
                          </td>
                          <td>
                            <div className="row" style={{ gap: 5 }}>
                              <Badge tone={p.waf_mode === "off" ? "warn" : "info"}>{WAF_LABELS[p.waf_mode] ?? p.waf_mode}</Badge>
                              <Badge>{BOT_LABELS[p.bot_level] ?? p.bot_level}</Badge>
                            </div>
                          </td>
                          <td><Badge tone={p.gate_mode === "off" ? "" : "ok"}>{GATE_LABELS[p.gate_mode] ?? p.gate_mode}</Badge></td>
                          <td className="num">{(p.requests ?? 0).toLocaleString()}</td>
                          <td className="num">{(p.blocked ?? 0).toLocaleString()}</td>
                          <td>
                            <Badge tone={p.maintenance ? "warn" : p.enabled ? "ok" : ""}>
                              {p.maintenance ? "Maintenance" : p.enabled ? "Enabled" : "Disabled"}
                            </Badge>
                          </td>
                          <td className="right" onClick={(e) => e.stopPropagation()} style={{ whiteSpace: "nowrap" }}>
                            <button className="xsmall" title="Configuration, traffic and upstream health" onClick={() => setInspect(p)}>360</button>{" "}
                            <button className="xsmall" onClick={() => openEdit(p)}>Edit</button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </div>

          {draft && (
            <Drawer
              wide
              title={draft.id ? draft.hostname : "New proxy"}
              sub={draft.id ? "Changes apply after saving." : "Create a hostname and its routing rules."}
              onClose={() => setDraft(null)}
              footer={
                <>
                  {draft.id && (
                    <button className="danger" style={{ marginRight: "auto" }} onClick={() => setConfirm({ kind: "delete", proxy: { ...draft, id: draft.id } as unknown as Proxy })}>
                      <Icon name="trash" size={13} /> Delete proxy
                    </button>
                  )}
                  <button onClick={() => setDraft(null)}>Cancel</button>
                  <button className="primary" disabled={saving} onClick={save}>{saving ? "Saving…" : "Save proxy"}</button>
                </>
              }
            >
              <div className="tabs" role="tablist">
                {([
                  ["overview", "Overview"],
                  ["routing", `Upstreams (${draft.upstreams.length})`],
                  ["protection", "Protection"],
                  ["access", "Access gate"],
                  ["routes", `Routes (${draft.routes.length})`],
                ] as [Tab, string][]).map(([id, label]) => (
                  <button key={id} role="tab" aria-selected={drawerTab === id} className={`tab ${drawerTab === id ? "active" : ""}`} onClick={() => setDrawerTab(id)}>
                    {label}
                  </button>
                ))}
              </div>

              {drawerTab === "overview" && (
                <>
                  {!draft.id && (
                    <Field label="Application preset" hint={chosenPreset ? `${chosenPreset.description} Creates an editable WAF profile and a protection profile with the headers this app needs.` : "A preset fills in the WAF and protection profiles for this site; it is not applied automatically."}>
                      <select
                        value={draft.preset}
                        onChange={(e) =>
                          patch((d) => {
                            d.preset = e.target.value;
                            const pre = presets.find((p) => p.id === d.preset);
                            // The preset brings its own hardening; drop an explicit
                            // choice so the server can create it. Clearing the
                            // preset falls back to the built-in profile.
                            d.protection_profile_id = pre ? null : protections.find((p) => p.builtin)?.id ?? null;
                            if (!pre) return;
                            if (pre.gate && d.gate_mode === "off" && gateAccounts > 0) d.gate_mode = pre.gate;
                            // The suggested body settings are prefilled and visible on
                            // the Protection tab, never applied where the operator
                            // cannot see or change them.
                            if (pre.proxy_max_body) d.max_body = pre.proxy_max_body;
                            if (pre.body_skip_paths?.length) {
                              d.body_skip = pre.body_skip_paths.map((line) => {
                                const [method, ...path] = line.trim().split(/\s+/);
                                return { method: method.toUpperCase(), prefix: path.join(" "), list_ids: [] };
                              });
                            }
                          })
                        }
                      >
                        <option value="">No preset — default profile</option>
                        {presets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                      </select>
                      {chosenPreset?.gate && (
                        <p className="faint" style={{ margin: "8px 0 0", fontSize: 11 }}>
                          The preset suggests the {GATE_LABELS[chosenPreset.gate] ?? chosenPreset.gate} gate in front of this app.
                          {gateAccounts > 0
                            ? " It is selected on the Access gate tab; turn it off if you do not want it."
                            : " It stays off until an account exists under Access gate, so this site cannot lock you out."}{" "}
                          A gate covers browser sessions only: turn it off if a mobile app or API token must reach this site.
                        </p>
                      )}
                      {chosenPreset && chosenPreset.notes?.length > 0 && (
                        <ul className="faint" style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 11 }}>
                          {chosenPreset.notes.map((n) => <li key={n}>{n}</li>)}
                        </ul>
                      )}
                    </Field>
                  )}
                  {!draft.id && chosenPreset && chosenPreset.steps?.length > 0 && (
                    <div className="banner" style={{ display: "block", marginTop: 2, marginBottom: 12 }}>
                      <strong style={{ fontSize: 12 }}>Steps for {chosenPreset.name}</strong>
                      <ol style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 12 }}>
                        {chosenPreset.steps.map((s) => <li key={s} style={{ marginBottom: 4 }}>{s}</li>)}
                      </ol>
                    </div>
                  )}
                  <Field label="Hostname">
                    <input value={draft.hostname} onChange={(e) => patch((d) => (d.hostname = e.target.value))} placeholder={`app.${base}`} />
                  </Field>
                  <div className="field-grid">
                    <Field label="Access profile">
                      <select
                        value={draft.access_profile_id ?? ""}
                        onChange={(e) =>
                          patch((d) => {
                            d.access_profile_id = e.target.value ? Number(e.target.value) : null;
                            d.profile_id = null;
                            d.protection_profile_id = null;
                          })
                        }
                      >
                        <option value="">Default settings</option>
                        {accessProfiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                      </select>
                    </Field>
                    <Field label="WAF profile">
                      <select value={draft.profile_id ?? ""} onChange={(e) => patch((d) => (d.profile_id = e.target.value ? Number(e.target.value) : null))}>
                        <option value="">From the access profile</option>
                        {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                      </select>
                    </Field>
                    <Field label="Certificate">
                      <select value={draft.cert_id ?? ""} onChange={(e) => patch((d) => (d.cert_id = e.target.value ? Number(e.target.value) : null))}>
                        <option value="">Auto / default</option>
                        {certs.map((c) => <option key={c.id} value={c.id}>{c.domains}</option>)}
                      </select>
                    </Field>
                  </div>
                  <div style={{ marginTop: 6 }}>
                    <Switch label="Proxy enabled" help="Disabled proxies stop accepting requests but keep their configuration." checked={draft.enabled} onChange={(v) => patch((d) => (d.enabled = v))} />
                    <Switch label="Maintenance mode" help="Serves a maintenance page while the upstream is being worked on." checked={draft.maintenance} onChange={(v) => patch((d) => (d.maintenance = v))} />
                  </div>
                </>
              )}

              {drawerTab === "routing" && (
                <>
                  {draft.upstreams.map((u, i) => (
                    <div key={i} className="upstream-row">
                      <Field label={i === 0 ? "Upstream URL" : `Upstream ${i + 1}`}>
                        <input value={u.url} placeholder="http://10.0.0.10:8080" onChange={(e) => patch((d) => { d.upstreams[i] = { ...d.upstreams[i], url: e.target.value }; })} />
                      </Field>
                      <Field label="Weight">
                        <input type="number" min={1} value={u.weight} onChange={(e) => patch((d) => { d.upstreams[i] = { ...d.upstreams[i], weight: Number(e.target.value) }; })} />
                      </Field>
                      <button className="ghost" style={{ marginTop: 22 }} aria-label={`Remove upstream ${i + 1}`} onClick={() => patch((d) => { d.upstreams.splice(i, 1); })}>
                        <Icon name="trash" size={14} />
                      </button>
                    </div>
                  ))}
                  <button className="small" onClick={() => patch((d) => { d.upstreams.push({ url: "", weight: 1, enabled: true }); })}>
                    <Icon name="plus" size={13} /> Add upstream
                  </button>
                  <p className="faint small-text" style={{ marginTop: 10 }}>
                    Requests are balanced across enabled upstreams by weight. Health probes use HTTP HEAD every 30 seconds.
                  </p>
                </>
              )}

              {drawerTab === "protection" && (
                <>
                <div className="field-grid">
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
                </div>
                <div style={{ marginTop: 16 }}>
                  <h3 style={{ margin: "0 0 8px", fontSize: 13 }}>Request body</h3>
                  <div className="field-grid">
                    <Field label="Site body ceiling (MiB)" hint="0 inherits the host setting. A buffered body above this is refused with 413.">
                      <input
                        type="number"
                        min={0}
                        max={1024}
                        value={draft.max_body ? Math.round(draft.max_body / (1 << 20)) : 0}
                        onChange={(e) => patch((d) => (d.max_body = Math.max(0, Math.min(1024, Number(e.target.value) || 0)) * (1 << 20)))}
                      />
                    </Field>
                  </div>
                  <p className="faint small-text" style={{ margin: "8px 0" }}>
                    A skip path streams its request body to the app without buffering or inspection, so uploads of any size pass. Method, path and header rules, bans, lists, rate limits and the access gate still apply; only the body is unseen, and neither the body deadline nor the site's upstream timeout cuts it short. A client that stops sending for two minutes is dropped.
                  </p>
                  {draft.body_skip.map((s, i) => (
                    <div key={i} className="skip-row">
                      <Field label={i === 0 ? "Method" : `Skip ${i + 1}`}>
                        <select value={s.method} onChange={(e) => patch((d) => { d.body_skip[i] = { ...d.body_skip[i], method: e.target.value }; })}>
                          <option value="POST">POST</option>
                          <option value="PUT">PUT</option>
                          <option value="PATCH">PATCH</option>
                        </select>
                      </Field>
                      <Field label="Path prefix">
                        <input placeholder="/api/assets" value={s.prefix} onChange={(e) => patch((d) => { d.body_skip[i] = { ...d.body_skip[i], prefix: e.target.value }; })} />
                      </Field>
                      <Field label="Trust lists (optional)" hint={lists.length === 0 ? "No lists yet: add one under Policies → Lists." : "Only these sources skip inspection."}>
                        {lists.length > 0 ? (
                          <select
                            multiple
                            size={Math.min(3, lists.length)}
                            value={(s.list_ids ?? []).map(String)}
                            onChange={(e) => patch((d) => { d.body_skip[i] = { ...d.body_skip[i], list_ids: Array.from(e.target.selectedOptions).map((o) => Number(o.value)) }; })}
                          >
                            {lists.map((l) => <option key={l.id} value={l.id}>{l.name} ({l.kind})</option>)}
                          </select>
                        ) : (
                          <p className="faint small-text" style={{ margin: 0, paddingTop: 6 }}>Any source</p>
                        )}
                      </Field>
                      <button className="ghost" style={{ marginTop: 22 }} aria-label={`Remove skip path ${i + 1}`} onClick={() => patch((d) => { d.body_skip.splice(i, 1); })}>
                        <Icon name="trash" size={14} />
                      </button>
                    </div>
                  ))}
                  <button className="small" onClick={() => patch((d) => { d.body_skip.push({ method: "POST", prefix: "", list_ids: [] }); })}>
                    <Icon name="plus" size={13} /> Add skip path
                  </button>
                  <p className="faint small-text" style={{ marginTop: 6 }}>
                    Without a trust list the prefix is skipped for every source. A trailing * covers everything below the prefix. Prefer a method and a narrow path, and leave the root out.
                  </p>
                </div>
                <div style={{ marginTop: 16 }}>
                  <h3 style={{ margin: "0 0 8px", fontSize: 13 }}>Closed paths</h3>
                  <p className="faint small-text" style={{ margin: "0 0 8px" }}>
                    This hostname answers these paths, and everything below them, with 403 before the access gate and WAF. The Security page's Block &amp; retest installs one when it closes an exposure; remove an entry here to reopen the path.
                  </p>
                  {draft.deny_paths.map((p, i) => (
                    <div key={i} className="deny-row">
                      <Field label={i === 0 ? "Path" : `Closed path ${i + 1}`} hint={i === 0 ? "Includes every path below it." : undefined}>
                        <input placeholder="/actuator/env" value={p} onChange={(e) => patch((d) => { d.deny_paths[i] = e.target.value; })} />
                      </Field>
                      <button className="ghost" style={{ marginTop: 22 }} aria-label={`Remove closed path ${i + 1}`} onClick={() => patch((d) => { d.deny_paths.splice(i, 1); })}>
                        <Icon name="trash" size={14} />
                      </button>
                    </div>
                  ))}
                  <button className="small" onClick={() => patch((d) => { d.deny_paths.push(""); })}>
                    <Icon name="plus" size={13} /> Add closed path
                  </button>
                </div>
                </>
              )}

              {drawerTab === "access" && (
                <>
                  <Field label="Gate mode">
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
                      <select value={draft.auth_provider_id ?? ""} onChange={(e) => patch((d) => (d.auth_provider_id = e.target.value ? Number(e.target.value) : null))}>
                        <option value="">Choose a provider…</option>
                        {providers.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                      </select>
                    </Field>
                  )}
                  {draft.gate_mode === "passphrase" && (
                    <Field label="Passphrase" hint="Leave blank to keep the current passphrase.">
                      <input type="password" value={draft.gate_secret} onChange={(e) => patch((d) => (d.gate_secret = e.target.value))} />
                    </Field>
                  )}
                  {(draft.gate_mode === "accounts" || draft.gate_mode === "accounts_totp") && (
                    <Field label="Allowed accounts" hint="Comma separated usernames; empty allows every gate account.">
                      <input value={draft.gate_users.join(",")} placeholder="alice,bob" onChange={(e) => patch((d) => (d.gate_users = e.target.value.split(",").map((x) => x.trim()).filter(Boolean)))} />
                    </Field>
                  )}
                  {draft.gate_mode !== "off" && draft.id && (
                    <div className="banner" style={{ marginTop: 6 }}>
                      <Icon name="lock" size={15} />
                      <span>Signed-in visitors keep their session until it expires.</span>
                      <span className="banner-actions">
                        <button className="xsmall" onClick={() => setConfirm({ kind: "revoke", proxy: { ...draft, id: draft.id } as unknown as Proxy })}>
                          Sign out visitors
                        </button>
                      </span>
                    </div>
                  )}
                </>
              )}

              {drawerTab === "routes" && (
                <>
                  {draft.routes.length === 0 && <p className="faint small-text">No redirects or aliases. Add one to send a path to another origin.</p>}
                  {draft.routes.map((rt, i) => (
                    <div key={i} className="route-row">
                      <Field label={i === 0 ? "Kind" : `Route ${i + 1}`}>
                        <select value={rt.kind} onChange={(e) => patch((d) => { d.routes[i] = { ...d.routes[i], kind: e.target.value }; })}>
                          <option value="redirect">redirect</option>
                          <option value="alias">alias</option>
                        </select>
                      </Field>
                      <Field label="Match">
                        <input placeholder="/old" value={rt.match} onChange={(e) => patch((d) => { d.routes[i] = { ...d.routes[i], match: e.target.value }; })} />
                      </Field>
                      <Field label="Target">
                        <input placeholder="https://example.com/new" value={rt.target} onChange={(e) => patch((d) => { d.routes[i] = { ...d.routes[i], target: e.target.value }; })} />
                      </Field>
                      <button className="ghost" style={{ marginTop: 22 }} aria-label={`Remove route ${i + 1}`} onClick={() => patch((d) => { d.routes.splice(i, 1); })}>
                        <Icon name="trash" size={14} />
                      </button>
                    </div>
                  ))}
                  <button className="small" onClick={() => patch((d) => { d.routes.push({ kind: "redirect", match: "/", target: "", strip_prefix: false, priority: 0 }); })}>
                    <Icon name="plus" size={13} /> Add route
                  </button>
                </>
              )}
            </Drawer>
          )}

          {inspect && (
            <ProxyDetail
              proxy={inspect}
              protection={protections.find((p) => p.id === inspect.protection_profile_id)}
              cert={certs.find((c) => c.id === inspect.cert_id)}
              onEdit={() => {
                setInspect(null);
                openEdit(inspect);
              }}
              onClose={() => setInspect(null)}
            />
          )}

          {confirm && (
            <ConfirmDialog
              title={confirm.kind === "delete" ? `Delete ${confirm.proxy.hostname}?` : `Sign out visitors?`}
              confirmLabel={confirm.kind === "delete" ? "Delete proxy" : "Sign out visitors"}
              busy={confirmBusy}
              onConfirm={runConfirm}
              onClose={() => setConfirm(null)}
            >
              {confirm.kind === "delete"
                ? "This removes the hostname, its routes, upstreams and gate bindings. Certificates and profiles are kept."
                : `Every visitor currently signed in through ${confirm.proxy.hostname} will have to authenticate again.`}
            </ConfirmDialog>
          )}
        </>
      )}
    </div>
  );
}
