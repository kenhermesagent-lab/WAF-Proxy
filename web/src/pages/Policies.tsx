import { useEffect, useRef, useState } from "react";
import type { DragEvent, MouseEvent as ReactMouseEvent } from "react";
import { api } from "../api";
import { bundleMode, hitsByBundle, profileBundleBadges } from "../bundles";
import { COUNTRIES, countryFlag, countryName } from "../countries";
import { confirmDialog, Badge, Card, Empty, Field, Modal, PageHead, errText, fmtAgo } from "../ui";
import { ASNRecommendations, ASNSuggestion, Ban, BundleHit, BundlesSnapshot, GlobalLists, Policy, PolicyPreflight, Profile, Proxy } from "../types";
import AccessLists from "../components/AccessLists";
import AccessProfiles from "../components/AccessProfiles";
import AuthProviders from "../components/AuthProviders";
import BotFilter from "../components/BotFilter";
import ProtectionProfiles from "../components/ProtectionProfiles";

// The console asks for a type and an action; the API stores them as one kind,
// so an allow IP policy and a block IP policy keep their existing rows.
const POLICY_TYPES: Record<string, string> = {
  ip: "IP / Subnet",
  country: "Country",
  asn: "ASN",
  decoy: "Decoy paths (instant ban)",
  rate_limit: "Rate limit (rps/burst)",
};

const KIND_LABELS: Record<string, string> = {
  ip_whitelist: "IP / Subnet",
  ip_blacklist: "IP / Subnet",
  country_whitelist: "Country",
  country_blacklist: "Country",
  asn_block: "ASN",
  decoy: "Decoy paths",
  rate_limit: "Rate limit",
};

function policyKind(type: string, action: string): string {
  if (type === "ip") return action === "allow" ? "ip_whitelist" : "ip_blacklist";
  if (type === "country") return action === "allow" ? "country_whitelist" : "country_blacklist";
  return type;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

const stamp = (iso?: string | null) => (iso ? iso.slice(0, 16).replace("T", " ") : "—");

function listSummary(l: { ips: string; countries: string }): string {
  const ips = l.ips ? l.ips.split(",").filter(Boolean).length : 0;
  const countries = l.countries ? l.countries.split(",").filter(Boolean).length : 0;
  return [ips ? `${ips} IP(s)` : "", countries ? `${countries} country(s)` : ""].filter(Boolean).join(" · ") || "empty";
}

// The full ban list, with both sides side by side so an address can be moved
// between them or lifted outright.
function BanMoveModal({
  bans,
  focus,
  onClose,
  onReload,
  onError,
  onOK,
}: {
  bans: Ban[];
  focus: "temp" | "perm";
  onClose: () => void;
  onReload: () => void;
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [tempSel, setTempSel] = useState<number[]>([]);
  const [permSel, setPermSel] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);
  const temp = bans.filter((b) => !b.permanent);
  const perm = bans.filter((b) => b.permanent);
  // A press-and-drag selects the rows it passes over; Ctrl keeps the rows
  // that were already selected as the base of the range.
  const drag = useRef<{ ids: number[]; from: number; base: number[]; set: (ids: number[]) => void } | null>(null);
  useEffect(() => {
    const stop = () => { drag.current = null; };
    window.addEventListener("mouseup", stop);
    return () => window.removeEventListener("mouseup", stop);
  }, []);

  const act = async (action: "permanent" | "temp" | "remove", ids: number[]) => {
    if (ids.length === 0) return;
    if (action === "remove" && !(await confirmDialog(`Remove ${ids.length} ban(s)?`))) return;
    setBusy(true);
    try {
      const r = await api.post<{ updated: number; skipped: number }>("/api/bans/bulk", { ids, action });
      const done = action === "permanent" ? "moved to permanent" : action === "temp" ? "moved back to temp" : "removed";
      onOK(`${r.updated} ban(s) ${done}${r.skipped ? `, ${r.skipped} skipped` : ""}`);
      setTempSel([]);
      setPermSel([]);
      onReload();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const toggle = (ids: number[], setIds: (ids: number[]) => void, id: number) =>
    setIds(ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]);

  const dropInto = (target: "permanent" | "temp") => (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const id = Number(e.dataTransfer.getData("text/plain"));
    if (!id) return;
    if (target === "permanent") act("permanent", tempSel.includes(id) ? tempSel : [id]);
    else act("temp", permSel.includes(id) ? permSel : [id]);
  };

  const rows = (list: Ban[], selected: number[], setSelected: (ids: number[]) => void) => {
    const all = list.length > 0 && selected.length === list.length;
    const select = (ids: number[]) => setSelected([...new Set(ids)]);
    return (
      <div style={{ maxHeight: 280, overflowY: "auto", border: "1px solid var(--border)", borderRadius: 9, padding: 6 }}>
        {list.length === 0 ? (
          <div className="muted" style={{ fontSize: 12, padding: 6 }}>Empty.</div>
        ) : (
          <>
            <label className="muted" style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 11, padding: "0 4px 6px", cursor: "pointer" }}>
              <input type="checkbox" style={{ width: "auto" }} checked={all} onChange={() => setSelected(all ? [] : list.map((b) => b.id))} />
              {all ? "clear all" : "select all"}
            </label>
            {list.map((b, i) => (
              <div
                key={b.id}
                onMouseDown={(e: ReactMouseEvent) => {
                  if (e.button !== 0 || (e.target as HTMLElement).tagName === "INPUT") return;
                  const base = e.ctrlKey || e.metaKey ? selected : [];
                  drag.current = { ids: list.map((x) => x.id), from: i, base, set: setSelected };
                  select([...base, b.id]);
                }}
                onMouseEnter={() => {
                  const d = drag.current;
                  if (!d || !d.ids.includes(b.id)) return;
                  const lo = Math.min(d.from, i);
                  const hi = Math.max(d.from, i);
                  d.set([...new Set([...d.base, ...d.ids.slice(lo, hi + 1)])]);
                }}
                style={{ display: "flex", gap: 8, alignItems: "center", padding: "3px 4px", borderRadius: 6, userSelect: "none" }}
                title="Ctrl-click to add, or hold and drag down to select a range"
              >
                <input
                  type="checkbox"
                  style={{ width: "auto" }}
                  checked={selected.includes(b.id)}
                  onChange={() => toggle(selected, setSelected, b.id)}
                />
                <span
                  className="mono"
                  draggable
                  onDragStart={(e) => {
                    if (!selected.includes(b.id)) select([b.id]);
                    e.dataTransfer.setData("text/plain", String(b.id));
                  }}
                  style={{ fontSize: 12, cursor: "grab" }}
                  title="Drag the address into the other box"
                >
                  {b.cidr}
                </span>
                <span className="faint" style={{ fontSize: 11, marginLeft: "auto" }}>{stamp(b.created_at)}</span>
              </div>
            ))}
          </>
        )}
      </div>
    );
  };

  return (
    <Modal title="Bans" onClose={onClose}>
      <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
        Drag an address into the other box, tick several (Ctrl-click or hold and drag down), and use the buttons. A
        permanent ban lasts until it is removed; moving one back to temporary gives it 24 hours from now.
      </p>
      <div className="ban-move-grid">
        <div>
          <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>
            Temporary ({temp.length}) {focus === "temp" && <Badge tone="info">current</Badge>}
          </div>
          <div onDragOver={(e) => e.preventDefault()} onDrop={dropInto("temp")}>
            {rows(temp, tempSel, setTempSel)}
          </div>
        </div>
        <div>
          <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>
            Permanent ({perm.length}) {focus === "perm" && <Badge tone="bad">current</Badge>}
          </div>
          <div onDragOver={(e) => e.preventDefault()} onDrop={dropInto("permanent")}>
            {rows(perm, permSel, setPermSel)}
          </div>
        </div>
      </div>
      <div className="row mt" style={{ justifyContent: "flex-end", flexWrap: "wrap" }}>
        <button disabled={busy || tempSel.length === 0} onClick={() => act("permanent", tempSel)}>
          Make permanent ({tempSel.length})
        </button>
        <button disabled={busy || permSel.length === 0} onClick={() => act("temp", permSel)}>
          Move back to temp ({permSel.length})
        </button>
        <button
          className="danger"
          disabled={busy || tempSel.length + permSel.length === 0}
          onClick={() => act("remove", [...tempSel, ...permSel])}
        >
          Remove selected
        </button>
        <button onClick={onClose}>Close</button>
      </div>
    </Modal>
  );
}

export default function Policies({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  // The Threat intel page links straight to the WAF profiles tab after a bundle
  // starts matching, so the operator lands on the switch they need.
  const [tab, setTab] = useState(() => {
    const query = window.location.hash.split("?")[1] ?? "";
    return new URLSearchParams(query).get("tab") ?? "bans";
  });
  const [bundles, setBundles] = useState<BundlesSnapshot | null>(null);
  const [bundleHits, setBundleHits] = useState<BundleHit[]>([]);
  const [bans, setBans] = useState<Ban[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [savingProfile, setSavingProfile] = useState(false);
  const [kernel, setKernel] = useState<{ active: boolean; reason: string } | null>(null);
  const [limited, setLimited] = useState(false);
  const [rolling, setRolling] = useState(false);
  const [banSearch, setBanSearch] = useState("");
  const [banView, setBanView] = useState<"temp" | "perm" | null>(null);
  const [globals, setGlobals] = useState<GlobalLists | null>(null);
  const [asnRecs, setAsnRecs] = useState<ASNRecommendations | null>(null);
  const [addingASN, setAddingASN] = useState("");
  const [check, setCheck] = useState<PolicyPreflight | null>(null);
  const [checking, setChecking] = useState(false);

  const [ban, setBan] = useState({ cidr: "", reason: "", permanent: false, ttl_seconds: 86400 });
  const [pol, setPol] = useState({
    type: "country",
    value: "",
    action: "block",
    scope: "global",
    proxy_id: "",
    note: "",
  });
  const isCountry = pol.type === "country";
  const needsAction = pol.type === "ip" || pol.type === "country";

  const loadGlobals = () =>
    api
      .get<GlobalLists>("/api/global-lists")
      .then(setGlobals)
      .catch(() => undefined);

  const load = () => {
    api
      .get<{ bans: Ban[]; active: number; limited?: boolean; kernel: { active: boolean; reason: string } }>(
        "/api/bans?limit=1000",
      )
      .then((r) => {
        setBans(r.bans || []);
        setLimited(!!r.limited);
        setKernel(r.kernel);
      })
      .catch((e) => onError(errText(e)));
    api.get<Policy[]>("/api/policies").then(setPolicies).catch((e) => onError(errText(e)));
    api.get<Proxy[]>("/api/proxies").then(setProxies).catch(() => undefined);
        api.get<Profile[]>("/api/profiles").then(setProfiles).catch(() => undefined);
    api.get<BundlesSnapshot>("/api/bundles").then(setBundles).catch(() => undefined);
    api
      .get<{ hours: number; rules: BundleHit[] }>("/api/bundles/hits?hours=24")
      .then((r) => setBundleHits(r.rules || []))
      .catch(() => undefined);
    api.get<ASNRecommendations>("/api/asn-recommendations").then(setAsnRecs).catch(() => undefined);
    loadGlobals();
  };

  useEffect(() => {
    load();
  }, []);

  const addBan = async () => {
    try {
      await api.post("/api/bans", ban);
      setBan({ cidr: "", reason: "", permanent: false, ttl_seconds: 86400 });
      onOK("Ban applied");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const removeBan = async (b: Ban) => {
    if (!(await confirmDialog(`Unban ${b.cidr}?`))) return;
    try {
      await api.del(`/api/bans/${b.id}`);
      onOK("Ban removed");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const promote = async (b: Ban) => {
    try {
      await api.post(`/api/bans/${b.id}/promote`);
      onOK("Ban promoted to permanent");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const demote = async (b: Ban) => {
    try {
      await api.post("/api/bans/bulk", { ids: [b.id], action: "temp" });
      onOK("Ban moved back to temporary (24 hours)");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  // Permanent bans can be folded into one local threat list so this table does
  // not grow for the life of the install.
  const permBans = bans.filter((b) => b.permanent);
  const tempBans = bans.filter((b) => !b.permanent);

  const rollup = async () => {
    if (!(await confirmDialog(`Move ${permBans.length} permanent ban(s) into the local threat list? They leave this table and stay blocked through the list.`))) return;
    setRolling(true);
    try {
      const r = await api.post<{ rolled_up: number; path: string }>("/api/bans/rollup");
      onOK(`${r.rolled_up} ban(s) rolled into ${r.path}`);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setRolling(false);
    }
  };

  // Preflight answers "what would this rule have done to the traffic we already
  // have?" before anything is saved, using the server's own matchers.
  const preflight = async () => {
    setChecking(true);
    try {
      setCheck(
        await api.post<PolicyPreflight>("/api/policies/preflight", {
          kind: policyKind(pol.type, pol.action),
          value: pol.value,
          scope: pol.scope,
          proxy_id: pol.scope === "proxy" && pol.proxy_id ? Number(pol.proxy_id) : null,
          hours: 24,
        }),
      );
    } catch (e) {
      setCheck(null);
      onError(errText(e));
    } finally {
      setChecking(false);
    }
  };

  const addPolicy = async () => {
    try {
      await api.post("/api/policies", {
        kind: policyKind(pol.type, pol.action),
        value: pol.value,
        scope: pol.scope,
        proxy_id: pol.scope === "proxy" && pol.proxy_id ? Number(pol.proxy_id) : null,
        note: pol.note,
        action: pol.action,
        enabled: true,
      });
      setPol({ ...pol, value: "", note: "" });
      setCheck(null);
      onOK("Policy added");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const toggleGlobal = async (kind: "whitelist" | "blocklist", id: number) => {
    if (!globals) return;
    const key = kind === "whitelist" ? "whitelist_ids" : "blocklist_ids";
    const current = globals[key];
    const next = current.includes(id) ? current.filter((x) => x !== id) : [...current, id];
    try {
      const r = await api.put<{ whitelist_ids: number[]; blocklist_ids: number[] }>("/api/global-lists", {
        whitelist_ids: kind === "whitelist" ? next : globals.whitelist_ids,
        blocklist_ids: kind === "blocklist" ? next : globals.blocklist_ids,
      });
      setGlobals({ ...globals, ...r });
      onOK("Global profiles saved");
    } catch (e) {
      onError(errText(e));
    }
  };

  const addASN = async (suggestion: ASNSuggestion) => {
    setAddingASN(suggestion.id);
    try {
      await api.post("/api/policies", {
        kind: "asn_block",
        value: suggestion.asns.join(","),
        scope: "global",
        action: "block",
        note: suggestion.name,
        enabled: true,
      });
      onOK(`${suggestion.name} ASNs blocked`);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setAddingASN("");
    }
  };

  const togglePolicy = async (p: Policy) => {
    try {
      await api.put(`/api/policies/${p.id}`, { ...p, enabled: !p.enabled });
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const removePolicy = async (p: Policy) => {
    if (!(await confirmDialog("Delete this policy?"))) return;
    try {
      await api.del(`/api/policies/${p.id}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const saveProfile = async () => {
    if (!profile) return;
    setSavingProfile(true);
    try {
      if (profile.id === 0) {
        await api.post("/api/profiles", profile);
        onOK(`${profile.name} profile created`);
      } else {
        await api.put(`/api/profiles/${profile.id}`, profile);
        onOK(`${profile.name} profile saved`);
      }
      setProfile(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSavingProfile(false);
    }
  };

  const removeProfile = async (p: Profile) => {
    if (!(await confirmDialog(`Delete the ${p.name} profile?`))) return;
    try {
      await api.del(`/api/profiles/${p.id}`);
      onOK("Profile deleted");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const newProfile = (): Profile => ({
    id: 0,
    name: "",
    builtin: false,
    mode: "block",
    responses: "off",
    paranoia: 1,
    anomaly: 5,
    allowed_methods: "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
    max_body: 131072,
    exceptions: "",
    max_response: 0,
    login_paths: "",
    login_rps: 0,
    login_burst: 0,
    admin_paths: "",
    admin_ips: "",
    bundle_modes: {},
  });

  const needle = banSearch.trim().toLowerCase();
  const matches = needle
    ? bans.filter((b) => b.cidr.toLowerCase().includes(needle) || b.reason.toLowerCase().includes(needle))
    : [];
  const installedBundles = bundles?.bundles ?? [];
  const installedNames = installedBundles.map((b) => b.name);
  const hitTotals = hitsByBundle(bundleHits);
  const hitsFor = (name: string) => hitTotals[name] ?? 0;
  const whitelists = globals?.lists.filter((l) => l.kind === "whitelist") ?? [];
  const blocklists = globals?.lists.filter((l) => l.kind === "blocklist") ?? [];
  const valuePlaceholder =
    pol.type === "ip"
      ? "203.0.113.7 or 198.51.100.0/24"
      : pol.type === "asn"
        ? "16509, 8075"
        : pol.type === "decoy"
          ? "/.env, /wp-login.php"
          : pol.type === "rate_limit"
            ? "40/80"
            : "Select a country…";

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead sub="Bans, WAF profiles and the lists applied before traffic reaches a proxy." />
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div className="tabs" style={{ marginBottom: 0, borderBottom: 0 }}>
          <button className={`tab ${tab === "bans" ? "active" : ""}`} onClick={() => setTab("bans")}>Bans</button>
          <button className={`tab ${tab === "global" ? "active" : ""}`} onClick={() => setTab("global")}>Global Profile</button>
          <button className={`tab ${tab === "profiles" ? "active" : ""}`} onClick={() => setTab("profiles")}>WAF profiles</button>
          <button className={`tab ${tab === "protection" ? "active" : ""}`} onClick={() => setTab("protection")}>Protection profiles</button>
          <button className={`tab ${tab === "blocklists" ? "active" : ""}`} onClick={() => setTab("blocklists")}>Blocklist profiles</button>
          <button className={`tab ${tab === "whitelists" ? "active" : ""}`} onClick={() => setTab("whitelists")}>Whitelist profiles</button>
          <button className={`tab ${tab === "access" ? "active" : ""}`} onClick={() => setTab("access")}>Access profiles</button>
          <button className={`tab ${tab === "providers" ? "active" : ""}`} onClick={() => setTab("providers")}>Identity providers</button>
          <button className={`tab ${tab === "bots" ? "active" : ""}`} onClick={() => setTab("bots")}>Bot filter</button>
        </div>
        {kernel && (
          <span
            className={`badge wrap ${kernel.active ? "ok" : "warn"}`}
            style={{ marginLeft: "auto", minWidth: 0 }}
            title={kernel.active ? undefined : kernel.reason}
          >
            {kernel.active ? "Kernel bans active" : "Kernel bans off"}
          </span>
        )}
      </div>

      {tab === "bans" && (
        <>
          <Card title="Search bans">
            <div className="row grow">
              <Field label="IP, subnet or reason">
                <input
                  value={banSearch}
                  onChange={(e) => setBanSearch(e.target.value)}
                  placeholder="203.0.113.7"
                  autoComplete="off"
                />
              </Field>
            </div>
            {needle === "" ? (
              <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
                Search both lists at once. A match can be removed here, or moved between temporary and permanent.
              </p>
            ) : matches.length === 0 ? (
              <Empty>No ban matches “{banSearch.trim()}”.</Empty>
            ) : (
              <div style={{ overflowX: "auto" }}>
              <div className="table-wrap"><table>
                <thead><tr><th>IP / CIDR</th><th>List</th><th>Reason</th><th>Created</th><th /></tr></thead>
                <tbody>
                  {matches.map((b) => (
                    <tr key={b.id}>
                      <td className="mono">{b.cidr}</td>
                      <td><Badge tone={b.permanent ? "bad" : "warn"}>{b.permanent ? "permanent" : "temporary"}</Badge></td>
                      <td>{b.reason}</td>
                      <td className="muted">{fmtAgo(b.created_at)}</td>
                      <td className="right" style={{ whiteSpace: "nowrap" }}>
                        {b.permanent
                          ? <button className="small" onClick={() => demote(b)}>Move to temp</button>
                          : <button className="small" onClick={() => promote(b)}>Make permanent</button>}{" "}
                        <button className="small danger" onClick={() => removeBan(b)}>Remove</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
              </div>
            )}
          </Card>

          <Card title="New ban">
            <div className="row grow">
              <Field label="IP or CIDR">
                <input value={ban.cidr} onChange={(e) => setBan({ ...ban, cidr: e.target.value })} placeholder="203.0.113.7" />
              </Field>
              <Field label="Reason (required)">
                <input value={ban.reason} onChange={(e) => setBan({ ...ban, reason: e.target.value })} placeholder="port scan" />
              </Field>
              <Field label="Duration">
                <input value={ban.permanent ? "Until removed" : "24 hours"} readOnly disabled />
              </Field>
              <label style={{ margin: "18px 0 0", display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
                <input type="checkbox" style={{ width: "auto" }} checked={ban.permanent} onChange={(e) => setBan({ ...ban, permanent: e.target.checked })} /> permanent
              </label>
              <button className="primary" style={{ marginTop: 18 }} onClick={addBan}>Ban</button>
            </div>
          </Card>

          <Card
            title={`Temp bans (${tempBans.length})`}
            actions={<button className="small" onClick={() => setBanView("temp")}>View all / move</button>}
          >
            {tempBans.length === 0 ? (
              <Empty>No temporary bans. Decoy hits and repeated failures add themselves here.</Empty>
            ) : (
              <>
                <p className="muted" style={{ fontSize: 12 }}>
                  Temporary bans last 24 hours and are deleted when they expire; the newest 10 are shown here.
                  {limited && " The list is capped at 1000 rows."}
                </p>
                <div style={{ overflowX: "auto" }}>
                <div className="table-wrap"><table>
                  <thead><tr><th>IP / CIDR</th><th>Reason</th><th>Source</th><th className="num">Hits</th><th>Created</th><th>Expires</th><th /></tr></thead>
                  <tbody>
                    {tempBans.slice(0, 10).map((b) => (
                      <tr key={b.id}>
                        <td className="mono">{b.cidr}</td>
                        <td>{b.reason}</td>
                        <td><Badge tone={b.source === "decoy" || b.source === "crowdsec" ? "bad" : "info"}>{b.source}</Badge></td>
                        <td className="num">{b.hits}</td>
                        <td className="muted">{fmtAgo(b.created_at)}</td>
                        <td className="muted">{fmtAgo(b.expires_at)}</td>
                        <td className="right" style={{ whiteSpace: "nowrap" }}>
                          <button className="small" onClick={() => promote(b)}>Make permanent</button>{" "}
                          <button className="small danger" onClick={() => removeBan(b)}>Unban</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table></div>
                </div>
              </>
            )}
          </Card>

          <Card
            title={`Permanent bans (${permBans.length})`}
            actions={
              <div className="row">
                <button className="small" onClick={() => setBanView("perm")}>View all / move</button>
                <button className="small" disabled={rolling || permBans.length === 0} onClick={rollup}>
                  {rolling ? "Rolling up…" : "Roll up into a local threat list"}
                </button>
              </div>
            }
          >
            {permBans.length === 0 ? (
              <Empty>No permanent bans.</Empty>
            ) : (
              <>
                <p className="muted" style={{ fontSize: 12 }}>Permanent bans stay until removed; the newest 10 are shown here.</p>
                <div style={{ overflowX: "auto" }}>
                <div className="table-wrap"><table>
                  <thead><tr><th>IP / CIDR</th><th>Reason</th><th>Source</th><th>Created by</th><th className="num">Hits</th><th /></tr></thead>
                  <tbody>
                    {permBans.slice(0, 10).map((b) => (
                      <tr key={b.id}>
                        <td className="mono">{b.cidr}</td>
                        <td>{b.reason}</td>
                        <td className="muted">{b.source}</td>
                        <td className="muted">{b.created_by || "system"}</td>
                        <td className="num">{b.hits}</td>
                        <td className="right" style={{ whiteSpace: "nowrap" }}>
                          <button className="small" onClick={() => demote(b)}>Move to temp</button>{" "}
                          <button className="small danger" onClick={() => removeBan(b)}>Remove</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table></div>
                </div>
              </>
            )}
          </Card>
        </>
      )}

      {tab === "profiles" && (
        <Card
          title="CRS protection profiles"
          actions={<button className="small primary" onClick={() => setProfile(newProfile())}>New profile</button>}
        >
          {profiles.length === 0 ? <Empty>No profiles available.</Empty> : (
            <div style={{ overflowX: "auto" }}>
              <div className="table-wrap"><table>
                <thead>
                  <tr><th>Profile</th><th>Mode</th><th className="num">Paranoia</th><th className="num">Anomaly</th><th>Methods</th><th className="num">Max body</th><th>Bundles</th><th /></tr>
                </thead>
                <tbody>
                  {profiles.map((p) => (
                    <tr key={p.id}>
                      <td style={{ whiteSpace: "nowrap" }}>
                        {p.name}
                        {p.exceptions ? <div className="faint" style={{ fontSize: 11 }}>{p.exceptions.split(",").filter(Boolean).length} rule exception(s)</div> : null}
                        {(p.login_rps > 0 || p.max_response > 0 || (p.admin_paths && p.admin_ips)) && (
                          <div className="faint" style={{ fontSize: 11 }}>
                            {[
                              p.login_rps > 0 ? `logins ${p.login_rps}/s` : "",
                              p.max_response > 0 ? `responses ${Math.round(p.max_response / 1024)} KiB` : "",
                              p.admin_paths && p.admin_ips ? "admin paths" : "",
                            ].filter(Boolean).join(" · ")}
                          </div>
                        )}
                      </td>
                      <td><Badge tone={p.mode === "block" ? "ok" : p.mode === "detect" ? "info" : "warn"}>{p.mode}</Badge></td>
                      <td className="num">{p.paranoia}</td>
                      <td className="num">{p.anomaly}</td>
                      <td className="muted mono" style={{ fontSize: 12, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={p.allowed_methods}>{p.allowed_methods}</td>
                      <td className="num">{p.max_body.toLocaleString()}</td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          {profileBundleBadges(p, installedNames).map((m) => <Badge key={m.label} tone={m.tone}>{m.label}</Badge>)}
                          {installedNames.length === 0 ? <span className="faint">—</span> : null}
                        </div>
                      </td>
                      <td className="right" style={{ whiteSpace: "nowrap" }}>
                        <button className="small" onClick={() => setProfile({ ...p })}>Edit</button>{" "}
                        {!p.builtin && <button className="small danger" onClick={() => removeProfile(p)}>Delete</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            </div>
          )}
          <p className="muted" style={{ fontSize: 12 }}>
            A proxy with WAF mode <code>inherit</code> uses its selected profile. Paranoia 1 is the CRS default and
            3–4 is strict enough to block some legitimate applications. Rule exceptions remove an OWASP CRS rule ID
            for this profile only. Changes reload the WAF without dropping connections.
          </p>
        </Card>
      )}

      {tab === "protection" && <ProtectionProfiles onError={onError} onOK={onOK} />}

      {tab === "blocklists" && <AccessLists kind="blocklist" onError={onError} onOK={onOK} />}
      {tab === "whitelists" && <AccessLists kind="whitelist" onError={onError} onOK={onOK} />}
      {tab === "access" && <AccessProfiles policies={policies} onError={onError} onOK={onOK} />}
      {tab === "providers" && <AuthProviders onError={onError} onOK={onOK} />}
      {tab === "bots" && <BotFilter onError={onError} onOK={onOK} />}

      {tab === "global" && (
        <>
          <Card title="Add policy">
            <div className="row grow">
              <Field label="Type">
                <select
                  value={pol.type}
                  onChange={(e) => {
                    const type = e.target.value;
                    setPol({ ...pol, type, value: "", action: type === "ip" || type === "country" ? "block" : pol.action });
                  }}
                >
                  {Object.entries(POLICY_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
              </Field>
              <Field label={isCountry ? "Country" : pol.type === "ip" ? "IP or subnet" : pol.type === "asn" ? "ASN numbers" : pol.type === "decoy" ? "Paths" : "Requests per second / burst"}>
                {isCountry ? (
                  <select value={pol.value} onChange={(e) => setPol({ ...pol, value: e.target.value })}>
                    <option value="">Select a country…</option>
                    {COUNTRIES.map((c) => (
                      <option key={c.code} value={c.code}>{countryFlag(c.code)} {c.name} ({c.code})</option>
                    ))}
                  </select>
                ) : (
                  <input
                    value={pol.value}
                    onChange={(e) => setPol({ ...pol, value: e.target.value })}
                    placeholder={valuePlaceholder}
                  />
                )}
              </Field>
              {needsAction && (
                <Field label="Action">
                  <select value={pol.action} onChange={(e) => setPol({ ...pol, action: e.target.value })}>
                    <option value="allow">Allow</option>
                    <option value="block">Block</option>
                  </select>
                </Field>
              )}
              <Field label="Scope">
                <select value={pol.scope} onChange={(e) => setPol({ ...pol, scope: e.target.value })}>
                  <option value="global">Global — every proxy</option>
                  <option value="proxy">One proxy</option>
                </select>
              </Field>
              {pol.scope === "proxy" && (
                <Field label="Proxy">
                  <select value={pol.proxy_id} onChange={(e) => setPol({ ...pol, proxy_id: e.target.value })}>
                    <option value="">Select…</option>
                    {proxies.map((p) => <option key={p.id} value={p.id}>{p.hostname}</option>)}
                  </select>
                </Field>
              )}
              <button style={{ marginTop: 18 }} onClick={preflight} disabled={checking || !pol.value.trim() || (pol.scope === "proxy" && !pol.proxy_id)}>
                {checking ? "Checking…" : "Preflight"}
              </button>
              <button className="primary" style={{ marginTop: 18 }} onClick={addPolicy}>Add</button>
            </div>
            {check && check.kind === policyKind(pol.type, pol.action) && check.value === pol.value && (
              <div className="grid" style={{ gap: 8, marginTop: 4 }}>
                <div className={`banner ${check.matched === 0 ? "" : pol.action === "allow" ? "warn" : "bad"}`.trim()} role="status">
                  <span>
                    {check.matched === 0
                      ? `No requests in the last ${check.hours}h match this rule. It would change nothing on this traffic.`
                      : `${plural(check.matched, "request")} from ${plural(check.addresses, "address", "addresses")} match; ${
                          pol.action === "allow"
                            ? `${check.blocked.toLocaleString()} ${check.blocked === 1 ? "is" : "are"} refused today and would be allowed.`
                            : `${check.allowed.toLocaleString()} ${check.allowed === 1 ? "is" : "are"} served today and would be refused.`
                        }`}
                  </span>
                </div>
                {check.notes.map((n) => (
                  <div className="faint small-text" key={n}>{n}</div>
                ))}
                {check.samples.length > 0 && (
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>When</th><th>Source</th><th>Host</th><th>Request</th><th>Stage</th><th>Now</th></tr></thead>
                      <tbody>
                        {check.samples.map((s, i) => (
                          <tr key={`${s.ts}-${i}`}>
                            <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtAgo(s.ts)}</td>
                            <td className="mono">{s.src_ip}</td>
                            <td className="muted">{s.host}</td>
                            <td className="mono" title={`${s.method} ${s.path}`} style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.method} {s.path}</td>
                            <td><Badge tone={s.action === "allow" ? "" : "bad"}>{s.stage || "—"}</Badge></td>
                            <td className="muted">{s.action}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
            <p className="muted" style={{ fontSize: 12 }}>
              <strong>IP / Subnet</strong> takes one address or a whole CIDR and allows or blocks it on every proxy
              unless one proxy is chosen. Country lists are ISO-3166 alpha-2; a country allow list is exclusive, so
              traffic from every other country is refused (an explicit IP allow still wins). ASNs block entire
              networks. Decoy paths trigger an instant permanent ban, so only list paths no legitimate visitor
              requests. Rate limits use <code>requests-per-second/burst</code>.
            </p>
          </Card>

          <Card title="Policies">
            {policies.length === 0 ? <Empty>No policies yet.</Empty> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Type</th><th>Value</th><th>Effect</th><th>Scope</th><th>State</th><th /></tr></thead>
                <tbody>
                  {policies.map((p) => {
                    const allow = p.kind === "country_whitelist" || p.kind === "ip_whitelist" || p.action === "allow";
                    return (
                      <tr key={p.id}>
                        <td>{KIND_LABELS[p.kind] ?? p.kind}</td>
                        <td className="mono">
                          {p.kind === "country_whitelist" || p.kind === "country_blacklist"
                            ? `${countryFlag(p.value)} ${countryName(p.value)} (${p.value})`
                            : p.value}
                        </td>
                        <td><Badge tone={allow ? "ok" : "bad"}>{allow ? "allow" : "block"}</Badge></td>
                        <td className="muted">{p.scope === "proxy" ? proxies.find((x) => x.id === p.proxy_id)?.hostname ?? `#${p.proxy_id}` : "global"}</td>
                        <td>{p.enabled ? <Badge tone="ok">on</Badge> : <Badge tone="warn">off</Badge>}</td>
                        <td className="right" style={{ whiteSpace: "nowrap" }}>
                          <button className="small" onClick={() => togglePolicy(p)}>{p.enabled ? "Disable" : "Enable"}</button>{" "}
                          <button className="small danger" onClick={() => removePolicy(p)}>Delete</button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table></div>
            )}
          </Card>

          <Card title="Global profiles">
            {!globals ? <Empty>Loading…</Empty> : (
              <>
                <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
                  Checked profiles apply to every proxy, including hosts added later. A whitelist is checked before
                  the blocklists, so an address on both is allowed. A host's own access-profile lists still apply to
                  that host and win over these.
                </p>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                  <div>
                    <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>Whitelist profiles</div>
                    {whitelists.length === 0 ? (
                      <Empty>No whitelist profiles yet.</Empty>
                    ) : (
                      whitelists.map((l) => (
                        <label
                          key={l.id}
                          style={{ display: "flex", gap: 8, alignItems: "center", margin: "6px 0", textTransform: "none", letterSpacing: 0 }}
                        >
                          <input
                            type="checkbox"
                            style={{ width: "auto" }}
                            checked={globals.whitelist_ids.includes(l.id)}
                            onChange={() => toggleGlobal("whitelist", l.id)}
                          />
                          <span>{l.name}</span>
                          <span className="faint" style={{ fontSize: 11 }}>{listSummary(l)}</span>
                        </label>
                      ))
                    )}
                  </div>
                  <div>
                    <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>Blocklist profiles</div>
                    {blocklists.length === 0 ? (
                      <Empty>No blocklist profiles yet.</Empty>
                    ) : (
                      blocklists.map((l) => (
                        <label
                          key={l.id}
                          style={{ display: "flex", gap: 8, alignItems: "center", margin: "6px 0", textTransform: "none", letterSpacing: 0 }}
                        >
                          <input
                            type="checkbox"
                            style={{ width: "auto" }}
                            checked={globals.blocklist_ids.includes(l.id)}
                            onChange={() => toggleGlobal("blocklist", l.id)}
                          />
                          <span>{l.name}</span>
                          <span className="faint" style={{ fontSize: 11 }}>{listSummary(l)}</span>
                        </label>
                      ))
                    )}
                  </div>
                </div>
              </>
            )}
          </Card>

          <Card title="ASN recommendations">
            {!asnRecs ? <Empty>Loading…</Empty> : (
              <>
                <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
                  Starting points for blocking whole networks, added as ordinary editable ASN policies. Verify
                  before enabling: providers move between networks, and blocking a hosting ASN also blocks any
                  legitimate site hosted there.
                </p>
                <div className="table-wrap"><table>
                  <thead><tr><th>Network</th><th>ASNs</th><th /></tr></thead>
                  <tbody>
                    {[asnRecs.hosting, ...asnRecs.vpn].map((s) => (
                      <tr key={s.id}>
                        <td>
                          {s.name}
                          <div className="faint" style={{ fontSize: 11 }}>{s.note}</div>
                        </td>
                        <td className="mono" style={{ fontSize: 12, overflowWrap: "anywhere" }}>{s.asns.join(", ")}</td>
                        <td className="right" style={{ whiteSpace: "nowrap" }}>
                          <button className="small" disabled={addingASN !== ""} onClick={() => addASN(s)}>
                            {addingASN === s.id ? "Adding…" : "Block"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table></div>
              </>
            )}
          </Card>
        </>
      )}

      {profile && (
        <Modal title={profile.id === 0 ? "New CRS profile" : `Edit ${profile.name}`} onClose={() => setProfile(null)}>
          {profile.id === 0 && (
            <Field label="Profile name">
              <input
                value={profile.name}
                onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                placeholder="WordPress (this site)"
              />
            </Field>
          )}
          <div className="row grow">
            <Field label="Mode">
              <select value={profile.mode} onChange={(e) => setProfile({ ...profile, mode: e.target.value })}>
                <option value="block">Block</option>
                <option value="detect">Detect only</option>
                <option value="off">Off</option>
              </select>
            </Field>
            <Field label="Upstream responses">
              <select value={profile.responses || "off"} onChange={(e) => setProfile({ ...profile, responses: e.target.value })}>
                <option value="off">Off</option>
                <option value="flag">Flag only</option>
                <option value="block">Block</option>
              </select>
            </Field>
            <Field label="Paranoia level (1–4)">
              <input
                type="number"
                min={1}
                max={4}
                value={profile.paranoia}
                onChange={(e) => setProfile({ ...profile, paranoia: Number(e.target.value) })}
              />
            </Field>
            <Field label="Anomaly threshold">
              <input
                type="number"
                min={1}
                max={100}
                value={profile.anomaly}
                onChange={(e) => setProfile({ ...profile, anomaly: Number(e.target.value) })}
              />
            </Field>
          </div>
          <Field label="Allowed HTTP methods (comma separated)">
            <input
              value={profile.allowed_methods}
              onChange={(e) => setProfile({ ...profile, allowed_methods: e.target.value })}
              placeholder="GET,HEAD,POST"
            />
          </Field>
          <Field label="Maximum inspected body (bytes)">
            <input
              type="number"
              min={1024}
              max={8388608}
              value={profile.max_body}
              onChange={(e) => setProfile({ ...profile, max_body: Number(e.target.value) })}
            />
          </Field>
          <Field label="Disabled CRS rule IDs (comma separated, e.g. 942100,930120)">
            <textarea
              value={profile.exceptions}
              onChange={(e) => setProfile({ ...profile, exceptions: e.target.value })}
              placeholder="only the rules this application needs removed"
            />
          </Field>
          {installedBundles.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <label>Signature bundle rules</label>
              <p className="faint" style={{ fontSize: 11, marginTop: 0, lineHeight: 1.55 }}>
                CRS rules keep following Mode above. Each bundle picks its own action on this profile; a bundle with no
                choice here logs only. Blocking refuses the match with the profile's normal refusal page.
              </p>
              {installedBundles.map((b) => (
                <div
                  key={b.name}
                  className="row"
                  style={{ justifyContent: "space-between", padding: "7px 0", borderTop: "1px solid var(--border-soft)" }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div>
                      {b.name}{" "}
                      {hitsFor(b.name) > 0 ? (
                        <span className="faint" style={{ fontSize: 11 }}>{hitsFor(b.name).toLocaleString()} hits / 24h</span>
                      ) : null}
                    </div>
                    <div className="faint mono" style={{ fontSize: 11 }}>
                      {b.version} · {b.rules} {b.rules === 1 ? "rule" : "rules"}
                    </div>
                  </div>
                  <select
                    aria-label={`Bundle ${b.name} mode`}
                    style={{ width: 132 }}
                    value={bundleMode(profile.bundle_modes, b.name)}
                    onChange={(e) =>
                      setProfile({
                        ...profile,
                        bundle_modes: { ...(profile.bundle_modes ?? {}), [b.name]: e.target.value },
                      })
                    }
                  >
                    <option value="off">Off</option>
                    <option value="log">Log only</option>
                    <option value="block">Block</option>
                  </select>
                </div>
              ))}
            </div>
          )}
          <div className="row grow">
            <Field label="Upstream response ceiling (bytes, 0 = unlimited)">
              <input
                type="number"
                min={0}
                value={profile.max_response}
                onChange={(e) => setProfile({ ...profile, max_response: Number(e.target.value) })}
              />
            </Field>
            <Field label="Login paths (comma separated)">
              <input
                value={profile.login_paths}
                onChange={(e) => setProfile({ ...profile, login_paths: e.target.value })}
                placeholder="/login,/api/session"
              />
            </Field>
          </div>
          <div className="row grow">
            <Field label="Login rate (requests/second)">
              <input
                type="number"
                min={0}
                value={profile.login_rps}
                onChange={(e) => setProfile({ ...profile, login_rps: Number(e.target.value) })}
              />
            </Field>
            <Field label="Login burst">
              <input
                type="number"
                min={0}
                value={profile.login_burst}
                onChange={(e) => setProfile({ ...profile, login_burst: Number(e.target.value) })}
              />
            </Field>
          </div>
          <div className="row grow">
            <Field label="Admin paths (comma separated)">
              <input
                value={profile.admin_paths}
                onChange={(e) => setProfile({ ...profile, admin_paths: e.target.value })}
                placeholder="/admin,/settings"
              />
            </Field>
            <Field label="Admin allowlist (CIDRs; empty leaves the rule off)">
              <input
                value={profile.admin_ips}
                onChange={(e) => setProfile({ ...profile, admin_ips: e.target.value })}
                placeholder="192.168.0.0/16"
              />
            </Field>
          </div>
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setProfile(null)}>Cancel</button>
            <button className="primary" onClick={saveProfile} disabled={savingProfile || profile.name.trim() === ""}>
              {savingProfile ? "Saving…" : profile.id === 0 ? "Create profile" : "Save profile"}
            </button>
          </div>
        </Modal>
      )}

      {banView && (
        <BanMoveModal
          bans={bans}
          focus={banView}
          onClose={() => setBanView(null)}
          onReload={load}
          onError={onError}
          onOK={onOK}
        />
      )}
    </div>
  );
}
