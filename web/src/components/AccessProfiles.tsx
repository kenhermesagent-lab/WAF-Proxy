import { useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, Field, Modal, errText } from "../ui";
import type { AccessList, AccessProfile, AccessRule, Policy, Profile, ProtectionProfile } from "../types";

const entries = (v: string) => (v ? v.split(",").filter(Boolean).length : 0);
const countLabel = (n: number) => (n === 1 ? "1 entry" : `${n} entries`);

const KIND_LABELS: Record<string, string> = {
  ip_whitelist: "IP / CIDR list",
  ip_blacklist: "IP / CIDR list",
  country_whitelist: "Country list",
  country_blacklist: "Country list",
  asn_block: "ASN list",
  decoy: "Decoy path",
  rate_limit: "Rate limit",
};

const ROLE_LABELS: Record<AccessRule["role"], string> = {
  allow: "Allow only these",
  deny: "Block these",
  inherit: "Use the list's own type",
};

export default function AccessProfiles({
  policies,
  onError,
  onOK,
}: {
  policies: Policy[];
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [list, setList] = useState<AccessProfile[]>([]);
  const [wafProfiles, setWafProfiles] = useState<Profile[]>([]);
  const [lists, setLists] = useState<AccessList[]>([]);
  const [protections, setProtections] = useState<ProtectionProfile[]>([]);
  const [draft, setDraft] = useState<AccessProfile | null>(null);
  const [saving, setSaving] = useState(false);

  const load = () =>
    Promise.all([
      api.get<AccessProfile[]>("/api/access-profiles"),
      api.get<Profile[]>("/api/profiles"),
      api.get<ProtectionProfile[]>("/api/protection-profiles"),
      api.get<AccessList[]>("/api/lists"),
    ])
      .then(([a, w, p, l]) => {
        setList(a);
        setWafProfiles(w);
        setProtections(p);
        setLists(l);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      if (draft.id === 0) await api.post("/api/access-profiles", draft);
      else await api.put(`/api/access-profiles/${draft.id}`, draft);
      onOK(draft.id === 0 ? "Access profile created" : `${draft.name} saved`);
      setDraft(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (a: AccessProfile) => {
    if (!(await confirmDialog(`Delete the ${a.name} profile? The lists and protection profiles themselves stay.`))) return;
    try {
      await api.del(`/api/access-profiles/${a.id}`);
      onOK("Access profile deleted");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  // A profile stored by an older build can carry no rules at all; treat that as
  // an empty list instead of failing the render.
  const rulesOf = (a: AccessProfile) => a.rules ?? [];

  const ruleFor = (a: AccessProfile, id: number) => rulesOf(a).find((r) => r.policy_id === id);

  const setRole = (id: number, role: AccessRule["role"]) => {
    if (!draft) return;
    const current = rulesOf(draft);
    const exists = current.some((r) => r.policy_id === id);
    const rules = exists
      ? current.map((r) => (r.policy_id === id ? { ...r, role } : r))
      : [...current, { policy_id: id, role }];
    setDraft({ ...draft, rules });
  };

  const clear = (id: number) => {
    if (!draft) return;
    setDraft({ ...draft, rules: rulesOf(draft).filter((r) => r.policy_id !== id) });
  };

  const describe = (a: AccessProfile) =>
    rulesOf(a)
      .map((r) => {
        const p = policies.find((x) => x.id === r.policy_id);
        if (!p) return null;
        const role = r.role === "allow" ? "allow" : r.role === "deny" ? "block" : "list";
        return `${role}: ${KIND_LABELS[p.kind] ?? p.kind} ${p.value}`;
      })
      .filter(Boolean)
      .join(" · ");

  const namesOf = (a: AccessProfile) =>
    (a.list_ids ?? [])
      .map((id) => lists.find((l) => l.id === id))
      .filter(Boolean)
      .map((l) => `${l!.kind === "blocklist" ? "block" : "allow"}: ${l!.name}`)
      .join(" · ");

  const toggleList = (id: number) => {
    if (!draft) return;
    const ids = draft.list_ids ?? [];
    setDraft({ ...draft, list_ids: ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id] });
  };

  const toggleWAFSkip = (id: number) => {
    if (!draft) return;
    const ids = draft.waf_skip_list_ids ?? [];
    setDraft({ ...draft, waf_skip_list_ids: ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id] });
  };

  const wafSkipNames = (a: AccessProfile) =>
    (a.waf_skip_list_ids ?? [])
      .map((id) => lists.find((l) => l.id === id)?.name)
      .filter(Boolean)
      .join(" · ");

  const wafName = (id: number | null) => wafProfiles.find((p) => p.id === id)?.name;
  const protectionName = (id: number | null) => protections.find((p) => p.id === id)?.name;

  return (
    <Card
      title="Access profiles"
      actions={
        <button
          className="small primary"
          onClick={() => setDraft({ id: 0, name: "", rules: [], list_ids: [], waf_profile_id: null, protection_profile_id: null, waf_skip_list_ids: [] })}
        >
          New profile
        </button>
      }
    >
      {list.length === 0 ? (
        <Empty>
          No access profiles. One profile holds the lists and protections for a site, so creating a proxy host means
          choosing a single thing.
        </Empty>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <div className="table-wrap"><table>
            <thead>
              <tr><th>Profile</th><th>Lists</th><th>Block/allow lists</th><th>Protection</th><th>WAF skip</th><th /></tr>
            </thead>
            <tbody>
              {list.map((a) => {
                const missing = rulesOf(a).filter((r) => !policies.some((p) => p.id === r.policy_id)).length;
                return (
                  <tr key={a.id}>
                    <td style={{ whiteSpace: "nowrap" }}>{a.name}</td>
                    <td className="muted" style={{ fontSize: 12 }}>
                      {describe(a) || "no lists"}
                      {missing > 0 && <> <Badge tone="warn">{missing} deleted list(s)</Badge></>}
                    </td>
                    <td className="muted" style={{ fontSize: 12 }}>
                      {namesOf(a)}
                    </td>
                    <td className="muted" style={{ fontSize: 12 }}>
                      {[wafName(a.waf_profile_id), protectionName(a.protection_profile_id)].filter(Boolean).join(" · ") || "none"}
                    </td>
                    <td className="muted" style={{ fontSize: 12 }}>
                      {wafSkipNames(a) || "none"}
                    </td>
                    <td className="right" style={{ whiteSpace: "nowrap" }}>
                      <button className="small" onClick={() => setDraft({ ...a })}>Edit</button>{" "}
                      <button className="small danger" onClick={() => remove(a)}>Delete</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        </div>
      )}
      <p className="muted" style={{ fontSize: 12 }}>
        A profile stacks on top of the global lists on the <strong>Profiles</strong> tab: an <em>allow only these</em>{" "}
        list narrows that host to the addresses and countries it names, and a <em>block these</em> list removes them even
        when a global allow list names them. Selected protection profiles travel with the profile, so the host form only
        asks for one choice.
      </p>

      {draft && (
        <Modal title={draft.id === 0 ? "New access profile" : `Edit ${draft.name}`} onClose={() => setDraft(null)}>
          <Field label="Profile name">
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder="Office only"
              autoFocus
              // The name is fixed once created so the proxies pointing at it keep
              // a label an operator recognises; showing it disabled beats
              // accepting an edit that the server would quietly drop.
              disabled={draft.id !== 0}
            />
          </Field>

          <Field label="Lists">
            {policies.length === 0 ? (
              <p className="muted" style={{ fontSize: 12 }}>
                No lists yet. Create them on the Profiles tab first.
              </p>
            ) : (
              <div style={{ maxHeight: 280, overflowY: "auto", display: "grid", gap: 6 }}>
                {policies.map((p) => {
                  const rule = ruleFor(draft, p.id);
                  return (
                    <div key={p.id} className="row" style={{ gap: 8, alignItems: "center", margin: 0 }}>
                      <span className="mono" style={{ fontSize: 12, minWidth: 120 }}>{KIND_LABELS[p.kind] ?? p.kind}</span>
                      <span className="muted" style={{ flex: 1, fontSize: 12 }}>{p.value}</span>
                      {!p.enabled && <Badge tone="warn">disabled</Badge>}
                      <select
                        value={rule?.role ?? ""}
                        onChange={(e) => (e.target.value ? setRole(p.id, e.target.value as AccessRule["role"]) : clear(p.id))}
                        style={{ width: 190 }}
                      >
                        <option value="">Not in this profile</option>
                        <option value="allow">{ROLE_LABELS.allow}</option>
                        <option value="deny">{ROLE_LABELS.deny}</option>
                        <option value="inherit">{ROLE_LABELS.inherit}</option>
                      </select>
                    </div>
                  );
                })}
              </div>
            )}
          </Field>

          <Field label="Blocklists and whitelists">
            {lists.length === 0 ? (
              <p className="muted" style={{ fontSize: 12 }}>
                No named lists yet. Create them on the Lists tab first.
              </p>
            ) : (
              <div style={{ maxHeight: 220, overflowY: "auto", display: "grid", gap: 4 }}>
                {lists.map((l) => (
                  <label
                    key={l.id}
                    style={{ margin: 0, display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}
                  >
                    <input
                      type="checkbox"
                      style={{ width: "auto" }}
                      checked={(draft.list_ids ?? []).includes(l.id)}
                      onChange={() => toggleList(l.id)}
                    />
                    <Badge tone={l.kind === "blocklist" ? "bad" : "ok"}>{l.kind === "blocklist" ? "block" : "allow"}</Badge>
                    <span>{l.name}</span>
                    <span className="muted" style={{ fontSize: 11 }}>
                      {countLabel(entries(l.ips) + entries(l.countries))}
                    </span>
                  </label>
                ))}
              </div>
            )}
          </Field>

          <Field label="Skip the WAF for these sources (whitelists)">
            {lists.filter((l) => l.kind === "whitelist").length === 0 ? (
              <p className="muted" style={{ fontSize: 12 }}>
                No whitelist yet. Create one on the Lists tab; a blocklist cannot be a trust list.
              </p>
            ) : (
              <div style={{ maxHeight: 160, overflowY: "auto", display: "grid", gap: 4 }}>
                {lists.filter((l) => l.kind === "whitelist").map((l) => (
                  <label
                    key={l.id}
                    style={{ margin: 0, display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}
                  >
                    <input
                      type="checkbox"
                      style={{ width: "auto" }}
                      checked={(draft.waf_skip_list_ids ?? []).includes(l.id)}
                      onChange={() => toggleWAFSkip(l.id)}
                    />
                    <span>{l.name}</span>
                    <span className="muted" style={{ fontSize: 11 }}>
                      {countLabel(entries(l.ips) + entries(l.countries))}
                    </span>
                  </label>
                ))}
              </div>
            )}
            <p className="muted" style={{ fontSize: 11, marginBottom: 0 }}>
              A source on one of these lists skips the whole WAF stage on every host using this profile: CRS rules,
              signature bundles and normalization checks do not run. Bans, lists, rate limits, the access gate and
              routing still apply, and each skipped request is logged as stage waf-skip.
              Leave this empty unless you mean it: a WAF skip exposes headers, query, cookies and body unfiltered to
              everything the list covers, including a whole NAT.
            </p>
          </Field>

          <div className="row grow">
            <Field label="WAF profile">
              <select
                value={draft.waf_profile_id ?? ""}
                onChange={(e) => setDraft({ ...draft, waf_profile_id: e.target.value ? Number(e.target.value) : null })}
              >
                <option value="">Inherit the default</option>
                {wafProfiles.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </Field>
            <Field label="Protection profile">
              <select
                value={draft.protection_profile_id ?? ""}
                onChange={(e) => setDraft({ ...draft, protection_profile_id: e.target.value ? Number(e.target.value) : null })}
              >
                <option value="">None</option>
                {protections.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </Field>
          </div>

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
