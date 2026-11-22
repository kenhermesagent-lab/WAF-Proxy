import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Modal, errText } from "../ui";
import type { AccessProfile, Policy } from "../types";

const KIND_LABELS: Record<string, string> = {
  ip_whitelist: "IP / CIDR allow",
  country_whitelist: "Allowed country",
  country_blacklist: "Blocked country",
  asn_block: "Blocked ASN",
  decoy: "Decoy path",
  rate_limit: "Rate limit",
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
  const [draft, setDraft] = useState<AccessProfile | null>(null);
  const [saving, setSaving] = useState(false);

  const load = () => api.get<AccessProfile[]>("/api/access-profiles").then(setList).catch((e) => onError(errText(e)));

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
    if (!confirm(`Delete the ${a.name} profile? The policies themselves stay.`)) return;
    try {
      await api.del(`/api/access-profiles/${a.id}`);
      onOK("Access profile deleted");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const toggle = (id: number) => {
    if (!draft) return;
    const ids = draft.policy_ids.includes(id)
      ? draft.policy_ids.filter((x) => x !== id)
      : [...draft.policy_ids, id];
    setDraft({ ...draft, policy_ids: ids });
  };

  const describe = (ids: number[]) =>
    ids
      .map((id) => policies.find((p) => p.id === id))
      .filter(Boolean)
      .map((p) => `${KIND_LABELS[p!.kind] ?? p!.kind}: ${p!.value}`)
      .join(" · ");

  return (
    <Card
      title="Access profiles"
      actions={<button className="small primary" onClick={() => setDraft({ id: 0, name: "", policy_ids: [] })}>New profile</button>}
    >
      {list.length === 0 ? (
        <Empty>No access profiles. Create one to apply a set of allow and block rules to several proxies.</Empty>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead><tr><th>Profile</th><th>Rules</th><th /></tr></thead>
            <tbody>
              {list.map((a) => {
                const missing = a.policy_ids.filter((id) => !policies.some((p) => p.id === id)).length;
                return (
                  <tr key={a.id}>
                    <td style={{ whiteSpace: "nowrap" }}>{a.name}</td>
                    <td className="muted" style={{ fontSize: 12 }}>
                      {describe(a.policy_ids) || "no rules selected"}
                      {missing > 0 && <> <Badge tone="warn">{missing} deleted rule(s)</Badge></>}
                    </td>
                    <td className="right" style={{ whiteSpace: "nowrap" }}>
                      <button className="small" onClick={() => setDraft({ ...a })}>Edit</button>{" "}
                      <button className="small danger" onClick={() => remove(a)}>Delete</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted" style={{ fontSize: 12 }}>
        A profile bundles existing rules from <strong>Countries, IPs, ASN</strong>. Attach it to a proxy and those rules
        apply to that site only; turning a rule off here still turns it off. Editing a rule updates every profile that
        contains it.
      </p>

      {draft && (
        <Modal title={draft.id === 0 ? "New access profile" : `Edit ${draft.name}`} onClose={() => setDraft(null)}>
          {draft.id === 0 && (
            <Field label="Profile name">
              <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Office only" autoFocus />
            </Field>
          )}
          <Field label={`Rules (${draft.policy_ids.length} selected)`}>
            {policies.length === 0 ? (
              <p className="muted" style={{ fontSize: 12 }}>
                No rules yet. Create allow or block rules on the Countries, IPs, ASN tab first.
              </p>
            ) : (
              <div style={{ maxHeight: 260, overflowY: "auto", display: "grid", gap: 6 }}>
                {policies.map((p) => (
                  <label key={p.id} className="row" style={{ margin: 0, gap: 8, textTransform: "none", letterSpacing: 0, fontSize: 13 }}>
                    <input
                      type="checkbox"
                      style={{ width: "auto" }}
                      checked={draft.policy_ids.includes(p.id)}
                      onChange={() => toggle(p.id)}
                    />
                    <span className="mono" style={{ fontSize: 12 }}>{KIND_LABELS[p.kind] ?? p.kind}</span>
                    <span className="muted">{p.value}</span>
                    {!p.enabled && <Badge tone="warn">disabled</Badge>}
                  </label>
                ))}
              </div>
            )}
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
