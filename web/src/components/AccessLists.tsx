import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { COUNTRIES, countryFlag, countryName } from "../countries";
import { Badge, Card, Empty, Field, Modal, errText } from "../ui";
import type { AccessList } from "../types";

const KIND_COPY = {
  blocklist: {
    title: "Blocklists",
    newLabel: "New blocklist",
    created: "Blocklist created",
    blurb:
      "A blocklist refuses the addresses and countries it holds on every site whose access profile attaches it. An access profile can attach any number of them.",
  },
  whitelist: {
    title: "Whitelists",
    newLabel: "New whitelist",
    created: "Whitelist created",
    blurb:
      "A whitelist makes a site reachable only from what it holds: once an access profile attaches one, every other address and country is refused for those hosts. A blocklist attached to the same profile still wins.",
  },
} as const;

export default function AccessLists({
  kind,
  onError,
  onOK,
}: {
  kind: "blocklist" | "whitelist";
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const copy = KIND_COPY[kind];
  const [lists, setLists] = useState<AccessList[]>([]);
  const [draft, setDraft] = useState<AccessList | null>(null);
  const [search, setSearch] = useState("");
  const [saving, setSaving] = useState(false);

  const load = () =>
    api
      .get<AccessList[]>("/api/lists")
      .then(setLists)
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const mine = lists.filter((l) => l.kind === kind);
  const other = lists.find((l) => l.kind !== kind && l.name === draft?.name.trim());

  const chosen = useMemo(
    () => (draft?.countries ? draft.countries.split(",").filter(Boolean) : []),
    [draft?.countries],
  );
  // The picker shows every country once, so "move over" is a click on either
  // side rather than a drag target.
  const available = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return COUNTRIES.filter(
      (c) =>
        !chosen.includes(c.code) &&
        (needle === "" || c.name.toLowerCase().includes(needle) || c.code === search.trim().toUpperCase()),
    );
  }, [chosen, search]);

  const edit = (l: AccessList) =>
    setDraft({ ...l, ips: l.ips.split(",").filter(Boolean).join("\n"), countries: l.countries });

  const setCountries = (codes: string[]) => draft && setDraft({ ...draft, countries: codes.join(",") });

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      if (draft.id === 0) await api.post("/api/lists", draft);
      else await api.put(`/api/lists/${draft.id}`, draft);
      onOK(draft.id === 0 ? copy.created : `${draft.name} saved`);
      setDraft(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (l: AccessList) => {
    if (!confirm(`Delete the ${l.name} list? Sites using it keep their other rules.`)) return;
    try {
      await api.del(`/api/lists/${l.id}`);
      onOK("List deleted");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const counts = (l: AccessList) => ({
    ips: l.ips ? l.ips.split(",").filter(Boolean).length : 0,
    countries: l.countries ? l.countries.split(",").filter(Boolean).length : 0,
  });

  return (
    <Card
      title={copy.title}
      actions={
        <button
          className="small primary"
          onClick={() => setDraft({ id: 0, kind, name: "", ips: "", countries: "" })}
        >
          {copy.newLabel}
        </button>
      }
    >
      {mine.length === 0 ? (
        <Empty>No {copy.title.toLowerCase()} yet. {copy.blurb}</Empty>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr><th>List</th><th>Addresses</th><th>Countries</th><th /></tr>
            </thead>
            <tbody>
              {mine.map((l) => {
                const n = counts(l);
                return (
                  <tr key={l.id}>
                    <td style={{ whiteSpace: "nowrap" }}>{l.name}</td>
                    <td className="num">{n.ips}</td>
                    <td>
                      {n.countries === 0 ? (
                        <span className="muted">none</span>
                      ) : (
                        <span className="muted" style={{ fontSize: 12 }}>
                          {l.countries
                            .split(",")
                            .filter(Boolean)
                            .slice(0, 8)
                            .map((c) => `${countryFlag(c)} ${c}`)
                            .join(" · ")}
                          {n.countries > 8 ? ` · +${n.countries - 8} more` : ""}
                        </span>
                      )}
                    </td>
                    <td className="right" style={{ whiteSpace: "nowrap" }}>
                      <button className="small" onClick={() => edit(l)}>Edit</button>{" "}
                      <button className="small danger" onClick={() => remove(l)}>Delete</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>{copy.blurb}</p>

      {draft && (
        <Modal
          title={draft.id === 0 ? copy.newLabel : `Edit ${draft.name}`}
          onClose={() => setDraft(null)}
        >
          <Field label="Name">
            <input
              value={draft.name}
              autoFocus
              placeholder={kind === "blocklist" ? "Known scanners" : "Our offices"}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              // A profile points at the id, but the name is what an operator
              // recognises in that profile, so it stays fixed after creation.
              disabled={draft.id !== 0}
            />
          </Field>
          {other && (
            <p className="muted" style={{ fontSize: 12, marginTop: -6 }}>
              A {other.kind} already uses that name; names are shared across both tabs.
            </p>
          )}

          <Field label="IP addresses and CIDRs (one per line)">
            <textarea
              rows={6}
              className="mono"
              style={{ fontSize: 12 }}
              value={draft.ips}
              placeholder={"203.0.113.7\n198.51.100.0/24"}
              onChange={(e) => setDraft({ ...draft, ips: e.target.value })}
            />
          </Field>

          <Field label={`Countries (${chosen.length} selected)`}>
            <div className="row" style={{ alignItems: "flex-start", flexWrap: "nowrap" }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <input
                  value={search}
                  placeholder="Search a country…"
                  onChange={(e) => setSearch(e.target.value)}
                  style={{ marginBottom: 6 }}
                />
                <div
                  style={{
                    maxHeight: 180,
                    overflowY: "auto",
                    border: "1px solid var(--border)",
                    borderRadius: 9,
                    padding: 4,
                  }}
                >
                  {available.length === 0 ? (
                    <div className="muted" style={{ fontSize: 12, padding: 6 }}>No match.</div>
                  ) : (
                    available.map((c) => (
                      <button
                        key={c.code}
                        className="small"
                        style={{ display: "block", width: "100%", textAlign: "left", margin: "2px 0" }}
                        title={`Add ${c.name}`}
                        onClick={() => setCountries([...chosen, c.code])}
                      >
                        {countryFlag(c.code)} {c.name}
                      </button>
                    ))
                  )}
                </div>
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>In this list</div>
                <div
                  style={{
                    maxHeight: 180,
                    overflowY: "auto",
                    border: "1px solid var(--border)",
                    borderRadius: 9,
                    padding: 4,
                    minHeight: 38,
                  }}
                >
                  {chosen.length === 0 ? (
                    <div className="muted" style={{ fontSize: 12, padding: 6 }}>None yet.</div>
                  ) : (
                    chosen.map((code) => (
                      <button
                        key={code}
                        className="small"
                        style={{ display: "block", width: "100%", textAlign: "left", margin: "2px 0" }}
                        title={`Remove ${countryName(code)}`}
                        onClick={() => setCountries(chosen.filter((c) => c !== code))}
                      >
                        <Badge tone={kind === "blocklist" ? "bad" : "ok"}>{kind === "blocklist" ? "block" : "allow"}</Badge>{" "}
                        {countryFlag(code)} {countryName(code)}
                      </button>
                    ))
                  )}
                </div>
              </div>
            </div>
          </Field>

          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setDraft(null)}>Cancel</button>
            <button
              className="primary"
              disabled={saving || draft.name.trim() === ""}
              onClick={save}
            >
              {saving ? "Saving…" : draft.id === 0 ? "Create list" : "Save list"}
            </button>
          </div>
        </Modal>
      )}
    </Card>
  );
}
