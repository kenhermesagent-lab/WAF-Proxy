import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText } from "../ui";
import type { AuthProvider } from "../types";

const KINDS: Record<string, string> = {
  authelia: "Authelia",
  authentik: "authentik",
  generic: "Generic forward-auth",
};

// The verify URL each product exposes for forward-auth, and what the portal URL
// does for a visitor who is not signed in yet.
const HINTS: Record<string, { verify: string; login: string }> = {
  authelia: {
    verify: "Authelia's /api/verify endpoint, e.g. http://authelia:9091/api/verify",
    login: "Your Authelia portal, e.g. https://auth.example.com — the visitor is sent here with ?rd= back to the site",
  },
  authentik: {
    verify: "The proxy outpost's Traefik endpoint, e.g. http://authentik:9000/outpost.goauthentik.io/auth/traefik",
    login: "Your authentik flow, e.g. https://authentik.example.com/outpost.goauthentik.io/start",
  },
  generic: {
    verify: "Any endpoint that answers 2xx when the forwarded session cookie is valid",
    login: "The page an unauthenticated visitor should be sent to",
  },
};

type Draft = {
  id?: number;
  name: string;
  kind: string;
  verify_url: string;
  login_url: string;
  header: string;
  secret: string;
  has_secret?: boolean;
};

const empty: Draft = { name: "", kind: "authelia", verify_url: "", login_url: "", header: "X-Wafproxy-Auth", secret: "" };

export default function AuthProviders({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [list, setList] = useState<AuthProvider[]>([]);
  const [draft, setDraft] = useState<Draft>({ ...empty });
  const [saving, setSaving] = useState(false);

  const load = () =>
    api.get<AuthProvider[]>("/api/auth-providers").then(setList).catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));

  const save = async () => {
    setSaving(true);
    try {
      const payload = {
        name: draft.name,
        kind: draft.kind,
        verify_url: draft.verify_url,
        login_url: draft.login_url,
        header: draft.header,
        secret: draft.secret,
      };
      if (draft.id) await api.put(`/api/auth-providers/${draft.id}`, payload);
      else await api.post("/api/auth-providers", payload);
      onOK(draft.id ? "Identity provider updated" : "Identity provider added");
      setDraft({ ...empty });
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (p: AuthProvider) => {
    if (!confirm(`Delete ${p.name}?`)) return;
    try {
      await api.del(`/api/auth-providers/${p.id}`);
      onOK("Identity provider deleted");
      if (draft.id === p.id) setDraft({ ...empty });
      await load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const hint = HINTS[draft.kind];

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="Identity providers">
        {list.length === 0 ? (
          <Empty>
            No provider yet. Add the Authelia, authentik or generic forward-auth endpoint you run, then pick it as the
            access gate of a site under <strong>Proxies</strong>.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Verify URL</th>
                <th>Login URL</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((p) => (
                <tr key={p.id}>
                  <td>{p.name}</td>
                  <td><Badge tone="info">{KINDS[p.kind] || p.kind}</Badge></td>
                  <td className="mono">{p.verify_url}</td>
                  <td className="mono">{p.login_url || "—"}</td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    <button
                      className="small"
                      onClick={() =>
                        setDraft({
                          id: p.id,
                          name: p.name,
                          kind: p.kind,
                          verify_url: p.verify_url,
                          login_url: p.login_url,
                          header: p.header,
                          secret: "",
                          has_secret: p.has_secret,
                        })
                      }
                    >
                      Edit
                    </button>{" "}
                    <button className="small danger" onClick={() => remove(p)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title={draft.id ? `Edit ${draft.name}` : "Add a provider"}>
        <div className="row grow">
          <Field label="Name">
            <input value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="Home Authelia" />
          </Field>
          <Field label="Product">
            <select value={draft.kind} onChange={(e) => set({ kind: e.target.value })}>
              {Object.entries(KINDS).map(([k, label]) => (
                <option key={k} value={k}>{label}</option>
              ))}
            </select>
          </Field>
        </div>
        <Field label="Verify URL">
          <input value={draft.verify_url} onChange={(e) => set({ verify_url: e.target.value })} placeholder="http://authelia:9091/api/verify" />
        </Field>
        <p className="muted" style={{ fontSize: 12, marginTop: -6 }}>{hint.verify}</p>
        <Field label="Login URL (where unauthenticated visitors go)">
          <input value={draft.login_url} onChange={(e) => set({ login_url: e.target.value })} placeholder="https://auth.example.com" />
        </Field>
        <p className="muted" style={{ fontSize: 12, marginTop: -6 }}>{hint.login}</p>
        <div className="row grow">
          <Field label="Secret header">
            <input value={draft.header} onChange={(e) => set({ header: e.target.value })} />
          </Field>
          <Field label={draft.has_secret ? "Shared secret (leave blank to keep)" : "Shared secret (optional)"}>
            <input type="password" value={draft.secret} onChange={(e) => set({ secret: e.target.value })} />
          </Field>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          The proxy checks every request against the verify URL, forwarding the visitor's cookies plus
          <span className="mono"> X-Forwarded-*</span> and <span className="mono">X-Original-URL</span>. Only a 2xx allows
          the request; a 401 sends the visitor to the login URL, a redirect is passed through, and an unreachable provider
          refuses access. The secret is sealed with the console key and never shown again.
        </p>
        <div className="row">
          <button className="primary" onClick={save} disabled={saving}>{saving ? "Saving…" : draft.id ? "Save provider" : "Add provider"}</button>
          {draft.id && <button onClick={() => setDraft({ ...empty })}>Cancel</button>}
        </div>
      </Card>
    </div>
  );
}
