import { useEffect, useState } from "react";
import { api } from "../api";
import Icon from "../components/Icon";
import { Badge, Field, PageHead, errText } from "../ui";
import type { Me, Site } from "../types";
import { can } from "../types";

type Draft = { slug: string; name: string; console_host: string };
const EMPTY: Draft = { slug: "", name: "", console_host: "" };

// Sites is the one page that reads across tenants: it lists every site, the
// hostnames and retention it owns, and creates, edits and removes them.
export default function SitesPage({ onError, onOK, me }: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  me?: Me | null;
}) {
  const [rows, setRows] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState("");
  const [edit, setEdit] = useState({ name: "", console_host: "", enabled: true });
  const [confirming, setConfirming] = useState("");
  const writable = can(me?.permissions, "sites.write");

  const load = () =>
    api
      .get<Site[]>("/api/sites")
      .then((r) => {
        setRows(r ?? []);
        setErr("");
      })
      .catch((e) => setErr(errText(e)))
      .finally(() => setLoading(false));

  useEffect(() => {
    load();
  }, []);

  // Every write reports the server's own words, so a duplicate slug or an
  // invalid hostname lands in the form instead of a generic failure.
  const run = async (action: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setErr("");
    try {
      await action();
      onOK(done);
      await load();
      return true;
    } catch (e) {
      const message = errText(e);
      setErr(message);
      onError(message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const create = async () => {
    if (await run(() => api.post("/api/sites", draft), `Site ${draft.slug} created`)) setDraft(EMPTY);
  };

  const startEdit = (site: Site) => {
    setEditing(site.slug);
    setEdit({ name: site.name, console_host: site.console_host, enabled: site.enabled });
    setErr("");
  };

  const save = async (slug: string) => {
    if (await run(() => api.put(`/api/sites/${encodeURIComponent(slug)}`, edit), `Site ${slug} updated`)) setEditing("");
  };

  const remove = async (slug: string) => {
    if (await run(() => api.del(`/api/sites/${encodeURIComponent(slug)}`), `Site ${slug} removed`)) setConfirming("");
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead sub="Every site this install serves, what each console host is, and the hostnames it owns." />

      {!writable && (
        <div className="card">
          <p style={{ margin: 0 }} className="muted">
            Your role can read the site list but not change it. Ask a host administrator to create, edit or remove a site.
          </p>
        </div>
      )}

      {err && (
        <div className="card" role="alert">
          <div className="row" style={{ gap: 8 }}>
            <Icon name="alert" size={15} />
            <strong>That request was refused</strong>
          </div>
          <p className="muted" style={{ margin: "6px 0 0", fontSize: 13 }}>{err}</p>
        </div>
      )}

      {rows.length === 0 && !loading && !err && (
        <div className="card">
          <p style={{ margin: 0 }} className="muted">No sites could be read. Reload the console or check the server log.</p>
        </div>
      )}

      {rows.length > 0 && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Site</th>
                  <th>Console host</th>
                  <th>Hostnames</th>
                  <th>Retention</th>
                  <th className="num">Admins</th>
                  <th>State</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((site) => (
                  <tr key={site.slug}>
                    <td>
                      <div className="row" style={{ gap: 8 }}>
                        <span className="mono" style={{ color: "var(--text)", fontSize: 12 }}>{site.name}</span>
                        {site.current && <Badge tone="ok">Signed in here</Badge>}
                      </div>
                      <div className="faint small-text mono">{site.slug}</div>
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>{site.console_host || <span className="faint">not set</span>}</td>
                    <td>
                      {site.hostnames.length === 0 ? (
                        <span className="faint small-text">no hostnames yet</span>
                      ) : (
                        <div className="grid" style={{ gap: 2 }}>
                          {site.hostnames.map((h) => <span key={h} className="mono" style={{ fontSize: 11.5 }}>{h}</span>)}
                        </div>
                      )}
                    </td>
                    <td className="muted">{site.retention_days ? `${site.retention_days} days` : "—"}</td>
                    <td className="num">{site.admins}</td>
                    <td><Badge tone={site.enabled ? "ok" : ""}>{site.enabled ? "Enabled" : "Disabled"}</Badge></td>
                    <td className="right" style={{ whiteSpace: "nowrap" }}>
                      {writable && editing !== site.slug && (
                        <>
                          <button className="xsmall" onClick={() => startEdit(site)}>Edit</button>{" "}
                          {site.slug === "default" ? (
                            <button className="xsmall" disabled title="The default site serves this console and cannot be removed">Delete</button>
                          ) : confirming === site.slug ? (
                            <>
                              <button className="xsmall danger" disabled={busy} onClick={() => remove(site.slug)}>Confirm delete</button>{" "}
                              <button className="xsmall" onClick={() => setConfirming("")}>Cancel</button>
                            </>
                          ) : (
                            <button className="xsmall" onClick={() => setConfirming(site.slug)}>Delete</button>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {writable && editing && (
        <div className="card">
          <div className="section-head">
            <h2>Edit {editing}</h2>
            <p>Renaming a site or its console host does not move the rows it owns, and does not reissue its certificate.</p>
          </div>
          <div className="field-grid">
            <Field label="Display name">
              <input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} />
            </Field>
            <Field label="Console host" hint="The hostname its administrators sign in on. No scheme or path.">
              <input value={edit.console_host} onChange={(e) => setEdit({ ...edit, console_host: e.target.value })} placeholder="console.example.com" />
            </Field>
          </div>
          <div className="row" style={{ gap: 10, marginTop: 10 }}>
            <label className="row" style={{ gap: 6 }}>
              <input type="checkbox" checked={edit.enabled} onChange={(e) => setEdit({ ...edit, enabled: e.target.checked })} />
              <span>Serve this site</span>
            </label>
            <button className="primary" disabled={busy} onClick={() => save(editing)}>Save</button>
            <button onClick={() => setEditing("")}>Cancel</button>
          </div>
        </div>
      )}

      {writable && (
        <div className="card">
          <div className="section-head">
            <h2>Add a site</h2>
            <p>A site starts empty: add its hostnames on the Proxies page and point DNS at this host.</p>
          </div>
          <div className="field-grid">
            <Field label="Slug" hint="Stable identifier: a-z, 0-9 and dashes.">
              <input value={draft.slug} onChange={(e) => setDraft({ ...draft, slug: e.target.value })} placeholder="acme" />
            </Field>
            <Field label="Display name">
              <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Acme Ltd" />
            </Field>
            <Field label="Console host" hint="Its administrators sign in here; it needs its own certificate.">
              <input value={draft.console_host} onChange={(e) => setDraft({ ...draft, console_host: e.target.value })} placeholder="console.acme.example" />
            </Field>
          </div>
          <button className="primary mt" disabled={busy || draft.slug.trim() === ""} onClick={create}>
            {busy ? "Working…" : "Create site"}
          </button>
        </div>
      )}
    </div>
  );
}
