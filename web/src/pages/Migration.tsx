import { useState } from "react";
import { api } from "../api";
import Icon from "../components/Icon";
import { Badge, Card, Field, TableWrap, errText } from "../ui";

type MigrationHost = {
  hostname: string;
  upstreams: string[];
  enabled: boolean;
  tls: boolean;
  access_list?: string;
  cert_ref?: string;
  cert_key_ref?: string;
  cert_name?: string;
  exists: boolean;
  problem?: string;
};
type MigrationRedirect = {
  hostname: string;
  target: string;
  status: number;
  exists: boolean;
  problem?: string;
};
type MigrationAccessList = { name: string; allow: string[]; deny: string[]; auth_users: number };
type MigrationCertificate = {
  ref: string;
  domains: string;
  provider: string;
  hosts?: string[];
  importable: boolean;
  problem?: string;
};
type MigrationPreview = {
  source: string;
  hosts: MigrationHost[];
  redirects: MigrationRedirect[];
  access_lists: MigrationAccessList[];
  certificates?: MigrationCertificate[];
  notes: string[];
  skipped: string[];
};
type MigrationResult = {
  created: number;
  redirects: number;
  access_lists: number;
  certificates: number;
  skipped: number;
  problems: string[];
};

type SourceID = "npm" | "zoraxy" | "traefik" | "caddy" | "nginx" | "haproxy" | "apache";

const SOURCES: {
  id: SourceID;
  label: string;
  live: boolean;
  accept: string;
  upload: string;
  hint: string;
  placeholder: string;
}[] = [
  {
    id: "npm", label: "Nginx Proxy Manager", live: true, accept: ".json,application/json",
    upload: "NPM JSON export",
    hint: "Upload an object with proxy_hosts, access_lists and redirection_hosts, or the bare array from /api/nginx/proxy-hosts. Certificates are only available over a live connection.",
    placeholder: "https://npm.example.com:81",
  },
  {
    id: "zoraxy", label: "Zoraxy", live: false, accept: ".zip,.json,application/zip",
    upload: "Zoraxy configuration ZIP",
    hint: "Upload the ZIP from Zoraxy's configuration export. Hostnames, upstreams, disabled state and redirects are read.",
    placeholder: "",
  },
  {
    id: "traefik", label: "Traefik", live: true, accept: ".yml,.yaml,.json,.zip,application/zip",
    upload: "Traefik dynamic config",
    hint: "Upload the dynamic YAML or JSON file with http.routers and http.services, or a ZIP that also contains the tls.certificates certFile and keyFile files. The live option reads the API at /api/http; the API must be reachable without a login.",
    placeholder: "http://traefik.example.com:8080",
  },
  {
    id: "caddy", label: "Caddy", live: true, accept: "",
    upload: "Caddyfile or JSON config",
    hint: "Upload a Caddyfile or the JSON returned by the admin API. Site blocks using reverse_proxy and redir are imported, and tls certificate files are imported when they are in the upload. Live reads the admin API.",
    placeholder: "http://caddy.example.com:2019",
  },
  {
    id: "nginx", label: "Nginx / SWAG", live: false, accept: ".conf,.zip,application/zip",
    upload: "Nginx or SWAG config",
    hint: "Upload one .conf or a ZIP of .conf files. server_name, proxy_pass, upstreams, return redirects and ssl_certificate are read. Certificates are imported when fullchain.pem and privkey.pem are inside the ZIP.",
    placeholder: "",
  },
  {
    id: "haproxy", label: "HAProxy", live: false, accept: ".cfg,.conf,.txt,.zip,application/zip",
    upload: "HAProxy config",
    hint: "Upload haproxy.cfg or a ZIP. frontend/listen sections with hdr(host) ACLs, use_backend, backend server lines and ssl crt PEM bundles are read.",
    placeholder: "",
  },
  {
    id: "apache", label: "Apache", live: false, accept: ".conf,.zip,application/zip",
    upload: "Apache vhost config",
    hint: "Upload one .conf or a ZIP. VirtualHost blocks with ServerName, ServerAlias, ProxyPass, Redirect and SSLEngine are read; SSLCertificateFile/KeyFile pairs are imported when in the ZIP.",
    placeholder: "",
  },
];

const hostKey = (h: string) => `h:${h}`;
const redirectKey = (h: string) => `r:${h}`;

async function fileAsBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x2000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x2000));
  }
  return btoa(binary);
}

// Migration moves hostnames from another reverse proxy. The preview is
// read-only and names every row that cannot be created; apply sends only the
// rows the operator kept plus the connection needed to fetch certificates.
export default function Migration({ onError, onOK }: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [source, setSource] = useState<SourceID>("npm");
  const [mode, setMode] = useState<"live" | "upload">("live");
  const [form, setForm] = useState({ url: "", username: "", secret: "", insecure: false });
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<MigrationPreview | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MigrationResult | null>(null);

  const config = SOURCES.find((s) => s.id === source) ?? SOURCES[0];
  const certs = preview?.certificates ?? [];
  const certByRef = new Map(certs.map((c) => [c.ref, c]));
  const pickable = preview
    ? [
        ...preview.hosts.filter((h) => !h.exists && !h.problem).map((h) => hostKey(h.hostname)),
        ...preview.redirects.filter((r) => !r.exists && !r.problem).map((r) => redirectKey(r.hostname)),
      ]
    : [];
  const allPicked = pickable.length > 0 && pickable.every((k) => picked.has(k));

  const reset = () => {
    setPreview(null);
    setPicked(new Set());
    setResult(null);
  };

  const chooseSource = (next: SourceID) => {
    setSource(next);
    const live = SOURCES.find((s) => s.id === next)?.live ?? false;
    setMode(live ? "live" : "upload");
    setFile(null);
    reset();
  };

  const buildBody = async () => {
    if (mode === "live") {
      if (!form.url.trim()) throw new Error(`Enter the ${config.label} URL.`);
      if (source === "npm" && (!form.username.trim() || !form.secret)) {
        throw new Error("Enter the NPM email and password.");
      }
      return {
        source, mode, url: form.url.trim(),
        username: source === "npm" ? form.username.trim() : "",
        secret: source === "npm" ? form.secret : "",
        insecure: form.insecure,
      };
    }
    if (!file) throw new Error("Choose the configuration file first.");
    return { source, mode, content: await fileAsBase64(file) };
  };

  const runPreview = async () => {
    setBusy(true);
    setResult(null);
    try {
      const p = await api.post<MigrationPreview>("/api/migrate/preview", await buildBody());
      setPreview(p);
      setPicked(new Set([
        ...p.hosts.filter((h) => !h.exists && !h.problem).map((h) => hostKey(h.hostname)),
        ...p.redirects.filter((r) => !r.exists && !r.problem).map((r) => redirectKey(r.hostname)),
      ]));
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const runApply = async () => {
    if (!preview) return;
    setBusy(true);
    try {
      const hosts = preview.hosts.filter((h) => picked.has(hostKey(h.hostname)));
      const r = await api.post<MigrationResult>("/api/migrate/apply", {
        source: preview.source,
        hosts,
        redirects: preview.redirects.filter((rd) => picked.has(redirectKey(rd.hostname))),
        // Only create the access lists a selected host actually references;
        // they are additive and never overwrite an existing list.
        access_lists: preview.access_lists.filter((al) => hosts.some((h) => h.access_list === al.name)),
        connection: await buildBody(),
      });
      setResult(r);
      setPreview(null);
      setPicked(new Set());
      const certs = r.certificates > 0 ? ` and ${r.certificates} certificate${r.certificates === 1 ? "" : "s"}` : "";
      onOK(`Imported ${r.created} host${r.created === 1 ? "" : "s"}, ${r.redirects} redirect${r.redirects === 1 ? "" : "s"}${certs}`);
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const toggle = (key: string) => {
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const toggleAll = () => {
    setPicked((prev) => (pickable.every((k) => prev.has(k)) ? new Set() : new Set(pickable)));
  };

  const status = (exists: boolean, problem?: string) =>
    exists ? <Badge tone="info">already here</Badge>
      : problem ? <Badge tone="warn">skipped</Badge>
        : <Badge tone="ok">new</Badge>;

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="Source">
        <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          {SOURCES.map((s) => (
            <button key={s.id} className={`small ${source === s.id ? "primary" : ""}`} onClick={() => chooseSource(s.id)}>
              {s.label}
            </button>
          ))}
        </div>

        {config.live ? (
          <div className="row" style={{ gap: 8, marginBottom: 12 }}>
            <button className={`small ${mode === "live" ? "primary" : ""}`} onClick={() => { setMode("live"); reset(); }}>
              Live connection
            </button>
            <button className={`small ${mode === "upload" ? "primary" : ""}`} onClick={() => { setMode("upload"); reset(); }}>
              Upload a file
            </button>
          </div>
        ) : (
          <p className="muted small-text" style={{ marginTop: 0 }}>
            {config.label} has no safe read-only API this importer supports. Upload its configuration instead.
          </p>
        )}

        {mode === "live" && config.live ? (
          <>
            <div className="field-grid">
              <Field
                label={`${config.label} URL`}
                hint={source === "npm"
                  ? "The console connects read-only; use https so the password is not sent in clear text."
                  : `Read-only API. Use a URL this console can reach on your network.`}
              >
                <input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder={config.placeholder} />
              </Field>
              {source === "npm" ? (
                <>
                  <Field label="Email"><input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="username" /></Field>
                  <Field label="Password"><input type="password" value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} autoComplete="current-password" /></Field>
                </>
              ) : null}
            </div>
            <label className="checkbox">
              <input type="checkbox" checked={form.insecure} onChange={(e) => setForm({ ...form, insecure: e.target.checked })} />
              Skip TLS verification (self-signed certificate)
            </label>
            {source === "npm" ? <p className="faint small-text">Credentials are used for this request only and are never stored.</p> : null}
          </>
        ) : (
          <>
            <Field label={config.upload} hint={config.hint}>
              <input type="file" accept={config.accept || undefined} onChange={(e) => { setFile(e.target.files?.[0] ?? null); setPreview(null); }} />
            </Field>
            {file ? <p className="faint small-text">{file.name} · {Math.ceil(file.size / 1024)} KB</p> : null}
          </>
        )}

        <button className="primary" onClick={runPreview} disabled={busy || (mode === "upload" && !file)} style={{ marginTop: 8 }}>
          <Icon name="search" size={14} /> {busy ? "Reading…" : "Preview import"}
        </button>
      </Card>

      {result && (
        <Card title="Import finished">
          <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
            <Badge tone="ok">{result.created} hosts</Badge>
            <Badge tone="ok">{result.redirects} redirects</Badge>
            {result.certificates > 0 ? <Badge tone="ok">{result.certificates} certificates</Badge> : null}
            <Badge tone="info">{result.access_lists} access lists</Badge>
            {result.skipped > 0 ? <Badge tone="warn">{result.skipped} skipped</Badge> : null}
          </div>
          {result.problems.length > 0 ? (
            <ul className="faint small-text" style={{ margin: 0 }}>
              {result.problems.map((p) => <li key={p}>{p}</li>)}
            </ul>
          ) : <p className="muted small-text" style={{ margin: 0 }}>Every selected row was created. Issue certificates for any hostname whose certificate was not imported in Proxies → Certificates.</p>}
          <p className="small-text" style={{ marginBottom: 0 }}>
            <a className="link-button" href="#/proxies/sites">Open Proxies</a>
          </p>
        </Card>
      )}

      {preview && (
        <>
          <Card
            title="Preview"
            actions={<button className="small" onClick={toggleAll}>{allPicked ? "Select none" : "Select all"}</button>}
          >
            <p className="muted small-text" style={{ marginTop: 0 }}>
              {preview.hosts.length} hostname{preview.hosts.length === 1 ? "" : "s"} · {preview.redirects.length} redirect
              {preview.redirects.length === 1 ? "" : "s"} · {preview.access_lists.length} access list
              {preview.access_lists.length === 1 ? "" : "s"} · {certs.length} certificate
              {certs.length === 1 ? "" : "s"}. Existing certificates are imported when the source exposes their key.
            </p>

            {preview.hosts.length > 0 && (
              <TableWrap>
                <table>
                  <thead>
                    <tr><th></th><th>Hostname</th><th>Upstream</th><th>TLS</th><th>Access list</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {preview.hosts.map((h) => {
                      const key = hostKey(h.hostname);
                      const cert = h.cert_ref ? certByRef.get(h.cert_ref) : undefined;
                      return (
                        <tr key={key}>
                          <td><input type="checkbox" aria-label={`Import ${h.hostname}`} checked={picked.has(key)} disabled={h.exists || !!h.problem} onChange={() => toggle(key)} /></td>
                          <td className="mono">
                            {h.hostname}{h.enabled ? null : <span className="faint small-text"> · disabled</span>}
                            {h.cert_name ? (
                              <div className="small-text">
                                <Badge tone={cert?.importable ? "ok" : "warn"}>{h.cert_name}</Badge>
                              </div>
                            ) : null}
                          </td>
                          <td className="mono small-text">{h.upstreams.join(", ") || "—"}</td>
                          <td>{h.tls ? <Badge>certificate</Badge> : "—"}</td>
                          <td>{h.access_list || "—"}</td>
                          <td>
                            {status(h.exists, h.problem)}
                            {h.problem ? <div className="faint small-text">{h.problem}</div> : null}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </TableWrap>
            )}

            {preview.redirects.length > 0 && (
              <>
                <h3 style={{ fontSize: 13, margin: "14px 0 6px" }}>Redirects</h3>
                <TableWrap>
                  <table>
                    <thead><tr><th></th><th>Hostname</th><th>Target</th><th>Status</th><th>Result</th></tr></thead>
                    <tbody>
                      {preview.redirects.map((rd) => {
                        const key = redirectKey(rd.hostname);
                        return (
                          <tr key={key}>
                            <td><input type="checkbox" aria-label={`Import redirect ${rd.hostname}`} checked={picked.has(key)} disabled={rd.exists || !!rd.problem} onChange={() => toggle(key)} /></td>
                            <td className="mono">{rd.hostname}</td>
                            <td className="mono small-text">{rd.target}</td>
                            <td>{rd.status}</td>
                            <td>{status(rd.exists, rd.problem)}{rd.problem ? <div className="faint small-text">{rd.problem}</div> : null}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </TableWrap>
              </>
            )}

            {certs.length > 0 && (
              <>
                <h3 style={{ fontSize: 13, margin: "14px 0 6px" }}>Certificates</h3>
                <TableWrap>
                  <table>
                    <thead><tr><th>Domains</th><th>Provider</th><th>Hosts</th><th>Result</th></tr></thead>
                    <tbody>
                      {certs.map((c) => (
                        <tr key={c.ref}>
                          <td className="mono small-text">{c.domains || "—"}</td>
                          <td>{c.provider || "—"}</td>
                          <td className="small-text">{c.hosts?.join(", ") || "—"}</td>
                          <td>
                            {c.importable ? <Badge tone="ok">will import</Badge> : <Badge tone="warn">not importable</Badge>}
                            {c.problem ? <div className="faint small-text">{c.problem}</div> : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              </>
            )}

            {preview.access_lists.length > 0 && (
              <>
                <h3 style={{ fontSize: 13, margin: "14px 0 6px" }}>Access lists</h3>
                <ul className="faint small-text" style={{ margin: 0 }}>
                  {preview.access_lists.map((al) => (
                    <li key={al.name}>
                      <b>{al.name}</b>: {al.allow.length} allow, {al.deny.length} deny
                      {al.auth_users > 0 ? ` · ${al.auth_users} basic-auth user${al.auth_users === 1 ? "" : "s"} cannot be imported` : ""}
                    </li>
                  ))}
                </ul>
              </>
            )}

            {preview.skipped.length > 0 && (
              <p className="faint small-text" style={{ marginBottom: 0 }}>
                Skipped from the export: {preview.skipped.join("; ")}
              </p>
            )}
          </Card>

          {preview.notes.length > 0 && (
            <Card title="Before you import">
              <ul className="faint small-text" style={{ margin: 0 }}>
                {preview.notes.map((n) => <li key={n}>{n}</li>)}
              </ul>
            </Card>
          )}

          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button className="primary" onClick={runApply} disabled={busy || picked.size === 0}>
              <Icon name="check" size={14} /> {busy ? "Importing…" : `Import ${picked.size} selected`}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
