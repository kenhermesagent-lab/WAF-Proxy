import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Modal, errText, fmtTime } from "../ui";
import { Cert } from "../types";

const RENEW_OPTIONS = [
  { value: "before_expiry", label: "1 month before expiry" },
  { value: "monthly", label: "Monthly" },
  { value: "every_2_months", label: "Every 2 months" },
  { value: "every_3_months", label: "Every 3 months" },
];

const PROVIDER_HINTS: Record<string, string> = {
  duckdns: '{"token":"your-duckdns-token"}',
  cloudflare: '{"api_token":"..."}',
  route53: '{"access_key_id":"...","secret_access_key":"...","region":"us-east-1"}',
  digitalocean: '{"token":"..."}',
  hetzner: '{"api_token":"..."}',
  ovh: '{"endpoint":"ovh-eu","application_key":"...","application_secret":"...","consumer_key":"..."}',
  godaddy: '{"api_key":"...","api_secret":"..."}',
  rfc2136: '{"nameserver":"10.0.0.2:53","tsig_key":"key","tsig_secret":"secret","zones":"example.com"}',
};

export default function Certs({ onError, onOK, base }: { onError: (m: string) => void; onOK: (m: string) => void; base: string }) {
  const [certs, setCerts] = useState<Cert[]>([]);
  const [providers, setProviders] = useState<string[]>([]);
  const [configured, setConfigured] = useState<string[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ domains: "", provider: "duckdns", creds: "" });

  const load = () =>
    api
      .get<{ certs: Cert[]; providers: string[]; configured: string[] }>("/api/certs")
      .then((r) => {
        const list = r.providers || [];
        setCerts(r.certs || []);
        setProviders(list);
        setConfigured(r.configured || []);
        setLoadError("");
        setLoaded(true);
        // Keep the select on a provider the server actually offered.
        if (list.length && !list.includes(form.provider)) {
          setForm((f) => ({ ...f, provider: list[0], creds: "" }));
        }
      })
      .catch((e) => {
        setProviders([]);
        setLoadError(errText(e));
        setLoaded(true);
        onError(errText(e));
      });

  useEffect(() => {
    load();
    setForm((f) => ({ ...f, domains: `*.${base},${base}` }));
  }, [base]);

  // Issuance runs in the background. Poll while a certificate is pending so the
  // row leaves "pending" (issued or failed) without a manual reload.
  const pending = certs.some((c) => c.status === "pending");
  useEffect(() => {
    if (!pending) return;
    const timer = setInterval(load, 4000);
    return () => clearInterval(timer);
  }, [pending]);

  const providersUnavailable = loaded && providers.length === 0;
  const unavailableMessage = !loaded
    ? "Loading DNS providers…"
    : loadError
      ? `DNS providers could not be loaded (${loadError}), so a certificate cannot be requested. Close this dialog, reload the page and try again.`
      : providers.length === 0
        ? "No DNS providers are available, so a certificate cannot be requested. Check the server log and try again."
        : "";

  const issue = async () => {
    if (!providers.length) {
      onError("No DNS provider is available; reload the page and try again");
      return;
    }
    const provider = form.provider;
    const example = PROVIDER_HINTS[provider] ?? "{}";
    let creds: Record<string, string> | undefined;
    const raw = form.creds.trim();
    if (raw) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        onError(`Credentials must be valid JSON, for example ${example}`);
        return;
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).length === 0) {
        onError(`Credentials must be a JSON object, for example ${example}`);
        return;
      }
      creds = parsed as Record<string, string>;
    } else if (!configured.includes(provider)) {
      // Without stored credentials the request would be accepted and then fail
      // in the background, which looks like the provider itself is broken.
      onError(`Enter ${provider} credentials as JSON, for example ${example}`);
      return;
    }
    try {
      await api.post("/api/certs", { domains: form.domains, provider, creds });
      setOpen(false);
      onOK("Certificate request started");
      setTimeout(load, 500);
    } catch (e) {
      onError(errText(e));
    }
  };

  const renew = async (c: Cert) => {
    try {
      await api.post(`/api/certs/${c.id}/renew`);
      onOK("Renewal started");
      setTimeout(load, 2500);
    } catch (e) {
      onError(errText(e));
    }
  };

  const setRenewMode = async (c: Cert, renewMode: string) => {
    try {
      await api.put(`/api/certs/${c.id}`, { renew_mode: renewMode });
      onOK("Auto-renew policy updated");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const remove = async (c: Cert) => {
    if (!confirm(`Delete certificate for ${c.domains}?`)) return;
    try {
      await api.del(`/api/certs/${c.id}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card
        title="Certificates"
        actions={<button className="primary" onClick={() => setOpen(true)}>Request certificate</button>}
      >
        {certs.length === 0 ? (
          <Empty>No certificates yet. A wildcard certificate for your base domain covers every proxy subdomain.</Empty>
        ) : (
          <table>
            <thead><tr><th>Domains</th><th>Provider</th><th>Status</th><th>Expires</th><th>Auto-renew</th><th /></tr></thead>
            <tbody>
              {certs.map((c) => (
                <tr key={c.id}>
                  <td className="mono">{c.domains}{c.wildcard ? <div className="faint" style={{ fontSize: 11 }}>wildcard</div> : null}</td>
                  <td className="muted">{c.provider}</td>
                  <td>
                    <Badge tone={c.status === "issued" ? "ok" : c.status === "error" ? "bad" : "info"}>{c.status}</Badge>
                    {c.last_error ? <div className="faint" style={{ fontSize: 11, maxWidth: 320 }}>{c.last_error}</div> : null}
                  </td>
                  <td className="muted">{fmtTime(c.expires_at)}</td>
                  <td>
                    <select
                      className="table-select"
                      aria-label={`Auto-renew for ${c.domains}`}
                      value={c.renew_mode}
                      onChange={(e) => setRenewMode(c, e.target.value)}
                    >
                      {RENEW_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                    {c.renews_at ? <div className="faint" style={{ fontSize: 11 }}>next {fmtTime(c.renews_at)}</div> : null}
                  </td>
                  <td className="right" style={{ whiteSpace: "nowrap" }}>
                    <button className="small" onClick={() => renew(c)}>Renew</button>{" "}
                    <button className="small danger" onClick={() => remove(c)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted mt" style={{ fontSize: 12 }}>
          DNS-01 is used because port 80 is not exposed. DuckDNS stores only one TXT record per domain, so use a single wildcard
          certificate there; the manager serialises ACME orders to avoid overwriting challenges.
        </p>
        <p className="muted" style={{ fontSize: 12 }}>
          Renewal is checked every 12 hours. Let&apos;s Encrypt certificates last 90 days, so the three-month policy is capped at
          seven days before expiry to leave time for a retry.
        </p>
      </Card>

      {open && (
        <Modal title="Request certificate" onClose={() => setOpen(false)}>
          <Field label="Domains (comma separated)">
            <input value={form.domains} onChange={(e) => setForm({ ...form, domains: e.target.value })} placeholder={`*.${base},${base}`} />
          </Field>
          <Field label="DNS provider">
            <select
              value={form.provider}
              disabled={!providers.length}
              onChange={(e) => setForm({ ...form, provider: e.target.value, creds: "" })}
            >
              {providers.length === 0 && <option value="">No providers available</option>}
              {providers.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </Field>
          {unavailableMessage && <div className="err-text" style={{ marginTop: 0 }}>{unavailableMessage}</div>}
          <Field label={configured.includes(form.provider) ? "Credentials (JSON, stored encrypted) — leave empty to reuse the stored ones" : "Credentials (JSON, stored encrypted)"}>
            <textarea value={form.creds} onChange={(e) => setForm({ ...form, creds: e.target.value })} placeholder={PROVIDER_HINTS[form.provider] ?? "{}"} />
          </Field>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button className="primary" onClick={issue} disabled={!loaded || providersUnavailable}>Request</button>
          </div>
        </Modal>
      )}
    </div>
  );
}
