import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Modal, errText, fmtTime } from "../ui";
import { Cert } from "../types";

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
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ domains: "", provider: "duckdns", creds: "" });

  const load = () =>
    api
      .get<{ certs: Cert[]; providers: string[]; configured: string[] }>("/api/certs")
      .then((r) => {
        setCerts(r.certs || []);
        setProviders(r.providers || []);
        setConfigured(r.configured || []);
      })
      .catch((e) => onError(errText(e)));

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

  const issue = async () => {
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
            <thead><tr><th>Domains</th><th>Provider</th><th>Status</th><th>Expires</th><th /></tr></thead>
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
      </Card>

      {open && (
        <Modal title="Request certificate" onClose={() => setOpen(false)}>
          <Field label="Domains (comma separated)">
            <input value={form.domains} onChange={(e) => setForm({ ...form, domains: e.target.value })} placeholder={`*.${base},${base}`} />
          </Field>
          <Field label="DNS provider">
            <select value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value, creds: "" })}>
              {providers.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </Field>
          <Field label={configured.includes(form.provider) ? "Credentials (JSON, stored encrypted) — leave empty to reuse the stored ones" : "Credentials (JSON, stored encrypted)"}>
            <textarea value={form.creds} onChange={(e) => setForm({ ...form, creds: e.target.value })} placeholder={PROVIDER_HINTS[form.provider] ?? "{}"} />
          </Field>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button className="primary" onClick={issue}>Request</button>
          </div>
        </Modal>
      )}
    </div>
  );
}
