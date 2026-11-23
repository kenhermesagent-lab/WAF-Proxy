import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Field, Modal, confirmDialog, errText, fmtTime } from "../ui";
import type { Ban, PolicyPreflight, Proxy } from "../types";

export type CommandId = "ban" | "unban" | "disable-proxy" | "preflight";

export const COMMANDS: { id: CommandId; title: string; subtitle: string; permission: string }[] = [
  { id: "ban", title: "Ban an IP…", subtitle: "Refuse every request from an address", permission: "policies.write" },
  { id: "unban", title: "Release a ban…", subtitle: "Lift an existing ban", permission: "policies.write" },
  { id: "disable-proxy", title: "Disable a proxy…", subtitle: "Stop accepting requests for a hostname", permission: "proxies.write" },
  { id: "preflight", title: "Run a preflight…", subtitle: "Test a rule against recorded traffic", permission: "policies.write" },
];

const TITLES: Record<CommandId, string> = {
  ban: "Ban a source",
  unban: "Release a ban",
  "disable-proxy": "Disable a proxy",
  preflight: "Run a policy preflight",
};

// The preflight summary names the subject the rule is about, not the rule kind.
function fromLabel(kind: string, value: string) {
  const parts = value.split(",").map((v) => v.trim()).filter(Boolean);
  if (kind === "asn_block") return parts.map((v) => `AS${v}`).join(", ");
  if (kind === "country_blacklist") return parts.map((v) => v.toUpperCase()).join(", ");
  return parts.join(", ");
}

const KINDS = [
  { value: "ip_blacklist", label: "IP or subnet", placeholder: "203.0.113.7" },
  { value: "country_blacklist", label: "Country (ISO code)", placeholder: "RU" },
  { value: "asn_block", label: "ASN (number)", placeholder: "64500" },
];

export default function QuickActions({
  command,
  canWrite,
  onClose,
  onError,
  onOK,
}: {
  command: CommandId;
  canWrite: boolean;
  onClose: () => void;
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("Banned from the command palette");
  const [hours, setHours] = useState("24");
  const [bans, setBans] = useState<Ban[]>([]);
  const [banId, setBanId] = useState("");
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [proxyId, setProxyId] = useState("");
  const [kind, setKind] = useState("ip_blacklist");
  const [value, setValue] = useState("");
  const [check, setCheck] = useState<PolicyPreflight | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (command === "unban") {
      api
        .get<{ bans: Ban[] }>("/api/bans")
        .then((r) => setBans(r.bans ?? []))
        .catch((e) => onError(errText(e)));
    }
    if (command === "disable-proxy") {
      api
        .get<Proxy[]>("/api/proxies")
        .then((r) => setProxies((r ?? []).filter((p) => p.enabled)))
        .catch((e) => onError(errText(e)));
    }
  }, [command]);

  const ban = async () => {
    const target = ip.trim();
    if (!target) return;
    const ttl = Number(hours) || 24;
    if (
      !(await confirmDialog(`Refuse every request from ${target} for ${ttl} hours? The ban is audited and can be released later.`, {
        title: "Ban source",
        confirmLabel: `Ban ${ttl}h`,
      }))
    )
      return;
    setBusy(true);
    try {
      await api.post("/api/bans", { cidr: target, reason: reason.trim() || "manual from console", permanent: false, ttl_seconds: ttl * 3600 });
      // The server keeps a stricter existing ban, so the message does not promise
      // that this request set the duration.
      onOK(`${target} banned`);
      onClose();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const unban = async () => {
    const target = bans.find((b) => String(b.id) === banId);
    if (!target) return;
    if (!(await confirmDialog(`Release the ban on ${target.cidr}?`, { title: "Release ban", confirmLabel: "Unban" }))) return;
    setBusy(true);
    try {
      await api.del(`/api/bans/${target.id}`);
      onOK(`${target.cidr} unbanned`);
      onClose();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const disableProxy = async () => {
    const p = proxies.find((x) => String(x.id) === proxyId);
    if (!p) return;
    if (
      !(await confirmDialog(
        `${p.hostname} stops accepting requests immediately. Its configuration and certificate are kept, and it can be re-enabled from the Proxies page.`,
        { title: "Disable proxy", confirmLabel: "Disable" },
      ))
    )
      return;
    setBusy(true);
    try {
      await api.put(`/api/proxies/${p.id}`, {
        hostname: p.hostname,
        enabled: false,
        cert_id: p.cert_id ?? null,
        profile_id: p.profile_id ?? null,
        protection_profile_id: p.protection_profile_id ?? null,
        access_profile_id: p.access_profile_id ?? null,
        auth_provider_id: p.auth_provider_id ?? null,
        gate_mode: p.gate_mode || "off",
        gate_secret: "",
        fingerprint: p.fingerprint || "strict",
        bot_level: p.bot_level || "light",
        maintenance: p.maintenance,
        waf_mode: p.waf_mode || "inherit",
        upstreams: p.upstreams ?? [],
        routes: p.routes ?? [],
        gate_users: p.gate_users ?? [],
      });
      onOK(`${p.hostname} disabled`);
      onClose();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const preflight = async () => {
    if (!value.trim()) return;
    setBusy(true);
    try {
      setCheck(await api.post<PolicyPreflight>("/api/policies/preflight", { kind, value: value.trim(), scope: "global", proxy_id: null, hours: 24 }));
    } catch (e) {
      setCheck(null);
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const footer =
    command === "ban" ? (
      <button className="danger" onClick={ban} disabled={busy || !ip.trim()}>
        {busy ? "Working…" : "Ban"}
      </button>
    ) : command === "unban" ? (
      <button className="danger" onClick={unban} disabled={busy || !banId}>
        {busy ? "Working…" : "Release"}
      </button>
    ) : command === "disable-proxy" ? (
      <button className="danger" onClick={disableProxy} disabled={busy || !proxyId}>
        {busy ? "Working…" : "Disable"}
      </button>
    ) : (
      <button className="primary" onClick={preflight} disabled={busy || !value.trim()}>
        {busy ? "Checking…" : "Preflight"}
      </button>
    );

  return (
    <Modal
      title={TITLES[command]}
      onClose={onClose}
      footer={
        <>
          <button onClick={onClose} disabled={busy}>Cancel</button>
          {canWrite ? footer : <button disabled>Your role cannot make this change</button>}
        </>
      }
    >
      {command === "ban" && (
        <>
          <Field label="Address or subnet" hint="An IP, or a CIDR such as 203.0.113.0/24.">
            <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.7" autoFocus />
          </Field>
          <div className="field-grid">
            <Field label="Duration (hours)">
              <select value={hours} onChange={(e) => setHours(e.target.value)}>
                <option value="1">1 hour</option>
                <option value="24">24 hours</option>
                <option value="168">7 days</option>
                <option value="720">30 days</option>
              </select>
            </Field>
            <Field label="Reason">
              <input value={reason} onChange={(e) => setReason(e.target.value)} />
            </Field>
          </div>
        </>
      )}

      {command === "unban" && (
        bans.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>No bans are in force.</p>
        ) : (
          <Field label="Ban">
            <select value={banId} onChange={(e) => setBanId(e.target.value)} autoFocus>
              <option value="">Choose a ban…</option>
              {bans.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.cidr} · {b.permanent ? "permanent" : b.expires_at ? `until ${fmtTime(b.expires_at)}` : "temporary"} · {b.reason || b.source}
                </option>
              ))}
            </select>
          </Field>
        )
      )}

      {command === "disable-proxy" && (
        proxies.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>Every proxy is already disabled.</p>
        ) : (
          <Field label="Proxy" hint="Disabled proxies keep their configuration and can be re-enabled from Proxies.">
            <select value={proxyId} onChange={(e) => setProxyId(e.target.value)} autoFocus>
              <option value="">Choose a hostname…</option>
              {proxies.map((p) => <option key={p.id} value={p.id}>{p.hostname}</option>)}
            </select>
          </Field>
        )
      )}

      {command === "preflight" && (
        <>
          <div className="field-grid">
            <Field label="Rule kind">
              <select value={kind} onChange={(e) => { setKind(e.target.value); setValue(""); setCheck(null); }} autoFocus>
                {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
              </select>
            </Field>
            <Field label="Value">
              <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={KINDS.find((k) => k.value === kind)?.placeholder ?? ""} />
            </Field>
          </div>
          <p className="faint small-text" style={{ marginTop: -4 }}>
            Replays the last 24 hours through the server's own matchers. Nothing is saved.
          </p>
          {check && (
            <div className="grid" style={{ gap: 8 }}>
              <div className={`banner ${check.matched === 0 ? "" : "warn"}`.trim()} role="status">
                <span>
                  {check.matched === 0
                    ? `No requests in the last ${check.hours}h came from ${fromLabel(kind, check.value)}.`
                    : `${check.matched.toLocaleString()} request${check.matched === 1 ? "" : "s"} from ${check.addresses} address${check.addresses === 1 ? "" : "es"} match; ${check.allowed.toLocaleString()} ${check.allowed === 1 ? "is" : "are"} served and ${check.blocked.toLocaleString()} refused today.`}
                </span>
              </div>
              {check.notes.map((n) => <div className="faint small-text" key={n}>{n}</div>)}
              {check.hosts.length > 0 && (
                <div className="facts">
                  {check.hosts.slice(0, 6).map((h) => <Badge key={h}>{h}</Badge>)}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </Modal>
  );
}
