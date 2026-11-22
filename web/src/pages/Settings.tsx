import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { Badge, Field, PageHead, Switch, TableWrap, errText, fmtAgo, fmtTime } from "../ui";
import type { AuditEntry, CrowdSecStatus, GeoIPStatus } from "../types";
import BackupCard from "../components/BackupCard";

type Settings = Record<string, string>;

const RUNTIME_KEYS = new Set(["kernel", "geoip", "iface_available"]);
function editable(s: Settings): Settings {
  const out: Settings = {};
  for (const [k, v] of Object.entries(s)) {
    if (RUNTIME_KEYS.has(k) || k.endsWith("_in_use") || k.endsWith("_auto")) continue;
    out[k] = v;
  }
  return out;
}

const SECTIONS = [
  { id: "network", label: "Network" },
  { id: "protection", label: "Protection" },
  { id: "retention", label: "Retention & ACME" },
  { id: "backup", label: "Backup" },
  { id: "runtime", label: "Runtime status" },
  { id: "geoip", label: "GeoIP database" },
  { id: "activity", label: "Administrator activity" },
];

export default function SettingsPage({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [s, setS] = useState<Settings>({});
  const [saved, setSaved] = useState<Settings>({});
  const [saving, setSaving] = useState(false);
  const [cs, setCs] = useState<CrowdSecStatus | null>(null);
  const [geo, setGeo] = useState<GeoIPStatus | null>(null);
  const [installingGeo, setInstallingGeo] = useState(false);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [activeSection, setActiveSection] = useState("network");
  const [iface, setIface] = useState<{ wan: string; lan: string; wanAuto: boolean; lanAuto: boolean; available: string[] }>({
    wan: "", lan: "", wanAuto: false, lanAuto: false, available: [],
  });
  const file = useRef<HTMLInputElement>(null);

  const load = () =>
    api
      .get<Settings>("/api/settings")
      .then((v) => {
        setS(v);
        setSaved(editable(v));
        setIface({
          wan: v.wan_iface_in_use ?? "",
          lan: v.lan_iface_in_use ?? "",
          wanAuto: v.wan_iface_auto === "1",
          lanAuto: v.lan_iface_auto === "1",
          available: (v.iface_available ?? "").split(",").map((n) => n.trim()).filter(Boolean),
        });
      })
      .catch((e) => onError(errText(e)));

  const loadGeo = () => api.get<GeoIPStatus>("/api/geoip").then(setGeo).catch(() => undefined);
  const loadAudit = () =>
    api.get<AuditEntry[]>("/api/audit").then((r) => setAudit((r || []).slice(0, 20))).catch(() => undefined);

  useEffect(() => {
    load();
    api.get<CrowdSecStatus>("/api/crowdsec/status").then(setCs).catch(() => undefined);
    loadGeo();
    loadAudit();
  }, []);

  useEffect(() => {
    if (!geo?.installing) return;
    const t = setInterval(loadGeo, 2000);
    return () => clearInterval(t);
  }, [geo?.installing]);

  useEffect(() => {
    const onScroll = () => {
      let current = SECTIONS[0].id;
      for (const sec of SECTIONS) {
        const el = document.getElementById(sec.id);
        if (el && el.getBoundingClientRect().top <= 140) current = sec.id;
      }
      setActiveSection(current);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const dirty = useMemo(() => {
    const a = editable(s);
    const keys = new Set([...Object.keys(a), ...Object.keys(saved)]);
    return [...keys].filter((k) => (a[k] ?? "") !== (saved[k] ?? "")).length;
  }, [s, saved]);

  const installGeo = async () => {
    setInstallingGeo(true);
    try {
      await api.post("/api/geoip/install");
      onOK("Downloading DB-IP Lite city and ASN databases");
      setGeo((prev) => (prev ? { ...prev, installing: true, last_error: "" } : prev));
      setTimeout(loadGeo, 1500);
    } catch (e) {
      onError(errText(e));
    } finally {
      setInstallingGeo(false);
    }
  };

  const set = (k: string, v: string) => setS((prev) => ({ ...prev, [k]: v }));

  const restore = async (f: File) => {
    try {
      const parsed = JSON.parse(await f.text());
      const r = await api.post<{ imported: Record<string, number>; problems: string[] }>("/api/backup/restore", parsed);
      const parts = Object.entries(r.imported || {}).map(([k, v]) => `${v} ${k}`);
      onOK(`Restored ${parts.join(", ")}${r.problems?.length ? ` (${r.problems.length} skipped)` : ""}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const save = async () => {
    setSaving(true);
    try {
      await api.put("/api/settings", editable(s));
      onOK("Settings saved");
      setSaved(editable(s));
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const ifaceHint = (name: string, auto: boolean) =>
    name ? `${name} (${auto ? "auto-detected" : "configured"})` : "— (none detected)";

  return (
    <div className="settings-layout">
      <nav className="settings-nav" aria-label="Settings sections">
        {SECTIONS.map((sec) => (
          <a
            key={sec.id}
            href={`#${sec.id}`}
            className={activeSection === sec.id ? "active" : ""}
            onClick={(e) => { e.preventDefault(); document.getElementById(sec.id)?.scrollIntoView({ behavior: "smooth", block: "start" }); }}
          >
            {sec.label}
          </a>
        ))}
      </nav>

      <div className="settings-sections">
        <PageHead title="Settings" sub="Node networking, protection defaults, retention and administrator controls." />

        <section id="network" className="settings-section card">
          <div className="section-head">
            <h2>Network</h2>
            <p>Listener addresses are read from the database at boot. Only 443 needs to be forwarded from the WAN.</p>
          </div>
          <div className="field-grid">
            <Field label="WAN address (443 listener)"><input value={s.wan_ip ?? ""} onChange={(e) => set("wan_ip", e.target.value)} placeholder="192.168.191.2" /></Field>
            <Field label="WAN port"><input value={s.wan_port ?? "443"} onChange={(e) => set("wan_port", e.target.value)} /></Field>
            <Field label="LAN egress address"><input value={s.lan_ip ?? ""} onChange={(e) => set("lan_ip", e.target.value)} placeholder="192.168.101.2" /></Field>
            <Field label="Admin GUI port"><input value={s.gui_port ?? "8443"} onChange={(e) => set("gui_port", e.target.value)} /></Field>
            <Field label="WAN interface"><input list="iface-names" value={s.wan_iface ?? ""} onChange={(e) => set("wan_iface", e.target.value)} placeholder={iface.wan || "eth0"} /></Field>
            <Field label="LAN interface"><input list="iface-names" value={s.lan_iface ?? ""} onChange={(e) => set("lan_iface", e.target.value)} placeholder={iface.lan || "eth1"} /></Field>
            <Field label="Home latitude (globe)"><input value={s.home_lat ?? "51.5"} onChange={(e) => set("home_lat", e.target.value)} /></Field>
            <Field label="Home longitude"><input value={s.home_lon ?? "-0.12"} onChange={(e) => set("home_lon", e.target.value)} /></Field>
          </div>
          <datalist id="iface-names">
            {iface.available.map((n) => <option key={n} value={n} />)}
          </datalist>
          <p className="faint small-text">
            Sampling WAN <span className="mono">{ifaceHint(iface.wan, iface.wanAuto)}</span> · LAN <span className="mono">{ifaceHint(iface.lan, iface.lanAuto)}</span>.
            Available: {iface.available.length ? <span className="mono">{iface.available.join(", ")}</span> : "none found"}.
          </p>
          <Field
            label="Admin allowlist (IPs / CIDRs)"
            hint="When set, only these addresses can open the sign-in form or call the admin API. Clear the field to allow any address again. A save that would exclude your current address is refused."
          >
            <input value={s.admin_allow_cidrs ?? ""} onChange={(e) => set("admin_allow_cidrs", e.target.value)} placeholder="192.168.0.0/16, 10.0.0.0/8" />
          </Field>
          <p className="faint small-text">
            Both addresses must exist on this host. A single-NIC host uses the same address for WAN and LAN; firewall the GUI port from the WAN.
            Restart the service after changing bind addresses.
          </p>
        </section>

        <section id="protection" className="settings-section card">
          <div className="section-head">
            <h2>Protection</h2>
            <p>Global defaults applied before per-proxy profiles.</p>
          </div>
          <div className="field-grid">
            <Field label="Global rate limit (rps/IP)"><input value={s.dos_rps ?? "100"} onChange={(e) => set("dos_rps", e.target.value)} /></Field>
            <Field label="Burst"><input value={s.dos_burst ?? "200"} onChange={(e) => set("dos_burst", e.target.value)} /></Field>
            <Field label="Max inspected body (bytes)"><input value={s.max_body ?? "131072"} onChange={(e) => set("max_body", e.target.value)} /></Field>
            <Field label="Sample allowed above (rps)"><input value={s.sample_above_rps ?? "500"} onChange={(e) => set("sample_above_rps", e.target.value)} /></Field>
          </div>
          <Field label="Request normalization" hint="Duplicate parameters and double encoding from the release checks.">
            <select value={s.normalization_mode ?? "flag"} onChange={(e) => set("normalization_mode", e.target.value)}>
              <option value="off">Off</option>
              <option value="flag">Flag in the event log</option>
              <option value="block">Block</option>
            </select>
          </Field>
          <Switch label="Protection pipeline enabled" checked={s.protection_enabled !== "0"} onChange={(v) => set("protection_enabled", v ? "1" : "0")} />
          <Switch label="Block hosting / VPS / cloud ASNs by default" help="Requires an ASN database; skipped and reported when unavailable." checked={s.asn_block !== "0"} onChange={(v) => set("asn_block", v ? "1" : "0")} />
          <Switch label="Stealth mode (DROP, no reset)" checked={s.stealth_drop !== "0"} onChange={(v) => set("stealth_drop", v ? "1" : "0")} />
          <Switch label="Ignore ICMP echo on the WAN interface" checked={s.stealth_ping === "1"} onChange={(v) => set("stealth_ping", v ? "1" : "0")} />
          <Field label="Decoy hostnames" hint="Requests for these names never reach a proxy and permanently ban the source. Comma separated.">
            <textarea value={s.decoy_hosts ?? ""} onChange={(e) => set("decoy_hosts", e.target.value)} placeholder="admin.example.org, old-panel" />
          </Field>
        </section>

        <section id="retention" className="settings-section card">
          <div className="section-head">
            <h2>Retention &amp; ACME</h2>
            <p>Event storage and certificate issuance defaults.</p>
          </div>
          <div className="field-grid">
            <Field label="Event retention (days, 1–30)"><input value={s.retention_days ?? "7"} onChange={(e) => set("retention_days", e.target.value)} /></Field>
            <Field label="ACME account email"><input value={s.acme_email ?? ""} onChange={(e) => set("acme_email", e.target.value)} placeholder="admin@your-domain.tld" /></Field>
          </div>
          <Switch label="Use the Let's Encrypt staging directory" help="Issues untrusted certificates for testing; switch off before going live." checked={s.acme_staging === "1"} onChange={(v) => set("acme_staging", v ? "1" : "0")} />
        </section>

        <section id="backup" className="settings-section">
          <BackupCard onError={onError} onOK={onOK} />
        </section>

        <section id="runtime" className="settings-section card">
          <div className="section-head">
            <h2>Runtime status</h2>
            <p>Live state of the enforcement and integration layers.</p>
          </div>
          <div className="bar-row">
            <div>Kernel ban enforcement</div>
            <div>{s.kernel === "active" ? <Badge tone="ok">active</Badge> : <Badge tone="warn">{s.kernel || "unknown"}</Badge>}</div>
          </div>
          <div className="bar-row">
            <div>GeoIP database</div>
            <div>{s.geoip === "true" ? <Badge tone="ok">loaded</Badge> : <Badge tone="warn">not loaded</Badge>}</div>
          </div>
          <div className="bar-row">
            <div>CrowdSec bouncer</div>
            <div>
              {cs?.configured
                ? <Badge tone="ok">stream · {cs.applied} applied</Badge>
                : <Badge tone="warn">{cs?.lapi_configured ? "configured, not connected" : "disabled"}</Badge>}
              <div className="faint small-text">configure on the CrowdSec page</div>
            </div>
          </div>
          {cs?.configured && (
            <div className="bar-row">
              <div>LAPI last poll</div>
              <div className="muted small-text">{cs.last_poll ? fmtAgo(cs.last_poll) : "waiting"} · <span className="mono">{cs.lapi}</span></div>
            </div>
          )}
          {cs?.last_error && (
            <div className="bar-row">
              <div>CrowdSec last error</div>
              <div className="err-text" style={{ margin: 0 }}>{cs.last_error}</div>
            </div>
          )}
          <div className="bar-row">
            <div>Configuration backup</div>
            <div><a href="/api/backup"><button className="small">Download JSON</button></a></div>
          </div>
          <div className="bar-row">
            <div>Restore backup <span className="faint small-text">(additive, gates reset to off)</span></div>
            <div>
              <input ref={file} type="file" accept="application/json" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && restore(e.target.files[0])} />
              <button className="small" onClick={() => file.current?.click()}>Import JSON</button>
            </div>
          </div>
          <p className="faint small-text">
            Backups exclude secrets, private keys and password hashes. Re-issue certificates and reset passwords after restoring.
          </p>
        </section>

        <section id="geoip" className="settings-section card">
          <div className="card-head">
            <h2>GeoIP database</h2>
            <div className="actions">
              <button className="small primary" onClick={installGeo} disabled={installingGeo || geo?.installing}>
                {geo?.installing ? "Installing…" : geo?.available ? "Update database" : "Install database"}
              </button>
            </div>
          </div>
          <div className="bar-row">
            <div>City database</div>
            <div>
              {geo?.city ? <Badge tone="ok">loaded</Badge> : <Badge tone="warn">missing</Badge>}
              {geo?.city_updated && <span className="faint small-text" style={{ marginLeft: 8 }}>updated {fmtTime(geo.city_updated)}</span>}
            </div>
          </div>
          <div className="bar-row">
            <div>ASN database</div>
            <div>
              {geo?.asn ? <Badge tone="ok">loaded</Badge> : <Badge tone="warn">missing</Badge>}
              {geo?.asn_updated && <span className="faint small-text" style={{ marginLeft: 8 }}>updated {fmtTime(geo.asn_updated)}</span>}
            </div>
          </div>
          <div className="bar-row">
            <div>
              Automatic update
              <div className="faint small-text">Refresh daily when a database is installed.</div>
            </div>
            <Switch label="" checked={s.geoip_auto_update !== "0"} onChange={(v) => set("geoip_auto_update", v ? "1" : "0")} />
          </div>
          <div className="bar-row">
            <div>Database source</div>
            <div className="muted small-text">DB-IP Lite · country and ASN rules pick up a new database without a restart</div>
          </div>
          {geo?.installing && <p className="muted small-text">Downloading and validating the databases. This can take a few minutes.</p>}
          {geo?.last_error && <p className="err-text">{geo.last_error}</p>}
          <p className="faint small-text">
            Free DB-IP Lite databases are licensed under CC BY 4.0. <a href="https://db-ip.com" target="_blank" rel="noreferrer">IP Geolocation by DB-IP</a>.
          </p>
        </section>

        <section id="activity" className="settings-section card">
          <div className="card-head">
            <h2>Recent administrator activity</h2>
            <div className="actions">
              <button className="small" onClick={loadAudit}>Refresh</button>
            </div>
          </div>
          {audit.length === 0 ? (
            <p className="muted small-text" style={{ margin: 0 }}>No audit entries yet.</p>
          ) : (
            <TableWrap>
              <table>
                <thead>
                  <tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>Source</th></tr>
                </thead>
                <tbody>
                  {audit.map((a) => (
                    <tr key={a.id}>
                      <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(a.ts)}</td>
                      <td className="mono">{a.user}</td>
                      <td>{a.action}</td>
                      <td className="muted" style={{ maxWidth: 380, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={a.detail}>{a.detail || "—"}</td>
                      <td className="mono">{a.ip || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
          <p className="faint small-text">
            Newest 20 entries: sign-ins, sign-outs, settings changes, proxy and certificate changes, bans and restores.
          </p>
        </section>

        <div className="save-bar">
          <span className="dirty">
            {dirty > 0 ? <><b>{dirty} unsaved change{dirty === 1 ? "" : "s"}</b> · changes apply after saving</> : "All changes saved"}
          </span>
          <span className="actions">
            <button disabled={dirty === 0 || saving} onClick={() => { setS({ ...saved }); onOK("Unsaved changes discarded"); }}>
              Discard
            </button>
            <button className="primary" onClick={save} disabled={saving || dirty === 0}>
              {saving ? "Saving…" : "Save settings"}
            </button>
          </span>
        </div>
      </div>
    </div>
  );
}
