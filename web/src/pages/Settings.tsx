import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import Icon from "../components/Icon";
import { COFFEE_URL, DOCS_URL } from "../links";
import { Badge, Field, PageHead, SaveBar, Switch, TableWrap, errText, fmtAgo, fmtTime } from "../ui";
import type { AuditEntry, CrowdSecStatus, GeoIPStatus, Me } from "../types";
import BackupCard from "../components/BackupCard";
import UpdatesPage from "./Updates";
import Readiness from "./Readiness";

type Settings = Record<string, string>;

// The parts of /api/ha the Settings switch needs for its help text.
type HAInfo = { enabled?: boolean; boot_enabled?: boolean; paired?: boolean; reason?: string };

const RUNTIME_KEYS = new Set(["kernel", "geoip", "iface_available", "host_wide_keys"]);
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
  { id: "updates", label: "Updates" },
  { id: "protection", label: "Protection" },
  { id: "retention", label: "Retention & ACME" },
  { id: "ha", label: "High availability" },
  { id: "backup", label: "Backup" },
  { id: "runtime", label: "Runtime status" },
  { id: "geoip", label: "GeoIP database" },
  { id: "activity", label: "Administrator activity" },
  { id: "readiness", label: "Readiness" },
  { id: "about", label: "About" },
];

export default function SettingsPage({ onError, onOK, version = "", me }: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  version?: string;
  me?: Me | null;
}) {
  const [s, setS] = useState<Settings>({});
  const [saved, setSaved] = useState<Settings>({});
  const [saving, setSaving] = useState(false);
  const [cs, setCs] = useState<CrowdSecStatus | null>(null);
  const [geo, setGeo] = useState<GeoIPStatus | null>(null);
  const [installingGeo, setInstallingGeo] = useState(false);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [chain, setChain] = useState("");
  const [backupPass, setBackupPass] = useState("");
  const [haInfo, setHaInfo] = useState<HAInfo | null>(null);
  const [activeSection, setActiveSection] = useState("network");
  const [iface, setIface] = useState<{ wan: string; lan: string; wanAuto: boolean; lanAuto: boolean; available: string[] }>({
    wan: "", lan: "", wanAuto: false, lanAuto: false, available: [],
  });
  const file = useRef<HTMLInputElement>(null);
  const yamlFile = useRef<HTMLInputElement>(null);

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

  const verifyChain = () =>
    api
      .get<{ ok: boolean; checked: number; problem?: string }>("/api/audit/verify")
      .then((r) =>
        setChain(r.ok ? `Hash chain intact across ${r.checked} entries.` : `${r.problem ?? "The chain does not match"}.`),
      )
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
    api.get<HAInfo>("/api/ha").then(setHaInfo).catch(() => setHaInfo(null));
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
    // Nearest section head to the top of the viewport, so the last short
    // sections still highlight when the page cannot scroll them any higher.
    const onScroll = () => {
      let current = SECTIONS[0].id;
      let best = Infinity;
      for (const sec of SECTIONS) {
        const el = document.getElementById(sec.id);
        if (!el) continue;
        const distance = Math.abs(el.getBoundingClientRect().top - 140);
        if (distance < best) {
          best = distance;
          current = sec.id;
        }
      }
      setActiveSection(current);
    };
    onScroll();
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

  type ImportResult = { imported: Record<string, number>; problems: string[] };

  const download = async (path: string) => {
    try {
      const headers: Record<string, string> = {};
      if (backupPass) headers["X-Backup-Passphrase"] = backupPass;
      const { blob, name } = await api.download(path, headers);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      onError(errText(e));
    }
  };

  const reportImport = (r: ImportResult, verb: string) => {
    const parts = Object.entries(r.imported || {}).map(([k, v]) => `${v} ${k}`);
    onOK(`${verb} ${parts.join(", ")}${r.problems?.length ? ` (${r.problems.length} skipped)` : ""}`);
    load();
  };

  const restore = async (f: File) => {
    try {
      // The encrypted body is binary, so it must not pass through text().
      const body = await f.arrayBuffer();
      const sealed = new TextDecoder().decode(body.slice(0, 13)) === "WAFPROXY-ENC1";
      const r = sealed
        ? await api.postRaw<ImportResult>("/api/backup/restore", new Blob([body]), {
            "Content-Type": "application/octet-stream",
            "X-Backup-Passphrase": backupPass,
          })
        : await api.post<ImportResult>("/api/backup/restore", JSON.parse(new TextDecoder().decode(body)));
      reportImport(r, "Restored");
    } catch (e) {
      onError(errText(e));
    }
  };

  const importYAML = async (f: File) => {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/yaml" };
      if (backupPass) headers["X-Backup-Passphrase"] = backupPass;
      const r = await api.postRaw<ImportResult>("/api/config/import.yaml", new Blob([await f.arrayBuffer()]), headers);
      reportImport(r, "Imported");
    } catch (e) {
      onError(errText(e));
    }
  };

  // The server returns the process-wide keys with the settings, so a site
  // console can leave them out of its save instead of posting them and being
  // refused as a whole.
  const siteEditable = (v: Settings): Settings => {
    const out = editable(v);
    if (hostWide) {
      for (const k of (s.host_wide_keys ?? "").split(",")) {
        if (k) delete out[k.trim()];
      }
    }
    return out;
  };

  const save = async () => {
    setSaving(true);
    try {
      await api.put("/api/settings", siteEditable(s));
      onOK("Settings saved");
      setSaved(editable(s));
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  // Network, updates and GeoIP bind the whole process, so their controls are
  // host-wide. A non-default site's console can read them and is refused on
  // save, so the form says so and turns them off instead of failing late.
  const hostWide = !!me?.site && me.site !== "default";
  const hostWideNote = (
    <p className="faint small-text" style={{ marginTop: -2 }}>
      Host-wide setting: it belongs to the default site's console and is read-only here.
    </p>
  );
  const ifaceHint = (name: string, auto: boolean) =>
    name ? `${name} (${auto ? "auto-detected" : "configured"})` : "— (none detected)";
  // The boot switch and the site console both own this decision, so the switch
  // explains which one is in the way instead of failing on save.
  const mayToggleHA = !hostWide && me?.role !== "host_admin";
  const haHelp = !mayToggleHA
    ? "Only an administrator on the default site can change this."
    : haInfo && haInfo.boot_enabled === false
      ? "Locked off: this host booted with WAFPROXY_HA_ENABLE=0. Set it to 1, restart, then use this switch."
      : haInfo?.enabled && haInfo.paired
        ? "This node is paired. Turning it off stops replication and the HA API on this node; the pair stays configured for when you turn it back on."
        : haInfo?.enabled
          ? "High availability is on but this node is not paired yet. Pair it from the High availability page to finish setup."
          : "Starts the HA role machine, replication and the management API on this node. Traffic does not move until you pair and run a move.";

  return (
    <>
    <PageHead
      sub={
        hostWide
          ? `Settings for ${me?.site_name ?? "this site"}. Protection, retention and backup apply to this site. The inspected body cap and the host-wide sections are read-only here.`
          : "Node networking, protection defaults, retention, updates and the hardening checklist."
      }
      actions={<Badge tone="info">Site: {me?.site_name ?? "default"}</Badge>}
    />
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
        <section id="network" className="settings-section card">
          <div className="section-head">
            <h2>Network</h2>
            <p>Listener addresses are read from the database at boot. Only 443 needs to be forwarded from the WAN.</p>
          </div>
          {hostWide && hostWideNote}
          <fieldset disabled={hostWide} style={{ border: 0, padding: 0, margin: 0 }}>
          <div className="field-grid">
            <Field label="WAN address (443 listener)"><input value={s.wan_ip ?? ""} onChange={(e) => set("wan_ip", e.target.value)} placeholder="192.168.191.2" /></Field>
            <Field label="WAN port"><input value={s.wan_port ?? "443"} onChange={(e) => set("wan_port", e.target.value)} /></Field>
            <Field label="LAN egress address"><input value={s.lan_ip ?? ""} onChange={(e) => set("lan_ip", e.target.value)} placeholder="10.0.0.2" /></Field>
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
          </fieldset>
        </section>

        <section id="updates" className="settings-section">
          <div className="section-head">
            <h2>Updates</h2>
            <p>Console and host package versions, with the restart that applies a rebuild.</p>
          </div>
          {hostWide && hostWideNote}
          <fieldset disabled={hostWide} style={{ border: 0, padding: 0, margin: 0 }}>
            <UpdatesPage onError={onError} onOK={onOK} head={false} />
          </fieldset>
        </section>

        <section id="protection" className="settings-section card">
          <div className="section-head">
            <h2>Protection</h2>
            <p>
              {hostWide
                ? `Rate limits and normalization apply to ${me?.site_name ?? "this site"}. The max inspected body is one process-wide buffer and is set on the default site's console.`
                : "Global defaults applied before per-proxy profiles. Rate limits and normalization are per site."}
            </p>
          </div>
          <div className="field-grid">
            <Field label="Global rate limit (rps/IP)" hint={hostWide ? "Applies to this site." : undefined}><input value={s.dos_rps ?? "100"} onChange={(e) => set("dos_rps", e.target.value)} /></Field>
            <Field label="Burst" hint={hostWide ? "Applies to this site." : undefined}><input value={s.dos_burst ?? "200"} onChange={(e) => set("dos_burst", e.target.value)} /></Field>
            <Field
              label="Max inspected body (bytes)"
              hint={hostWide ? "Host-wide: the proxy buffers every site's requests up to the default site's value, so this field is read-only here." : "Process-wide request buffer; per-profile body limits still apply."}
            >
              <input value={s.max_body ?? "131072"} onChange={(e) => set("max_body", e.target.value)} disabled={hostWide} />
            </Field>
            <Field label="Sample allowed above (rps)" hint="Per-site sampling threshold for the request log."><input value={s.sample_above_rps ?? "500"} onChange={(e) => set("sample_above_rps", e.target.value)} /></Field>
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
            <Field label="Event retention (days, 1–30)" hint="Deletes this site's events after this many days."><input value={s.retention_days ?? "7"} onChange={(e) => set("retention_days", e.target.value)} /></Field>
            <Field label="ACME account email"><input value={s.acme_email ?? ""} onChange={(e) => set("acme_email", e.target.value)} placeholder="admin@your-domain.tld" /></Field>
          </div>
          <Switch label="Use the Let's Encrypt staging directory" help="Issues untrusted certificates for testing; switch off before going live." checked={s.acme_staging === "1"} onChange={(v) => set("acme_staging", v ? "1" : "0")} />
        </section>

        <section id="ha" className="settings-section card">
          <div className="section-head">
            <h2>High availability</h2>
            <p>Two nodes, one service address. Off by default, and the data plane does not change until a move.</p>
          </div>
          <Switch
            label="Enable high availability"
            help={haHelp}
            checked={s.ha_enabled === "1"}
            onChange={(v) => set("ha_enabled", v ? "1" : "0")}
            disabled={!mayToggleHA || haInfo?.boot_enabled === false}
          />
          {hostWide && hostWideNote}
          <p className="faint small-text">
            Status, pairing and moves live on the <a href="#/ha">High availability page</a>.
          </p>
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
            <div>{s.kernel === "active" ? <Badge tone="ok">active</Badge> : <span className="badge wrap warn">{s.kernel || "unknown"}</span>}</div>
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
              <div className="faint small-text">configure under Threat intel → CrowdSec</div>
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
            <div className="row" style={{ gap: 6 }}>
              <button className="small" onClick={() => download("/api/backup")}>Download JSON</button>
              <button className="small" onClick={() => download("/api/config/export.yaml")}>Download YAML</button>
            </div>
          </div>
          <div className="bar-row">
            <div>Restore backup <span className="faint small-text">(additive, gates reset to off)</span></div>
            <div>
              <div className="row" style={{ gap: 8 }}>
                <input
                  type="password"
                  value={backupPass}
                  onChange={(e) => setBackupPass(e.target.value)}
                  placeholder="Passphrase (16+ chars) to encrypt or restore"
                  style={{ width: 200 }}
                />
                <input ref={file} type="file" accept=".json,.enc,application/json" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && restore(e.target.files[0])} />
                <input ref={yamlFile} type="file" accept=".yaml,.yml,.enc" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && importYAML(e.target.files[0])} />
                <button className="small" onClick={() => file.current?.click()}>Import backup</button>
                <button className="small" onClick={() => yamlFile.current?.click()}>Import YAML</button>
              </div>
            </div>
          </div>
          <p className="faint small-text">
            Backups exclude secrets, private keys and password hashes. Re-issue certificates and reset passwords after restoring.
          </p>
        </section>

        <section id="geoip" className="settings-section card">
          {hostWide && hostWideNote}
          <fieldset disabled={hostWide} style={{ border: 0, padding: 0, margin: 0 }}>
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
          </fieldset>
        </section>

        <section id="activity" className="settings-section card">
          <div className="card-head">
            <h2>Recent administrator activity</h2>
            <div className="actions">
              <button className="small" onClick={verifyChain}>Verify chain</button>
              <button className="small" onClick={loadAudit}>Refresh</button>
            </div>
          </div>
          {audit.length === 0 ? (
            <p className="muted small-text" style={{ margin: 0 }}>No audit entries yet.</p>
          ) : (
            <TableWrap>
              <table className="audit-table">
                <thead>
                  <tr><th>Time</th><th className="hide-compact">User</th><th>Action</th><th>Detail</th><th className="hide-compact">Source</th></tr>
                </thead>
                <tbody>
                  {audit.map((a) => (
                    <tr key={a.id}>
                      <td className="muted">{fmtTime(a.ts)}</td>
                      <td className="mono hide-compact">{a.user}</td>
                      <td>{a.action}</td>
                      <td className="muted audit-detail" title={a.detail}>{a.detail || "—"}</td>
                      <td className="mono hide-compact">{a.ip || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
          {chain && <p className="faint small-text">{chain}</p>}
          <p className="faint small-text">
            Newest 20 entries: sign-ins, sign-outs, settings changes, proxy and certificate changes, bans and restores.
          </p>
        </section>

        <section id="readiness" className="settings-section">
          <div className="section-head">
            <h2>Readiness</h2>
            <p>What a hardened install has that a working one may not. Every row links to the control that fixes it.</p>
          </div>
          <Readiness me={me ?? null} onError={onError} head={false} />
        </section>

        <section id="about" className="settings-section card">
          <div className="section-head">
            <h2>About</h2>
            <p>WAF-Proxy is a self-hosted web application firewall and reverse proxy.</p>
          </div>
          <div className="bar-row">
            <div>Console version</div>
            <div className="mono">{version ? `v${version}` : "unknown"}</div>
          </div>
          <div className="bar-row">
            <div>Documentation</div>
            <div><a className="link-button" href={DOCS_URL} target="_blank" rel="noreferrer"><Icon name="external" size={14} /> Operations guide</a></div>
          </div>
          <div className="bar-row">
            <div>
              Buy me a coffee
              <div className="faint small-text">Optional tip for the maintainer; nothing in the console depends on it.</div>
            </div>
            <div><a className="link-button" href={COFFEE_URL} target="_blank" rel="noreferrer"><Icon name="coffee" size={14} /> Buy me a coffee</a></div>
          </div>
        </section>

        {/* Only present while something is unsaved, so it never hovers over fields. */}
        {(dirty > 0 || saving) && (
          <SaveBar
            note={<><b>{dirty} unsaved change{dirty === 1 ? "" : "s"}</b> · changes apply after saving</>}
            saving={saving}
            onDiscard={() => { setS({ ...saved }); onOK("Unsaved changes discarded"); }}
            onSave={save}
          />
        )}
      </div>
    </div>
    </>
  );
}
