import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import Icon from "../components/Icon";
import { COFFEE_URL, DOCS_URL } from "../links";
import { NAV } from "../nav";
import { Badge, Field, PageHead, PageTabs, SaveBar, Switch, TableWrap, confirmDialog, errText, fmtAgo, fmtTime } from "../ui";
import type { AuditEntry, CrowdSecStatus, GeoIPStatus, IntelStatus, Me } from "../types";
import { describePlan, quotaView } from "../threatintel";
import BackupCard from "../components/BackupCard";
import UpdatesPage from "./Updates";
import Readiness from "./Readiness";

type Settings = Record<string, string>;

const RUNTIME_KEYS = new Set(["kernel", "geoip", "iface_available", "host_wide_keys", "site_slug", "site_name"]);

// The parts of /api/ha the Settings switch needs for its help text.
type HAInfo = { enabled?: boolean; paired?: boolean; cluster_id?: string; reason?: string };

function haSwitchHelp(hostWide: boolean, me: Me | null | undefined, info: HAInfo | null): string {
  if (hostWide || me?.role === "host_admin") {
    return "Only an administrator on the default site can change this.";
  }
  if (info?.enabled && info.paired) {
    return "This node is paired. Turning it off stops replication and the HA API on this node; the pair stays configured for when you turn it back on.";
  }
  if (info?.enabled) {
    return "High availability is on but this node is not paired yet. Pair it from the High availability page to finish setup.";
  }
  return "Starts the HA role machine, replication and the management API on this node. Traffic does not move until you pair and run a move.";
}

function editable(s: Settings): Settings {
  const out: Settings = {};
  for (const [k, v] of Object.entries(s)) {
    if (RUNTIME_KEYS.has(k) || k.endsWith("_in_use") || k.endsWith("_auto")) continue;
    out[k] = v;
  }
  return out;
}

// The tab strip is the nav's own list, so a label cannot drift between them.
const SECTIONS = NAV.find((n) => n.id === "settings")?.tabs ?? [];

export default function SettingsPage({ onError, onOK, version = "", me, onMeChanged, tab, tabs, onTab }: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  version?: string;
  me?: Me | null;
  // Called after a save that changes the HA switch, so the nav follows /api/me.
  onMeChanged?: () => void;
  // The page's tab is its route, as on every other tabbed page. The local copy
  // keeps the switch instant and lets the page stand alone without a router.
  tab?: string;
  tabs?: { id: string; label: string }[];
  onTab?: (id: string) => void;
}) {
  const [s, setS] = useState<Settings>({});
  const [saved, setSaved] = useState<Settings>({});
  const [saving, setSaving] = useState(false);
  const [cs, setCs] = useState<CrowdSecStatus | null>(null);
  const [geo, setGeo] = useState<GeoIPStatus | null>(null);
  const [intel, setIntel] = useState<IntelStatus | null>(null);
  const [intelKey, setIntelKey] = useState("");
  const [intelBusy, setIntelBusy] = useState(false);
  const [installingGeo, setInstallingGeo] = useState(false);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [chain, setChain] = useState("");
  const [backupPass, setBackupPass] = useState("");
  const [haInfo, setHaInfo] = useState<HAInfo | null>(null);
  const [haConfirm, setHaConfirm] = useState("");
  // Set while the supervisor restarts the process for the first HA enable, so
  // the page waits for the service instead of firing requests at it.
  const [restart, setRestart] = useState<"idle" | "restarting" | "lost">("idle");
  const [active, setActive] = useState(tab ?? "network");
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

  const loadHA = () => api.get<HAInfo>("/api/ha").then(setHaInfo).catch(() => setHaInfo(null));
  const loadGeo = () => api.get<GeoIPStatus>("/api/geoip").then(setGeo).catch(() => undefined);
  const loadIntel = () => api.get<IntelStatus>("/api/threat-intel").then(setIntel).catch(() => undefined);
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
    loadHA();
    api.get<CrowdSecStatus>("/api/crowdsec/status").then(setCs).catch(() => undefined);
    loadGeo();
    loadIntel();
    loadAudit();
  }, []);

  useEffect(() => {
    if (!geo?.installing) return;
    const t = setInterval(loadGeo, 2000);
    return () => clearInterval(t);
  }, [geo?.installing]);

  useEffect(() => {
    if (tab) setActive(tab);
  }, [tab]);

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

  const saveIntelKey = async () => {
    if (!intelKey.trim()) return;
    setIntelBusy(true);
    try {
      // The save checks the key against AbuseIPDB, so a refusal here is the
      // API's answer and nothing is stored.
      await api.put("/api/threat-intel", { abuseipdb_key: intelKey.trim() });
      setIntelKey("");
      onOK("AbuseIPDB key saved; the allowance is read from the API's response headers");
      loadIntel();
    } catch (e) {
      onError(errText(e));
    } finally {
      setIntelBusy(false);
    }
  };

  const removeIntelKey = async () => {
    if (!(await confirmDialog("Lookups stop using AbuseIPDB until a key is saved again. RDAP keeps working without a key.", { title: "Remove key", confirmLabel: "Remove" }))) return;
    setIntelBusy(true);
    try {
      await api.put("/api/threat-intel", { abuseipdb_key: "" });
      onOK("AbuseIPDB key removed");
      loadIntel();
    } catch (e) {
      onError(errText(e));
    } finally {
      setIntelBusy(false);
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

  // The first enable restarts the process to bind the HA listeners. Wait past
  // the restart, then require two successful health checks a second apart so a
  // response from the outgoing process is not mistaken for the new one.
  const waitForRestart = async () => {
    await new Promise((r) => setTimeout(r, 1500));
    for (let i = 0; i < 60; i++) {
      try {
        await api.get("/api/health");
        await new Promise((r) => setTimeout(r, 1000));
        await api.get("/api/health");
        return true;
      } catch {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    return false;
  };

  const save = async () => {
    setSaving(true);
    try {
      const posted = siteEditable(s);
      // A paired node needs the cluster id typed before HA may be turned off.
      const headers =
        posted.ha_enabled === "0" && haInfo?.paired && haConfirm.trim()
          ? { "X-HA-Cluster-ID": haConfirm.trim() }
          : undefined;
      const res = await api.put<{ restart_required?: boolean }>("/api/settings", posted, headers);
      setSaved(editable(s));
      // The typed id belongs to one save; never leave it in the field.
      if ("ha_enabled" in posted) setHaConfirm("");
      if (res?.restart_required) {
        setRestart("restarting");
        select("ha");
        onOK("High availability is enabled; the service is restarting");
        if (!(await waitForRestart())) {
          setRestart("lost");
          onError("The console did not reconnect. Check WAF-Proxy on the host, then reload this page.");
          return;
        }
        setRestart("idle");
        onOK("WAF-Proxy is back; high availability is on");
      } else {
        setRestart("idle");
        onOK("Settings saved");
      }
      load();
      // The help text depends on the server's view of the switch, and the nav
      // depends on /api/me, so both are refreshed instead of guessed at.
      loadHA();
      if (posted.ha_enabled !== saved.ha_enabled) onMeChanged?.();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  // Network, updates and GeoIP bind the whole process, so their controls are
  // host-wide. The request's site is the one the form saves, which may differ
  // from the console's own site when an administrator switched through the
  // topbar, so the server names it with the settings rather than using me.site.
  const siteSlug = s.site_slug || me?.site || "";
  const siteName = s.site_name || me?.site_name || "default";
  const hostWide = !!siteSlug && siteSlug !== "default";
  const hostWideNote = (
    <p className="faint small-text" style={{ marginTop: -2 }}>
      Host-wide setting: it belongs to the default site's console and is read-only here.
    </p>
  );
  const ifaceHint = (name: string, auto: boolean) =>
    name ? `${name} (${auto ? "auto-detected" : "configured"})` : "— (none detected)";
  // A tenant console cannot change the host-wide switch, so the control says
  // which console owns it instead of failing on save.
  const mayToggleHA = !hostWide && me?.role !== "host_admin";
  const sections = (tabs?.length ? tabs : SECTIONS).filter((sec) => !(hostWide && sec.id === "ha"));
  // A deep link to a tab this console may not show falls back to the first one.
  const shown = sections.some((sec) => sec.id === active) ? active : sections[0]?.id ?? "network";
  const intelQuota = quotaView(intel?.quota);
  const select = (id: string) => {
    setActive(id);
    onTab?.(id);
    window.scrollTo({ top: 0 });
  };

  return (
    <>
    <PageHead
      sub={
        hostWide
          ? `Settings for ${siteName}. Protection, retention and backup apply to this site. The inspected body cap and the host-wide sections are read-only here.`
          : "Node networking, protection defaults, retention, updates and the hardening checklist."
      }
      actions={<Badge tone="info">Site: {siteName}</Badge>}
    />
    <div className="settings-sections">
      <PageTabs tabs={sections} active={shown} onSelect={select} />
        <section id="network" hidden={shown !== "network"} className="settings-section card">
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

        <section id="updates" hidden={shown !== "updates"} className="settings-section">
          <div className="section-head">
            <h2>Updates</h2>
            <p>Console and host package versions, with the restart that applies a rebuild.</p>
          </div>
          {hostWide && hostWideNote}
          <fieldset disabled={hostWide} style={{ border: 0, padding: 0, margin: 0 }}>
            <UpdatesPage onError={onError} onOK={onOK} head={false} />
          </fieldset>
        </section>

        <section id="protection" hidden={shown !== "protection"} className="settings-section card">
          <div className="section-head">
            <h2>Protection</h2>
            <p>
              {hostWide
                				? `Rate limits and normalization apply to ${siteName}. The max inspected body is one process-wide buffer and is set on the default site's console.`
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
              <input value={s.max_body ?? "67108864"} onChange={(e) => set("max_body", e.target.value)} disabled={hostWide} />
            </Field>
            <Field
              label="Queue wait (ms)"
              hint="Per site: how long a request waits for capacity before it is refused with a 503. 0 refuses at once."
            >
              <input value={s.queue_ms ?? "250"} onChange={(e) => set("queue_ms", e.target.value)} />
            </Field>
            <Field
              label="Body deadline (s)"
              hint="Per site: how long a client may take to send its body before the request is cut with a 408. 0 disables the deadline."
            >
              <input value={s.body_timeout_s ?? "30"} onChange={(e) => set("body_timeout_s", e.target.value)} />
            </Field>
            <Field
              label="Idle upstream connections"
              hint="Per site: idle connections kept open to each upstream address, so a repeat request reuses one instead of dialling again. Default 64."
            >
              <input value={s.upstream_idle_conns ?? "64"} onChange={(e) => set("upstream_idle_conns", e.target.value)} />
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
          <Switch
            label="Serve cache hits before the WAF"
            help="Per site: a cached GET is answered before the CRS and the per-IP WAF rules, so those rules never see a repeat visitor. Only for sites with no access gate whose WAF mode is block or detect."
            checked={s.cache_pre_waf === "1"}
            onChange={(v) => set("cache_pre_waf", v ? "1" : "0")}
          />
          <Switch label="Protection pipeline enabled" checked={s.protection_enabled !== "0"} onChange={(v) => set("protection_enabled", v ? "1" : "0")} />
          <Switch label="Block hosting / VPS / cloud ASNs by default" help="Requires an ASN database; skipped and reported when unavailable." checked={s.asn_block !== "0"} onChange={(v) => set("asn_block", v ? "1" : "0")} />
          <Switch label="Stealth mode (DROP, no reset)" checked={s.stealth_drop !== "0"} onChange={(v) => set("stealth_drop", v ? "1" : "0")} />
          <Switch label="Ignore ICMP echo on the WAN interface" checked={s.stealth_ping === "1"} onChange={(v) => set("stealth_ping", v ? "1" : "0")} />
          <Field label="Decoy hostnames" hint="Requests for these names never reach a proxy and permanently ban the source. Comma separated.">
            <textarea value={s.decoy_hosts ?? ""} onChange={(e) => set("decoy_hosts", e.target.value)} placeholder="admin.example.org, old-panel" />
          </Field>
        </section>

        <section id="retention" hidden={shown !== "retention"} className="settings-section card">
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

        {!hostWide && (
        <section id="ha" hidden={shown !== "ha"} className="settings-section card">
          <div className="section-head">
            <h2>High availability</h2>
            <p>Two nodes, one service address. Off by default, and the data plane does not change until a move.</p>
          </div>
          <Switch
            label="Enable high availability"
            help={haSwitchHelp(hostWide, me, haInfo)}
            checked={s.ha_enabled === "1"}
            onChange={(v) => set("ha_enabled", v ? "1" : "0")}
            disabled={!mayToggleHA}
          />
          {restart !== "idle" && (
            <div
              className={`banner ${restart === "restarting" ? "warn" : "bad"}`}
              role="status"
              aria-live="polite"
              style={{ marginTop: 8 }}
            >
              {restart === "restarting"
                ? "Enabling high availability restarts WAF-Proxy. The console reconnects when the service is back…"
                : "WAF-Proxy has not reconnected. Check the service on the host, then reload this page."}
            </div>
          )}
          {haInfo?.paired && s.ha_enabled === "0" && !hostWide && (
            <Field
              label="Type the cluster id to confirm"
              hint={`With HA off, no node takes over if this one fails. Type ${haInfo.cluster_id} to confirm, or unpair first on the High availability page.`}
            >
              <input value={haConfirm} onChange={(e) => setHaConfirm(e.target.value)} placeholder={haInfo.cluster_id} />
            </Field>
          )}
          {hostWide && hostWideNote}
          <p className="faint small-text">
            Status, pairing and moves live on the <a href="#/ha">High availability page</a>.
          </p>
        </section>
        )}

        <section id="backup" hidden={shown !== "backup"} className="settings-section">
          <BackupCard onError={onError} onOK={onOK} />
        </section>

        <section id="runtime" hidden={shown !== "runtime"} className="settings-section card">
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
              <div className="faint small-text">
                {hostWide ? "configured on the default site's console" : "configure under Threat intel → CrowdSec"}
              </div>
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

        <section id="geoip" hidden={shown !== "geoip"} className="settings-section card">
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

        <section id="threat-intel" hidden={shown !== "threat-intel"} className="settings-section card">
          <div className="card-head">
            <h2>Threat intelligence</h2>
            <div className="actions">
              <button className="small" onClick={loadIntel}>Refresh</button>
            </div>
          </div>
          <p className="muted small-text">
            Third-party enrichment for a source address. Nothing is sent until an operator opens a source, and
            answers are cached per address so a busy map does not spend the allowance.
          </p>
          <div className="bar-row">
            <div>
              RDAP / whois
              <div className="faint small-text">Network, organisation, abuse contact and registration date, asked of the registry that owns the address.</div>
            </div>
            <div>
              <Badge tone="ok">on · keyless</Badge>
              <span className="faint small-text" style={{ marginLeft: 8 }}>cached with the lookup</span>
            </div>
          </div>
          <div className="bar-row">
            <div>
              AbuseIPDB
              <div className="faint small-text">Confidence score, report count and the abuse categories other operators reported.</div>
            </div>
            <div>
              {intel?.configured ? (
                <Badge tone="ok">connected · {intel.key_tail}</Badge>
              ) : (
                <Badge tone="warn">no key</Badge>
              )}
            </div>
          </div>

          {!intel?.configured ? (
            <div className="intel-key-row">
              <input
                type="password"
                value={intelKey}
                onChange={(e) => setIntelKey(e.target.value)}
                placeholder="Paste your AbuseIPDB API key"
                aria-label="AbuseIPDB API key"
                autoComplete="off"
                spellCheck={false}
              />
              <button className="small primary" onClick={saveIntelKey} disabled={intelBusy || !intelKey.trim()}>
                {intelBusy ? "Checking…" : "Save key"}
              </button>
            </div>
          ) : (
            <>
              <div className="intel-plan">
                <span className="intel-plan-name">{describePlan(intel.plan, intel.quota)}</span>
                {intel.quota && (
                  <span className="faint small-text">
                    remaining {intel.quota.remaining.toLocaleString()} of {intel.quota.limit.toLocaleString()}
                    {intel.quota.reset_at ? ` · resets ${intel.quota.reset_at.slice(11, 16)} UTC` : ""}
                  </span>
                )}
              </div>
              {intelQuota && (
                <div className="intel-meter" role="img" aria-label={`${intelQuota.used.toLocaleString()} of ${intelQuota.limit.toLocaleString()} checks used today`}>
                  <i style={{ width: `${intelQuota.percent}%` }} />
                </div>
              )}
              <div className="row between" style={{ marginTop: 8 }}>
                <a className="link-button" href="https://www.abuseipdb.com/account/api" target="_blank" rel="noreferrer">
                  <Icon name="external" size={14} /> Manage the key at AbuseIPDB
                </a>
                <button className="small" onClick={removeIntelKey} disabled={intelBusy}>Remove key</button>
              </div>
            </>
          )}
          <p className="faint small-text">
            Plan and allowance come from the key's own response headers — <span className="mono">X-RateLimit-Limit</span>,{" "}
            <span className="mono">Remaining</span> and <span className="mono">Reset</span> — so a paid plan shows its real
            ceiling. AbuseIPDB does not name the plan, so the tier above is inferred from that limit. The free Individual
            plan allows 1,000 checks a day; a lookup spends one check per address every {intel?.cache_hours ?? 6} hours.
          </p>
          <p className="faint small-text">
            The key is sealed with this console's master key and only ever leaves the server as the request header
            AbuseIPDB expects; the page receives a masked tail.
          </p>
        </section>

        <section id="activity" hidden={shown !== "activity"} className="settings-section card">
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

        <section id="readiness" hidden={shown !== "readiness"} className="settings-section">
          <div className="section-head">
            <h2>Readiness</h2>
            <p>What a hardened install has that a working one may not. Every row links to the control that fixes it.</p>
          </div>
          <Readiness me={me ?? null} onError={onError} head={false} />
        </section>

        <section id="about" hidden={shown !== "about"} className="settings-section card">
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
    </>
  );
}
