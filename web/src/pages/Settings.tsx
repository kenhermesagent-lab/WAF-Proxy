import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Badge, Card, Field, errText, fmtAgo, fmtTime } from "../ui";
import type { AuditEntry, CrowdSecStatus, GeoIPStatus } from "../types";
import BackupCard from "../components/BackupCard";

type Settings = Record<string, string>;

export default function SettingsPage({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [s, setS] = useState<Settings>({});
  const [saving, setSaving] = useState(false);
  const [cs, setCs] = useState<CrowdSecStatus | null>(null);
  const [geo, setGeo] = useState<GeoIPStatus | null>(null);
  const [installingGeo, setInstallingGeo] = useState(false);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [iface, setIface] = useState<{ wan: string; lan: string; wanAuto: boolean; lanAuto: boolean; available: string[] }>({
    wan: "",
    lan: "",
    wanAuto: false,
    lanAuto: false,
    available: [],
  });
  const file = useRef<HTMLInputElement>(null);

  const load = () =>
    api
      .get<Settings>("/api/settings")
      .then((v) => {
        setS(v);
        setIface({
          wan: v.wan_iface_in_use ?? "",
          lan: v.lan_iface_in_use ?? "",
          wanAuto: v.wan_iface_auto === "1",
          lanAuto: v.lan_iface_auto === "1",
          available: (v.iface_available ?? "").split(",").map((n) => n.trim()).filter(Boolean),
        });
      })
      .catch((e) => onError(errText(e)));

  const loadGeo = () =>
    api.get<GeoIPStatus>("/api/geoip").then(setGeo).catch(() => undefined);

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

  const loadAudit = () =>
    api.get<AuditEntry[]>("/api/audit").then((r) => setAudit((r || []).slice(0, 20))).catch(() => undefined);

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
      const payload: Settings = {};
      for (const [k, v] of Object.entries(s)) {
        if (k === "kernel" || k === "geoip" || k.endsWith("_in_use") || k.endsWith("_auto") || k === "iface_available") continue;
        payload[k] = v;
      }
      await api.put("/api/settings", payload);
      onOK("Settings saved");
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  // Name plus how Settings arrived at it: configured here, or picked by
  // auto-detection because the matching field is empty.
  const ifaceHint = (name: string, auto: boolean) =>
    name ? `${name} (${auto ? "auto-detected" : "configured"})` : "— (none detected)";

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="grid cols-2">
        <Card title="Network">
          <div className="row grow">
            <Field label="WAN address (443 listener)">
              <input value={s.wan_ip ?? ""} onChange={(e) => set("wan_ip", e.target.value)} placeholder="192.168.191.2" />
            </Field>
            <Field label="WAN port">
              <input value={s.wan_port ?? "443"} onChange={(e) => set("wan_port", e.target.value)} />
            </Field>
          </div>
          <div className="row grow">
            <Field label="LAN egress address">
              <input value={s.lan_ip ?? ""} onChange={(e) => set("lan_ip", e.target.value)} placeholder="192.168.101.2" />
            </Field>
            <Field label="Admin GUI port">
              <input value={s.gui_port ?? "8443"} onChange={(e) => set("gui_port", e.target.value)} />
            </Field>
          </div>
          <div className="row grow">
            <Field label="WAN interface">
              <input list="iface-names" value={s.wan_iface ?? ""} onChange={(e) => set("wan_iface", e.target.value)} placeholder={iface.wan || "eth0"} />
            </Field>
            <Field label="LAN interface">
              <input list="iface-names" value={s.lan_iface ?? ""} onChange={(e) => set("lan_iface", e.target.value)} placeholder={iface.lan || "eth1"} />
            </Field>
          </div>
          <datalist id="iface-names">
            {iface.available.map((n) => <option key={n} value={n} />)}
          </datalist>
          <p className="muted" style={{ fontSize: 12, marginTop: -4 }}>
            The dashboard samples WAN <span className="mono">{ifaceHint(iface.wan, iface.wanAuto)}</span> · LAN{" "}
            <span className="mono">{ifaceHint(iface.lan, iface.lanAuto)}</span>. Available on this host:{" "}
            {iface.available.length ? <span className="mono">{iface.available.join(", ")}</span> : "none found"}.
          </p>
          <div className="row grow">
            <Field label="Home latitude (globe)"><input value={s.home_lat ?? "51.5"} onChange={(e) => set("home_lat", e.target.value)} /></Field>
            <Field label="Home longitude"><input value={s.home_lon ?? "-0.12"} onChange={(e) => set("home_lon", e.target.value)} /></Field>
          </div>
          <Field label="Admin allowlist (IPs / CIDRs; empty allows any address)">
            <input
              value={s.admin_allow_cidrs ?? ""}
              onChange={(e) => set("admin_allow_cidrs", e.target.value)}
              placeholder="192.168.0.0/16, 10.0.0.0/8"
            />
          </Field>
          <p className="muted" style={{ fontSize: 12, marginTop: -4 }}>
            When set, only these addresses can open the sign-in form or call the admin API. The save is refused if the
            list would exclude your current address. Clear the field to allow any address again.
          </p>
          <p className="muted" style={{ fontSize: 12 }}>
            Both addresses must be configured on this host. A single-NIC host uses the same address for WAN and
            LAN — then the GUI port must be firewalled from the WAN. Restart WAF-Proxy after changing the bind
            addresses (<code>docker compose restart wafproxy</code> or <code>systemctl restart wafproxy</code>); the
            listener reads them from the database on boot. Only 443 needs to be forwarded on the WAN side; the admin
            GUI should stay on the LAN.
          </p>
        </Card>

        <Card title="Protection">
          <div className="row grow">
            <Field label="Global rate limit (rps/IP)"><input value={s.dos_rps ?? "100"} onChange={(e) => set("dos_rps", e.target.value)} /></Field>
            <Field label="Burst"><input value={s.dos_burst ?? "200"} onChange={(e) => set("dos_burst", e.target.value)} /></Field>
          </div>
          <div className="row grow">
            <Field label="Max inspected body (bytes)"><input value={s.max_body ?? "131072"} onChange={(e) => set("max_body", e.target.value)} /></Field>
            <Field label="Sample allowed above (rps)"><input value={s.sample_above_rps ?? "500"} onChange={(e) => set("sample_above_rps", e.target.value)} /></Field>
          </div>
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={s.protection_enabled !== "0"} onChange={(e) => set("protection_enabled", e.target.checked ? "1" : "0")} />
            Protection pipeline enabled
          </label>
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={s.asn_block !== "0"} onChange={(e) => set("asn_block", e.target.checked ? "1" : "0")} />
            Block hosting/VPS/cloud ASNs by default
          </label>
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={s.stealth_drop !== "0"} onChange={(e) => set("stealth_drop", e.target.checked ? "1" : "0")} />
            Stealth mode (DROP, no reset)
          </label>
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={s.stealth_ping === "1"} onChange={(e) => set("stealth_ping", e.target.checked ? "1" : "0")} />
            Ignore ICMP echo on the WAN interface
          </label>
          <Field label="Decoy hostnames (comma separated, instant ban)">
            <textarea
              value={s.decoy_hosts ?? ""}
              onChange={(e) => set("decoy_hosts", e.target.value)}
              placeholder="admin.kendk.duckdns.org, test, old-panel"
            />
          </Field>
          <p className="muted" style={{ fontSize: 12 }}>
            Requests for these names never reach a real proxy and permanently ban the source. A
            name already used by a proxy is refused. ASN blocking needs an ASN database; without
            one the stage is skipped and reported as unavailable. Country rules need a GeoIP
            database in the data directory.
          </p>
        </Card>
      </div>

      <div className="grid cols-2">
        <Card title="Retention and ACME">
          <div className="row grow">
            <Field label="Event retention (days, 1–30)"><input value={s.retention_days ?? "7"} onChange={(e) => set("retention_days", e.target.value)} /></Field>
            <Field label="ACME account email"><input value={s.acme_email ?? ""} onChange={(e) => set("acme_email", e.target.value)} placeholder="admin@your-domain.tld" /></Field>
          </div>
          <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={s.acme_staging === "1"} onChange={(e) => set("acme_staging", e.target.checked ? "1" : "0")} />
            Use the Let's Encrypt staging directory
          </label>
        </Card>

        <BackupCard onError={onError} onOK={onOK} />

        <Card title="Runtime status">
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
              <div className="faint" style={{ fontSize: 11 }}>configure on the CrowdSec page</div>
            </div>
          </div>
          {cs?.configured && (
            <div className="bar-row">
              <div>LAPI last poll</div>
              <div className="muted" style={{ fontSize: 12 }}>
                {cs.last_poll ? fmtAgo(cs.last_poll) : "waiting"} · <span className="mono">{cs.lapi}</span>
              </div>
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
          <div className="bar-row" style={{ borderBottom: 0 }}>
            <div>Restore backup (additive, gates reset to off)</div>
            <div>
              <input ref={file} type="file" accept="application/json" style={{ display: "none" }} onChange={(e) => e.target.files?.[0] && restore(e.target.files[0])} />
              <button className="small" onClick={() => file.current?.click()}>Import JSON</button>
            </div>
          </div>
          <p className="muted" style={{ fontSize: 12 }}>
            Backups intentionally exclude secrets, private keys and password hashes. Re-issue certificates and reset passwords after
            restoring.
          </p>
        </Card>
      </div>

      <Card
        title="GeoIP database"
        actions={
          <button className="small primary" onClick={installGeo} disabled={installingGeo || geo?.installing}>
            {geo?.installing ? "Installing…" : geo?.available ? "Update database" : "Install database"}
          </button>
        }
      >
        <div className="bar-row">
          <div>City database</div>
          <div>
            {geo?.city ? <Badge tone="ok">loaded</Badge> : <Badge tone="warn">missing</Badge>}
            {geo?.city_updated && <span className="muted" style={{ fontSize: 12, marginLeft: 8 }}>updated {fmtTime(geo.city_updated)}</span>}
          </div>
        </div>
        <div className="bar-row">
          <div>ASN database</div>
          <div>
            {geo?.asn ? <Badge tone="ok">loaded</Badge> : <Badge tone="warn">missing</Badge>}
            {geo?.asn_updated && <span className="muted" style={{ fontSize: 12, marginLeft: 8 }}>updated {fmtTime(geo.asn_updated)}</span>}
          </div>
        </div>
        <div className="bar-row">
          <div>Automatic update</div>
          <label style={{ margin: 0, display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
            <input
              type="checkbox"
              style={{ width: "auto" }}
              checked={s.geoip_auto_update !== "0"}
              onChange={(e) => set("geoip_auto_update", e.target.checked ? "1" : "0")}
            />
            refresh daily when a database is installed
          </label>
        </div>
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>Database source</div>
          <div className="muted" style={{ fontSize: 12 }}>DB-IP Lite · downloads into the data directory and reloads without a restart</div>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          The daily refresh keeps country and ASN rules current. The Update database button above still works at any
          time. Remember to save settings after changing the checkbox.
        </p>
        {geo?.installing && <p className="muted" style={{ fontSize: 12 }}>Downloading and validating the databases. This can take a few minutes.</p>}
        {geo?.last_error && <p className="err-text">{geo.last_error}</p>}
        <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
          The free DB-IP Lite databases are licensed under CC BY 4.0.{" "}
          <a href="https://db-ip.com" target="_blank" rel="noreferrer">IP Geolocation by DB-IP</a>. Country and
          ASN policy use these files immediately after installation.
        </p>
      </Card>

      <Card
        title="Recent administrator activity"
        actions={<button className="small" onClick={loadAudit}>Refresh</button>}
      >
        {audit.length === 0 ? (
          <p className="muted" style={{ fontSize: 13, margin: 0 }}>No audit entries yet.</p>
        ) : (
          <div style={{ overflowX: "auto" }}>
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
                    <td className="muted" style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={a.detail}>{a.detail || "—"}</td>
                    <td className="mono">{a.ip || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted" style={{ fontSize: 12 }}>
          The newest 20 entries: sign-ins, sign-outs, settings changes, proxy and certificate changes,
          bans and restores. Activities are also written to the container log.
        </p>
      </Card>

      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button className="primary" onClick={save} disabled={saving}>{saving ? "Saving…" : "Save settings"}</button>
      </div>
    </div>
  );
}
