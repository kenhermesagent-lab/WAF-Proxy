import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Badge, Card, Field, errText } from "../ui";

type Settings = Record<string, string>;

export default function SettingsPage({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [s, setS] = useState<Settings>({});
  const [saving, setSaving] = useState(false);
  const file = useRef<HTMLInputElement>(null);

  const load = () =>
    api.get<Settings>("/api/settings").then(setS).catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

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
        if (k === "kernel" || k === "geoip") continue;
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
            <Field label="WAN interface"><input value={s.wan_iface ?? ""} onChange={(e) => set("wan_iface", e.target.value)} placeholder="eth0" /></Field>
            <Field label="LAN interface"><input value={s.lan_iface ?? ""} onChange={(e) => set("lan_iface", e.target.value)} placeholder="eth1" /></Field>
          </div>
          <div className="row grow">
            <Field label="Home latitude (globe)"><input value={s.home_lat ?? "51.5"} onChange={(e) => set("home_lat", e.target.value)} /></Field>
            <Field label="Home longitude"><input value={s.home_lon ?? "-0.12"} onChange={(e) => set("home_lon", e.target.value)} /></Field>
          </div>
          <p className="muted" style={{ fontSize: 12 }}>
            Restart the container after changing the bind addresses; the listener reads them from
            the database on boot. Only 443 needs to be forwarded on the WAN side; the admin GUI should stay on the LAN.
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
          <p className="muted" style={{ fontSize: 12 }}>
            ASN blocking needs an ASN database; without one the stage is skipped and reported as unavailable. Country rules need a
            GeoIP database in the data directory.
          </p>
        </Card>
      </div>

      <div className="grid cols-2">
        <Card title="Retention and ACME">
          <div className="row grow">
            <Field label="Event retention (days, 1–30)"><input value={s.retention_days ?? "7"} onChange={(e) => set("retention_days", e.target.value)} /></Field>
            <Field label="ACME account email"><input value={s.acme_email ?? ""} onChange={(e) => set("acme_email", e.target.value)} placeholder="admin@example.com" /></Field>
          </div>
          <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={s.acme_staging === "1"} onChange={(e) => set("acme_staging", e.target.checked ? "1" : "0")} />
            Use the Let's Encrypt staging directory
          </label>
        </Card>

        <Card title="Runtime status">
          <div className="bar-row">
            <div>Kernel ban enforcement</div>
            <div>{String(s.kernel ?? "").includes("true") ? <Badge tone="ok">active</Badge> : <Badge tone="warn">{s.kernel || "unknown"}</Badge>}</div>
          </div>
          <div className="bar-row">
            <div>GeoIP database</div>
            <div>{s.geoip === "true" ? <Badge tone="ok">loaded</Badge> : <Badge tone="warn">not loaded</Badge>}</div>
          </div>
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

      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button className="primary" onClick={save} disabled={saving}>{saving ? "Saving…" : "Save settings"}</button>
      </div>
    </div>
  );
}
