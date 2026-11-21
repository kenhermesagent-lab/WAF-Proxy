import { useEffect, useState } from "react";
import { api } from "../api";
import { COUNTRIES, countryFlag, countryName } from "../countries";
import { Badge, Card, Empty, Field, Modal, errText, fmtAgo } from "../ui";
import { Ban, Policy, Profile, Proxy } from "../types";

const KINDS: Record<string, string> = {
  ip_whitelist: "IP / CIDR allow list",
  country_whitelist: "Allowed countries",
  country_blacklist: "Blocked countries",
  asn_block: "Blocked ASNs",
  decoy: "Decoy paths (instant ban)",
  rate_limit: "Rate limit (rps/burst)",
};

export default function Policies({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [tab, setTab] = useState("bans");
  const [bans, setBans] = useState<Ban[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [savingProfile, setSavingProfile] = useState(false);
  const [kernel, setKernel] = useState<{ active: boolean; reason: string } | null>(null);
  const [showAll, setShowAll] = useState(false);

  const [ban, setBan] = useState({ cidr: "", reason: "", permanent: false, ttl_seconds: 86400 });
  const [pol, setPol] = useState({
    kind: "country_blacklist",
    value: "",
    action: "block",
    scope: "global",
    proxy_id: "",
    note: "",
  });
  const isCountry = pol.kind === "country_whitelist" || pol.kind === "country_blacklist";

  const load = () => {
    api
      .get<{ bans: Ban[]; active: number; kernel: { active: boolean; reason: string } }>(`/api/bans?all=${showAll ? 1 : 0}`)
      .then((r) => {
        setBans(r.bans || []);
        setKernel(r.kernel);
      })
      .catch((e) => onError(errText(e)));
    api.get<Policy[]>("/api/policies").then(setPolicies).catch((e) => onError(errText(e)));
    api.get<Proxy[]>("/api/proxies").then(setProxies).catch(() => undefined);
    api.get<Profile[]>("/api/profiles").then(setProfiles).catch(() => undefined);
  };

  useEffect(() => {
    load();
  }, [showAll]);

  const addBan = async () => {
    try {
      await api.post("/api/bans", ban);
      setBan({ cidr: "", reason: "", permanent: false, ttl_seconds: 86400 });
      onOK("Ban applied");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const removeBan = async (b: Ban) => {
    if (!confirm(`Unban ${b.cidr}?`)) return;
    try {
      await api.del(`/api/bans/${b.id}`);
      onOK("Ban removed");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const promote = async (b: Ban) => {
    try {
      await api.post(`/api/bans/${b.id}/promote`);
      onOK("Ban promoted to permanent");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const addPolicy = async () => {
    try {
      await api.post("/api/policies", {
        kind: pol.kind,
        value: pol.value,
        scope: pol.scope,
        proxy_id: pol.scope === "proxy" && pol.proxy_id ? Number(pol.proxy_id) : null,
        note: pol.note,
        action: pol.action,
        enabled: true,
      });
      setPol({ ...pol, value: "", note: "" });
      onOK("Policy added");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const togglePolicy = async (p: Policy) => {
    try {
      await api.put(`/api/policies/${p.id}`, { ...p, enabled: !p.enabled });
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const removePolicy = async (p: Policy) => {
    if (!confirm("Delete this policy?")) return;
    try {
      await api.del(`/api/policies/${p.id}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const saveProfile = async () => {
    if (!profile) return;
    setSavingProfile(true);
    try {
      await api.put(`/api/profiles/${profile.id}`, profile);
      onOK(`${profile.name} profile saved`);
      setProfile(null);
      load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSavingProfile(false);
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div className="tabs" style={{ marginBottom: 0, borderBottom: 0 }}>
          <button className={`tab ${tab === "bans" ? "active" : ""}`} onClick={() => setTab("bans")}>Temp bans</button>
          <button className={`tab ${tab === "permanent" ? "active" : ""}`} onClick={() => setTab("permanent")}>Permanent</button>
          <button className={`tab ${tab === "rules" ? "active" : ""}`} onClick={() => setTab("rules")}>Countries, IPs, ASN</button>
          <button className={`tab ${tab === "profiles" ? "active" : ""}`} onClick={() => setTab("profiles")}>WAF profiles</button>
        </div>
        {kernel && (
          <span className={`badge ${kernel.active ? "ok" : "warn"}`}>
            kernel: {kernel.active ? "nftables active" : kernel.reason || "unavailable"}
          </span>
        )}
      </div>

      {tab === "bans" && (
        <>
          <Card title="New ban">
            <div className="row grow">
              <Field label="IP or CIDR">
                <input value={ban.cidr} onChange={(e) => setBan({ ...ban, cidr: e.target.value })} placeholder="203.0.113.7" />
              </Field>
              <Field label="Reason (required)">
                <input value={ban.reason} onChange={(e) => setBan({ ...ban, reason: e.target.value })} placeholder="port scan" />
              </Field>
              <Field label="Duration (seconds)">
                <input type="number" value={ban.ttl_seconds} disabled={ban.permanent} onChange={(e) => setBan({ ...ban, ttl_seconds: Number(e.target.value) })} />
              </Field>
              <label style={{ margin: "18px 0 0", display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
                <input type="checkbox" style={{ width: "auto" }} checked={ban.permanent} onChange={(e) => setBan({ ...ban, permanent: e.target.checked })} /> permanent
              </label>
              <button className="primary" style={{ marginTop: 18 }} onClick={addBan}>Ban</button>
            </div>
          </Card>
          <Card
            title={`Active bans (${bans.length})`}
            actions={
              <label style={{ margin: 0, display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
                <input type="checkbox" style={{ width: "auto" }} checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> include expired
              </label>
            }
          >
            {bans.length === 0 ? <Empty>No bans. Decoy hits and repeated failures add themselves here.</Empty> : (
              <table>
                <thead>
                  <tr><th>IP / CIDR</th><th>Reason</th><th>Source</th><th>Hits</th><th>Created</th><th>Expires</th><th /></tr>
                </thead>
                <tbody>
                  {bans.map((b) => (
                    <tr key={b.id}>
                      <td className="mono">{b.cidr}</td>
                      <td>{b.reason}</td>
                      <td><Badge tone={b.source === "decoy" || b.source === "crowdsec" ? "bad" : "info"}>{b.source}</Badge></td>
                      <td className="num">{b.hits}</td>
                      <td className="muted">{fmtAgo(b.created_at)}</td>
                      <td>{b.permanent ? <Badge tone="bad">permanent</Badge> : <span className="muted">{fmtAgo(b.expires_at)}</span>}</td>
                      <td className="right" style={{ whiteSpace: "nowrap" }}>
                        {!b.permanent && <button className="small" onClick={() => promote(b)}>Make permanent</button>}{" "}
                        <button className="small danger" onClick={() => removeBan(b)}>Unban</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}

      {tab === "permanent" && (
        <Card title="Permanent ban list">
          {bans.filter((b) => b.permanent).length === 0 ? <Empty>No permanent bans.</Empty> : (
            <table>
              <thead><tr><th>IP / CIDR</th><th>Reason</th><th>Source</th><th>Created by</th><th>Hits</th><th /></tr></thead>
              <tbody>
                {bans.filter((b) => b.permanent).map((b) => (
                  <tr key={b.id}>
                    <td className="mono">{b.cidr}</td>
                    <td>{b.reason}</td>
                    <td className="muted">{b.source}</td>
                    <td className="muted">{b.created_by || "system"}</td>
                    <td className="num">{b.hits}</td>
                    <td className="right"><button className="small danger" onClick={() => removeBan(b)}>Remove</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}

      {tab === "profiles" && (
        <Card title="CRS protection profiles">
          {profiles.length === 0 ? <Empty>No profiles available.</Empty> : (
            <div style={{ overflowX: "auto" }}>
              <table>
                <thead>
                  <tr><th>Profile</th><th>Mode</th><th className="num">Paranoia</th><th className="num">Anomaly</th><th>Methods</th><th className="num">Max body</th><th /></tr>
                </thead>
                <tbody>
                  {profiles.map((p) => (
                    <tr key={p.id}>
                      <td style={{ whiteSpace: "nowrap" }}>{p.name}{p.exceptions ? <div className="faint" style={{ fontSize: 11 }}>{p.exceptions.split(",").filter(Boolean).length} rule exception(s)</div> : null}</td>
                      <td><Badge tone={p.mode === "block" ? "ok" : p.mode === "detect" ? "info" : "warn"}>{p.mode}</Badge></td>
                      <td className="num">{p.paranoia}</td>
                      <td className="num">{p.anomaly}</td>
                      <td className="muted mono" style={{ fontSize: 12, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={p.allowed_methods}>{p.allowed_methods}</td>
                      <td className="num">{p.max_body.toLocaleString()}</td>
                      <td className="right"><button className="small" onClick={() => setProfile({ ...p })}>Edit</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="muted" style={{ fontSize: 12 }}>
            A proxy with WAF mode <code>inherit</code> uses its selected profile. Paranoia 1 is the CRS default and
            3–4 is strict enough to block some legitimate applications. Rule exceptions remove an OWASP CRS rule ID
            for this profile only. Changes reload the WAF without dropping connections.
          </p>
        </Card>
      )}

      {tab === "rules" && (
        <>
          <Card title="Add policy">
            <div className="row grow">
              <Field label="Type">
                <select
                  value={pol.kind}
                  onChange={(e) => {
                    const kind = e.target.value;
                    setPol({
                      ...pol,
                      kind,
                      value: "",
                      action: kind === "country_whitelist" ? "allow" : "block",
                    });
                  }}
                >
                  {Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
              </Field>
              <Field label={isCountry ? "Country" : "Value"}>
                {isCountry ? (
                  <select value={pol.value} onChange={(e) => setPol({ ...pol, value: e.target.value })}>
                    <option value="">Select a country…</option>
                    {COUNTRIES.map((c) => (
                      <option key={c.code} value={c.code}>{countryFlag(c.code)} {c.name} ({c.code})</option>
                    ))}
                  </select>
                ) : (
                  <input
                    value={pol.value}
                    onChange={(e) => setPol({ ...pol, value: e.target.value })}
                    placeholder={pol.kind === "rate_limit" ? "40/80" : pol.kind === "asn_block" ? "16509,8075" : "/.env,/wp-login.php"}
                  />
                )}
              </Field>
              {isCountry && (
                <Field label="Action">
                  <select
                    value={pol.action}
                    onChange={(e) => {
                      const action = e.target.value;
                      setPol({
                        ...pol,
                        action,
                        kind: action === "allow" ? "country_whitelist" : "country_blacklist",
                      });
                    }}
                  >
                    <option value="allow">Allow</option>
                    <option value="block">Block</option>
                  </select>
                </Field>
              )}
              <Field label="Scope">
                <select value={pol.scope} onChange={(e) => setPol({ ...pol, scope: e.target.value })}>
                  <option value="global">Global</option>
                  <option value="proxy">One proxy</option>
                </select>
              </Field>
              {pol.scope === "proxy" && (
                <Field label="Proxy">
                  <select value={pol.proxy_id} onChange={(e) => setPol({ ...pol, proxy_id: e.target.value })}>
                    <option value="">Select…</option>
                    {proxies.map((p) => <option key={p.id} value={p.id}>{p.hostname}</option>)}
                  </select>
                </Field>
              )}
              <button className="primary" style={{ marginTop: 18 }} onClick={addPolicy}>Add</button>
            </div>
            <p className="muted" style={{ fontSize: 12 }}>
              Country codes are ISO-3166 alpha-2. A country allow list is exclusive: once it names any country,
              traffic from every other country is blocked (an explicit IP allow list still wins). Rate limits use
              <code>requests-per-second/burst</code>. Decoy paths trigger an instant permanent ban, so only list paths
              no legitimate visitor requests.
            </p>
          </Card>

          <Card title="Policies">
            {policies.length === 0 ? <Empty>No policies yet.</Empty> : (
              <table>
                <thead><tr><th>Type</th><th>Value</th><th>Effect</th><th>Scope</th><th>State</th><th /></tr></thead>
                <tbody>
                  {policies.map((p) => (
                    <tr key={p.id}>
                      <td>{KINDS[p.kind] ?? p.kind}</td>
                      <td className="mono">
                        {p.kind === "country_whitelist" || p.kind === "country_blacklist"
                          ? `${countryFlag(p.value)} ${countryName(p.value)} (${p.value})`
                          : p.value}
                      </td>
                      <td><Badge tone={p.kind === "country_whitelist" || p.action === "allow" ? "ok" : "bad"}>{p.kind === "country_whitelist" || p.action === "allow" ? "allow" : "block"}</Badge></td>
                      <td className="muted">{p.scope === "proxy" ? proxies.find((x) => x.id === p.proxy_id)?.hostname ?? `#${p.proxy_id}` : "global"}</td>
                      <td>{p.enabled ? <Badge tone="ok">on</Badge> : <Badge tone="warn">off</Badge>}</td>
                      <td className="right" style={{ whiteSpace: "nowrap" }}>
                        <button className="small" onClick={() => togglePolicy(p)}>{p.enabled ? "Disable" : "Enable"}</button>{" "}
                        <button className="small danger" onClick={() => removePolicy(p)}>Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}

      {profile && (
        <Modal title={`Edit ${profile.name}`} onClose={() => setProfile(null)}>
          <div className="row grow">
            <Field label="Mode">
              <select value={profile.mode} onChange={(e) => setProfile({ ...profile, mode: e.target.value })}>
                <option value="block">Block</option>
                <option value="detect">Detect only</option>
                <option value="off">Off</option>
              </select>
            </Field>
            <Field label="Paranoia level (1–4)">
              <input
                type="number"
                min={1}
                max={4}
                value={profile.paranoia}
                onChange={(e) => setProfile({ ...profile, paranoia: Number(e.target.value) })}
              />
            </Field>
            <Field label="Anomaly threshold">
              <input
                type="number"
                min={1}
                max={100}
                value={profile.anomaly}
                onChange={(e) => setProfile({ ...profile, anomaly: Number(e.target.value) })}
              />
            </Field>
          </div>
          <Field label="Allowed HTTP methods (comma separated)">
            <input
              value={profile.allowed_methods}
              onChange={(e) => setProfile({ ...profile, allowed_methods: e.target.value })}
              placeholder="GET,HEAD,POST"
            />
          </Field>
          <Field label="Maximum inspected body (bytes)">
            <input
              type="number"
              min={1024}
              max={8388608}
              value={profile.max_body}
              onChange={(e) => setProfile({ ...profile, max_body: Number(e.target.value) })}
            />
          </Field>
          <Field label="Disabled CRS rule IDs (comma separated, e.g. 942100,930120)">
            <textarea
              value={profile.exceptions}
              onChange={(e) => setProfile({ ...profile, exceptions: e.target.value })}
              placeholder="only the rules this application needs removed"
            />
          </Field>
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setProfile(null)}>Cancel</button>
            <button className="primary" onClick={saveProfile} disabled={savingProfile}>
              {savingProfile ? "Saving…" : "Save profile"}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
