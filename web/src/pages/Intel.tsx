import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, Field, PageHead, PageTabs, errText, fmtAgo } from "../ui";
import { loggedOnly, modeBadges, outcomeBadges } from "../bundles";
import { BundleHit, BundlesSnapshot, Feed, IntelLookup } from "../types";
import type { NavTab } from "../nav";
import Sources from "./Sources";
import CrowdSecPage from "./CrowdSec";

export default function Intel({
  onError,
  onOK,
  onOpenSource,
  onOpenPolicies,
  tab,
  tabs,
  onTab,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  onOpenSource: (ip: string) => void;
  onOpenPolicies: () => void;
  tab: string;
  tabs: NavTab[];
  onTab: (id: string) => void;
}) {
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [total, setTotal] = useState(0);
  const [form, setForm] = useState({ name: "", url: "", action: "block", interval_s: 900 });
  const [uploadName, setUploadName] = useState("");
  const [uploading, setUploading] = useState(false);
  const [probe, setProbe] = useState("");
  const [lookup, setLookup] = useState<IntelLookup | null>(null);
  const [checking, setChecking] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const [bundles, setBundles] = useState<BundlesSnapshot | null>(null);
  const [bundleHits, setBundleHits] = useState<BundleHit[]>([]);
  // null is idle; "" checks every provider, a name checks only that one.
  const [checkingBundles, setCheckingBundles] = useState<string | null>(null);
  const [providerForm, setProviderForm] = useState({ name: "", url: "", public_key: "" });
  const [savingProvider, setSavingProvider] = useState(false);
  const [togglingBundle, setTogglingBundle] = useState<string | null>(null);

  const load = () =>
    api
      .get<{ feeds: Feed[]; total: number }>("/api/feeds")
      .then((r) => {
        setFeeds(r.feeds || []);
        setTotal(r.total || 0);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const loadBundles = () => {
    api.get<BundlesSnapshot>("/api/bundles").then(setBundles).catch(() => undefined);
    api
      .get<{ hours: number; rules: BundleHit[] }>("/api/bundles/hits?hours=24")
      .then((r) => setBundleHits(r.rules || []))
      .catch(() => undefined);
  };

  useEffect(() => {
    loadBundles();
    const t = setInterval(loadBundles, 30000);
    return () => clearInterval(t);
  }, []);

  // Each provider is checked on its own, so one unreachable publisher does not
  // hide the packs the others still deliver.
  const checkBundles = async (provider: string) => {
    setCheckingBundles(provider);
    try {
      const path = provider ? `/api/bundles/check?provider=${encodeURIComponent(provider)}` : "/api/bundles/check";
      const snap = await api.post<BundlesSnapshot>(path);
      setBundles(snap);
      const failed = snap.providers.filter((p) => p.error);
      if (failed.length) onError(failed.map((p) => `${p.name}: ${p.error}`).join(" · "));
      else onOK(provider ? `${provider} checked` : "Bundle providers checked");
      loadBundles();
    } catch (e) {
      onError(errText(e));
    } finally {
      setCheckingBundles(null);
    }
  };

  const enableBundle = async (name: string, enabled: boolean) => {
    setTogglingBundle(name);
    try {
      setBundles(await api.post<BundlesSnapshot>("/api/bundles/enable", { name, enabled }));
      onOK(`${name} ${enabled ? "enabled" : "disabled"}`);
    } catch (e) {
      onError(errText(e));
    } finally {
      setTogglingBundle(null);
    }
  };

  // A provider saved here is stored in the database, so it survives a restart
  // without an environment variable.
  const saveProvider = async () => {
    setSavingProvider(true);
    try {
      setBundles(await api.put<BundlesSnapshot>("/api/bundles/providers", providerForm));
      setProviderForm({ name: "", url: "", public_key: "" });
      onOK("Bundle provider saved");
      loadBundles();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSavingProvider(false);
    }
  };

  const removeProvider = async (name: string) => {
    if (!(await confirmDialog(`Remove the bundle provider ${name}? Packs it already installed keep serving until you disable them.`))) return;
    try {
      setBundles(await api.del<BundlesSnapshot>(`/api/bundles/providers?name=${encodeURIComponent(name)}`));
      onOK(`${name} removed`);
      loadBundles();
    } catch (e) {
      onError(errText(e));
    }
  };

  const toggle = async (f: Feed) => {
    try {
      await api.put(`/api/feeds/${f.id}`, { ...f, enabled: !f.enabled });
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const setAction = async (f: Feed, action: string) => {
    try {
      await api.put(`/api/feeds/${f.id}`, { ...f, action });
      onOK(`${f.name} now ${action === "log" ? "logs only" : action + "s"}`);
    } catch (e) {
      onError(errText(e));
    }
    load();
  };

  const refresh = async (f: Feed) => {
    try {
      await api.post(`/api/feeds/${f.id}/refresh`);
      onOK(`Refreshing ${f.name}`);
      setTimeout(load, 1500);
    } catch (e) {
      onError(errText(e));
    }
  };

  const add = async () => {
    try {
      await api.post("/api/feeds", form);
      setForm({ name: "", url: "", action: "block", interval_s: 900 });
      onOK("Feed added");
      setTimeout(load, 1200);
    } catch (e) {
      onError(errText(e));
    }
  };

  const upload = async () => {
    const chosen = file.current?.files?.[0];
    if (!chosen) {
      onError("Choose a .txt or .csv file first");
      return;
    }
    setUploading(true);
    try {
      const body = new FormData();
      body.append("file", chosen);
      if (uploadName.trim()) body.append("name", uploadName.trim());
      const r = await api.upload<{ id: number; entries: number }>("/api/feeds/upload", body);
      onOK(`Uploaded ${r.entries.toLocaleString()} entries as a local feed`);
      setUploadName("");
      if (file.current) file.current.value = "";
      setTimeout(load, 1200);
    } catch (e) {
      onError(errText(e));
    } finally {
      setUploading(false);
    }
  };

  const remove = async (f: Feed) => {
    if (!(await confirmDialog(`Delete feed ${f.name}?`))) return;
    try {
      await api.del(`/api/feeds/${f.id}`);
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const checkIP = async () => {
    setChecking(true);
    try {
      setLookup(await api.get<IntelLookup>(`/api/intel/lookup?ip=${encodeURIComponent(probe.trim())}`));
    } catch (e) {
      setLookup(null);
      onError(errText(e));
    } finally {
      setChecking(false);
    }
  };
  const knownBundles = (bundles?.bundles ?? []).filter((b) => b.builtin);
  const installedBundles = (bundles?.bundles ?? []).filter((b) => !b.builtin);

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead sub="Feeds, address lookups, source analysis and the CrowdSec decisions applied to traffic." />
      <PageTabs tabs={tabs} active={tab} onSelect={onTab} />

      {tab === "explorer" && <Sources head={false} onError={onError} onOpenSource={onOpenSource} />}

      {tab === "crowdsec" && <CrowdSecPage head={false} onError={onError} onOK={onOK} />}

      {tab === "bundles" && (
        <>
          <Card
            title="Known good bundles"
            actions={<Badge tone="info">shipped with this release</Badge>}
          >
            <p className="muted" style={{ fontSize: 12 }}>
              Signature packs compiled into this release and validated on startup, so no provider is needed to use them.
              Enabling one adds its rules to every profile; the profile still decides whether a match is logged or blocked,
              and a new pack logs only.
            </p>
            {!bundles ? (
              <Empty>Loading…</Empty>
            ) : knownBundles.length === 0 ? (
              <Empty>This build ships no signature packs.</Empty>
            ) : (
              knownBundles.map((b) => (
                <div key={b.name} className="provider-row">
                  <div style={{ minWidth: 0 }}>
                    <div className="row" style={{ gap: 6 }}>
                      <b>{b.name}</b>
                      <span className="faint mono" style={{ fontSize: 11 }}>v{b.version} · {b.rules} rules</span>
                      {b.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>off</Badge>}
                    </div>
                    {b.description ? <div className="faint" style={{ fontSize: 11.5, marginTop: 3 }}>{b.description}</div> : null}
                  </div>
                  <button
                    className="small"
                    disabled={togglingBundle !== null}
                    onClick={() => enableBundle(b.name, !b.enabled)}
                  >
                    {togglingBundle === b.name ? "Saving…" : b.enabled ? "Disable" : "Enable"}
                  </button>
                </div>
              ))
            )}
          </Card>

          <Card
            title="Installed bundles"
            actions={
              <>
                <Badge tone={bundles?.configured ? "ok" : "warn"}>
                  {bundles && bundles.providers.filter((p) => p.configured).length > 1
                    ? "signed channels"
                    : bundles?.configured ? "signed channel" : "no channel"}
                </Badge>
                <button
                  className="small"
                  onClick={() => checkBundles("")}
                  disabled={checkingBundles !== null || !bundles?.configured}
                >
                  {checkingBundles === "" ? "Checking…" : "Check all"}
                </button>
              </>
            }
          >
            {!bundles ? (
              <Empty>Loading…</Empty>
            ) : installedBundles.length === 0 ? (
              <Empty>No packs installed from a provider yet. Add a provider below, then press Check.</Empty>
            ) : (
              <>
                <div style={{ overflowX: "auto" }}>
                  <div className="table-wrap"><table className="bundle-table">
                    <thead>
                      <tr><th>Bundle</th><th className="hide-narrow">Version</th><th className="num hide-phone">Rules</th><th className="hide-phone">Installed</th><th>Profile modes</th><th /></tr>
                    </thead>
                    <tbody>
                      {installedBundles.map((b) => (
                        <tr key={`${b.provider || ""}/${b.name}`}>
                          <td className="bundle-name">
                            {b.name}
                            {b.provider ? <div className="faint" style={{ fontSize: 10.5 }}>{b.provider}</div> : null}
                            <div className="faint mono phone-only" style={{ fontSize: 10.5 }}>{b.version}</div>
                            {!b.enabled ? <div style={{ marginTop: 2 }}><Badge>disabled</Badge></div> : null}
                          </td>
                          <td className="mono bundle-version hide-narrow">{b.version}</td>
                          <td className="num hide-phone">{b.rules}</td>
                          <td className="muted hide-phone">{fmtAgo(b.installed_at)}</td>
                          <td>
                            <div className="row" style={{ gap: 4 }}>
                              {modeBadges(b.modes).map((m) => <Badge key={m.label} tone={m.tone}>{m.label}</Badge>)}
                            </div>
                          </td>
                          <td className="num">
                            <button
                              className="small"
                              disabled={togglingBundle !== null}
                              onClick={() => enableBundle(b.name, !b.enabled)}
                            >
                              {togglingBundle === b.name ? "Saving…" : b.enabled ? "Disable" : "Enable"}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table></div>
                </div>
                <p className="muted mt" style={{ fontSize: 12, marginBottom: 0 }}>
                  Every provider's manifest is read hourly and a pack is downloaded only when its version changes. A
                  disabled pack keeps its files, so enabling it again needs no download.
                </p>
              </>
            )}
          </Card>

          <Card
            title="Bundle providers"
            sub="Signed manifests the console reads. A provider added here is stored in the database, so it needs no environment variable, and a name that already exists has its URL and key replaced."
          >
            {!bundles ? (
              <Empty>Loading…</Empty>
            ) : bundles.providers.length === 0 ? (
              <Empty>No providers added yet.</Empty>
            ) : (
              bundles.providers.map((p) => (
                <div key={p.name} className="provider-row">
                  <div style={{ minWidth: 0 }}>
                    <div className="row" style={{ gap: 6 }}>
                      <b>{p.name}</b>
                      {p.error
                        ? <Badge tone="warn">check failed</Badge>
                        : p.configured ? <Badge tone="ok">signed</Badge> : <Badge tone="warn">no channel</Badge>}
                    </div>
                    <div className="facts" style={{ marginTop: 3 }}>
                      <span><code>{p.url || "no URL"}</code></span>
                      {p.key_id ? <span><b>Publisher</b> <code>{p.key_id}</code></span> : null}
                      <span><b>Sequence</b> {p.sequence}</span>
                      <span><b>Checked</b> {fmtAgo(p.last_check)} · next {fmtAgo(p.next_check)}</span>
                    </div>
                    {p.error ? <div className="banner warn" style={{ marginTop: 6 }} role="status">{p.error}</div> : null}
                  </div>
                  <div className="row" style={{ gap: 6 }}>
                    <button
                      className="small"
                      onClick={() => checkBundles(p.name)}
                      disabled={checkingBundles !== null || !p.configured}
                    >
                      {checkingBundles === p.name ? "Checking…" : "Check"}
                    </button>
                    <button className="small danger" onClick={() => removeProvider(p.name)}>Remove</button>
                  </div>
                </div>
              ))
            )}
            <div className="row grow mt">
              <Field label="Name"><input value={providerForm.name} onChange={(e) => setProviderForm({ ...providerForm, name: e.target.value })} placeholder="vendor" /></Field>
              <Field label="Manifest URL"><input value={providerForm.url} onChange={(e) => setProviderForm({ ...providerForm, url: e.target.value })} placeholder="https://bundles.example.com/stable/manifest.json" /></Field>
              <Field label="Publisher public key"><input value={providerForm.public_key} onChange={(e) => setProviderForm({ ...providerForm, public_key: e.target.value })} placeholder="ed25519 key, hex or base64" /></Field>
              <button
                className="primary"
                style={{ marginTop: 18 }}
                onClick={saveProvider}
                disabled={savingProvider || !providerForm.name.trim() || !providerForm.url.trim() || !providerForm.public_key.trim()}
              >
                {savingProvider ? "Saving…" : "Save provider"}
              </button>
            </div>
            <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
              The key must be the ed25519 publisher key the manifest is signed with. Removing a provider stops future
              refreshes; packs it already installed keep serving until you disable them.
            </p>
          </Card>

          <Card
            title="Bundle hits"
            actions={<span className="faint" style={{ fontSize: 11.5 }}>last 24 hours</span>}
          >
            {bundleHits.length === 0 ? (
              <Empty>No bundle rule has matched in the last 24 hours.</Empty>
            ) : (
              <>
                {loggedOnly(bundleHits) ? (
                  <div className="banner warn" style={{ marginBottom: 10 }} role="status">
                    <span>These requests were served: no profile blocks these rules yet, so every match was only logged.</span>
                    <div className="banner-actions">
                      <button className="small" onClick={onOpenPolicies}>
                        Set bundle mode →
                      </button>
                    </div>
                  </div>
                ) : null}
                <div style={{ overflowX: "auto" }}>
                  <div className="table-wrap"><table className="hits-table">
                    <thead>
                      <tr><th className="hide-narrow">Rule</th><th>Bundle</th><th>What it matched</th><th className="num hide-narrow">Hits</th><th className="num hide-tablet">Addresses</th><th className="hide-compact">Last seen</th><th>Outcome</th></tr>
                    </thead>
                    <tbody>
                      {bundleHits.map((h) => (
                        <tr key={h.rule_id}>
                          <td className="mono hit-rule hide-narrow">{h.rule_id}</td>
                          <td className="hit-bundle">
                            <div>{h.bundle || <span className="faint">removed</span>}</div>
                            {h.version || h.provider ? (
                              <div className="faint mono" style={{ fontSize: 10.5 }}>
                                {h.provider || ""}
                                {h.version ? <span className="hide-narrow">{h.provider ? " · " : ""}{h.version}</span> : null}
                              </div>
                            ) : null}
                          </td>
                          <td className="muted hit-message" title={h.message}>{h.message}</td>
                          <td className="num hide-narrow">{h.hits.toLocaleString()}</td>
                          <td className="num hide-tablet">{h.addresses.toLocaleString()}</td>
                          <td className="muted hide-compact">{fmtAgo(h.last_seen)}</td>
                          <td>
                            <div className="row" style={{ gap: 4 }}>
                              {outcomeBadges(h).map((m) => <Badge key={m.label} tone={m.tone}>{m.label}</Badge>)}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table></div>
                </div>
                <p className="muted mt" style={{ fontSize: 12, marginBottom: 0 }}>
                  A hit proves a rule matched, not that the request was hostile. The counts come from the request log, so
                  they follow the retention window and the sampling setting.
                </p>
              </>
            )}
          </Card>
        </>
      )}

      {tab === "lookup" && (
          <Card title="Check an address">
            <div className="row grow">
              <Field label="IP address">
                <input value={probe} onChange={(e) => setProbe(e.target.value)} placeholder="203.0.113.10" />
              </Field>
              <button className="primary" style={{ marginTop: 18 }} disabled={checking || !probe.trim()} onClick={checkIP}>
                {checking ? "Checking…" : "Check"}
              </button>
            </div>
            {lookup && (
              <>
                <div className="bar-row">
                  <div>Threat feed</div>
                  <div>
                    {lookup.feed ? (
                      <>
                        <Badge tone={lookup.feed.action === "block" ? "bad" : "warn"}>{lookup.feed.action}</Badge>{" "}
                        {lookup.feed.name}
                      </>
                    ) : (
                      <span className="muted">not listed</span>
                    )}
                  </div>
                </div>
                <div className="bar-row" style={{ borderBottom: 0 }}>
                  <div>Ban</div>
                  <div>
                    {lookup.ban ? (
                      <>
                        <Badge tone={lookup.ban.permanent ? "bad" : "warn"}>
                          {lookup.ban.permanent ? "permanent" : "temporary"}
                        </Badge>{" "}
                        {lookup.ban.cidr} — {lookup.ban.reason} (source: {lookup.ban.source})
                        {lookup.ban.expires_at && (
                          <span className="muted"> · until {lookup.ban.expires_at.slice(0, 16).replace("T", " ")}Z</span>
                        )}
                      </>
                    ) : (
                      <span className="muted">not banned</span>
                    )}
                  </div>
                </div>
              </>
            )}
          </Card>
      )}

      {tab === "feeds" && (
        <>
          <div className="grid cols-3">
            <Card>
              <div className="stat"><div className="k">Merged entries</div><div className="v">{total.toLocaleString()}</div><div className="sub">deduplicated CIDRs in memory</div></div>
            </Card>
            <Card>
              <div className="stat"><div className="k">Enabled feeds</div><div className="v">{feeds.filter((f) => f.enabled).length}</div><div className="sub">of {feeds.length} configured</div></div>
            </Card>
            <Card>
              <div className="stat"><div className="k">Frozen</div><div className="v">{feeds.filter((f) => f.state === "frozen").length}</div><div className="sub">guardrails held a suspicious list</div></div>
            </Card>
          </div>
          <Card title="Upload local blocklist">
            <div className="row grow">
              <Field label="Name (optional)">
                <input value={uploadName} onChange={(e) => setUploadName(e.target.value)} placeholder="Defaults to the file name" />
              </Field>
              <Field label="File (.txt or .csv, max 10 MB)">
                <input ref={file} type="file" accept=".txt,.csv,text/plain,text/csv" />
              </Field>
              <button className="primary" style={{ marginTop: 18 }} onClick={upload} disabled={uploading}>
                {uploading ? "Uploading…" : "Upload and enable"}
              </button>
            </div>
            <p className="muted" style={{ fontSize: 12 }}>
              The file is stored locally and appears in Feeds as a local list. Its action is always
              <strong> block</strong>, so every address is dropped globally. CSV files may have the IP in any column.
            </p>
          </Card>
          <Card title="Add custom feed">
            <div className="row grow">
              <Field label="Name"><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="My blocklist" /></Field>
              <Field label="URL"><input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="https://example.com/blocklist.txt" /></Field>
              <Field label="Action">
                <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}>
                  <option value="block">block</option>
                  <option value="challenge">challenge</option>
                  <option value="log">log only</option>
                </select>
              </Field>
              <Field label="Interval (s)"><input type="number" value={form.interval_s} onChange={(e) => setForm({ ...form, interval_s: Number(e.target.value) })} /></Field>
              <button className="primary" style={{ marginTop: 18 }} onClick={add}>Add feed</button>
            </div>
          </Card>
          <Card title="Feeds">
            {feeds.length === 0 ? <Empty>No feeds configured.</Empty> : (
              <div style={{ overflowX: "auto" }}>
                <div className="table-wrap"><table className="feeds-table">
                  <thead>
                    <tr><th>Feed</th><th>Action</th><th className="num hide-tablet">Entries</th><th className="hide-compact">Last refresh</th><th className="hide-narrow">State</th><th /></tr>
                  </thead>
                  <tbody>
                    {feeds.map((f) => {
                      const tone = f.state === "ok" ? "ok" : f.state === "frozen" ? "bad" : f.state === "error" ? "warn" : "info";
                      return (
                        <tr key={f.id}>
                          <td>
                            <div className="feed-name" title={f.name}>{f.name}</div>
                            {/* The state column drops at phone width, so its badge rides here instead. */}
                            <div className="phone-only" style={{ marginTop: 2 }}><Badge tone={tone}>{f.state}</Badge></div>
                            <div className="faint mono feed-source" style={{ fontSize: 11 }}>
                              {f.local ? `Local upload · ${f.filename || "file"}` : f.url}
                            </div>
                          </td>
                          <td>
                            {f.local ? (
                              <Badge tone="bad">block</Badge>
                            ) : (
                              <select
                                value={f.action}
                                aria-label={`Action for ${f.name}`}
                                className="feed-action"
                                onChange={(e) => setAction(f, e.target.value)}
                              >
                                <option value="block">block</option>
                                <option value="challenge">challenge</option>
                                <option value="log">log only</option>
                              </select>
                            )}
                          </td>
                          <td className="num hide-tablet">{f.last_count.toLocaleString()}</td>
                          <td className="muted hide-compact">{fmtAgo(f.last_fetch)}</td>
                          <td className="hide-narrow">
                            <Badge tone={tone}>{f.state}</Badge>
                            {f.last_error ? <div className="faint feed-error" style={{ fontSize: 11 }}>{f.last_error}</div> : null}
                          </td>
                          <td className="right feed-actions">
                            <button className="small" onClick={() => toggle(f)}>{f.enabled ? "Disable" : "Enable"}</button>{" "}
                            <button className="small" onClick={() => refresh(f)}>Refresh</button>{" "}
                            {!f.builtin && <button className="small danger" onClick={() => remove(f)}>Delete</button>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table></div>
              </div>
            )}
            <p className="muted mt" style={{ fontSize: 12 }}>
              Feeds are fetched with ETag/If-Modified-Since caching, deduplicated and merged into one in-memory table. A list that grows
              more than five times in a single refresh is frozen instead of applied.
            </p>
          </Card>
        </>
      )}
    </div>
  );
}
