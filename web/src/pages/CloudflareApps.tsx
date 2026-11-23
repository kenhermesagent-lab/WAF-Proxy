import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, SaveBar, Switch, errText } from "../ui";
import type { CloudflareAppsView, CloudflareCheck } from "../types";

type CheckResults = { checks: Record<string, CloudflareCheck[]>; checked: Record<string, string> };

// Published names live in the Cloudflare dashboard's ingress list, so each row
// hands over the values to paste rather than claiming the console wrote them.
export default function CloudflareApps({
  onError,
  onOK,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [view, setView] = useState<CloudflareAppsView | null>(null);
  const [saved, setSaved] = useState<string[]>([]);
  const [draft, setDraft] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [checking, setChecking] = useState("");

  const apply = (v: CloudflareAppsView) => {
    setView(v);
    const published = v.apps.filter((a) => a.published).map((a) => a.hostname);
    setSaved(published);
    setDraft(published);
  };

  useEffect(() => {
    api
      .get<CloudflareAppsView>("/api/cloudflare/apps")
      .then(apply)
      .catch((e) => onError(errText(e)));
  }, []);

  if (!view) {
    return (
      <Card title="Apps">
        <p className="muted">Loading hostnames…</p>
      </Card>
    );
  }

  const dirty = draft.join(",") !== saved.join(",");

  const toggle = (host: string, on: boolean) =>
    setDraft((prev) => (on ? [...new Set([...prev, host])].sort() : prev.filter((h) => h !== host)));

  const save = async () => {
    setSaving(true);
    try {
      apply(await api.put<CloudflareAppsView>("/api/cloudflare/apps", { published: draft }));
      onOK("Published hostnames saved");
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const check = async (hosts: string[]) => {
    if (hosts.length === 0) return;
    setChecking(hosts.length === 1 ? hosts[0] : "all");
    try {
      const res = await api.post<CheckResults>("/api/cloudflare/apps/check", { hostnames: hosts });
      setView((v) =>
        v ? { ...v, checks: { ...v.checks, ...res.checks }, checked: { ...v.checked, ...res.checked } } : v,
      );
    } catch (e) {
      onError(errText(e));
    } finally {
      setChecking("");
    }
  };

  const copy = (text: string) => {
    navigator.clipboard?.writeText(text).then(() => onOK("Copied"), () => onError("The browser refused clipboard access"));
  };

  return (
    <>
      <Card title="How publishing works">
        <p className="muted" style={{ marginTop: 0 }}>
          A published hostname keeps every WAF rule and stays behind Cloudflare Access; the tunnel only replaces the
          port forward. Cloudflare terminates TLS for it, so its edge certificate is the one browsers see.
        </p>
        <p className="muted">
          For each hostname, add a Public Hostname on the tunnel in the Cloudflare dashboard with the service, origin
          server name and no-TLS-verify values shown below.
        </p>
        {!view.connected && (
          <p className="hint warn">
            The connector is not running, so published hostnames will not answer until it is enabled on the Admin tab.
          </p>
        )}
      </Card>

      {view.apps.length === 0 ? (
        <Card title="Apps">
          <Empty title="No hostnames on this site yet" icon="globe">
            Add a proxy on the Proxies page first; it can be published here once it exists.
          </Empty>
        </Card>
      ) : (
        <Card
          title="Site hostnames"
          actions={
            draft.length > 0 ? (
              <button
                onClick={() => check(draft)}
                disabled={checking !== "" || dirty}
                title={dirty ? "Save the publish list first" : undefined}
              >
                {checking === "all" ? "Checking…" : "Check published"}
              </button>
            ) : undefined
          }
        >
          <div className="grid" style={{ gap: 10 }}>
            {view.apps.map((app) => {
              const isPublished = draft.includes(app.hostname);
              const results = view.checks[app.hostname] ?? [];
              const checked = view.checked[app.hostname];
              const ingress = [
                `hostname: ${app.hostname}`,
                `service: ${app.service}`,
                `originServerName: ${app.origin_server_name}`,
                `noTLSVerify: ${app.no_tls_verify ? "true" : "false"}`,
              ].join("\n");
              return (
                <div
                  key={app.hostname}
                  className="card"
                  style={{ padding: 14, display: "grid", gap: 10, background: "var(--panel-2, transparent)" }}
                >
                  <div className="row" style={{ justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                    <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                      <b className="mono">{app.hostname}</b>
                      {!app.enabled && <Badge tone="warn">proxy disabled</Badge>}
                      {isPublished && <Badge tone="ok">published</Badge>}
                    </div>
                    <Switch
                      checked={isPublished}
                      onChange={(on) => toggle(app.hostname, on)}
                      label="Publish through the tunnel"
                    />
                  </div>

                  {isPublished && (
                    <>
                      <div className="grid" style={{ gap: 4 }}>
                        <Value label="Service" value={app.service} />
                        <Value label="Origin server name" value={app.origin_server_name} />
                        <Value label="No TLS verify" value={app.no_tls_verify ? "on" : "off"} />
                      </div>
                      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                        <button className="small" onClick={() => copy(ingress)}>
                          Copy ingress values
                        </button>
                        <Badge tone={app.has_cert ? "ok" : ""}>
                          {app.has_cert ? "local certificate kept for the direct path" : "Cloudflare edge certificate"}
                        </Badge>
                      </div>
                      <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                        A local HTTP-01 or TLS-ALPN-01 certificate cannot be renewed for this hostname while it is
                        published; DNS-01 still works. The console refuses those orders instead of leaving one pending.
                      </p>
                    </>
                  )}

                  {isPublished && (
                    <div className="grid" style={{ gap: 6 }}>
                      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                        <button className="small" onClick={() => check([app.hostname])} disabled={checking !== "" || dirty}>
                          {checking === app.hostname ? "Checking…" : "Check hostname"}
                        </button>
                        {checked && <span className="muted" style={{ fontSize: 12 }}>checked {new Date(checked).toLocaleTimeString()}</span>}
                      </div>
                      {results.map((c) => (
                        <div key={c.id} className="row" style={{ gap: 8, alignItems: "flex-start" }}>
                          <div style={{ flex: 1 }}>
                            <div>{c.label}</div>
                            <div className="muted" style={{ fontSize: 12 }}>{c.detail}</div>
                          </div>
                          <div>{c.ok ? <Badge tone="ok">pass</Badge> : <Badge tone="warn">needs attention</Badge>}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {dirty && (
        <SaveBar
          note={<><b>Unsaved changes</b> · publish state applies when you save</>}
          saveLabel="Save published hostnames"
          saving={saving}
          onDiscard={() => {
            setDraft(saved);
            onOK("Unsaved changes discarded");
          }}
          onSave={save}
        />
      )}
    </>
  );
}

function Value({ label, value }: { label: string; value: string }) {
  return (
    <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
      <span className="muted" style={{ minWidth: 130 }}>{label}</span>
      <span className="mono" style={{ wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}
