import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Field, errText, fmtAgo } from "../ui";
import type { CrowdSecStatus } from "../types";

export default function CrowdSecPage({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [status, setStatus] = useState<CrowdSecStatus | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [url, setUrl] = useState("");
  const [key, setKey] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  const applyStatus = (s: CrowdSecStatus) => {
    setStatus(s);
    setEnabled(s.config?.enabled ?? s.configured);
    setUrl(s.config?.url ?? s.lapi ?? "");
  };

  const load = () =>
    api
      .get<CrowdSecStatus>("/api/crowdsec")
      .then(applyStatus)
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
    const t = setInterval(() => {
      api.get<CrowdSecStatus>("/api/crowdsec").then(setStatus).catch(() => undefined);
    }, 15000);
    return () => clearInterval(t);
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const next = await api.put<CrowdSecStatus>("/api/crowdsec", {
        enabled,
        url,
        key,
        clear_key: clearKey,
      });
      applyStatus(next);
      setKey("");
      setClearKey(false);
      onOK(enabled ? "CrowdSec bouncer enabled" : "CrowdSec bouncer disabled");
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    setTesting(true);
    try {
      await api.post("/api/crowdsec/test", { url, key });
      onOK("CrowdSec LAPI accepted the connection and bouncer key");
    } catch (e) {
      onError(errText(e));
    } finally {
      setTesting(false);
    }
  };

  const keySet = status?.config?.key_set || false;
  const configured = status?.configured || false;

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card
        title="Security engine and bouncer"
        actions={<button className="small" onClick={load}>Refresh</button>}
      >
        <div className="bar-row">
          <div>Bouncer</div>
          <div>
            {configured ? (
              <Badge tone="ok">streaming decisions</Badge>
            ) : enabled ? (
              <Badge tone="warn">enabled, waiting for configuration</Badge>
            ) : (
              <Badge>disabled</Badge>
            )}
          </div>
        </div>
        <div className="bar-row">
          <div>LAPI</div>
          <div className="mono" style={{ fontSize: 12 }}>{status?.lapi || "not configured"}</div>
        </div>
        <div className="bar-row">
          <div>Last successful poll</div>
          <div className="muted" style={{ fontSize: 12 }}>{status?.last_poll ? fmtAgo(status.last_poll) : "never"}</div>
        </div>
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>Decisions applied</div>
          <div className="mono">{status?.applied ?? 0}</div>
        </div>
        {status?.last_error && <p className="err-text">{status.last_error}</p>}
        <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
          The bouncer is an outbound client: it polls the CrowdSec Security Engine's Local API for ban
          decisions and applies them to the local ban engine. The Security Engine (and its LAPI) must be
          installed and running separately. No CrowdSec port is exposed to the WAN.
        </p>
      </Card>

      <Card title="Bouncer configuration">
        <div className="row grow">
          <Field label="LAPI URL">
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://127.0.0.1:8081" />
          </Field>
          <Field label={keySet ? "Bouncer key (leave blank to keep the saved key)" : "Bouncer key"}>
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={keySet ? "•••••••• saved" : "paste the key from cscli bouncers add"}
              autoComplete="off"
            />
          </Field>
        </div>
        <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, textTransform: "none", letterSpacing: 0 }}>
          <input type="checkbox" style={{ width: "auto" }} checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enable the CrowdSec bouncer
        </label>
        {keySet && (
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, textTransform: "none", letterSpacing: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={clearKey} onChange={(e) => setClearKey(e.target.checked)} />
            Remove the saved key
          </label>
        )}
        <div className="row" style={{ justifyContent: "flex-end", gap: 8 }}>
          <button className="small" onClick={test} disabled={testing || (!url && !status?.lapi)}>
            {testing ? "Testing…" : "Test connection"}
          </button>
          <button className="primary" onClick={save} disabled={saving}>{saving ? "Saving…" : "Save and apply"}</button>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          The key is encrypted with the installation master key and never returned to the browser. Changing
          the configuration takes effect within 30 seconds without restarting WAF-Proxy.
        </p>
      </Card>

      <div className="grid cols-2">
        <Card title="Docker Compose engine">
          <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
            The repository includes an optional CrowdSec sidecar that reads the WAF access log. Start it,
            create a bouncer key, then paste the key above.
          </p>
          <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, margin: 0 }}>{`cd /path/to/WAF-Proxy-Docker
docker compose -f deploy/docker-compose.yml --profile crowdsec up -d crowdsec
docker exec crowdsec cscli bouncers add wafproxy

# LAPI URL for the bouncer:
http://127.0.0.1:8081`}</pre>
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            The sidecar uses host networking and its LAPI listens on loopback only.
          </p>
        </Card>

        <Card title="Native engine">
          <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
            Install the CrowdSec Security Engine from the CrowdSec repository, add the nginx collection,
            and create a bouncer key. Point its acquisition at the WAF access log with the nginx parser.
          </p>
          <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, margin: 0 }}>{`sudo cscli collections install crowdsecurity/nginx
sudo cscli bouncers add wafproxy

# LAPI URL for the bouncer (stock native default):
http://127.0.0.1:8080`}</pre>
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            Use the listen URI from the engine's config if it was customised. Keep the LAPI on loopback or a
            private network; the bouncer needs only outbound access to it.
          </p>
        </Card>
      </div>

      <Card title="What the bouncer applies">
        <p className="muted" style={{ fontSize: 12, lineHeight: 1.7, marginTop: 0 }}>
          IP and range ban decisions are added to the local ban table with source <code>crowdsec</code> and
          the scenario name. When CrowdSec withdraws a decision, only the matching CrowdSec-sourced ban is
          removed. Decisions with non-ban types or simulated decisions are ignored. This bouncer does not
          replace the WAF, threat feeds, or the local ban engine.
        </p>
      </Card>
    </div>
  );
}
