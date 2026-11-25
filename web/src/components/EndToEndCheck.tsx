import { useMemo, useState } from "react";
import { api } from "../api";
import { Badge, Card, Field, errText } from "../ui";
import type { Proxy, SimResult } from "../types";

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";

const BOUNDARY = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
const UPLOAD_BODY = [
  `--${BOUNDARY}`,
  'Content-Disposition: form-data; name="file"; filename="holiday.mp4"',
  "Content-Type: video/mp4",
  "",
  "x".repeat(64 << 10),
  `--${BOUNDARY}`,
  'Content-Disposition: form-data; name="parent_dir"',
  "",
  "/",
  `--${BOUNDARY}--`,
  "",
].join("\r\n");

type Traffic = {
  id: string;
  label: string;
  method: string;
  path: string;
  query: string;
  body: string;
  headers: Record<string, string>;
  why: string;
};

// Each preset is the request a client of that kind actually sends, so the
// replay exercises the same rules the real traffic meets: the path decides the
// body-skip entry and the routes, the content type decides 920420, and the user
// agent decides the bot filter.
const TRAFFIC: Traffic[] = [
  {
    id: "web",
    label: "Web page (browser)",
    method: "GET",
    path: "/",
    query: "",
    body: "",
    headers: { "User-Agent": BROWSER_UA, Accept: "text/html,application/xhtml+xml" },
    why: "A page view: screen, WAF and the route to the app.",
  },
  {
    id: "upload",
    label: "Upload (Seafile / Nextcloud)",
    method: "POST",
    path: "/seafhttp/upload-aj/00000000-0000-0000-0000-000000000000?ret-json=1",
    query: "ret-json=1",
    body: UPLOAD_BODY,
    headers: {
      "User-Agent": BROWSER_UA,
      "Content-Type": `multipart/form-data; boundary=${BOUNDARY}`,
      "X-Requested-With": "XMLHttpRequest",
    },
    why: "A multipart upload: the body-skip entry, the restricted-header rules and the WAF body limit all apply here.",
  },
  {
    id: "download",
    label: "Download (large file)",
    method: "GET",
    path: "/media/upload-link/00000000-0000-0000-0000-000000000000",
    query: "",
    body: "",
    headers: { "User-Agent": BROWSER_UA, Accept: "*/*" },
    why: "A range download: no request body, so only the header rules and the route matter.",
  },
  {
    id: "backup",
    label: "Backup / sync client (rclone)",
    method: "PUT",
    path: "/backup/daily-2026-11-25.tar.gz",
    query: "",
    body: "x".repeat(16 << 10),
    headers: { "User-Agent": "rclone/v1.68.0", "Content-Type": "application/octet-stream" },
    why: "A client that is not a browser: the bot filter and the content-type list are the usual refusals.",
  },
  {
    id: "api",
    label: "API client (JSON)",
    method: "POST",
    path: "/api/v1/items",
    query: "",
    body: '{"name":"test","value":42}',
    headers: { "User-Agent": "curl/8.11.0", "Content-Type": "application/json" },
    why: "A JSON call, the shape most scripts and integrations send.",
  },
  {
    id: "stream",
    label: "Streaming media (Plex / Jellyfin)",
    method: "GET",
    path: "/video/1/hls/segment/0.ts",
    query: "",
    body: "",
    headers: { "User-Agent": "PlexMediaPlayer/2.100", Accept: "*/*" },
    why: "A media segment: long-lived streaming, skipped bodies and the response hardening profile.",
  },
];

function privateIP(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip)
  );
}

function stageTone(verdict: string): "ok" | "bad" | "warn" | "" {
  if (verdict === "allow" || verdict === "log") return "ok";
  if (verdict === "block" || verdict === "ban") return "bad";
  if (verdict === "skipped") return "warn";
  return "";
}

// The advice is keyed by the stage that refuses, because that is what decides
// where an operator has to go to change the outcome.
function advice(stage: string): string {
  switch (stage) {
    case "permanent-ban":
    case "temp-ban":
      return "The address is banned. Policies → Bans lists it; remove it there.";
    case "asn-block":
      return "The source's network is blocked for this site. Policies → Bans (ASN) or the site's access profile.";
    case "geo-block":
      return "The source's country is blocked for this site. Policies → Bans (country).";
    case "list-allow":
      return "The site only admits listed sources. Add the address to its whitelist in Policies → Lists, or to the body-skip entry's trust list.";
    case "list-block":
      return "The address is on a blocklist applied to this site. Policies → Lists.";
    case "admin-path":
      return "The path is an admin path and the source is not an admin address. Policies → Profiles → admin addresses.";
    case "decoy":
      return "The path is a decoy: any request to it is a block. That is the intended answer for a scanner.";
    case "waf":
      return "A WAF rule refused it. The rule id and its message are below; the profile's exceptions take it out.";
    case "body-limit":
      return "The body is larger than the site's ceiling. Raise the ceiling or stream the path under body-skip.";
    case "rate-limit":
      return "The client exceeded its request rate. This replay never spends the limiter, so a real client can still be refused here.";
    default:
      return "";
  }
}

/**
 * End-to-end check: pick a source and the kind of traffic it sends, and the
 * request is replayed through the same pipeline a real one goes through. The
 * stage list is ordered, so the first refusal is the answer.
 */
export default function EndToEndCheck({
  proxies,
  onError,
}: {
  proxies: Proxy[];
  onError: (m: string) => void;
}) {
  const [proxyId, setProxyId] = useState<string>("");
  const [ip, setIP] = useState("203.0.113.10");
  const [trafficId, setTrafficId] = useState("web");
  const [path, setPath] = useState(TRAFFIC[0].path);
  const [result, setResult] = useState<SimResult | null>(null);
  const [busy, setBusy] = useState(false);

  const traffic = TRAFFIC.find((t) => t.id === trafficId) ?? TRAFFIC[0];
  const site = proxies.find((p) => String(p.id) === proxyId);
  const blockedAt = useMemo(
    () => result?.stages.findIndex((s) => s.verdict === "block" || s.verdict === "ban") ?? -1,
    [result],
  );

  const pick = (id: string) => {
    const next = TRAFFIC.find((t) => t.id === id) ?? TRAFFIC[0];
    setTrafficId(next.id);
    setPath(next.path);
    setResult(null);
  };

  const run = async () => {
    if (!site) {
      onError("Choose the proxy the traffic is for.");
      return;
    }
    setBusy(true);
    setResult(null);
    try {
      setResult(
        await api.post<SimResult>("/api/simulate", {
          proxy_id: site.id,
          method: traffic.method,
          path,
          query: traffic.query,
          body: traffic.body,
          client_ip: ip.trim(),
          headers: traffic.headers,
        }),
      );
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="What the request would meet">
        <p className="muted" style={{ marginTop: 0, fontSize: 12.5 }}>
          The request is replayed in this process through the real pipeline — bans, lists, the WAF, body-skip and the
          route — and nothing is sent upstream. The stages below are in the order a live request meets them, so the
          first one that refuses is what an operator has to change.
        </p>
        <div className="row grow">
          <Field label="Proxy">
            <select value={proxyId} onChange={(e) => { setProxyId(e.target.value); setResult(null); }}>
              <option value="">Select a proxy…</option>
              {proxies.map((p) => (
                <option key={p.id} value={p.id}>{p.hostname}</option>
              ))}
            </select>
          </Field>
          <Field label="Source address">
            <input
              value={ip}
              onChange={(e) => { setIP(e.target.value); setResult(null); }}
              placeholder="203.0.113.10"
              autoComplete="off"
              className="mono"
            />
          </Field>
          <Field label="Traffic">
            <select value={trafficId} onChange={(e) => pick(e.target.value)}>
              {TRAFFIC.map((t) => (
                <option key={t.id} value={t.id}>{t.label}</option>
              ))}
            </select>
          </Field>
        </div>
        <div className="row grow">
          <div className="field" style={{ flex: "2 1 320px" }}>
            <label>Path</label>
            <input value={path} onChange={(e) => { setPath(e.target.value); setResult(null); }} className="mono" />
          </div>
          <div className="field" style={{ flex: "0 0 110px" }}>
            <label>Method</label>
            <input value={traffic.method} readOnly />
          </div>
          <div className="field" style={{ flex: "0 0 130px" }}>
            <label>Body</label>
            <input value={traffic.body ? `${traffic.body.length.toLocaleString()} bytes` : "none"} readOnly />
          </div>
          <button className="primary" style={{ alignSelf: "flex-end" }} disabled={busy || !site} onClick={run}>
            {busy ? "Checking…" : "Run the check"}
          </button>
        </div>
        <p className="faint" style={{ fontSize: 11.5, marginBottom: 0 }}>
          {traffic.why}
          {privateIP(ip.trim()) &&
            " · This source is on a private range, so it is treated as a LAN client, not a public one."}
        </p>
      </Card>

      {result && (
        <Card
          title="Stage by stage"
          actions={
            blockedAt === -1
              ? <Badge tone="ok">would reach {result.upstream || "the route"}</Badge>
              : <Badge tone="bad">refused at {result.stages[blockedAt]?.stage}</Badge>
          }
        >
          <div className="grid" style={{ gap: 8 }}>
            {result.stages.map((s, i) => {
              const stops = i === blockedAt;
              return (
                <div
                  key={`${s.stage}-${i}`}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "26px 130px 72px 1fr",
                    gap: 10,
                    alignItems: "baseline",
                    padding: "8px 10px",
                    borderRadius: 8,
                    border: `1px solid ${stops ? "var(--danger-border)" : "var(--border)"}`,
                    background: stops ? "var(--danger-soft)" : "transparent",
                  }}
                >
                  <span className="faint mono" style={{ fontSize: 11 }}>{i + 1}</span>
                  <span style={{ fontWeight: 600 }}>{s.stage}</span>
                  <Badge tone={stageTone(s.verdict)}>{s.verdict}</Badge>
                  <span className="muted" style={{ fontSize: 12 }}>
                    {s.reason || s.skipped || "—"}
                    {s.rule_ids && s.rule_ids.length > 0 && (
                      <span className="mono faint"> · {s.rule_ids.join(", ")}</span>
                    )}
                    {stops && advice(s.stage) && (
                      <div style={{ marginTop: 3, color: "var(--muted)" }}>{advice(s.stage)}</div>
                    )}
                  </span>
                </div>
              );
            })}
          </div>

          {result.matches.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div className="faint" style={{ fontSize: 11.5, marginBottom: 4 }}>
                Rules that matched ({result.matches.length})
              </div>
              <div className="table-wrap"><table className="table-compact">
                <thead>
                  <tr><th>Rule</th><th>Message</th><th className="num">Severity</th></tr>
                </thead>
                <tbody>
                  {result.matches.map((m) => (
                    <tr key={`${m.rule_id}-${m.message}`}>
                      <td className="mono">{m.rule_id}</td>
                      <td className="muted">{m.message}</td>
                      <td className="num">{m.severity ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            </div>
          )}

          {(result.upstream || result.route) && (
            <div className="facts" style={{ marginTop: 12, fontSize: 12 }}>
              {result.route && <span>route: {result.route}</span>}
              {result.upstream && <span>upstream: <span className="mono">{result.upstream}</span></span>}
            </div>
          )}

          {result.notes.length > 0 && (
            <ul className="muted" style={{ fontSize: 11.5, margin: "10px 0 0", paddingLeft: 18 }}>
              {result.notes.map((n) => <li key={n}>{n}</li>)}
            </ul>
          )}
        </Card>
      )}
    </div>
  );
}
