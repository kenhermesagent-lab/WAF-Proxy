import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo } from "../ui";

type Settings = Record<string, string>;
type Alert = { id: number; channel: string; kind: string; payload: string; state: string; created_at: string; sent_at?: string | null };

export default function Notifications({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [settings, setSettings] = useState<Settings>({});
  const [channels, setChannels] = useState<Record<string, boolean>>({});
  const [recent, setRecent] = useState<Alert[]>([]);

  const load = () =>
    api
      .get<{ settings: Settings; channels: Record<string, boolean>; recent: Alert[] }>("/api/notifications")
      .then((r) => {
        setSettings(r.settings || {});
        setChannels(r.channels || {});
        setRecent(r.recent || []);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const set = (k: string, v: string) => setSettings((s) => ({ ...s, [k]: v }));

  const save = async () => {
    try {
      await api.put("/api/notifications", settings);
      onOK("Notification settings saved");
      load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const test = async (channel: string) => {
    try {
      await api.post("/api/notifications/test", { channel });
      onOK(`Test sent to ${channel}`);
      setTimeout(load, 800);
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="grid cols-3">
        <Card>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0 }}>Telegram</h2>
            <Badge tone={channels.telegram ? "ok" : "warn"}>{channels.telegram ? "configured" : "not configured"}</Badge>
          </div>
          <div className="mt">
            <Field label="Bot token"><input type="password" value={settings.telegram_token ?? ""} onChange={(e) => set("telegram_token", e.target.value)} placeholder="123456:ABC..." /></Field>
            <Field label="Chat ID"><input value={settings.telegram_chat ?? ""} onChange={(e) => set("telegram_chat", e.target.value)} placeholder="-1001234567890" /></Field>
            <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={settings.telegram_enabled === "1"} onChange={(e) => set("telegram_enabled", e.target.checked ? "1" : "0")} /> enabled
            </label>
            <button className="small mt" onClick={() => test("telegram")}>Send test</button>
          </div>
        </Card>

        <Card>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0 }}>Email / Gmail</h2>
            <Badge tone={channels.email ? "ok" : "warn"}>{channels.email ? "configured" : "not configured"}</Badge>
          </div>
          <div className="mt">
            <Field label="SMTP host"><input value={settings.smtp_host ?? ""} onChange={(e) => set("smtp_host", e.target.value)} placeholder="smtp.gmail.com" /></Field>
            <div className="row grow">
              <Field label="Port"><input value={settings.smtp_port ?? "587"} onChange={(e) => set("smtp_port", e.target.value)} /></Field>
              <Field label="Username"><input value={settings.smtp_user ?? ""} onChange={(e) => set("smtp_user", e.target.value)} /></Field>
            </div>
            <Field label="App password"><input type="password" value={settings.smtp_password ?? ""} onChange={(e) => set("smtp_password", e.target.value)} /></Field>
            <div className="row grow">
              <Field label="From"><input value={settings.smtp_from ?? ""} onChange={(e) => set("smtp_from", e.target.value)} /></Field>
              <Field label="To"><input value={settings.smtp_to ?? ""} onChange={(e) => set("smtp_to", e.target.value)} /></Field>
            </div>
            <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={settings.email_enabled === "1"} onChange={(e) => set("email_enabled", e.target.checked ? "1" : "0")} /> enabled
            </label>
            <button className="small mt" onClick={() => test("email")}>Send test</button>
          </div>
        </Card>

        <Card>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0 }}>Webhook</h2>
            <Badge tone={channels.webhook ? "ok" : "warn"}>{channels.webhook ? "configured" : "not configured"}</Badge>
          </div>
          <div className="mt">
            <Field label="Slack / Teams / generic URL">
              <input type="password" value={settings.webhook_url ?? ""} onChange={(e) => set("webhook_url", e.target.value)} placeholder="https://hooks.slack.com/services/..." />
            </Field>
            <label style={{ display: "flex", gap: 8, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={settings.webhook_enabled === "1"} onChange={(e) => set("webhook_enabled", e.target.checked ? "1" : "0")} /> enabled
            </label>
            <button className="small mt" onClick={() => test("webhook")}>Send test</button>
            <p className="muted mt" style={{ fontSize: 12 }}>
              WhatsApp needs a paid Business API provider and is intentionally not included.
            </p>
          </div>
        </Card>
      </div>

      <div className="row" style={{ justifyContent: "space-between" }}>
        <p className="muted" style={{ fontSize: 12, margin: 0 }}>
          Ban additions are batched into a five-minute digest. Permanent bans, feed freezes and certificate problems are sent immediately.
        </p>
        <button className="primary" onClick={save}>Save settings</button>
      </div>

      <Card title="Recent deliveries">
        {recent.length === 0 ? <Empty>No notifications sent yet.</Empty> : (
          <table>
            <thead><tr><th>Time</th><th>Channel</th><th>Kind</th><th>Message</th><th>State</th></tr></thead>
            <tbody>
              {recent.map((a) => (
                <tr key={a.id}>
                  <td className="muted">{fmtAgo(a.created_at)}</td>
                  <td>{a.channel}</td>
                  <td className="muted">{a.kind}</td>
                  <td style={{ maxWidth: 520 }}>{a.payload}</td>
                  <td><Badge tone={a.state === "sent" ? "ok" : a.state === "failed" ? "bad" : "info"}>{a.state}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
