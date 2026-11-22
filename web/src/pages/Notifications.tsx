import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo } from "../ui";

type Settings = Record<string, string>;
type Alert = { id: number; channel: string; kind: string; payload: string; state: string; created_at: string; sent_at?: string | null; class?: string; muted?: boolean };
type EventKind = { kind: string; label: string };

const FALLBACK_KINDS: EventKind[] = [
  { kind: "ban", label: "Temporary ban" },
  { kind: "permanent_ban", label: "Permanent ban" },
  { kind: "gate", label: "Access gate lockout" },
  { kind: "cert", label: "Certificate expiry" },
];

export default function Notifications({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [settings, setSettings] = useState<Settings>({});
  const [channels, setChannels] = useState<Record<string, boolean>>({});
  const [recent, setRecent] = useState<Alert[]>([]);
  const [kinds, setKinds] = useState<EventKind[]>(FALLBACK_KINDS);

  const load = () =>
    api
      .get<{ settings: Settings; channels: Record<string, boolean>; recent: Alert[]; event_kinds?: EventKind[] }>("/api/notifications")
      .then((r) => {
        setSettings(r.settings || {});
        setChannels(r.channels || {});
        setRecent(r.recent || []);
        if (r.event_kinds?.length) setKinds(r.event_kinds);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const set = (k: string, v: string) => setSettings((s) => ({ ...s, [k]: v }));

  const rawEvents = (settings.events ?? "").trim();
  const allEvents = rawEvents === "";
  const noEvents = rawEvents === "none";
  const chosen = new Set(
    allEvents || noEvents ? [] : rawEvents.split(",").map((v) => v.trim()).filter(Boolean),
  );
  const eventOn = (kind: string) => allEvents || (!noEvents && chosen.has(kind));

  const toggleEvent = (kind: string, on: boolean) => {
    const next = new Set(allEvents ? kinds.map((k) => k.kind) : noEvents ? [] : [...chosen]);
    if (on) next.add(kind);
    else next.delete(kind);
    const value = next.size === 0 ? "none" : next.size === kinds.length ? "" : [...next].join(",");
    set("events", value);
  };

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
            <Field label="Chat ID"><input value={settings.telegram_chat ?? ""} onChange={(e) => set("telegram_chat", e.target.value)} placeholder="@channelname or -1001234567890" /></Field>
            <p className="muted" style={{ fontSize: 12, marginTop: -4 }}>
              Public channels use @name; private channels use their -100… ID. The bot must be a channel admin.
            </p>
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

      <Card title="Event routing">
        <div className="grid cols-4">
          {kinds.map((k) => (
            <label key={k.kind} style={{ display: "flex", gap: 9, alignItems: "center", textTransform: "none", letterSpacing: 0, margin: 0 }}>
              <input
                type="checkbox"
                style={{ width: "auto" }}
                checked={eventOn(k.kind)}
                onChange={(e) => toggleEvent(k.kind, e.target.checked)}
              />
              {k.label}
            </label>
          ))}
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          Every event is delivered by default. Untick a class to suppress it on all channels and on
          agent webhooks; explicit channel test messages are always sent.
        </p>
      </Card>

      <div className="row" style={{ justifyContent: "space-between" }}>
        <p className="muted" style={{ fontSize: 12, margin: 0 }}>
          Ban additions are batched into a five-minute digest. Permanent bans, feed freezes and certificate problems are sent
          immediately. Muting a class also suppresses what is already queued for it.
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
                  <td className="muted">
                    <div>{a.kind}</div>
                    <div style={{ fontSize: 11 }}>
                      class {a.class ?? a.kind}
                      {a.muted && <> <Badge tone="warn">muted</Badge></>}
                    </div>
                  </td>
                  <td style={{ maxWidth: 520 }}>{a.payload}</td>
                  <td>
                    <Badge tone={a.state === "sent" ? "ok" : a.state === "failed" ? "bad" : a.state === "suppressed" ? "warn" : "info"}>
                      {a.state}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
