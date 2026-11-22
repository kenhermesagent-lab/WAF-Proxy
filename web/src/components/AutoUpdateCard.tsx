import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Field, errText } from "../ui";

export default function AutoUpdateCard({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [enabled, setEnabled] = useState(false);
  const [time, setTime] = useState("04:00");
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api
      .get<{ enabled: boolean; time: string }>("/api/updates/auto")
      .then((r) => {
        setEnabled(r.enabled);
        setTime(r.time || "04:00");
      })
      .catch((e) => onError(errText(e)))
      .finally(() => setLoaded(true));
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      await api.put("/api/updates/auto", { enabled, time });
      onOK(enabled ? `Automatic updates scheduled at ${time}` : "Automatic updates disabled");
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card
      title="Automatic updates"
      actions={<button className="small primary" onClick={save} disabled={saving || !loaded}>{saving ? "Saving…" : "Save"}</button>}
    >
      <div className="row grow">
        <label style={{ margin: "18px 0 0", display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
          <input type="checkbox" style={{ width: "auto" }} checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          apply a newer build automatically
        </label>
        <Field label="Run at (HH:MM)">
          <input value={time} onChange={(e) => setTime(e.target.value)} placeholder="04:00" />
        </Field>
      </div>
      <p className="muted" style={{ fontSize: 12 }}>
        Once a day, at that time, the console checks the tracked branch and — only when a newer build exists and this host
        supports the update — pulls, rebuilds and restarts. The result is sent to the notification channels that route
        <span className="mono"> Application update</span>. Left off, updates stay a button you press. Unattended rebuilds
        run as root with the checkout's code, so enable this only for a repository you trust.
      </p>
    </Card>
  );
}
