import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, errText, fmtAgo } from "../ui";
import type { AgentLink } from "../types";

type Draft = { name: string; endpoint: string; secret: string };

const empty: Draft = { name: "hermes-agent", endpoint: "", secret: "" };

export default function AgentLinks({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [list, setList] = useState<AgentLink[]>([]);
  const [draft, setDraft] = useState<Draft>({ ...empty });
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState(0);

  const load = () => api.get<AgentLink[]>("/api/agents").then(setList).catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const create = async () => {
    setSaving(true);
    try {
      await api.post("/api/agents", draft);
      onOK("Agent link added");
      setDraft({ ...empty });
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const test = async (l: AgentLink) => {
    setBusy(l.id);
    try {
      await api.post(`/api/agents/${l.id}/test`);
      onOK(`Test event delivered to ${l.name}`);
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(0);
    }
  };

  const toggle = async (l: AgentLink) => {
    try {
      await api.put(`/api/agents/${l.id}`, { name: l.name, endpoint: l.endpoint, enabled: !l.enabled });
      await load();
    } catch (e) {
      onError(errText(e));
    }
  };

  const remove = async (l: AgentLink) => {
    if (!confirm(`Delete ${l.name}? The agent stops receiving events.`)) return;
    try {
      await api.del(`/api/agents/${l.id}`);
      onOK("Agent link deleted");
      await load();
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card title="Agent links">
        {list.length === 0 ? (
          <Empty>
            No agent attached. Add the webhook your agent listens on and it receives every anomaly event, signed with
            the shared secret.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr><th>Agent</th><th>Endpoint</th><th>State</th><th>Added</th><th /></tr>
            </thead>
            <tbody>
              {list.map((l) => (
                <tr key={l.id}>
                  <td>{l.name}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{l.endpoint}</td>
                  <td>{l.enabled ? <Badge tone="ok">enabled</Badge> : <Badge tone="warn">paused</Badge>}</td>
                  <td className="muted">{fmtAgo(l.created_at)}</td>
                  <td className="right" style={{ whiteSpace: "nowrap" }}>
                    <button className="small" disabled={busy === l.id} onClick={() => test(l)}>
                      {busy === l.id ? "Sending…" : "Test"}
                    </button>{" "}
                    <button className="small" onClick={() => toggle(l)}>{l.enabled ? "Pause" : "Enable"}</button>{" "}
                    <button className="small danger" onClick={() => remove(l)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted" style={{ fontSize: 12 }}>
          Each anomaly event is POSTed as JSON with <span className="mono">X-Wafproxy-Signature: sha256=HMAC(secret, body)</span>{" "}
          and a timestamp header, so the agent can verify it came from this console and reject replays. The secret is
          sealed with the console key and shown once.
        </p>
      </Card>

      <Card title="Add an agent link">
        <div className="row grow">
          <Field label="Name">
            <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          </Field>
          <Field label="Webhook URL">
            <input
              value={draft.endpoint}
              onChange={(e) => setDraft({ ...draft, endpoint: e.target.value })}
              placeholder="https://hermes.internal/wafproxy/events"
            />
          </Field>
          <Field label="Shared secret (optional)">
            <input type="password" value={draft.secret} onChange={(e) => setDraft({ ...draft, secret: e.target.value })} />
          </Field>
        </div>
        <button className="primary" onClick={create} disabled={saving || !draft.name.trim() || !draft.endpoint.trim()}>
          {saving ? "Saving…" : "Add link"}
        </button>
      </Card>
    </div>
  );
}
