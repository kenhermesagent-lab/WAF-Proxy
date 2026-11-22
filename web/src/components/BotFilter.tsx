import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Field, errText } from "../ui";

const MODES = [
  { value: "off", label: "Off — only the per-proxy challenge runs", hint: "Nothing is refused by user agent." },
  { value: "scrapers", label: "Block known scrapers", hint: "SEO, marketing and AI-training crawlers. Search engines and social previews are kept." },
  { value: "all", label: "Block scrapers and any declared bot", hint: "Adds empty user agents and every unlisted agent that calls itself a bot, spider or crawler." },
];

export default function BotFilter({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [mode, setMode] = useState("off");
  const [allow, setAllow] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);

  const load = () =>
    api
      .get<Record<string, string>>("/api/settings")
      .then((s) => {
        setMode(s.bot_filter || "off");
        setAllow(s.bot_filter_allow ?? "");
        setLoaded(true);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      await api.put("/api/settings", { bot_filter: mode, bot_filter_allow: allow });
      onOK("Bot filter saved");
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const active = MODES.find((m) => m.value === mode) ?? MODES[0];

  return (
    <Card title="Bot filter">
      <Field label="Mode">
        <select value={mode} onChange={(e) => setMode(e.target.value)} disabled={!loaded}>
          {MODES.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
        </select>
      </Field>
      <p className="muted" style={{ fontSize: 12, marginTop: -4 }}>{active.hint}</p>
      <Field label="Always allow (comma separated user-agent fragments)">
        <input
          value={allow}
          onChange={(e) => setAllow(e.target.value)}
          placeholder="Googlebot, Bingbot, DuckDuckBot"
          disabled={!loaded}
        />
      </Field>
      <p className="muted" style={{ fontSize: 12, marginTop: -4 }}>
        A matching fragment exempts a client from both modes. Keep real search crawlers here so a scraper rule never
        removes your pages from search results.
      </p>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button className="primary" onClick={save} disabled={!loaded || saving}>
          {saving ? "Saving…" : "Save bot filter"}
        </button>
      </div>
      <p className="muted" style={{ fontSize: 12, lineHeight: 1.7, marginBottom: 0 }}>
        The filter refuses the request outright and records a <code>bot-filter</code> stage. The per-proxy proof-of-work
        challenge on the Proxies page is separate: it makes a browser solve a small puzzle, while this filter is for
        automation that never pretends to be a browser.
      </p>
    </Card>
  );
}
