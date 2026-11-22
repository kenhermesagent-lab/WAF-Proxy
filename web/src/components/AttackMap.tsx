import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { countryFlag, countryName } from "../countries";
import type { Event, GlobeHit, GlobePoint } from "../types";
import { Badge, Drawer, Empty, Skeleton, fmtAgo, fmtTime } from "../ui";
import Globe from "./Globe";

export default function AttackMap({
  points,
  hits,
  home,
  hours,
  onHours,
  onClose,
  onError,
}: {
  points: GlobePoint[];
  hits: GlobeHit[];
  home: { lat: number; lon: number };
  hours: number;
  onHours: (h: number) => void;
  onClose: () => void;
  onError: (m: string) => void;
}) {
  const [focus, setFocus] = useState<string | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(false);

  const regions = useMemo(() => {
    const map = new Map<string, { country: string; count: number; category: string; hosts: Set<string> }>();
    for (const p of points) {
      const cur = map.get(p.country) ?? { country: p.country, count: 0, category: p.category, hosts: new Set<string>() };
      cur.count += p.count;
      cur.hosts.add(p.host);
      if (p.count > 0) cur.category = p.category;
      map.set(p.country, cur);
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  }, [points]);

  const total = regions.reduce((n, r) => n + r.count, 0);
  const max = Math.max(1, ...regions.map((r) => r.count));
  const selected = focus ? regions.find((r) => r.country === focus) : undefined;
  const selectedHosts = selected?.hosts.size ?? 0;

  useEffect(() => {
    if (!focus) {
      setEvents([]);
      return;
    }
    let alive = true;
    setLoading(true);
    api
      .get<{ events: Event[] }>(`/api/events?limit=10&blocked=1&hours=${hours}&country=${encodeURIComponent(focus)}`)
      .then((r) => {
        if (alive) setEvents(r.events ?? []);
      })
      .catch((e) => {
        if (alive) onError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [focus, hours, onError]);

  return (
    <Drawer
      wide
      title={
        <span className="row" style={{ gap: 8 }}>
          <span style={{ color: "#9dc0ff", display: "inline-flex" }}><GlobeGlyph /></span>
          Attack map
        </span>
      }
      sub={`Blocked requests in the last ${hours} hour${hours === 1 ? "" : "s"} · ${total.toLocaleString()} events across ${regions.length} regions`}
      onClose={onClose}
      footer={<button onClick={onClose}>Close</button>}
    >
      <div className="map-shell">
        <div className="map-stage">
          <div className="map-toolbar">
            <div className="btn-group">
              {[1, 6, 24].map((h) => (
                <button key={h} className={`small ${hours === h ? "primary" : ""}`} onClick={() => { onHours(h); setFocus(null); }} aria-pressed={hours === h}>
                  {h}h
                </button>
              ))}
            </div>
            <span className="faint small-text">Drag to rotate · click a country or hotspot to isolate it.</span>
          </div>
          <Globe
            points={points}
            hits={hits}
            home={home}
            hours={hours}
            variant="expanded"
            focus={focus}
            onFocusChange={setFocus}
          />
        </div>
        <aside className="map-side">
          <div className="map-side-head">
            <h3>{focus ? `${countryFlag(focus)} ${countryName(focus)}` : "Attacks by region"}</h3>
            <p>
              {focus
                ? `${selected?.count.toLocaleString() ?? 0} blocked · ${selectedHosts} ${selectedHosts === 1 ? "host" : "hosts"}`
                : "Ranked by blocked requests"}
            </p>
          </div>
          <div className="map-side-body">
            {!focus ? (
              regions.length === 0 ? (
                <Empty title="No blocked traffic" icon="shield">Nothing has been blocked in this window.</Empty>
              ) : (
                <div className="region-list" role="list">
                  {regions.slice(0, 14).map((r) => (
                    <button
                      key={r.country}
                      className="region-row"
                      role="listitem"
                      onClick={() => setFocus(r.country)}
                    >
                      <span className="flag">{countryFlag(r.country) || "•"}</span>
                      <span className="region-name">{countryName(r.country) || "Unknown"}</span>
                      <span className="region-count">{r.count.toLocaleString()}</span>
                      <span className="region-bar"><i style={{ width: `${Math.max(2, (r.count / max) * 100)}%` }} /></span>
                    </button>
                  ))}
                </div>
              )
            ) : (
              <>
                <div className="row between" style={{ marginBottom: 8 }}>
                  <button className="small ghost" onClick={() => setFocus(null)}>← All regions</button>
                  <Badge tone="bad">{events.length} recent</Badge>
                </div>
                {loading ? (
                  <>
                    <Skeleton kind="line" count={5} />
                    <Skeleton kind="line" width="w60" />
                  </>
                ) : events.length === 0 ? (
                  <Empty title="No recent events" icon="search">No blocked requests from this region in the selected range.</Empty>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {events.map((e) => (
                      <div key={e.id} style={{ padding: "8px 0", borderBottom: "1px solid var(--border-soft)" }}>
                        <div className="row between" style={{ gap: 8 }}>
                          <span className="mono" style={{ fontSize: 12 }}>{e.src_ip}</span>
                          <span className="faint small-text" title={fmtTime(e.ts)}>{fmtAgo(e.ts)}</span>
                        </div>
                        <div className="faint small-text" style={{ marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {e.host} · {e.method} {e.path}
                        </div>
                        <div className="row" style={{ gap: 5, marginTop: 4 }}>
                          <Badge tone="bad">{e.stage}</Badge>
                          <span className="faint small-text">{e.rule_msg || e.rule_id || "policy"}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
          <div className="map-side-foot">
            <div className="row between small-text faint">
              <span>Top region</span>
              <span style={{ color: "var(--muted)" }}>
                {regions[0] ? `${countryName(regions[0].country)} · ${regions[0].count.toLocaleString()}` : "—"}
              </span>
            </div>
            <div className="row between small-text faint" style={{ marginTop: 4 }}>
              <span>Live rate</span>
              <span style={{ color: "var(--muted)" }}>{hits.filter((h) => Date.now() - Date.parse(h.ts) < 60000).length}/min</span>
            </div>
          </div>
        </aside>
      </div>
    </Drawer>
  );
}

function GlobeGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M3.5 12h17M12 3c3 2.5 4.5 5.5 4.5 9s-1.5 6.5-4.5 9c-3-2.5-4.5-5.5-4.5-9S9 5.5 12 3" />
    </svg>
  );
}
