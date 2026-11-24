import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { countryFlag, countryName } from "../countries";
import { nearMissTotal, reachedApps, reachedGlobePoints, statusTone } from "../reach";
import type { Event, GlobeHit, GlobePoint, Reach } from "../types";
import { Badge, Drawer, Empty, Skeleton, fmtAgo, fmtTime } from "../ui";
import Globe from "./Globe";

type Tab = "blocked" | "reached" | "near";

export default function AttackMap({
  points,
  hits,
  reach,
  home,
  hours,
  onHours,
  onClose,
  onError,
  onOpenSource,
}: {
  points: GlobePoint[];
  hits: GlobeHit[];
  reach: Reach | null;
  home: { lat: number; lon: number };
  hours: number;
  onHours: (h: number) => void;
  onClose: () => void;
  onError: (m: string) => void;
  onOpenSource: (ip: string) => void;
}) {
  const [focus, setFocus] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("blocked");
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

  const reachedPoints = useMemo(() => reachedGlobePoints(reach), [reach]);
  const reachedAgg = useMemo(() => reachedApps(reach), [reach]);
  const near = reach?.near_miss ?? [];
  const nearCount = nearMissTotal(reach);

  const total = regions.reduce((n, r) => n + r.count, 0);
  const reachedCount = reach?.reached ?? 0;
  const allowed = reach?.allowed ?? 0;
  const max = Math.max(1, ...regions.map((r) => r.count));
  const selected = focus ? regions.find((r) => r.country === focus) : undefined;
  const selectedHosts = selected?.hosts.size ?? 0;
  const regionLine = (region: (typeof regions)[number] | undefined) =>
    region ? `${countryName(region.country)} · ${region.count.toLocaleString()}` : "—";

  const focusUpper = focus?.toUpperCase() ?? null;
  const visibleReached = useMemo(
    () => (focusUpper ? reachedAgg.filter((r) => r.countries.some((c) => c.toUpperCase() === focusUpper)) : reachedAgg),
    [reachedAgg, focusUpper],
  );
  const visibleNear = useMemo(
    () => (focusUpper ? near.filter((n) => n.country.toUpperCase() === focusUpper) : near),
    [near, focusUpper],
  );
  const reachedMax = Math.max(1, ...visibleReached.map((r) => r.count));
  const blockedShare = total + allowed > 0 ? (total / (total + allowed)) * 100 : 0;
  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: "blocked", label: "Blocked", count: total },
    { id: "reached", label: "Reached", count: reachedCount },
    { id: "near", label: "Near miss", count: nearCount },
  ];

  useEffect(() => {
    if (!focus || tab !== "blocked") {
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
  }, [focus, hours, tab, onError]);

  const openSource = (ip: string) => {
    // One drawer at a time: the map closes so the source drawer owns the only
    // focus trap on screen.
    onClose();
    onOpenSource(ip);
  };

  return (
    <Drawer
      wide
      title={
        <span className="row" style={{ gap: 8 }}>
          <span style={{ color: "#9dc0ff", display: "inline-flex" }}><GlobeGlyph /></span>
          Attack map
        </span>
      }
      sub={`${total.toLocaleString()} blocked · ${reachedCount.toLocaleString()} reached your applications in the last ${hours} hour${hours === 1 ? "" : "s"}`}
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
            reached={reachedPoints}
            home={home}
            hours={hours}
            variant="expanded"
            focus={focus}
            onFocusChange={setFocus}
          />
        </div>
        <aside className="map-side">
          <div className="reach-kpis">
            <div className="reach-kpi blocked">
              <span><i aria-hidden="true" />Blocked</span>
              <b>{total.toLocaleString()}</b>
            </div>
            <div className="reach-kpi reached">
              <span><i aria-hidden="true" />Reached app</span>
              <b>{reachedCount.toLocaleString()}</b>
            </div>
            <div className="reach-kpi near">
              <span><i aria-hidden="true" />Near miss</span>
              <b>{nearCount.toLocaleString()}</b>
            </div>
          </div>
          <div className="reach-split" aria-hidden="true" title={`${blockedShare.toFixed(1)}% of screened requests were refused`}>
            <i className="blocked" style={{ width: `${blockedShare}%` }} />
            <i className="reached" style={{ width: `${100 - blockedShare}%` }} />
          </div>
          <div className="map-tabs" role="tablist" aria-label="Map detail">
            {tabs.map((t) => (
              <button
                key={t.id}
                role="tab"
                aria-selected={tab === t.id}
                className={`small ${tab === t.id ? "primary" : "ghost"}`}
                onClick={() => setTab(t.id)}
              >
                {t.label} <span className="map-tab-count">{t.count.toLocaleString()}</span>
              </button>
            ))}
          </div>

          {tab === "blocked" ? (
            <>
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
                          <span className="region-count">
                            {r.count.toLocaleString()}
                            <span className="region-share"> · {Math.round((r.count / Math.max(1, total)) * 100)}%</span>
                          </span>
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
                              <button
                                className="link-cell mono"
                                style={{ fontSize: 12 }}
                                title={`Investigate ${e.src_ip}`}
                                onClick={() => openSource(e.src_ip)}
                              >
                                {e.src_ip}
                              </button>
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
                  <span>{focus ? "Selected region" : "Top region"}</span>
                  <span style={{ color: "var(--muted)" }}>{regionLine(focus ? selected : regions[0])}</span>
                </div>
                <div className="row between small-text faint" style={{ marginTop: 4 }}>
                  <span>Live rate</span>
                  <span style={{ color: "var(--muted)" }}>{hits.filter((h) => Date.now() - Date.parse(h.ts) < 60000).length}/min</span>
                </div>
              </div>
            </>
          ) : tab === "reached" ? (
            <>
              <div className="map-side-head">
                <h3>Reached the application</h3>
                <p>Allowed requests on login and admin endpoints · ranked by volume</p>
              </div>
              <div className="map-side-body">
                {visibleReached.length === 0 ? (
                  <Empty title="Nothing landed" icon="check">
                    No allowed request touched a login, admin or token endpoint in this window.
                  </Empty>
                ) : (
                  <>
                    <div className="region-list" role="list">
                      {visibleReached.slice(0, 12).map((r) => (
                        <div className="reach-row" key={r.key} role="listitem">
                          <div className="row between" style={{ gap: 8 }}>
                            <span className="mono reach-path" title={`${r.method} ${r.path}`}>
                              <b>{r.method}</b> {r.path}
                            </span>
                            <span className="reach-count">{r.count.toLocaleString()}</span>
                          </div>
                          <div className="row between reach-sub">
                            <span className="reach-host">{r.host}</span>
                            <span>
                              <span className={`reach-status ${statusTone(r.status)}`}>{r.status}</span>
                              {" · "}
                              {r.countries.length === 1
                                ? `${countryFlag(r.countries[0])} ${countryName(r.countries[0])}`
                                : `${r.countries.length} sources`}
                              {" · "}
                              {fmtAgo(r.last)}
                            </span>
                          </div>
                          <div className="reach-bar"><i style={{ width: `${Math.max(3, (r.count / reachedMax) * 100)}%` }} /></div>
                        </div>
                      ))}
                    </div>
                    {(reach?.sources.length ?? 0) > 0 && (
                      <>
                        <h4 className="reach-h4">Sources that got in</h4>
                        <div className="reach-sources">
                          {reach!.sources.map((s) => (
                            <div className="reach-source" key={s.ip}>
                              <button className="link-cell mono" title={`Investigate ${s.ip}`} onClick={() => openSource(s.ip)}>
                                {s.ip}
                              </button>
                              <span className="faint small-text">
                                {countryFlag(s.country)} {countryName(s.country) || s.country || "—"}
                                {s.asn ? ` · AS${s.asn}` : ""} · {s.count.toLocaleString()}
                              </span>
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                  </>
                )}
              </div>
              <div className="map-side-foot">
                <div className="row between small-text faint">
                  <span>Allowed of screened</span>
                  <span style={{ color: "var(--muted)" }}>{allowed.toLocaleString()} · {(100 - blockedShare).toFixed(1)}%</span>
                </div>
                <div className="row between small-text faint" style={{ marginTop: 4 }}>
                  <span>Endpoints touched</span>
                  <span style={{ color: "var(--muted)" }}>{reachedAgg.length}</span>
                </div>
              </div>
            </>
          ) : (
            <>
              <div className="map-side-head">
                <h3>Near miss</h3>
                <p>Detections that logged instead of blocking · a stricter profile would refuse them</p>
              </div>
              <div className="map-side-body">
                {visibleNear.length === 0 ? (
                  <Empty title="No near misses" icon="check">
                    Nothing in this window was logged instead of blocked. A WAF profile in detect mode, or a
                    bundle or feed rule set to log, appears here.
                  </Empty>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
                    {visibleNear.map((n) => (
                      <div className="near-row" key={`${n.stage}|${n.rule_id}|${n.rule_msg}`}>
                        <div className="row between" style={{ gap: 8 }}>
                          <span className="mono near-rule">{n.rule_id || n.stage}</span>
                          <span className="reach-count">{n.count.toLocaleString()}×</span>
                        </div>
                        <div className="near-msg">{n.rule_msg || n.stage}</div>
                        <div className="reach-sub">
                          <span className="reach-host">{n.host}</span>
                          <span>{countryFlag(n.country)} {fmtAgo(n.last_seen)}</span>
                        </div>
                        <div className="near-path mono" title={n.path}>{n.path}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div className="map-side-foot">
                <div className="row between small-text faint">
                  <span>Logged matches</span>
                  <span style={{ color: "var(--muted)" }}>{nearCount.toLocaleString()} across {near.length} rules</span>
                </div>
              </div>
            </>
          )}
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
