import { fmtBytes } from "../ui";

export type Capacity = {
  inflight: number;
  max_inflight: number;
  queued: number;
  buffer_bytes: number;
  max_buffer_bytes: number;
  shed: Record<string, number>;
  cache: { bytes: number; max_bytes: number; hits: number; misses: number };
  sites: {
    host: string;
    inflight: number;
    shed_site: number;
    shed_client: number;
    cache_bytes: number;
    cache_hits: number;
    cache_misses: number;
  }[];
  pools: number;
  heap_bytes: number;
  memory_limit: number;
};

// The budget numbers the dashboard could not show before: what the node holds,
// how much it cached, and whether it had to refuse anything.
export default function CapacityCard({ capacity }: { capacity: Capacity | null }) {
  if (!capacity) return <div className="skeleton kpi" />;
  const shed = Object.values(capacity.shed ?? {}).reduce((a, b) => a + b, 0);
  const lookups = capacity.cache.hits + capacity.cache.misses;
  const hitRate = lookups ? Math.round((capacity.cache.hits / lookups) * 100) : 0;
  const used = capacity.max_inflight ? Math.min(100, Math.round((capacity.inflight / capacity.max_inflight) * 100)) : 0;
  return (
    <div className="kpi">
      <div className="kpi-label">Capacity</div>
      <div className="kpi-pair">
        <div>
          <div className="kpi-dir">In flight</div>
          <div className="kpi-value">
            {capacity.inflight}
            <small> / {capacity.max_inflight}</small>
          </div>
          <div className="kpi-sub">
            {capacity.queued.toLocaleString()} queued · {capacity.pools} pool{capacity.pools === 1 ? "" : "s"}
          </div>
        </div>
        <div>
          <div className="kpi-dir">Cache</div>
          <div className="kpi-value">{fmtBytes(capacity.cache.bytes)}</div>
          <div className="kpi-sub">{lookups ? `${hitRate}% hit · ${lookups.toLocaleString()} lookups` : "no lookups yet"}</div>
        </div>
      </div>
      <div className="kpi-meter" aria-hidden="true">
        <span style={{ width: `${used}%` }} />
      </div>
      <div className="kpi-sub">
        {shed > 0 ? (
          <>
            Shed {shed.toLocaleString()} at capacity · <a href="#/settings">raise the budget or add a site cap</a>
          </>
        ) : (
          `${fmtBytes(capacity.buffer_bytes)} buffered · nothing refused`
        )}
      </div>
    </div>
  );
}
