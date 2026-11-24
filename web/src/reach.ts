import type { GlobePoint, Reach } from "./types";

// One application endpoint that allowed requests landed on, merged across the
// source countries the window reported it from.
export type ReachedApp = {
  key: string;
  host: string;
  path: string;
  method: string;
  status: number;
  count: number;
  last: string;
  countries: string[];
};

export function reachedApps(reach: Reach | null): ReachedApp[] {
  const map = new Map<string, ReachedApp>();
  for (const e of reach?.endpoints ?? []) {
    const key = `${e.host}|${e.method}|${e.path}|${e.status}`;
    const cur = map.get(key);
    if (!cur) {
      map.set(key, {
        key,
        host: e.host,
        path: e.path,
        method: e.method,
        status: e.status,
        count: e.count,
        last: e.last_seen,
        countries: e.country ? [e.country] : [],
      });
      continue;
    }
    cur.count += e.count;
    if (Date.parse(e.last_seen) > Date.parse(cur.last)) cur.last = e.last_seen;
    if (e.country && !cur.countries.includes(e.country)) cur.countries.push(e.country);
  }
  return [...map.values()].sort((a, b) => b.count - a.count || Date.parse(b.last) - Date.parse(a.last));
}

// The globe draws one arc per source country and host, so a login page under
// attack from three countries reads as three strands rather than one blur.
export function reachedGlobePoints(reach: Reach | null): GlobePoint[] {
  const map = new Map<string, GlobePoint>();
  for (const e of reach?.endpoints ?? []) {
    if (!e.country || (e.lat === 0 && e.lon === 0)) continue;
    const key = `${e.country.toUpperCase()}|${e.host}`;
    const cur = map.get(key);
    if (!cur) {
      map.set(key, {
        country: e.country.toUpperCase(),
        host: e.host,
        category: "reached",
        count: e.count,
        last_seen: e.last_seen,
        lat: e.lat,
        lon: e.lon,
      });
      continue;
    }
    cur.count += e.count;
    if (Date.parse(e.last_seen) > Date.parse(cur.last_seen)) cur.last_seen = e.last_seen;
  }
  return [...map.values()].sort((a, b) => b.count - a.count);
}

export function nearMissTotal(reach: Reach | null): number {
  return (reach?.near_miss ?? []).reduce((n, r) => n + r.count, 0);
}

// A status the application answered with: 2xx landed, 3xx bounced to a login,
// 401/403 was the application refusing after the proxy let it in.
export function statusTone(status: number): "ok" | "warn" | "info" {
  if (status >= 200 && status < 300) return "ok";
  if (status >= 300 && status < 400) return "warn";
  return "info";
}
