import { describe, expect, it } from "vitest";
import { reachedApps, reachedGlobePoints } from "./reach";
import type { Reach, ReachEndpoint } from "./types";

function snapshot(endpoints: ReachEndpoint[]): Reach {
  return { since: "2026-11-24T10:00:00Z", allowed: 0, reached: 0, endpoints, sources: [], near_miss: [] };
}

function endpoint(over: Partial<ReachEndpoint>): ReachEndpoint {
  return {
    host: "app.example.com",
    path: "/login",
    method: "POST",
    status: 401,
    country: "us",
    count: 1,
    last_seen: "2026-11-24T10:00:00Z",
    lat: 38.9,
    lon: -77.0,
    ...over,
  };
}

describe("reachedApps", () => {
  it("merges one endpoint across countries and keeps the newest sighting", () => {
    const rows = reachedApps(
      snapshot([
        endpoint({ country: "us", count: 3, last_seen: "2026-11-24T10:05:00Z" }),
        endpoint({ country: "de", count: 2, last_seen: "2026-11-24T10:20:00Z" }),
        endpoint({ path: "/admin", method: "GET", status: 200, count: 4 }),
      ]),
    );

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ path: "/login", count: 5, last: "2026-11-24T10:20:00Z" });
    expect(rows[0].countries.sort()).toEqual(["de", "us"]);
    expect(rows[1]).toMatchObject({ path: "/admin", count: 4 });
  });

  it("keeps a different answer for the same path apart", () => {
    const rows = reachedApps(
      snapshot([
        endpoint({ status: 401, count: 2 }),
        endpoint({ status: 200, count: 7 }),
      ]),
    );

    expect(rows.map((r) => [r.status, r.count])).toEqual([
      [200, 7],
      [401, 2],
    ]);
  });

  it("ranks by volume and handles an empty window", () => {
    expect(reachedApps(null)).toEqual([]);
    const rows = reachedApps(snapshot([endpoint({ path: "/login", count: 1 }), endpoint({ path: "/admin", count: 9 })]));
    expect(rows.map((r) => r.path)).toEqual(["/admin", "/login"]);
  });
});

describe("reachedGlobePoints", () => {
  it("aggregates per country and host", () => {
    const points = reachedGlobePoints(
      snapshot([
        endpoint({ country: "us", path: "/login", count: 2, last_seen: "2026-11-24T10:05:00Z" }),
        endpoint({ country: "us", path: "/admin", count: 3, last_seen: "2026-11-24T10:30:00Z" }),
        endpoint({ country: "de", host: "vue.example.com", count: 1 }),
      ]),
    );

    expect(points).toHaveLength(2);
    expect(points[0]).toMatchObject({
      country: "US",
      host: "app.example.com",
      category: "reached",
      count: 5,
      last_seen: "2026-11-24T10:30:00Z",
    });
    expect(points[1]).toMatchObject({ country: "DE", host: "vue.example.com" });
  });

  it("drops rows the globe cannot place", () => {
    const points = reachedGlobePoints(
      snapshot([
        endpoint({ country: "" }),
        endpoint({ lat: 0, lon: 0 }),
        endpoint({ country: "nl", count: 4 }),
      ]),
    );

    expect(points).toHaveLength(1);
    expect(points[0]).toMatchObject({ country: "NL", count: 4 });
  });
});
