import { describe, expect, it } from "vitest";
import { NAV, href, navAllowed, routeFromHash, tabAllowed } from "./nav";
import type { Me } from "./types";

const asMe = (fields: Partial<Me>) => fields as unknown as Me;

describe("navAllowed", () => {
  const ha = NAV.find((n) => n.id === "ha");
  if (!ha) throw new Error("the HA item is missing from NAV");

  it("hides high availability until the switch is on", () => {
    expect(navAllowed(ha, asMe({ permissions: ["ha.read"], role: "administrator", site: "default", ha_enabled: false }))).toBe(false);
    expect(navAllowed(ha, asMe({ permissions: ["ha.read"], role: "administrator", site: "default", ha_enabled: true }))).toBe(true);
  });

  it("still needs the permission and hides it from a host admin", () => {
    expect(navAllowed(ha, asMe({ permissions: [], role: "viewer", site: "default", ha_enabled: true }))).toBe(false);
    expect(navAllowed(ha, asMe({ permissions: ["ha.read"], role: "host_admin", site: "default", ha_enabled: true }))).toBe(false);
  });

  it("hides host-wide pages on a tenant console", () => {
    expect(navAllowed(ha, asMe({ permissions: ["ha.read"], role: "administrator", site: "bravo", ha_enabled: true }))).toBe(false);
    const bundles = NAV.find((n) => n.id === "intel")?.tabs?.find((t) => t.id === "bundles");
    const crowdsec = NAV.find((n) => n.id === "intel")?.tabs?.find((t) => t.id === "crowdsec");
    if (!bundles || !crowdsec) throw new Error("the host-only intel tabs are missing");
    expect(tabAllowed(bundles, asMe({ permissions: ["sources.read"], site: "bravo" }))).toBe(false);
    expect(tabAllowed(crowdsec, asMe({ permissions: ["sources.read"], site: "bravo" }))).toBe(false);
    expect(tabAllowed(bundles, asMe({ permissions: ["sources.read"], site: "default" }))).toBe(true);
  });

  it("leaves other items alone", () => {
    const dashboard = NAV.find((n) => n.id === "dashboard");
    if (!dashboard) throw new Error("the dashboard item is missing");
    expect(navAllowed(dashboard, asMe({ permissions: ["dashboard.read"], role: "viewer", site: "bravo" }))).toBe(true);
  });
});

describe("routeFromHash", () => {
  it("maps a canonical page hash to its page and default tab", () => {
    expect(routeFromHash("#/policies")).toEqual({ page: "policies", tab: "bans" });
    expect(routeFromHash("#/access")).toEqual({ page: "access", tab: "accounts" });
    expect(routeFromHash("#/proxies")).toEqual({ page: "proxies", tab: "sites" });
    expect(routeFromHash("#/intel")).toEqual({ page: "intel", tab: "feeds" });
    expect(routeFromHash("#/statistics")).toEqual({ page: "statistics", tab: "overview" });
  });

  it("keeps an explicit tab and drops a trailing slash", () => {
    expect(routeFromHash("#/intel/lookup")).toEqual({ page: "intel", tab: "lookup" });
    expect(routeFromHash("#proxies/certs")).toEqual({ page: "proxies", tab: "certs" });
    expect(routeFromHash("#/statistics/gate")).toEqual({ page: "statistics", tab: "gate" });
    expect(routeFromHash("#/settings/")).toEqual({ page: "settings", tab: "network" });
    expect(routeFromHash("#/settings/readiness")).toEqual({ page: "settings", tab: "readiness" });
  });

  it("falls back to the default tab for an unknown one", () => {
    expect(routeFromHash("#/policies/nope")).toEqual({ page: "policies", tab: "bans" });
  });

  it("folds the old page ids into a parent page's tab", () => {
    expect(routeFromHash("#/sources")).toEqual({ page: "intel", tab: "explorer" });
    expect(routeFromHash("#/crowdsec")).toEqual({ page: "intel", tab: "crowdsec" });
    expect(routeFromHash("#/certs")).toEqual({ page: "proxies", tab: "certs" });
    expect(routeFromHash("#/streaming")).toEqual({ page: "proxies", tab: "streaming" });
    expect(routeFromHash("#/updates")).toEqual({ page: "settings", tab: "updates" });
    expect(routeFromHash("#/readiness")).toEqual({ page: "settings", tab: "readiness" });
  });

  it("ignores the query string", () => {
    expect(routeFromHash("#/logs?ip=1.2.3.4")).toEqual({ page: "logs", tab: "" });
    expect(routeFromHash("#/sources?q=1.2.3.4")).toEqual({ page: "intel", tab: "explorer" });
  });

  it("falls back to the dashboard for an empty or unknown hash", () => {
    expect(routeFromHash("")).toEqual({ page: "dashboard", tab: "" });
    expect(routeFromHash("#")).toEqual({ page: "dashboard", tab: "" });
    expect(routeFromHash("#/")).toEqual({ page: "dashboard", tab: "" });
    expect(routeFromHash("#/nope")).toEqual({ page: "dashboard", tab: "" });
  });

  it("round-trips every canonical page through href", () => {
    // The absorbed ids are redirects, not page ids any more.
    const absorbed = new Set(["sources", "crowdsec", "certs", "streaming", "updates", "readiness"]);
    for (const item of NAV.filter((n) => !absorbed.has(n.id))) {
      const route = routeFromHash(href(item.id));
      expect(route.page).toBe(item.id);
      expect(href(route.page, route.tab)).toBe(href(item.id, route.tab));
    }
  });
});
