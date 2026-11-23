import { describe, expect, it } from "vitest";
import { NAV, href, routeFromHash } from "./nav";

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
    expect(routeFromHash("#/settings/")).toEqual({ page: "settings", tab: "" });
    expect(routeFromHash("#/settings/readiness")).toEqual({ page: "settings", tab: "" });
  });

  it("falls back to the default tab for an unknown one", () => {
    expect(routeFromHash("#/policies/nope")).toEqual({ page: "policies", tab: "bans" });
  });

  it("folds the old page ids into a parent page's tab", () => {
    expect(routeFromHash("#/sources")).toEqual({ page: "intel", tab: "explorer" });
    expect(routeFromHash("#/crowdsec")).toEqual({ page: "intel", tab: "crowdsec" });
    expect(routeFromHash("#/certs")).toEqual({ page: "proxies", tab: "certs" });
    expect(routeFromHash("#/streaming")).toEqual({ page: "proxies", tab: "streaming" });
    expect(routeFromHash("#/updates")).toEqual({ page: "settings", tab: "" });
    expect(routeFromHash("#/readiness")).toEqual({ page: "settings", tab: "" });
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
