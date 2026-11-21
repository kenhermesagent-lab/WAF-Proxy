import { describe, expect, it } from "vitest";
import { NAV, pageFromHash } from "./nav";

describe("pageFromHash", () => {
  it("maps a section hash to its page", () => {
    expect(pageFromHash("#/crowdsec")).toBe("crowdsec");
    expect(pageFromHash("#proxies")).toBe("proxies");
    expect(pageFromHash("#/settings/")).toBe("settings");
  });

  it("falls back to the dashboard for an empty or unknown hash", () => {
    expect(pageFromHash("")).toBe("dashboard");
    expect(pageFromHash("#")).toBe("dashboard");
    expect(pageFromHash("#/")).toBe("dashboard");
    expect(pageFromHash("#/nope")).toBe("dashboard");
  });

  it("resolves every navigation entry", () => {
    for (const item of NAV) expect(pageFromHash(`#/${item.id}`)).toBe(item.id);
  });
});
