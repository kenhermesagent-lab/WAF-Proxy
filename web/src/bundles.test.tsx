import { describe, expect, it } from "vitest";
import { bundleMode, hitsByBundle, loggedOnly, modeBadges, outcomeBadges, profileBundleBadges } from "./bundles";

describe("bundle modes", () => {
  it("defaults an unset bundle to log only", () => {
    expect(bundleMode({}, "cve-2026-11")).toBe("log");
    expect(bundleMode(undefined, "cve-2026-11")).toBe("log");
    expect(bundleMode({ "cve-2026-11": "nonsense" }, "cve-2026-11")).toBe("log");
    expect(bundleMode({ "cve-2026-11": "block" }, "cve-2026-11")).toBe("block");
  });

  it("summarises a profile against the installed packs", () => {
    expect(
      profileBundleBadges({ bundle_modes: { a: "block", b: "off" } }, ["a", "b", "c"]),
    ).toEqual([
      { tone: "bad", label: "1 block" },
      { tone: "warn", label: "1 log only" },
      { tone: "", label: "1 off" },
    ]);
  });

  it("omits modes no profile uses", () => {
    expect(modeBadges({ block: 0, log: 2, off: 0 })).toEqual([{ tone: "warn", label: "2 log only" }]);
    expect(modeBadges(undefined)).toEqual([]);
  });

  it("reports what the matching requests got, not what the profile allows", () => {
    expect(outcomeBadges({ blocked: 3, logged: 1 })).toEqual([
      { tone: "bad", label: "3 blocked" },
      { tone: "warn", label: "1 logged" },
    ]);
    expect(outcomeBadges({ blocked: 1200, logged: 0 })).toEqual([{ tone: "bad", label: "1,200 blocked" }]);
    expect(outcomeBadges({ blocked: 0, logged: 0 })).toEqual([{ tone: "", label: "off" }]);
  });

  it("warns only when every match was served", () => {
    expect(loggedOnly([{ blocked: 0, logged: 4 }])).toBe(true);
    expect(loggedOnly([{ blocked: 0, logged: 4 }, { blocked: 2, logged: 0 }])).toBe(false);
    expect(loggedOnly([])).toBe(false);
  });

  it("groups hits per bundle and drops unattributed rules", () => {
    expect(
      hitsByBundle([
        { bundle: "a", hits: 3 },
        { bundle: "a", hits: 2 },
        { hits: 9 },
        { bundle: "b", hits: 1 },
      ]),
    ).toEqual({ a: 5, b: 1 });
  });
});
