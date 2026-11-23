import { describe, expect, it } from "vitest";
import { bundleMode, hitsByBundle, modeBadges, profileBundleBadges } from "./bundles";

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
