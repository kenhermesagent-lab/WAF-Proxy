import { describe, expect, it } from "vitest";
import { abuseSummary, abuseTone, describePlan, quotaView } from "./threatintel";
describe("plan detection", () => {
  it("names the plan the rate-limit ceiling belongs to", () => {
    expect(describePlan({ name: "Individual (free)", checks_per_day: 1000 }, { limit: 1000, remaining: 871 })).toBe(
      "Individual (free) · 1,000 checks/day",
    );
  });

  it("says the allowance when the ceiling is not a known plan", () => {
    expect(describePlan(undefined, { limit: 2500, remaining: 10 })).toBe(
      "allowance 2,500/day · plan not recognised",
    );
  });

  it("waits rather than guessing before the first check reports headers", () => {
    expect(describePlan(undefined, undefined)).toBe("checking the key…");
  });

});

describe("quota view", () => {
  it("counts used checks from the remaining header", () => {
    const q = quotaView({ limit: 1000, remaining: 750, reset_at: "2026-11-25T00:00:00Z" });
    expect(q).toMatchObject({ limit: 1000, remaining: 750, used: 250, percent: 25, reset: "00:00 UTC" });
  });

  it("clamps a remaining header the API should never send", () => {
    expect(quotaView({ limit: 1000, remaining: 5000 })).toMatchObject({ remaining: 1000, used: 0, percent: 0 });
    expect(quotaView({ limit: 1000, remaining: -5 })).toMatchObject({ remaining: 0, used: 1000, percent: 100 });
  });

  it("has nothing to show without a ceiling", () => {
    expect(quotaView(undefined)).toBeNull();
    expect(quotaView({ limit: 0, remaining: 0 })).toBeNull();
  });
});

describe("abuse score", () => {
  it("follows the documented thresholds", () => {
    expect(abuseTone(0)).toBe("ok");
    expect(abuseTone(24)).toBe("ok");
    expect(abuseTone(25)).toBe("warn");
    expect(abuseTone(75)).toBe("bad");
  });

  it("summarises reports and reporters", () => {
    expect(
      abuseSummary({ score: 100, reports: 3410, reporters: 486, last_reported: "2026-11-24T17:41:00Z" }),
    ).toBe("3,410 reports · 486 reporters · last 2026-11-24");
    expect(abuseSummary(undefined)).toBe("No key saved; add one in Settings");
    expect(abuseSummary({ score: 0, reports: 0, reporters: 0, error: "quota spent" })).toBe("quota spent");
  });
});
