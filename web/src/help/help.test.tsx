import { describe, expect, it } from "vitest";
import { NAV } from "../nav";
import { HELP, helpFor } from "./index";

describe("page help", () => {
  it("covers every page in the navigation", () => {
    expect(NAV.map((n) => n.id).filter((id) => !helpFor(id))).toEqual([]);
  });

  it("does not ship help for a page that no longer exists", () => {
    const ids = new Set(NAV.map((n) => n.id));
    expect(Object.keys(HELP).filter((id) => !ids.has(id))).toEqual([]);
  });
});
