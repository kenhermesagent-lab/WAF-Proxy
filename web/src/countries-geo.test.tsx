import { describe, expect, it } from "vitest";
import { COUNTRIES } from "./countries";
import { COUNTRY_SHAPES } from "./countries-geo";

describe("country geometry", () => {
  it("maps every country picker code to at least one ring", () => {
    const missing = COUNTRIES.map((country) => country.code).filter((code) => {
      const rings = COUNTRY_SHAPES[code];
      return !rings?.length || rings.some((ring) => ring.length < 3);
    });
    expect(missing).toEqual([]);
  });
});
