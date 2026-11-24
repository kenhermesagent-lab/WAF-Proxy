import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import CapacityCard, { Capacity } from "./CapacityCard";

const base: Capacity = {
  inflight: 12,
  max_inflight: 256,
  queued: 3,
  buffer_bytes: 4096,
  max_buffer_bytes: 536870912,
  shed: { bytes: 0, queue: 5, site: 1, client: 2 },
  cache: { bytes: 1048576, max_bytes: 134217728, hits: 30, misses: 10 },
  sites: [],
  pools: 1,
  heap_bytes: 20971520,
  memory_limit: 1073741824,
};

describe("capacity card", () => {
  afterEach(() => cleanup());

  it("shows the queue and the refusals with the way out", () => {
    render(<CapacityCard capacity={base} />);
    expect(screen.getByText(/3 queued/)).toBeTruthy();
    expect(screen.getByText(/Shed 8 at capacity/)).toBeTruthy();
    expect(screen.getByText(/75% of 40 lookups hit/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "raise the budget or add a site cap" }).getAttribute("href")).toBe("#/settings");
  });

  it("says nothing was refused on a quiet node", () => {
    render(<CapacityCard capacity={{ ...base, shed: {}, queued: 0 }} />);
    expect(screen.getByText(/nothing refused/)).toBeTruthy();
    expect(screen.queryByText(/Shed /)).toBeNull();
  });
});
