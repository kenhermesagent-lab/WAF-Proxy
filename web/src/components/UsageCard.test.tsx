import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import UsageCard from "./UsageCard";

describe("usage card", () => {
  afterEach(() => cleanup());

  it("shows both dials against the host's cores and RAM", () => {
    render(<UsageCard load={{ cpu_percent: 42, cores: 8, mem_used: 6 * 1024 ** 3, mem_total: 16 * 1024 ** 3 }} />);
    expect(screen.getByRole("img", { name: "CPU 42% · 8 vCPU" })).toBeTruthy();
    expect(screen.getByRole("img", { name: "Memory 38% · 6.0 GB / 16.0 GB" })).toBeTruthy();
  });

  it("waits for the first frame instead of drawing empty dials", () => {
    render(<UsageCard load={null} />);
    expect(screen.queryByRole("img")).toBeNull();
  });
});
