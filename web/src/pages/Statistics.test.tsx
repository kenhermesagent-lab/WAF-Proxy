import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import Statistics from "./Statistics";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);

const analytics = {
  from: "2026-11-20T00:00:00Z",
  to: "2026-11-21T23:59:59Z",
  totals: { requests: 153532, blocked: 151, bytes_in: 1000, bytes_out: 2000, src_ips: 42 },
  series: [{ bucket: "2026-11-21T00:00:00Z", requests: 10, success: 9, errors: 1, bytes_in: 100, bytes_out: 200 }],
  proxies: [{ proxy_id: 1, host: "app.example.com", requests: 10, success: 9, errors: 1, bytes_in: 100, bytes_out: 200 }],
  countries: [{ name: "US", count: 8 }, { name: "DE", count: 2 }],
  stages: [{ name: "route", count: 9 }, { name: "waf", count: 1 }],
};

const uptime = {
  process_uptime_s: 90061,
  checked_at: "2026-11-21T12:00:00Z",
  proxies: [{ proxy_id: 1, host: "app.example.com", state: "down", targets: 1, up: 0 }],
  targets: [{
    id: "upstream:1", proxy_id: 1, proxy_host: "app.example.com", url: "http://192.0.2.10",
    state: "down", status_code: 503, latency_ms: 12, last_check: "2026-11-21T12:00:00Z",
    last_change: "2026-11-21T11:59:00Z", error: "backend returned 503", uptime_24: 98.5, checks_24: 200,
  }],
};

describe("Statistics page", () => {
  beforeEach(() => {
    get.mockReset();
    get.mockImplementation((url: string) =>
      Promise.resolve(url.startsWith("/api/analytics") ? analytics : uptime),
    );
  });

  afterEach(() => {
    cleanup();
  });

  it("shows request outcomes, proxy traffic, countries and backend uptime", async () => {
    render(<Statistics onError={vi.fn()} />);

    expect(await screen.findByText("153,532")).toBeTruthy();
    expect(screen.getAllByText("app.example.com").length).toBeGreaterThan(0);
    expect(screen.getByText(/United States/)).toBeTruthy();
    expect(screen.getByText("backend returned 503")).toBeTruthy();
    expect(screen.getByText("98.5%")).toBeTruthy();
    expect(screen.getByText("1d 1h")).toBeTruthy();
  });
});
