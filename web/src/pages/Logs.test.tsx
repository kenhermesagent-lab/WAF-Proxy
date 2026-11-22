import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Logs from "./Logs";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);

const blockedEvent = {
  id: 9,
  ts: "2026-11-22T16:03:00Z",
  host: "app.lab.local",
  src_ip: "203.0.113.7",
  country: "RU",
  asn: 64500,
  method: "GET",
  path: "/.env",
  status: 403,
  bytes_in: 0,
  bytes_out: 0,
  latency_ms: 3,
  stage: "decoy",
  rule_id: "decoy",
  rule_msg: "decoy path",
  action: "ban",
  ua: "curl/8",
};

const simulated = {
  verdict: { action: "block", stage: "decoy", rule: "decoy", reason: "decoy path /.env", status: 403 },
  stages: [
    { stage: "screen", verdict: "allow" },
    { stage: "decoy", verdict: "block", reason: "decoy path /.env" },
    { stage: "waf", verdict: "skipped", skipped: "not reached" },
  ],
  matches: [],
  truncated: false,
  notes: ["rate limiting is stateful; it was not evaluated"],
};

describe("Logs request simulator", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/events")) return { events: [blockedEvent], total: 1 };
      if (path === "/api/proxies") return [{ id: 7, hostname: "app.lab.local" }];
      return [];
    });
    post.mockResolvedValue(simulated);
  });

  afterEach(() => {
    cleanup();
  });

  it("opens the simulator for a blocked row and renders the returned stages and verdict", async () => {
    render(<Logs onError={vi.fn()} onOpenSource={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Why?" }));
    expect(await screen.findByText(/Why was this request handled this way\? · app.lab.local/)).toBeTruthy();

    const run = await screen.findByRole("button", { name: "Simulate" });
    await waitFor(() => expect((run as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(run);

    expect((await screen.findAllByText("decoy path /.env")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("decoy").length).toBeGreaterThan(0);
    expect(screen.getByText("not reached")).toBeTruthy();
    expect(screen.getByText(/rate limiting is stateful/)).toBeTruthy();
    expect(post).toHaveBeenCalledWith(
      "/api/simulate",
      expect.objectContaining({ proxy_id: 7, method: "GET", path: "/.env", client_ip: "203.0.113.7" }),
    );
  });

  it("opens the source drawer from a source cell", async () => {
    const onOpenSource = vi.fn();
    render(<Logs onError={vi.fn()} onOpenSource={onOpenSource} />);

    fireEvent.click(await screen.findByRole("button", { name: "203.0.113.7" }));
    expect(onOpenSource).toHaveBeenCalledWith("203.0.113.7");
  });

  it("polls the newest page while the live tail is on", async () => {
    render(<Logs onError={vi.fn()} onOpenSource={vi.fn()} />);
    await screen.findByText("GET /.env");
    const before = get.mock.calls.filter(([path]) => path.startsWith("/api/events")).length;

    fireEvent.click(screen.getByRole("button", { name: "Live tail" }));
    expect(screen.getByRole("button", { name: "● Live" })).toBeTruthy();

    await waitFor(
      () => expect(get.mock.calls.filter(([path]) => path.startsWith("/api/events")).length).toBeGreaterThan(before + 1),
      { timeout: 4000 },
    );
  });
});
