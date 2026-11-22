import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Simulator from "./Simulator";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);

const event = {
  id: 1, ts: "2026-11-21T12:00:00Z", host: "app.example.com", src_ip: "203.0.113.7",
  country: "RU", asn: 64500, method: "GET", path: "/search", status: 403,
  bytes_in: 0, bytes_out: 0, latency_ms: 3, stage: "waf", rule_id: "942100",
  rule_msg: "sqli", action: "block", ua: "curl/8",
};

const blocked = {
  verdict: { action: "block", stage: "waf", rule: "942100", reason: "sqli: SQL Injection", status: 403 },
  stages: [
    { stage: "screen", verdict: "allow" },
    { stage: "rate-limit", verdict: "skipped", skipped: "state is per client" },
    { stage: "waf", verdict: "block", reason: "sqli: SQL Injection", rule_ids: ["942100"] },
  ],
  matches: [{ rule_id: 942100, message: "SQL Injection Attack Detected", severity: 2, disruptive: true }],
  upstream: "http://127.0.0.1:8080",
  truncated: false,
  notes: ["rate limiting is stateful; it was not evaluated"],
  exception: { profile_id: 2, profile: "Generic Web", rule_id: 942100, other_hosts: ["shop.example.com"] },
};

describe("Simulator", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    get.mockResolvedValue({ proxies: [{ id: 7, hostname: "app.example.com" }] });
    post.mockResolvedValue(blocked);
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the stage and rules behind a blocked event", async () => {
    render(<Simulator event={event} onClose={vi.fn()} onError={vi.fn()} />);

    const run = await screen.findByRole("button", { name: "Simulate" });
    await waitFor(() => expect((run as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(run);

    expect(await screen.findByText(/SQL Injection Attack Detected/)).toBeTruthy();
    expect(screen.getByText("state is per client")).toBeTruthy();
    expect(screen.getByText("served by http://127.0.0.1:8080")).toBeTruthy();
    expect(post).toHaveBeenCalledWith("/api/simulate", expect.objectContaining({ proxy_id: 7 }));

    fireEvent.click(screen.getByRole("button", { name: /Except rule 942100/ }));
    expect(screen.getByText(/also stops rule/)).toBeTruthy();
    expect(screen.getByText("shop.example.com")).toBeTruthy();
  });
});
