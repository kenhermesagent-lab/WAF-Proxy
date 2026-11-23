import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import ProxyDetail from "./ProxyDetail";
import type { Proxy } from "../types";

vi.mock("../api", () => ({ api: { get: vi.fn() } }));

import { api } from "../api";

const get = vi.mocked(api.get);

const proxy = {
  id: 7,
  hostname: "app.lab.local",
  enabled: true,
  maintenance: false,
  waf_mode: "block",
  bot_level: "standard",
  gate_mode: "off",
  fingerprint: "strict",
  profile_id: null,
  protection_profile_id: 3,
  access_profile_id: null,
  auth_provider_id: null,
  cert_id: 2,
  upstreams: [{ url: "http://10.0.0.10:8080", weight: 1, enabled: true }],
  routes: [],
  requests: 0,
  blocked: 0,
} as unknown as Proxy;

describe("ProxyDetail", () => {
  beforeEach(() => {
    get.mockReset();
    get.mockImplementation(async (path: string) => {
      if (path === "/api/metrics") {
        return { proxies: { "7": { requests: 120, blocked: 30, bytes_in: 1024, bytes_out: 2048 } } };
      }
      if (path === "/api/uptime") {
        return {
          targets: [
            {
              id: "t1",
              proxy_id: 7,
              proxy_host: "app.lab.local",
              url: "http://10.0.0.10:8080",
              state: "up",
              status_code: 200,
              latency_ms: 12,
              last_check: "2026-11-22T16:03:00Z",
              last_change: "2026-11-22T15:00:00Z",
              error: "",
              uptime_24: 99.5,
              checks_24: 40,
            },
            {
              id: "t2",
              proxy_id: 7,
              proxy_host: "app.lab.local",
              url: "http://10.0.0.11:8080",
              state: "up",
              status_code: 200,
              latency_ms: 8,
              last_check: "2026-11-22T16:03:00Z",
              last_change: "2026-11-22T15:00:00Z",
              error: "",
              uptime_24: 100,
              checks_24: 40,
            },
          ],
        };
      }
      return {};
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the measured traffic, upstream health and the assigned profile", async () => {
    render(
      <ProxyDetail
        proxy={proxy}
        protection={{ id: 3, name: "Balanced", builtin: true } as never}
        cert={undefined}
        onEdit={vi.fn()}
        onClose={vi.fn()}
      />,
    );

    expect(await screen.findByText("120")).toBeTruthy();
    expect(screen.getByText("30")).toBeTruthy();
    expect(screen.getByText("25.0% of requests")).toBeTruthy();
    // 99.5% is not rounded up to a perfect day.
    expect(screen.getByText("99.5%")).toBeTruthy();
    expect(screen.getByText("100%")).toBeTruthy();
    expect(screen.getByText("Balanced")).toBeTruthy();
    // Once in the health table and once in the upstream list.
    expect(screen.getAllByText("http://10.0.0.10:8080")).toHaveLength(2);
  });
});
