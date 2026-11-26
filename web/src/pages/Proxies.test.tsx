import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Proxies from "./Proxies";
import type { Proxy } from "../types";

vi.mock("../api", () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() } }));

import { api } from "../api";

const get = vi.mocked(api.get);
const put = vi.mocked(api.put);

const proxy = {
  id: 7,
  hostname: "app.example.com",
  enabled: true,
  maintenance: false,
  profile_id: null,
  protection_profile_id: null,
  access_profile_id: null,
  auth_provider_id: null,
  cert_id: null,
  gate_mode: "off",
  fingerprint: "strict",
  bot_level: "light",
  waf_mode: "inherit",
  max_body: 0,
  body_skip: [],
  deny_paths: ["/actuator/env", "/.env"],
  upstreams: [{ url: "http://10.0.0.10:8080", weight: 1, enabled: true }],
  routes: [],
  gate_users: [],
  requests: 0,
  blocked: 0,
} as unknown as Proxy;

describe("Proxies", () => {
  beforeEach(() => {
    get.mockReset();
    put.mockReset();
    get.mockImplementation(async (path: string) => {
      if (path === "/api/proxies") return [proxy];
      if (path === "/api/certs") return { certs: [] };
      return [];
    });
    put.mockResolvedValue({});
  });

  afterEach(() => {
    cleanup();
  });

  it("saves the closed paths that remain after one is removed", async () => {
    render(<Proxies onError={vi.fn()} onOK={vi.fn()} base="example.com" tab="sites" tabs={[]} onTab={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    fireEvent.click(screen.getByRole("tab", { name: "Protection" }));

    expect(screen.getByText("Closed paths")).toBeTruthy();
    expect((screen.getByDisplayValue("/actuator/env") as HTMLInputElement).value).toBe("/actuator/env");
    expect((screen.getByDisplayValue("/.env") as HTMLInputElement).value).toBe("/.env");

    fireEvent.click(screen.getByRole("button", { name: "Remove closed path 1" }));
    expect(screen.queryByDisplayValue("/actuator/env")).toBeNull();
    expect(screen.getByDisplayValue("/.env")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Save proxy" }));

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
    const [path, body] = put.mock.calls[0] as [string, { deny_paths: string[] }];
    expect(path).toBe("/api/proxies/7");
    expect(body.deny_paths).toEqual(["/.env"]);
    expect(JSON.stringify(body)).not.toContain("/actuator/env");
  });
});
