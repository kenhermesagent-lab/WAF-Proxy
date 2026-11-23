import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import Readiness from "./Readiness";
import type { Me } from "../types";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);

const me: Me = {
  username: "alice",
  csrf: "t",
  version: "1.37.0",
  base_domain: "waf.example.com",
  totp_enabled: true,
  role: "admin",
  permissions: ["settings.read"],
};

function settings() {
  return { base_domain: "waf.example.com", kernel: "active" };
}
function geoip() {
  return { available: true, city: true, asn: true, installing: false, attribution: "" };
}

describe("Readiness", () => {
  beforeEach(() => get.mockReset());
  afterEach(() => cleanup());

  it("scores the checklist from the endpoints and links each gap to its fix", async () => {
    get.mockImplementation(async (path: string) => {
      switch (path) {
        case "/api/settings":
          return settings();
        case "/api/certs":
          return { certs: [{ id: 1, domains: "waf.example.com", status: "issued" }] };
        case "/api/geoip":
          return geoip();
        case "/api/backup/schedule":
          return { config: { enabled: false }, status: {} };
        case "/api/notifications":
          return { channels: {} };
        case "/api/audit/verify":
          return { ok: true, checked: 42 };
        default:
          return { configured: false, applied: 0 };
      }
    });

    render(<Readiness me={me} onError={vi.fn()} />);

    expect(await screen.findByText("6 of 8 ready")).toBeTruthy();
    expect(screen.getByText(/^75% complete/)).toBeTruthy();

    // Backups and notifications are the gaps; both link to the page that fixes them.
    const fixes = screen.getAllByRole("link").map((a) => a.getAttribute("href"));
    expect(fixes).toContain("#/settings");
    expect(fixes).toContain("#/notifications");

    expect(screen.getByText("waf.example.com")).toBeTruthy();
    expect(screen.getByText("Intact across 42 entries.")).toBeTruthy();
  });

  it("never marks an unreadable source ready", async () => {
    get.mockImplementation(async (path: string) => {
      switch (path) {
        case "/api/settings":
          return settings();
        case "/api/certs":
          throw new Error("certificates unavailable");
        case "/api/geoip":
          return geoip();
        case "/api/backup/schedule":
          return { config: { enabled: true }, status: {} };
        case "/api/notifications":
          return { channels: { telegram: true } };
        case "/api/audit/verify":
          return { ok: true, checked: 1 };
        default:
          return { configured: false, applied: 0 };
      }
    });

    render(<Readiness me={me} onError={vi.fn()} />);

    expect(await screen.findByText("unknown")).toBeTruthy();
    expect(screen.getByText(/could not be checked/)).toBeTruthy();
    expect(screen.queryByText("8 of 8 ready")).toBeNull();
    expect(screen.getByText("7 of 8 ready")).toBeTruthy();
  });
});
