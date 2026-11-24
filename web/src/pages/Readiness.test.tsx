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
  email: "admin@example.com",
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
        case "/api/proxies":
          return { proxies: [{ id: 1, hostname: "app.example.com", requests: 4 }] };
        case "/api/users":
          return { users: [{ id: 1 }, { id: 2 }] };
        case "/api/me/prefs":
          return {};
        default:
          return { configured: false, applied: 0 };
      }
    });

    render(<Readiness me={me} onError={vi.fn()} />);

    // Every first-run row but notifications is done, so the page is still in
    // setup mode and does not claim a hardening score yet.
    expect(await screen.findByText("6 of 7 set up")).toBeTruthy();
    expect(screen.getByText(/switches to the hardening checklist/)).toBeTruthy();
    expect(screen.queryByText(/% complete/)).toBeNull();

    // The gaps link to the page that fixes them.
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
        case "/api/proxies":
          return { proxies: [{ id: 1, hostname: "app.example.com", requests: 4 }] };
        case "/api/users":
          return { users: [{ id: 1 }, { id: 2 }] };
        case "/api/me/prefs":
          return {};
        default:
          return { configured: false, applied: 0 };
      }
    });

    render(<Readiness me={me} onError={vi.fn()} />);

    expect(await screen.findByText("unknown")).toBeTruthy();
    expect(screen.getByText("6 of 7 set up")).toBeTruthy();
    expect(screen.queryByText("7 of 7 set up")).toBeNull();
    expect(screen.queryByText(/% complete/)).toBeNull();
  });

  it("leaves the host-wide CrowdSec row off a tenant console", async () => {
    get.mockImplementation(async (path: string) => {
      switch (path) {
        case "/api/settings":
          return settings();
        case "/api/certs":
          return { certs: [] };
        case "/api/geoip":
          return geoip();
        case "/api/backup/schedule":
          return { config: { enabled: false }, status: {} };
        case "/api/notifications":
          return { channels: {} };
        case "/api/audit/verify":
          return { ok: true, checked: 0 };
        case "/api/proxies":
          return { proxies: [] };
        case "/api/users":
          return { users: [] };
        case "/api/me/prefs":
          return {};
        default:
          return { configured: true, applied: 3 };
      }
    });

    render(<Readiness me={{ ...me, site: "bravo" }} onError={vi.fn()} />);

    expect(await screen.findByText("A second administrator exists")).toBeTruthy();
    expect(screen.queryByText("CrowdSec connected")).toBeNull();
  });
});
