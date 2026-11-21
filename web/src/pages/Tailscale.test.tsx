import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import TailscalePage from "./Tailscale";

vi.mock("../api", () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(),
    post: vi.fn(),
  },
}));

import { api } from "../api";

const get = vi.mocked(api.get);

const base = {
  available: true,
  ip: "100.101.102.103",
  error: "",
  admin_enabled: false,
  admin_active: false,
  admin_url: "",
  proxy_enabled: false,
  proxy_active: false,
  proxy_addr: "",
  dns_enabled: false,
  dns_active: false,
  dns_addr: "",
  restart_required: false,
  base_domain: "example.com",
  gui_port: 8443,
  wan_port: 443,
};

function renderPage() {
  return render(<TailscalePage onError={vi.fn()} onOK={vi.fn()} />);
}

describe("Tailscale page", () => {
  beforeEach(() => {
    get.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("disables both switches and explains why when tailscale0 is absent", async () => {
    get.mockResolvedValue({ ...base, available: false, error: "tailscale0 interface not found" });
    renderPage();

    expect(await screen.findByText(/tailscale0 interface not found/)).toBeTruthy();
    expect((screen.getByRole("checkbox", { name: /Admin console over Tailscale/ }) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole("checkbox", { name: /Proxy app traffic over Tailscale/ }) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole("checkbox", { name: /Answer split DNS/ }) as HTMLInputElement).disabled).toBe(true);
  });

  it("shows active listeners, URLs, and the split-DNS values", async () => {
    get.mockResolvedValue({
      ...base,
      admin_enabled: true,
      admin_active: true,
      admin_url: "http://100.101.102.103:8443",
      proxy_enabled: true,
      proxy_active: true,
      proxy_addr: "100.101.102.103:443",
      dns_enabled: true,
      dns_active: true,
      dns_addr: "100.101.102.103:53",
    });
    renderPage();

    expect((await screen.findAllByText("http://100.101.102.103:8443")).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/100.101.102.103:443/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/100.101.102.103:53/).length).toBeGreaterThan(0);
    expect((screen.getByRole("checkbox", { name: /Admin console over Tailscale/ }) as HTMLInputElement).checked).toBe(true);
    expect(screen.getByText(/dig \+short app\.example\.com/)).toBeTruthy();
  });

  it("surfaces a DNS bind failure and a pending restart", async () => {
    get.mockResolvedValue({
      ...base,
      proxy_enabled: true,
      dns_enabled: true,
      dns_error: "listen DNS UDP 100.101.102.103:53: address already in use",
      restart_required: true,
    });
    renderPage();

    expect(await screen.findByText(/address already in use/)).toBeTruthy();
    expect(screen.getByText("Restart required")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Restart service" })).toBeTruthy();
  });

  it("saves all three switches together", async () => {
    get.mockResolvedValue({ ...base, admin_enabled: true });
    const put = vi.mocked(api.put).mockResolvedValue({ status: "ok", restart_required: true });
    renderPage();

    await waitFor(() => expect(screen.getByRole("button", { name: "Save Tailscale settings" })).toBeTruthy());
    screen.getByRole("button", { name: "Save Tailscale settings" }).click();
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/tailscale", {
        admin_enabled: true,
        proxy_enabled: false,
        dns_enabled: false,
      }),
    );
  });
});
