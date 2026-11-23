import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import CloudflarePage from "./Cloudflare";
import type { CloudflareStatus } from "../types";

vi.mock("../api", () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(),
    post: vi.fn(),
  },
}));

import { api } from "../api";

const get = vi.mocked(api.get);

const base: CloudflareStatus = {
  enabled: false,
  installed: true,
  version: "2025.1.0",
  state: "stopped",
  connections: 0,
  token_set: true,
  token_tail: "wxyz",
  tunnel_id: "",
  strict_origin: true,
  metrics_addr: "127.0.0.1:20241",
  container: false,
  helper_ready: true,
  install_supported: true,
  install_running: false,
  console_host: "console.example.com",
  gui_port: 8443,
  gui_tls: false,
  restart_required: false,
  log: [],
  checks: null,
};

function renderPage() {
  const onError = vi.fn();
  const onOK = vi.fn();
  render(<CloudflarePage onError={onError} onOK={onOK} />);
  return { onError, onOK };
}

describe("Cloudflare page", () => {
  beforeEach(() => {
    get.mockReset();
    vi.mocked(api.put).mockReset();
    vi.mocked(api.post).mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("offers the manual commands when the helper is missing", async () => {
    get.mockResolvedValue({
      ...base,
      installed: false,
      version: "",
      token_set: false,
      helper_ready: false,
      install_supported: false,
      install_reason: "The privileged host helper is not installed.",
    });
    renderPage();

    expect(await screen.findByText(/privileged host helper is not installed/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Install connector" })).toBeNull();
    expect(screen.getAllByText(/pkg\.cloudflare\.com/).length).toBeGreaterThan(0);
  });

  it("sends a container console to the host install instead of an install button", async () => {
    get.mockResolvedValue({ ...base, installed: false, version: "", container: true, install_supported: false });
    renderPage();

    expect(await screen.findByText(/Install cloudflared on the host/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Install connector" })).toBeNull();
  });

  it("never renders the stored token, only its tail", async () => {
    get.mockResolvedValue(base);
    renderPage();

    const input = (await screen.findByPlaceholderText(/Saved token ends in/)) as HTMLInputElement;
    expect(input.value).toBe("");
    expect(input.type).toBe("password");
    expect(document.body.textContent).not.toContain("eyJ");
  });

  it("refuses to enable the tunnel before a token is saved", async () => {
    get.mockResolvedValue({ ...base, token_set: false, token_tail: undefined });
    const { onError } = renderPage();

    const toggle = (await screen.findByRole("switch", { name: /Enable Cloudflare Tunnel/ })) as HTMLInputElement;
    toggle.click();

    expect(onError).toHaveBeenCalledWith(expect.stringMatching(/token/));
    expect(toggle.checked).toBe(false);
  });

  it("saves the enable switch without touching the token", async () => {
    get.mockResolvedValue(base);
    vi.mocked(api.put).mockResolvedValue({ status: "ok" });
    renderPage();

    const toggle = (await screen.findByRole("switch", { name: /Enable Cloudflare Tunnel/ })) as HTMLInputElement;
    toggle.click();
    const save = await screen.findByRole("button", { name: "Save tunnel settings" });
    save.click();

    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith("/api/cloudflare", {
        enabled: true,
        strict_origin: true,
        tunnel_id: "",
      }),
    );
  });

  it("renders the checks after a run", async () => {
    get.mockResolvedValue(base);
    vi.mocked(api.post).mockResolvedValue({
      checks: [
        { id: "binary", label: "Connector installed", ok: true, detail: "cloudflared 2025.1.0" },
        { id: "edge", label: "Request reaches the edge", ok: false, detail: "no CF-Ray" },
      ],
    });
    renderPage();

    (await screen.findByRole("button", { name: "Run checks" })).click();

    expect(await screen.findByText("Connector installed")).toBeTruthy();
    expect(screen.getByText("Request reaches the edge")).toBeTruthy();
    expect(screen.getAllByText("pass").length).toBe(1);
    expect(screen.getAllByText("needs attention").length).toBe(1);
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith("/api/cloudflare/check", { hostnames: ["console.example.com"] }),
    );
  });
});
