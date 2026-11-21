import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import UpdatesPage from "./Updates";

vi.mock("../api", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
  },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);

const base = {
  available: true,
  platform: "Debian GNU/Linux 12 (bookworm)",
  container: false,
  checked_at: new Date().toISOString(),
  packages: [
    {
      name: "nftables",
      role: "Kernel-mode ban enforcement (nft)",
      current: "1.0.6-1",
      candidate: "1.0.6-1+deb12u1",
      status: "security",
      severity: "critical",
      security: true,
      advisories: [{ id: "DEBIAN-CVE-2026-9999", severity: "critical", summary: "A critical packet filtering issue." }],
      can_update: true,
      note: "",
    },
    {
      name: "ca-certificates",
      role: "Trusted roots",
      current: "20230311",
      candidate: "20230311",
      status: "current",
      security: false,
      advisories: [],
      can_update: false,
      note: "",
    },
  ],
  helper_ready: true,
  updating: false,
  app_version: "1.1.1",
  app_commit: "abc123",
  app_build_date: "2026-11-21T00:00:00Z",
  go_version: "go1.27.4",
};

function renderPage() {
  return render(<UpdatesPage onError={vi.fn()} onOK={vi.fn()} />);
}

describe("Updates page", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("shows high/critical advisories and updates one managed package", async () => {
    get.mockResolvedValue(base);
    post.mockResolvedValue({ snapshot: { ...base, packages: [{ ...base.packages[0], can_update: false, status: "current" }, base.packages[1]] }, output: "updated nftables" });
    renderPage();

    expect(await screen.findByText("DEBIAN-CVE-2026-9999")).toBeTruthy();
    expect(screen.getByText(/1 high\/critical security advisory/)).toBeTruthy();
    screen.getByRole("button", { name: "Update" }).click();

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/updates/apply", { package: "nftables" }));
  });

  it("disables host management inside a container", async () => {
    get.mockResolvedValue({
      ...base,
      available: false,
      container: true,
      reason: "Host package updates are unavailable inside a container.",
      packages: [],
    });
    renderPage();

    expect(await screen.findByText(/unavailable inside a container/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Check for updates" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/compiled into the binary/)).toBeTruthy();
  });
});
