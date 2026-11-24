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
  app_version: "1.2.0",
  app_commit: "abc123",
  app_build_date: "2026-11-21T00:00:00Z",
  go_version: "go1.27.4",
  app_update_available: false,
  app_update_supported: true,
  app_updating: false,
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
    (await screen.findByRole("button", { name: "Confirm" })).click();

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/updates/apply", { package: "nftables" }));
  });

  it("applies an application update and waits for the new commit", async () => {
    let applied = false;
    get.mockImplementation(async (path: string) => {
      if (path === "/api/updates") {
        return applied
          ? { ...base, app_version: "1.2.1", app_commit: "def4567", app_update_available: false }
          : {
              ...base,
              app_update_available: true,
              app_remote_version: "1.2.1",
              app_remote_commit: "def4567890abcdef",
              app_update_supported: true,
            };
      }
      if (path === "/api/updates/app") return { updating: false };
      if (path === "/api/version") return { commit: "def4567" };
      return { enabled: false, time: "04:00" };
    });
    post.mockImplementation(async () => {
      applied = true;
      return {};
    });
    const onOK = vi.fn();
    render(<UpdatesPage onError={vi.fn()} onOK={onOK} />);

    (await screen.findByRole("button", { name: "Update to v1.2.1" })).click();
    (await screen.findByRole("button", { name: "Confirm" })).click();

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/updates/app"), { timeout: 3000 });
    await waitFor(() => expect(onOK).toHaveBeenCalledWith("Update applied"), { timeout: 5000 });
    await waitFor(() => expect(screen.queryByRole("button", { name: /Update to/ })).toBeNull());
  });

  it("shows the updater's own stage while the rebuild runs", async () => {
    let polls = 0;
    get.mockImplementation(async (path: string) => {
      if (path === "/api/updates") {
        return {
          ...base,
          app_update_available: true,
          app_remote_version: "1.2.1",
          app_remote_commit: "def4567890abcdef",
        };
      }
      if (path === "/api/updates/app") {
        polls++;
        return polls === 1
          ? { updating: true, percent: 45, stage: "building the binaries" }
          : { updating: false };
      }
      return { enabled: false, time: "04:00" };
    });
    post.mockResolvedValue({});
    renderPage();

    (await screen.findByRole("button", { name: "Update to v1.2.1" })).click();
    (await screen.findByRole("button", { name: "Confirm" })).click();

    await screen.findByText("building the binaries", {}, { timeout: 4000 });
    const bar = screen.getByRole("progressbar", { name: /application update progress/i });
    expect(bar.getAttribute("aria-valuenow")).toBe("45");
    expect(screen.getByText("45%")).toBeTruthy();
  });

  it("checks application updates but keeps host packages read-only in a container", async () => {
    get.mockResolvedValue({
      ...base,
      available: false,
      container: true,
      reason: "Host package updates are unavailable inside a container.",
      packages: [],
      app_update_available: true,
      app_remote_version: "1.2.1",
      app_remote_commit: "def4567890ab",
      app_update_supported: true,
    });
    renderPage();

    expect(await screen.findByText(/unavailable inside a container/)).toBeTruthy();
    // One check per card: the application and the host packages.
    const checks = screen.getAllByRole("button", { name: "Check for updates" });
    expect(checks).toHaveLength(2);
    expect(checks.every((b) => !(b as HTMLButtonElement).disabled)).toBe(true);
    expect(screen.getByRole("button", { name: "Update to v1.2.1" })).toBeTruthy();
    expect(screen.getByText(/compiled into the binary/)).toBeTruthy();
  });
});
