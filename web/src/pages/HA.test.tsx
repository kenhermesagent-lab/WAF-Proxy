import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import HAPage from "./HA";
import type { HAStatus, Me } from "../types";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);

const status = (over: Partial<HAStatus> = {}): HAStatus => ({
  enabled: true,
  paired: false,
  role: "standalone",
  state: "standalone",
  serving: true,
  epoch: 3,
  can_write: true,
  max_failovers_per_hour: 3,
  ...over,
});

const me = { username: "ops", ha_enabled: true, permissions: ["ha.read", "ha.write"] } as unknown as Me;

function renderPage(ha: HAStatus) {
  get.mockImplementation(async (path: string) => {
    switch (path) {
      case "/api/ha":
        return ha;
      case "/api/ha/diagnostics":
        return {
          enabled: ha.enabled, role: ha.role, state: ha.state, serving: ha.serving, epoch: ha.epoch,
          outbox: { depth: 2, bytes: 2048, pending_by_kind: { config: 2 } },
          ack: { seq: 1, at: new Date().toISOString() },
        };
      case "/api/ha/events":
        return { events: [] };
      default:
        return {};
    }
  });
  return render(<HAPage me={me} version="1.57.0" onError={vi.fn()} onOK={vi.fn()} />);
}

describe("High availability page", () => {
  beforeEach(() => {
    get.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("offers create or join while unpaired and disables the other actions", async () => {
    renderPage(status());
    expect(await screen.findByRole("button", { name: "Create a pair" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Join the pair" })).toBeTruthy();
    expect(screen.getByText(/prerequisites|Both nodes need certificates/i)).toBeTruthy();
    expect(screen.queryByText("Fail over")).toBeNull();

    const sync = screen.getByRole("button", { name: "Sync now" }) as HTMLButtonElement;
    expect(sync.disabled).toBe(true);
    expect(sync.title).toBe("Pair this node first.");
  });

  it("lets an active node fail over but not fail back", async () => {
    renderPage(status({ paired: true, cluster_id: "cluster-abc", role: "active", state: "active" }));
    expect(await screen.findByText("Role and state")).toBeTruthy();
    expect(screen.getByText("ACTIVE")).toBeTruthy();
    expect(screen.queryByText(/STANDBY — READ ONLY/)).toBeNull();

    expect((screen.getByRole("button", { name: "Fail over" }) as HTMLButtonElement).disabled).toBe(false);
    const back = screen.getByRole("button", { name: "Fail back" }) as HTMLButtonElement;
    expect(back.disabled).toBe(true);
    expect(back.title).toBe("Only a standby can fail back.");
  });

  it("puts a standby in a read-only ribbon and only offers fail back", async () => {
    renderPage(status({ paired: true, cluster_id: "cluster-abc", role: "standby", state: "standby", serving: false }));
    expect(await screen.findByText(/STANDBY — READ ONLY/)).toBeTruthy();

    const over = screen.getByRole("button", { name: "Fail over" }) as HTMLButtonElement;
    expect(over.disabled).toBe(true);
    expect(over.title).toBe("Only the active node can fail over.");
    expect((screen.getByRole("button", { name: "Fail back" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Sync now" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("shows a startup failure with its reason while HA is enabled", async () => {
    renderPage(status({
      paired: true, cluster_id: "cluster-abc", role: "active", state: "active",
      runtime_error: "ha: control socket: listen unix /var/lib/wafproxy/ha/control.sock: address already in use",
    }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/HA IS ENABLED BUT NOT RUNNING/);
    expect(alert.textContent).toMatch(/control socket: listen unix .*address already in use/);
  });

  it("explains why HA is off and links to Settings", async () => {
    renderPage(status({ enabled: false, paired: true, serving: false, reason: "this node is a paired standby; it stays out of service while high availability is off" }));
    expect(await screen.findByText("High availability is turned off")).toBeTruthy();
    expect(screen.getByText(/paired standby; it stays out of service/)).toBeTruthy();
    const link = screen.getByRole("link", { name: "Open Settings" }) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("#/settings");
  });

  it("disables every mutation for a role without ha.write", async () => {
    renderPage(status({ paired: true, cluster_id: "cluster-abc", role: "active", can_write: false }));
    const over = (await screen.findByRole("button", { name: "Fail over" })) as HTMLButtonElement;
    expect(over.disabled).toBe(true);
    expect(over.title).toBe("Your role cannot run HA actions.");
    expect((screen.getByRole("button", { name: "Sync now" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
