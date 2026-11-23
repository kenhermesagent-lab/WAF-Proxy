import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import Activity from "./Activity";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);

const entries = [
  {
    id: 12,
    ts: new Date(Date.now() - 60000).toISOString(),
    user: "alice",
    action: "policy.update",
    detail: "country_blacklist DE",
    ip: "10.0.0.9",
    entity: "policy",
  },
  {
    id: 11,
    ts: new Date(Date.now() - 120000).toISOString(),
    user: "alice",
    action: "backup.run",
    detail: "nightly.json",
    ip: "10.0.0.9",
  },
];

const before = JSON.stringify({ id: 3, kind: "country_blacklist", value: "RU", action: "block", enabled: true });
const after = JSON.stringify({ id: 3, kind: "country_blacklist", value: "DE", action: "block", enabled: true });

describe("Activity", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    get.mockImplementation(async (path: string) => {
      if (path === "/api/audit") return entries;
      if (path === "/api/audit/12") {
        return {
          entry: entries[0],
          snapshot: { audit_id: 12, entity: "policy", entity_id: 3, before, after },
        };
      }
      return {};
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the field-level difference for an entry", async () => {
    render(<Activity onError={vi.fn()} onOK={vi.fn()} permissions={["policies.write"]} />);
    fireEvent.click(await screen.findByRole("button", { name: "Changes" }));

    const dialog = await screen.findByRole("dialog", { name: /policy.update/ });
    expect(within(dialog).getByText("value")).toBeTruthy();
    expect(within(dialog).getByText("RU")).toBeTruthy();
    expect(within(dialog).getByText("DE")).toBeTruthy();
  });

  it("rolls an edit back and reports it", async () => {
    const onOK = vi.fn();
    render(<Activity onError={vi.fn()} onOK={onOK} permissions={["policies.write"]} />);
    fireEvent.click(await screen.findByRole("button", { name: "Changes" }));

    fireEvent.click(await screen.findByRole("button", { name: "Roll back" }));
    const confirm = await screen.findByRole("dialog", { name: "Roll back this change" });
    post.mockResolvedValue({ restored: "policy", id: 3 });
    fireEvent.click(within(confirm).getByRole("button", { name: "Roll back" }));

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/audit/12/rollback"));
    await waitFor(() => expect(onOK).toHaveBeenCalledWith("Change rolled back"));
  });

  it("hides rollback from a role that cannot write the entity", async () => {
    render(<Activity onError={vi.fn()} onOK={vi.fn()} permissions={["traffic.read"]} />);
    fireEvent.click(await screen.findByRole("button", { name: "Changes" }));
    const dialog = await screen.findByRole("dialog", { name: /policy.update/ });
    expect(within(dialog).getByText("RU")).toBeTruthy();
    expect(within(dialog).queryByRole("button", { name: "Roll back" })).toBeNull();
  });

  it("does not report upstream ids as a change", async () => {
    const snap = (id: number, level: string) =>
      JSON.stringify({
        proxy: { id: 1, hostname: "app.lab.local", bot_level: level },
        upstreams: [{ id, proxy_id: 1, url: "http://10.0.0.10:8080", weight: 1, enabled: true }],
        routes: [],
      });
    get.mockImplementation(async (path: string) => {
      if (path === "/api/audit") return entries;
      if (path === "/api/audit/12") {
        return { entry: entries[0], snapshot: { audit_id: 12, entity: "proxy", entity_id: 1, before: snap(4, "light"), after: snap(9, "light") } };
      }
      return {};
    });
    render(<Activity onError={vi.fn()} onOK={vi.fn()} permissions={["proxies.write"]} />);
    fireEvent.click(await screen.findByRole("button", { name: "Changes" }));

    const dialog = await screen.findByRole("dialog", { name: /policy.update/ });
    expect(within(dialog).getByText("Nothing changed")).toBeTruthy();
    expect(within(dialog).queryByText("upstreams")).toBeNull();
  });

  it("offers no diff for an action that changed no entity", async () => {
    render(<Activity onError={vi.fn()} onOK={vi.fn()} permissions={[]} />);
    await screen.findByText("backup.run");
    expect(screen.getAllByRole("button", { name: "Changes" })).toHaveLength(1);
  });
});
