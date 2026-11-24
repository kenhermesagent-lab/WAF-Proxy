import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import Logs from "./Logs";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), text: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);
const put = vi.mocked(api.put);
const text = vi.mocked(api.text);

const blockedEvent = {
  id: 9,
  ts: "2026-11-22T16:03:00Z",
  host: "app.lab.local",
  src_ip: "203.0.113.7",
  country: "RU",
  asn: 64500,
  method: "GET",
  path: "/.env",
  status: 403,
  bytes_in: 0,
  bytes_out: 0,
  latency_ms: 3,
  stage: "decoy",
  rule_id: "decoy",
  rule_msg: "decoy path",
  action: "ban",
  ua: "curl/8",
};

const simulated = {
  verdict: { action: "block", stage: "decoy", rule: "decoy", reason: "decoy path /.env", status: 403 },
  stages: [
    { stage: "screen", verdict: "allow" },
    { stage: "decoy", verdict: "block", reason: "decoy path /.env" },
    { stage: "waf", verdict: "skipped", skipped: "not reached" },
  ],
  matches: [],
  truncated: false,
  notes: ["rate limiting is stateful; it was not evaluated"],
};

describe("Logs request simulator", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    put.mockReset();
    text.mockReset();
    text.mockResolvedValue("# Incident report — log window\n\n- Window: last 24h");
    // The test environment has no storage, so each test gets a fresh fake one.
    const store: Record<string, string> = {};
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => { store[k] = v; },
      removeItem: (k: string) => { delete store[k]; },
      clear: () => { for (const k of Object.keys(store)) delete store[k]; },
    });
    get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/events")) return { events: [blockedEvent], total: 1 };
      if (path === "/api/proxies") return [{ id: 7, hostname: "app.lab.local" }];
      return [];
    });
    post.mockResolvedValue(simulated);
  });

  afterEach(() => {
    cleanup();
  });

  it("opens the simulator for a blocked row and renders the returned stages and verdict", async () => {
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />);

    fireEvent.click(await screen.findByRole("button", { name: "Why?" }));
    expect(await screen.findByText(/Why was this request handled this way\? · app.lab.local/)).toBeTruthy();

    const run = await screen.findByRole("button", { name: "Simulate" });
    await waitFor(() => expect((run as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(run);

    expect((await screen.findAllByText("decoy path /.env")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("decoy").length).toBeGreaterThan(0);
    expect(screen.getByText("not reached")).toBeTruthy();
    expect(screen.getByText(/rate limiting is stateful/)).toBeTruthy();
    expect(post).toHaveBeenCalledWith(
      "/api/simulate",
      expect.objectContaining({ proxy_id: 7, method: "GET", path: "/.env", client_ip: "203.0.113.7" }),
    );
  });

  it("opens the source drawer from a source cell", async () => {
    const onOpenSource = vi.fn();
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={onOpenSource} canWrite canShareViews />);

    fireEvent.click(await screen.findByRole("button", { name: "203.0.113.7" }));
    expect(onOpenSource).toHaveBeenCalledWith("203.0.113.7");
  });

  it("polls the newest page while the live tail is on", async () => {
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />);
    await screen.findByText("GET /.env");
    const before = get.mock.calls.filter(([path]) => path.startsWith("/api/events")).length;

    fireEvent.click(screen.getByRole("button", { name: "Live tail" }));
    expect(screen.getByRole("button", { name: "● Live" })).toBeTruthy();

    await waitFor(
      () => expect(get.mock.calls.filter(([path]) => path.startsWith("/api/events")).length).toBeGreaterThan(before + 1),
      { timeout: 4000 },
    );
  });

  it("saves a filter view and reloads it on the next visit", async () => {
    const store: Record<string, string> = {};
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => { store[k] = v; },
      removeItem: (k: string) => { delete store[k]; },
      clear: () => { for (const k of Object.keys(store)) delete store[k]; },
    });
    const onOK = vi.fn();
    render(<Logs onError={vi.fn()} onOK={onOK} onOpenSource={vi.fn()} canWrite canShareViews />);
    await screen.findByText("GET /.env");

    fireEvent.change(screen.getByPlaceholderText("203.0.113.7"), { target: { value: "203.0.113.7" } });
    fireEvent.change(screen.getByPlaceholderText("Port scans"), { target: { value: "Port scans" } });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));

    await waitFor(() => expect(onOK).toHaveBeenCalledWith("View “Port scans” saved for the team"));
    expect(put).toHaveBeenCalledWith("/api/log-views/Port%20scans", { query: "hours=24&ip=203.0.113.7" });
    expect(JSON.parse(store["waf.logs.views"])).toEqual([{ name: "Port scans", query: "hours=24&ip=203.0.113.7" }]);

    // A fresh mount reads the saved view back from storage.
    cleanup();
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />);
    expect(await screen.findByRole("option", { name: "Port scans" })).toBeTruthy();
  });

  it("loads the team's saved views from the server and keeps a browser copy", async () => {
    get.mockImplementation(async (path: string) => {
      if (path === "/api/log-views") {
        return { views: [{ name: "Team scans", query: "stage=waf", updated_by: "admin", updated_at: "2026-11-23T10:00:00Z" }] };
      }
      if (path.startsWith("/api/events")) return { events: [blockedEvent], total: 1 };
      return [];
    });
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />);

    expect(await screen.findByRole("option", { name: "Team scans" })).toBeTruthy();
    await waitFor(() =>
      expect(JSON.parse(localStorage.getItem("waf.logs.views") ?? "[]")).toEqual([{ name: "Team scans", query: "stage=waf" }]),
    );
  });

  it("falls back to the browser's saved views when the server list is unreachable", async () => {
    localStorage.setItem("waf.logs.views", JSON.stringify([{ name: "Offline scans", query: "stage=waf" }]));
    get.mockImplementation(async (path: string) => {
      if (path === "/api/log-views") throw new Error("offline");
      if (path.startsWith("/api/events")) return { events: [blockedEvent], total: 1 };
      return [];
    });
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />);

    expect(await screen.findByRole("option", { name: "Offline scans" })).toBeTruthy();
  });

  it("keeps a view in this browser when the server refuses the save", async () => {
    put.mockRejectedValue(new Error("forbidden"));
    const onError = vi.fn();
    render(<Logs onError={onError} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />);
    await screen.findByText("GET /.env");

    fireEvent.change(screen.getByPlaceholderText("203.0.113.7"), { target: { value: "203.0.113.7" } });
    fireEvent.change(screen.getByPlaceholderText("Port scans"), { target: { value: "Mine" } });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));

    await waitFor(() => expect(onError).toHaveBeenCalledWith("Saved on this browser only: forbidden"));
    expect(await screen.findByRole("option", { name: "Mine" })).toBeTruthy();
  });

  it("reapplies the query when the same page is targeted again", async () => {
    const view = (version: number) => (
      <Logs query="ip=203.0.113.7" queryVersion={version} onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />
    );
    const { rerender } = render(view(1));
    await waitFor(() => expect(get).toHaveBeenCalledWith(expect.stringContaining("ip=203.0.113.7")));
    get.mockClear();

    // Same query, same hash: only the navigation counter changes.
    rerender(view(2));
    await waitFor(() => expect(get).toHaveBeenCalledWith(expect.stringContaining("ip=203.0.113.7")));
  });

  it("fetches the report Markdown for the current filters", async () => {
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />);
    await screen.findByText("GET /.env");

    fireEvent.change(screen.getByPlaceholderText("203.0.113.7"), { target: { value: "203.0.113.7" } });
    fireEvent.click(screen.getByRole("button", { name: "Report" }));

    await waitFor(() => expect(text).toHaveBeenCalledWith("/api/events/incident.md?hours=24&ip=203.0.113.7"));
    expect((await screen.findByLabelText("Incident report in Markdown")).textContent).toContain("Incident report — log window");
  });

  it("disables the shared-view controls for a read-only role", async () => {
    get.mockImplementation(async (path: string) => {
      if (path === "/api/log-views") {
        return { views: [{ name: "Team scans", query: "stage=waf", updated_by: "admin", updated_at: "2026-11-23T10:00:00Z" }] };
      }
      if (path.startsWith("/api/events")) return { events: [blockedEvent], total: 1 };
      return [];
    });
    const onOK = vi.fn();
    render(<Logs onError={vi.fn()} onOK={onOK} onOpenSource={vi.fn()} canWrite={false} canShareViews={false} />);

    // The shared list still loads for a reader.
    expect(await screen.findByRole("option", { name: "Team scans" })).toBeTruthy();

    const save = screen.getByRole("button", { name: "Save view" }) as HTMLButtonElement;
    const remove = screen.getByRole("button", { name: "Delete view" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect(remove.disabled).toBe(true);

    // Typing a name and pressing Enter must not save either.
    const name = screen.getByPlaceholderText("Port scans");
    fireEvent.change(name, { target: { value: "Mine" } });
    fireEvent.keyDown(name, { key: "Enter" });
    expect(save.disabled).toBe(true);
    expect(put).not.toHaveBeenCalled();
    expect(onOK).not.toHaveBeenCalled();
  });

  it("ignores a corrupt saved-view list", async () => {
    vi.stubGlobal("localStorage", {
      getItem: () => "{not json",
      setItem: () => {},
      removeItem: () => {},
      clear: () => {},
    });
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite canShareViews />);
    expect(await screen.findByText("GET /.env")).toBeTruthy();
    expect(screen.queryByRole("option", { name: "Port scans" })).toBeNull();
  });

  it("bans the selected sources after confirmation", async () => {
    const onOK = vi.fn();
    render(<Logs onError={vi.fn()} onOK={onOK} onOpenSource={vi.fn()} canWrite canShareViews />);
    await screen.findByText("GET /.env");

    fireEvent.click(screen.getByLabelText("Select 203.0.113.7"));
    expect(screen.getByRole("button", { name: "Copy IPs" })).toBeTruthy();

    post.mockResolvedValue({});
    fireEvent.click(screen.getByRole("button", { name: "Ban 24h" }));
    const dialog = await screen.findByRole("dialog", { name: "Ban selected sources" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Ban 24h" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/bans", {
        cidr: "203.0.113.7",
        reason: "bulk ban from log",
        permanent: false,
        ttl_seconds: 86400,
      }),
    );
    await waitFor(() => expect(onOK).toHaveBeenCalledWith("1 source banned"));
  });

  it("hides the bulk ban from a read-only role", async () => {
    render(<Logs onError={vi.fn()} onOK={vi.fn()} onOpenSource={vi.fn()} canWrite={false} canShareViews />);
    await screen.findByText("GET /.env");
    fireEvent.click(screen.getByLabelText("Select 203.0.113.7"));
    expect(screen.getByRole("button", { name: "Copy IPs" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Ban 24h" })).toBeNull();
    expect(screen.getByRole("button", { name: "Copy IPs" })).toBeTruthy();
  });
});
