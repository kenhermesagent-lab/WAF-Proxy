import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import SecurityPage from "./Security";
import type { Me } from "../types";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const patch = vi.mocked(api.patch);
const post = vi.mocked(api.post);

const finding = (over: Record<string, unknown> = {}) => ({
  key: "exposure:/billing.env",
  target: "billing.example.com",
  stage: "exposure",
  class: "exposure",
  title: ".env is readable through the proxy",
  severity: "high",
  exploitation: "Known exploited",
  product: "nginx",
  version: "1.25.3",
  recommendation: "Block /.env at the edge and rotate the keys it held",
  state: "open",
  first_seen: new Date(Date.now() - 86_400_000).toISOString(),
  ...over,
});

// An exposure the published path refuses while the application still serves it.
const coveredFinding = finding({
  key: "exposure:/server-status",
  title: "The application serves /server-status",
  severity: "medium",
  covered: true,
  recommendation: "Remove the file from the web root, or keep the published path refused until it is gone",
  note: "the application served HTTP 200, 12 bytes, headers: date; the published path refuses it with HTTP 403; blocked at the edge, but the file itself is still there",
});

const run = {
  id: 7,
  target: "billing.example.com",
  trigger: "manual",
  actor: "ops",
  path: "local",
  started_at: new Date(Date.now() - 60_000).toISOString(),
  ended_at: new Date().toISOString(),
  verdicts: '{"blocked-waf":9,"inconclusive":2,"not-run":1}',
};

const overview = {
  posture: "unknown",
  open_findings: 2,
  severities: { high: 1, medium: 1 },
  findings: [finding(), coveredFinding],
  runs: [run],
  sources: [
    { source: "kev", stale: true, bytes: 1024, records: 1200, last_error: "fetch failed" },
    { source: "osv", stale: false, bytes: 2048, records: 40, last_ok: new Date().toISOString() },
  ],
};

const evidence = [
  { seq: 0, stage: "waf", class: "sqli", method: "GET", path: "/.wafscan/7/0?q=1", verdict: "blocked-waf", wan_status: 403, upstream_status: 200 },
  { seq: 1, stage: "waf", class: "catch-all", method: "POST", path: "/.wafscan/7/1", verdict: "not-run", wan_status: 0, upstream_status: 0, note: "catch-all route" },
  { seq: 2, stage: "gate", class: "login", method: "POST", path: "/__gate/login", verdict: "inconclusive", wan_status: 200, upstream_status: 0 },
];

function mockAPI() {
  get.mockImplementation(async (path: string) => {
    switch (path) {
      case "/api/security/overview":
        return overview;
      case "/api/security/runs":
        return { runs: [run] };
      case "/api/security/runs/7":
        return { run, evidence };
      case "/api/security/findings":
        return { findings: [finding(), coveredFinding, finding({ key: "exposure:/git", title: "git config exposed", state: "accepted", severity: "medium", reason: "WAF rule blocks it", note: "scans say served 200" })] };
      case "/api/security/feed":
        return { sources: overview.sources, storage_cap_bytes: 30 << 20 };
      case "/api/security/schedule":
        return { schedule: { site_id: 1, cadence: "daily", hour: 3, day: 0, enabled: true, triggers: ["config"] } };
      case "/api/security/limits":
        return { paused: false, probes_per_second: 12 };
      case "/api/proxies":
        return { proxies: [{ id: 4, hostname: "billing.example.com", enabled: true }] };
      default:
        return {};
    }
  });
}

const reader = { username: "reader", permissions: ["security.read"] } as unknown as Me;
const scanner = { username: "scanner", permissions: ["security.read", "security.run"] } as unknown as Me;
const writer = { username: "writer", permissions: ["security.read", "security.write"] } as unknown as Me;

function renderPage(tab: string, me: Me = reader) {
  return render(<SecurityPage me={me} tab={tab} onTab={vi.fn()} onError={vi.fn()} onOK={vi.fn()} />);
}

describe("Security scan page", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    mockAPI();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders the five tabs and says unknown rather than clean", async () => {
    renderPage("overview");
    const tabs = screen.getAllByRole("tab").map((t) => t.textContent);
    expect(tabs).toEqual(["Overview", "Scans", "Findings", "Vulnerability feed", "Schedule"]);

    expect(await screen.findByText("Unknown")).toBeTruthy();
    expect(screen.getByText(/unknown — not clean/i)).toBeTruthy();
    expect(screen.queryByText(/^Covered$/)).toBeNull();
    expect(screen.getByText(/stale — claims unknown/i)).toBeTruthy();
  });

  it("says an exposure the published path refuses is covered, not patched", async () => {
    renderPage("overview");
    const covered = (await screen.findByText("The application serves /server-status")).closest("tr");
    expect(within(covered as HTMLElement).getByText("Covered — not patched")).toBeTruthy();

    // The same list must not label an exposure nobody refuses as covered.
    const plain = screen.getByText(".env is readable through the proxy").closest("tr");
    expect(within(plain as HTMLElement).queryByText("Covered — not patched")).toBeNull();
    expect(screen.getByText(/not patched: the file is still behind the proxy/)).toBeTruthy();
  });

  it("disables a run for a role without security.run and explains why", async () => {
    renderPage("overview");
    const button = screen.getByRole("button", { name: "Run scan" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.title).toBe("Your role cannot start scans.");
    expect(((await screen.findByRole("button", { name: "Detail" })) as HTMLButtonElement).disabled).toBe(false);

    cleanup();
    renderPage("overview", scanner);
    expect((screen.getByRole("button", { name: "Run scan" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("refetches on a tab switch instead of showing the first load", async () => {
    const { rerender } = renderPage("overview");
    await screen.findByText("Posture");
    const before = get.mock.calls.length;

    rerender(<SecurityPage me={reader} tab="findings" onTab={vi.fn()} onError={vi.fn()} onOK={vi.fn()} />);
    await screen.findByRole("heading", { name: "Findings" });
    expect(get.mock.calls.length).toBeGreaterThan(before);
    expect(get.mock.calls.slice(before).some(([path]) => path === "/api/security/findings")).toBe(true);
  });

  it("shows a run that never finished as abandoned, not running", async () => {
    const dead = { ...run, id: 9, ended_at: undefined, started_at: new Date(Date.now() - 3 * 3600_000).toISOString(), abandoned: true };
    get.mockImplementation(async (path: string) => {
      switch (path) {
        case "/api/security/runs":
          return { runs: [dead] };
        case "/api/security/runs/9":
          return { run: dead, evidence: [] };
        default:
          return {};
      }
    });
    renderPage("scans");

    expect((await screen.findAllByText("abandoned")).length).toBeGreaterThan(0);
    expect(screen.queryByText("running")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Evidence" }));
    expect(await screen.findByText(/never finished: the process died/i)).toBeTruthy();
  });

  it("renders a probe that did not run as not clean, never as blocked", async () => {
    renderPage("scans");
    fireEvent.click(await screen.findByRole("button", { name: "Evidence" }));

    expect(await screen.findByText("Not run — not clean")).toBeTruthy();
    expect(screen.getByText("Inconclusive — not clean")).toBeTruthy();
    expect(screen.getByText("Blocked by the WAF")).toBeTruthy();

    // Only the one probe that actually got a 403 is described as blocked.
    expect(screen.getAllByText("Blocked by the WAF")).toHaveLength(1);
    expect(screen.getByText(/catch-all route/)).toBeTruthy();
    expect(screen.getByText(/never left this node/)).toBeTruthy();
  });

  it("marks an accepted finding and its KEV state, and disables decisions without security.write", async () => {
    renderPage("findings");
    const acceptedRow = (await screen.findByText("git config exposed")).closest("tr");
    expect(acceptedRow).toBeTruthy();
    expect(within(acceptedRow as HTMLElement).getByText("accepted")).toBeTruthy();
    expect(within(acceptedRow as HTMLElement).getByText(/Accepted reason: WAF rule blocks it/)).toBeTruthy();
    expect(within(acceptedRow as HTMLElement).getByText(/Scan note: scans say served 200/)).toBeTruthy();
    expect(within(acceptedRow as HTMLElement).getByText("Accept…")).toHaveProperty("disabled", true);

    expect((screen.getAllByRole("button", { name: "Accept…" })[0] as HTMLButtonElement).title).toBe(
      "Your role cannot change findings.",
    );

    cleanup();
    renderPage("findings", writer);
    const accept = (await screen.findAllByRole("button", { name: "Accept…" }))[0] as HTMLButtonElement;
    expect(accept.disabled).toBe(false);
    fireEvent.click(accept);
    expect(await screen.findByRole("dialog", { name: /Accept “.env is readable/ })).toBeTruthy();
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "keys rotated, rule pending" } });
    fireEvent.click(screen.getByRole("button", { name: "Accept with reason" }));
    expect(patch).toHaveBeenCalledWith("/api/security/findings/exposure%3A%2Fbilling.env", {
      state: "accepted",
      reason: "keys rotated, rule pending",
    });
  });

  it("closes an exposure finding with a block and retest, and offers it only to a writer", async () => {
    renderPage("findings");
    expect(((await screen.findAllByRole("button", { name: "Block & retest" }))[0] as HTMLButtonElement).disabled).toBe(true);
    cleanup();

    post.mockResolvedValue({ proved: true, run: { ...run, id: 8, trigger: "remediation" }, finding: finding({ state: "resolved" }) });
    const ok = vi.fn();
    render(<SecurityPage me={writer} tab="findings" onTab={vi.fn()} onError={vi.fn()} onOK={ok} />);
    const block = (await screen.findAllByRole("button", { name: "Block & retest" }))[0] as HTMLButtonElement;
    expect(block.disabled).toBe(false);
    fireEvent.click(block);
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/security/findings/exposure%3A%2Fbilling.env/remediate", {}),
    );
    expect(ok).toHaveBeenCalledWith(expect.stringContaining("rerun proved it"));
  });

  it("keeps the schedule read-only for a reader and saveable for a writer", async () => {
    renderPage("schedule");
    const enabled = (await screen.findByRole("switch", { name: /Enabled/ })) as HTMLInputElement;
    expect(enabled.disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Save settings" }) as HTMLButtonElement).disabled).toBe(true);

    cleanup();
    renderPage("schedule", writer);
    const toggle = (await screen.findByRole("switch", { name: /Enabled/ })) as HTMLInputElement;
    expect(toggle.disabled).toBe(false);
    fireEvent.click(toggle);
    expect(toggle.checked).toBe(false);
  });
});
