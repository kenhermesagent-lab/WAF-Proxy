import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import SourceDrawer from "./SourceDrawer";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), text: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);
const text = vi.mocked(api.text);

const detail = {
  summary: {
    ip: "203.0.113.7",
    country: "RU",
    asn: 64500,
    requests: 42,
    blocked: 9,
    bytes_out: 0,
    hosts: 2,
    first_seen: "2026-11-20T10:00:00Z",
    last_seen: "2026-11-22T16:03:00Z",
    banned: false,
    permanent: false,
  },
  events: [
    {
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
    },
  ],
  total: 42,
};

function renderDrawer(canWrite = true) {
  return render(
    <SourceDrawer ip="203.0.113.7" canWrite={canWrite} onClose={vi.fn()} onError={vi.fn()} onOK={vi.fn()} />,
  );
}

describe("SourceDrawer", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    text.mockReset();
    get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/ips/")) return detail;
      if (path.startsWith("/api/intel/lookup")) return { ip: "203.0.113.7", feed: null, ban: null };
      return {};
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("summarises the address and its recent requests", async () => {
    renderDrawer();

    expect(await screen.findByText("42")).toBeTruthy();
    expect(screen.getByText("GET /.env")).toBeTruthy();
    expect(screen.getByText(/Showing the newest 1 of 42/)).toBeTruthy();
    expect(get).toHaveBeenCalledWith("/api/ips/203.0.113.7?hours=24");
  });

  it("fetches its incident report from the server", async () => {
    text.mockResolvedValue("# Incident report — 203.0.113.7\n\n- Window: last 24h");
    renderDrawer();
    await screen.findByText("42");

    fireEvent.click(screen.getByRole("button", { name: "Report" }));

    await waitFor(() => expect(text).toHaveBeenCalledWith("/api/ips/203.0.113.7/incident.md?hours=24"));
    expect((await screen.findByLabelText("Incident report in Markdown")).textContent).toContain("Window: last 24h");
  });

  it("bans the address for 24 hours after confirmation", async () => {
    const onOK = vi.fn();
    render(
      <SourceDrawer ip="203.0.113.7" canWrite onClose={vi.fn()} onError={vi.fn()} onOK={onOK} />,
    );
    await screen.findByText("42");

    fireEvent.click(screen.getByRole("button", { name: "Ban 24h" }));
    const dialog = await screen.findByRole("dialog", { name: "Ban source" });
    post.mockResolvedValue({});
    fireEvent.click(within(dialog).getByRole("button", { name: "Ban 24h" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/bans", {
        cidr: "203.0.113.7",
        reason: "Manual ban from source investigation",
        permanent: false,
        ttl_seconds: 86400,
      }),
    );
    await waitFor(() => expect(onOK).toHaveBeenCalledWith("203.0.113.7 banned"));
  });

  it("hides the ban controls from a read-only role", async () => {
    renderDrawer(false);
    await screen.findByText("42");
    expect(screen.queryByRole("button", { name: "Ban 24h" })).toBeNull();
  });
});
