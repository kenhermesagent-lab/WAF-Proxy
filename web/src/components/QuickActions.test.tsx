import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import QuickActions from "./QuickActions";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);
const put = vi.mocked(api.put);

describe("palette command actions", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    put.mockReset();
  });
  afterEach(() => cleanup());

  it("bans an address only after the operator confirms", async () => {
    const onOK = vi.fn();
    const onClose = vi.fn();
    post.mockResolvedValue({});
    render(<QuickActions command="ban" canWrite onClose={onClose} onError={vi.fn()} onOK={onOK} />);

    fireEvent.change(screen.getByPlaceholderText("203.0.113.7"), { target: { value: "203.0.113.9" } });
    fireEvent.click(screen.getByRole("button", { name: "Ban" }));

    const confirm = await screen.findByRole("dialog", { name: "Ban source" });
    expect(post).not.toHaveBeenCalled();
    fireEvent.click(within(confirm).getByRole("button", { name: "Ban 24h" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/bans", {
        cidr: "203.0.113.9",
        reason: "Banned from the command palette",
        permanent: false,
        ttl_seconds: 86400,
      }),
    );
    expect(onOK).toHaveBeenCalledWith("203.0.113.9 banned");
    expect(onClose).toHaveBeenCalled();
  });

  it("releases a chosen ban from the bans endpoint's wrapped list", async () => {
    get.mockResolvedValue({
      active: 1,
      total: 1,
      bans: [{ id: 9, cidr: "198.51.100.4/32", reason: "scan", source: "manual", permanent: false, hits: 2, created_by: "admin", created_at: "" }],
    });
    const del = vi.mocked(api.del);
    del.mockResolvedValue({});
    const onOK = vi.fn();
    render(<QuickActions command="unban" canWrite onClose={vi.fn()} onError={vi.fn()} onOK={onOK} />);

    fireEvent.change(await screen.findByRole("combobox"), { target: { value: "9" } });
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    const confirm = await screen.findByRole("dialog", { name: "Release ban" });
    fireEvent.click(within(confirm).getByRole("button", { name: "Unban" }));

    await waitFor(() => expect(del).toHaveBeenCalledWith("/api/bans/9"));
    expect(onOK).toHaveBeenCalledWith("198.51.100.4/32 unbanned");
  });

  it("disables the chosen proxy by sending only the switch", async () => {
    get.mockResolvedValue([
      {
        id: 4,
        hostname: "app.example.com",
        enabled: true,
        gate_mode: "off",
        fingerprint: "strict",
        bot_level: "light",
        maintenance: false,
        waf_mode: "inherit",
        upstreams: [{ url: "http://10.0.0.10:8080", weight: 1, enabled: true }],
        routes: [],
        gate_users: [],
      },
    ]);
    put.mockResolvedValue({});
    const onOK = vi.fn();
    render(<QuickActions command="disable-proxy" canWrite onClose={vi.fn()} onError={vi.fn()} onOK={onOK} />);

    fireEvent.change(await screen.findByRole("combobox"), { target: { value: "4" } });
    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    const confirm = await screen.findByRole("dialog", { name: "Disable proxy" });
    fireEvent.click(within(confirm).getByRole("button", { name: "Disable" }));

    // The upstream pool is not in the request at all: the update merges, so an
    // omitted field keeps its stored value instead of being replaced by this
    // row's copy.
    await waitFor(() => expect(put).toHaveBeenCalledWith("/api/proxies/4", { enabled: false }));
    expect(onOK).toHaveBeenCalledWith("app.example.com disabled");
  });

  it("renders no action button for a role that cannot write", async () => {
    render(<QuickActions command="ban" canWrite={false} onClose={vi.fn()} onError={vi.fn()} onOK={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Your role cannot make this change" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Ban" })).toBeNull();
  });

  it("preflights a rule against recorded traffic without saving anything", async () => {
    post.mockResolvedValue({
      kind: "country_blacklist",
      value: "RU",
      hours: 24,
      scanned: 10,
      matched: 4,
      allowed: 1,
      blocked: 3,
      addresses: 2,
      hosts: ["app.example.com"],
      samples: [],
      notes: ["Shadowed by a whitelist on app.example.com"],
    });
    render(<QuickActions command="preflight" canWrite onClose={vi.fn()} onError={vi.fn()} onOK={vi.fn()} />);

    fireEvent.change(screen.getByRole("combobox"), { target: { value: "country_blacklist" } });
    fireEvent.change(screen.getByPlaceholderText("RU"), { target: { value: "RU" } });
    fireEvent.click(screen.getByRole("button", { name: "Preflight" }));

    expect(await screen.findByText(/requests from 2 addresses match/)).toBeTruthy();
    expect(screen.getByText("Shadowed by a whitelist on app.example.com")).toBeTruthy();
    expect(post).toHaveBeenCalledWith("/api/policies/preflight", {
      kind: "country_blacklist",
      value: "RU",
      scope: "global",
      proxy_id: null,
      hours: 24,
    });
  });

  it("names the subject, not the rule kind, when nothing matches", async () => {
    post.mockResolvedValue({ kind: "asn_block", value: "64500", hours: 24, scanned: 10, matched: 0, allowed: 0, blocked: 0, addresses: 0, hosts: [], samples: [], notes: [] });
    render(<QuickActions command="preflight" canWrite onClose={vi.fn()} onError={vi.fn()} onOK={vi.fn()} />);

    fireEvent.change(screen.getByRole("combobox"), { target: { value: "asn_block" } });
    fireEvent.change(screen.getByPlaceholderText("64500"), { target: { value: "64500" } });
    fireEvent.click(screen.getByRole("button", { name: "Preflight" }));

    expect(await screen.findByText("No requests in the last 24h came from AS64500.")).toBeTruthy();
  });
});
