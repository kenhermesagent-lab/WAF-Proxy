import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import AgentPage from "./Agent";

vi.mock("../api", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    del: vi.fn(),
  },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);

const status = {
  endpoint: "/mcp",
  env_token: false,
  token_count: 1,
  protocols: ["2025-06-18", "2026-07-28"],
  tokens: [
    {
      id: 7,
      name: "hermes-agent",
      prefix: "abc12345",
      created_by: "admin",
      created_at: new Date().toISOString(),
      last_used_at: null,
      revoked_at: null,
    },
  ],
};

function renderPage() {
  return render(<AgentPage onError={vi.fn()} onOK={vi.fn()} />);
}

// The page loads its MCP status and its agent links separately.
function mockStatus(value: unknown) {
  get.mockImplementation(async (path: string) => (path === "/api/agents" ? [] : value));
}

describe("Agent access page", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the endpoint, active token and security tools", async () => {
    mockStatus(status);
    renderPage();

    expect(await screen.findByText("hermes-agent")).toBeTruthy();
    expect(screen.getAllByText(/\/mcp/).length).toBeGreaterThan(0);
    expect(screen.getByText("block_ip")).toBeTruthy();
    expect(screen.getByText("revoke_session")).toBeTruthy();
    expect(screen.getByText(/never a shell/)).toBeTruthy();
  });

  it("creates a token and reveals it once", async () => {
    mockStatus({ ...status, token_count: 0, tokens: [] });
    post.mockResolvedValue({ name: "hermes-agent", token: "one-time-secret-token" });
    renderPage();

    await screen.findByText(/No agent tokens yet/);
    screen.getByRole("button", { name: "New agent token" }).click();
    (await screen.findByRole("button", { name: "Create token" })).click();

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/mcp/tokens", {
        name: "hermes-agent",
        scopes: [
          "get_security_overview",
          "query_logs",
          "get_ip_activity",
          "list_anomalies",
          "list_proxies",
          "block_ip",
          "unblock_ip",
          "list_blocks",
          "list_gate_users",
          "block_username",
          "unblock_username",
          "list_sessions",
          "revoke_session",
          "revoke_sessions_for_ip",
        ],
      }),
    );
    expect(await screen.findByText("one-time-secret-token")).toBeTruthy();
    expect(screen.getAllByText(/shown once/).length).toBeGreaterThan(0);
  });
});
