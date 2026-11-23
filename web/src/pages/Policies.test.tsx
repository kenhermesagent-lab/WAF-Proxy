import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Policies from "./Policies";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);

describe("Policies preflight", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    get.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/bans")) return { bans: [], active: 0, kernel: { active: false, reason: "" } };
      if (path === "/api/global-lists") return { whitelist_ids: [], blocklist_ids: [], lists: [] };
      if (path === "/api/asn-recommendations") {
        return { hosting: { id: "hosting", name: "Hosting", note: "", asns: [] }, vpn: [] };
      }
      return [];
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("previews what a country block would refuse before it is added", async () => {
    post.mockResolvedValue({
      kind: "country_blacklist",
      value: "RU",
      hours: 24,
      scanned: 40,
      matched: 12,
      allowed: 7,
      blocked: 5,
      addresses: 3,
      hosts: ["app.example.com"],
      samples: [],
      notes: [],
    });

    render(<Policies onError={vi.fn()} onOK={vi.fn()} />);
    fireEvent.click(await screen.findByRole("tab", { name: "Profiles" }));

    const countrySelect = screen
      .getAllByRole("combobox")
      .find((el) => el.querySelector('option[value="RU"]')) as HTMLSelectElement;
    fireEvent.change(countrySelect, { target: { value: "RU" } });
    fireEvent.click(screen.getByRole("button", { name: "Preflight" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith(
        "/api/policies/preflight",
        expect.objectContaining({ kind: "country_blacklist", value: "RU", hours: 24 }),
      ),
    );
    expect(await screen.findByText(/7 are served today and would be refused/)).toBeTruthy();
    // Preflight must never save anything on its own.
    expect(post).not.toHaveBeenCalledWith("/api/policies", expect.anything());
  });
});
