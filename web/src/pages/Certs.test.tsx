import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Certs from "./Certs";

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
const put = vi.mocked(api.put);

function renderCerts() {
  return render(<Certs base="example.com" onError={vi.fn()} onOK={vi.fn()} />);
}

async function openDialog() {
  await waitFor(() => expect(get).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Request certificate" }));
}

describe("certificate controls", () => {
  beforeEach(() => {
    get.mockReset();
    put.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("explains a failed /api/certs load and disables both controls", async () => {
    get.mockRejectedValue(new Error("simulated certificate API failure"));
    renderCerts();
    await openDialog();

    expect(await screen.findByText(/DNS providers could not be loaded/)).toBeTruthy();
    expect(screen.getByText(/simulated certificate API failure/)).toBeTruthy();
    expect((screen.getByRole("combobox") as HTMLSelectElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Request" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("explains an empty provider list and disables both controls", async () => {
    get.mockResolvedValue({ certs: [], providers: [], configured: [] });
    renderCerts();
    await openDialog();

    expect(await screen.findByText(/No DNS providers are available/)).toBeTruthy();
    expect((screen.getByRole("combobox") as HTMLSelectElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Request" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("keeps the normal path enabled when providers load", async () => {
    get.mockResolvedValue({ certs: [], providers: ["duckdns"], configured: [] });
    renderCerts();
    await openDialog();

    await waitFor(() => expect((screen.getByRole("combobox") as HTMLSelectElement).disabled).toBe(false));
    expect(screen.queryByText(/No DNS providers are available/)).toBeNull();
    expect((screen.getByRole("button", { name: "Request" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("saves a certificate renewal policy change", async () => {
    get.mockResolvedValue({
      certs: [{
        id: 7,
        domains: "*.example.com",
        provider: "duckdns",
        status: "issued",
        expires_at: "2026-04-01T00:00:00Z",
        renews_at: "2026-02-01T00:00:00Z",
        renew_mode: "before_expiry",
        wildcard: true,
      }],
      providers: ["duckdns"],
      configured: ["duckdns"],
    });
    put.mockResolvedValue({ status: "ok", renew_mode: "monthly" });
    renderCerts();

    const select = await screen.findByLabelText("Auto-renew for *.example.com");
    fireEvent.change(select, { target: { value: "monthly" } });

    await waitFor(() => expect(put).toHaveBeenCalledWith("/api/certs/7", { renew_mode: "monthly" }));
  });
});
