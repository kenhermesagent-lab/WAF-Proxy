import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Certs from "./Certs";

vi.mock("../api", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    del: vi.fn(),
  },
}));

import { api } from "../api";

const get = vi.mocked(api.get);

function renderCerts() {
  return render(<Certs base="example.com" onError={vi.fn()} onOK={vi.fn()} />);
}

async function openDialog() {
  await waitFor(() => expect(get).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "Request certificate" }));
}

describe("certificate dialog provider availability", () => {
  beforeEach(() => {
    get.mockReset();
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
});
