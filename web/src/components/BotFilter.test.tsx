import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import BotFilter from "./BotFilter";

vi.mock("../api", () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    del: vi.fn(),
    upload: vi.fn(),
  },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const put = vi.mocked(api.put);

function settings(overrides: Record<string, string> = {}) {
  return {
    bot_filter: "off",
    bot_filter_allow: "Googlebot, Bingbot, DuckDuckBot, Applebot",
    ...overrides,
  };
}

function renderFilter(onOK = vi.fn(), onError = vi.fn()) {
  return render(<BotFilter onOK={onOK} onError={onError} />);
}

describe("Bot filter", () => {
  beforeEach(() => {
    get.mockReset();
    put.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("saves the selected mode", async () => {
    get.mockResolvedValue(settings());
    put.mockResolvedValue({ status: "ok" });
    const onOK = vi.fn();
    renderFilter(onOK);

    const mode = (await screen.findByRole("combobox")) as HTMLSelectElement;
    await waitFor(() => expect(mode.disabled).toBe(false));
    fireEvent.change(mode, { target: { value: "scrapers" } });
    fireEvent.click(screen.getByRole("button", { name: "Save bot filter" }));

    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/settings", {
        bot_filter: "scrapers",
        bot_filter_allow: "Googlebot, Bingbot, DuckDuckBot, Applebot",
      }),
    );
    expect(onOK).toHaveBeenCalledWith("Bot filter saved");
  });

  it("loads and saves the allow list", async () => {
    get.mockResolvedValue(settings({ bot_filter: "all", bot_filter_allow: "Googlebot, Bingbot" }));
    put.mockResolvedValue({ status: "ok" });
    renderFilter();

    const allow = screen.getByPlaceholderText("Googlebot, Bingbot, DuckDuckBot") as HTMLInputElement;
    await waitFor(() => expect(allow.value).toBe("Googlebot, Bingbot"));
    fireEvent.change(allow, { target: { value: "Googlebot, Bingbot, DuckDuckBot" } });
    fireEvent.click(screen.getByRole("button", { name: "Save bot filter" }));

    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/settings", {
        bot_filter: "all",
        bot_filter_allow: "Googlebot, Bingbot, DuckDuckBot",
      }),
    );
  });

  it("surfaces a failed save", async () => {
    get.mockResolvedValue(settings());
    put.mockRejectedValue(new Error("permission denied"));
    const onError = vi.fn();
    renderFilter(vi.fn(), onError);

    const allow = screen.getByPlaceholderText("Googlebot, Bingbot, DuckDuckBot") as HTMLInputElement;
    await waitFor(() => expect(allow.disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Save bot filter" }));

    await waitFor(() => expect(onError).toHaveBeenCalledWith("permission denied"));
  });
});
