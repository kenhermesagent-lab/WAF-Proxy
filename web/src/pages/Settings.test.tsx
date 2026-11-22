import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import SettingsPage from "./Settings";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), postRaw: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const postRaw = vi.mocked(api.postRaw);

const backupConfig = {
  enabled: false, transport: "local", schedule: "daily", time: "03:00", weekday: 0, keep: 7,
  local_dir: "/var/lib/waf-proxy/data/backups", git_dir: "", git_remote: "", git_branch: "",
  host: "", port: 22, user: "", dir: "", host_key: "", password: "", has_password: false,
  encrypt: false, passphrase: "", has_passphrase: false,
};

function renderPage() {
  return render(<SettingsPage onError={vi.fn()} onOK={vi.fn()} />);
}

describe("Settings configuration transport", () => {
  beforeEach(() => {
    get.mockReset();
    postRaw.mockReset();
    get.mockImplementation(async (path: string) => {
      switch (path) {
        case "/api/settings":
          return {};
        case "/api/backup/schedule":
          return { config: backupConfig, status: {} };
        case "/api/geoip":
          return { available: false };
        case "/api/crowdsec/status":
          return { configured: false };
        case "/api/audit":
          return [];
        default:
          return {};
      }
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("offers the YAML download next to the JSON one", async () => {
    renderPage();
    await screen.findByText("Configuration backup");

    const link = screen.getByText("Download YAML").closest("a");
    expect(link?.getAttribute("href")).toBe("/api/config/export.yaml");
    expect(screen.getByText("Download JSON").closest("a")?.getAttribute("href")).toBe("/api/backup");
  });

  it("imports a YAML file and reports the result", async () => {
    const onOK = vi.fn();
    render(<SettingsPage onError={vi.fn()} onOK={onOK} />);
    await screen.findByText("Import YAML");

    postRaw.mockResolvedValue({ imported: { waf_profiles: 1 }, problems: [] });
    const input = document.querySelector('input[accept=".yaml,.yml"]') as HTMLInputElement;
    const file = new File(["version: \"1.0\"\n"], "config.yaml", { type: "application/yaml" });
    // jsdom's File has no text() in this environment.
    Object.defineProperty(file, "text", { value: async () => "version: \"1.0\"\n" });
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => expect(postRaw).toHaveBeenCalledTimes(1));
    expect(postRaw.mock.calls[0][0]).toBe("/api/config/import.yaml");
    expect(postRaw.mock.calls[0][1]).toContain("version:");
    expect(postRaw.mock.calls[0][2]).toEqual({ "Content-Type": "application/yaml" });
    await waitFor(() => expect(onOK).toHaveBeenCalledWith("Imported 1 waf_profiles"));
  });

  it("surfaces an import error through the page handler", async () => {
    const onError = vi.fn();
    render(<SettingsPage onError={onError} onOK={vi.fn()} />);
    await screen.findByText("Import YAML");

    postRaw.mockRejectedValue(new Error("invalid configuration file"));
    const input = document.querySelector('input[accept=".yaml,.yml"]') as HTMLInputElement;
        const bad = new File(["nope"], "config.yaml", { type: "application/yaml" });
    Object.defineProperty(bad, "text", { value: async () => "nope" });
    fireEvent.change(input, { target: { files: [bad] } });

    await waitFor(() => expect(onError).toHaveBeenCalledWith("invalid configuration file"));
  });
});
