import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import SettingsPage from "./Settings";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), postRaw: vi.fn(), download: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const postRaw = vi.mocked(api.postRaw);
const download = vi.mocked(api.download);

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
    download.mockReset();
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
        case "/api/audit/verify":
          return { ok: true, checked: 0 };
        case "/api/updates":
          return { packages: [], updating: false, app_updating: false };
        case "/api/certs":
          return { certs: [] };
        case "/api/notifications":
          return { settings: {}, channels: {}, recent: [], event_kinds: [] };
        default:
          return {};
      }
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("downloads both formats, encrypting them when a passphrase is set", async () => {
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    URL.createObjectURL = vi.fn(() => "blob:file");
    URL.revokeObjectURL = vi.fn();
    download.mockResolvedValue({ blob: new Blob(["sealed"]), name: "wafproxy.yaml.enc" });
    renderPage();
    await screen.findByText("Configuration backup");

    fireEvent.click(screen.getByText("Download JSON"));
    expect(download).toHaveBeenLastCalledWith("/api/backup", {});

    fireEvent.change(screen.getByPlaceholderText(/passphrase/i), {
      target: { value: "a-16-character-passphrase" },
    });
    fireEvent.click(screen.getByText("Download YAML"));
    await waitFor(() =>
      expect(download).toHaveBeenLastCalledWith("/api/config/export.yaml", {
        "X-Backup-Passphrase": "a-16-character-passphrase",
      }),
    );
    click.mockRestore();
  });

  it("imports a YAML file and reports the result", async () => {
    const onOK = vi.fn();
    render(<SettingsPage onError={vi.fn()} onOK={onOK} />);
    await screen.findByText("Import YAML");

    postRaw.mockResolvedValue({ imported: { waf_profiles: 1 }, problems: [] });
    const input = document.querySelector('input[accept=".yaml,.yml,.enc"]') as HTMLInputElement;
    const file = new File(["version: \"1.0\"\n"], "config.yaml", { type: "application/yaml" });
    // jsdom's File has no arrayBuffer() in this environment.
    Object.defineProperty(file, "arrayBuffer", {
      value: async () => new TextEncoder().encode("version: \"1.0\"\n").buffer,
    });
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => expect(postRaw).toHaveBeenCalledTimes(1));
    expect(postRaw.mock.calls[0][0]).toBe("/api/config/import.yaml");
    // Bytes, not a decoded string: ciphertext must survive the round trip.
    expect(postRaw.mock.calls[0][1]).toBeInstanceOf(Blob);
    expect(postRaw.mock.calls[0][2]).toEqual({ "Content-Type": "application/yaml" });
    await waitFor(() => expect(onOK).toHaveBeenCalledWith("Imported 1 waf_profiles"));
  });

  it("restores an encrypted backup as bytes", async () => {
    renderPage();
    await screen.findByText("Configuration backup");

    postRaw.mockResolvedValue({ imported: { proxies: 1 }, problems: [] });
    const sealed = new Uint8Array(14);
    sealed.set(new TextEncoder().encode("WAFPROXY-ENC1"));
    sealed[13] = 0x80;
    const file = new File([sealed], "backup.json.enc");
    Object.defineProperty(file, "arrayBuffer", { value: async () => sealed.buffer });
    const input = document.querySelector('input[accept*=".json"]') as HTMLInputElement;
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => expect(postRaw).toHaveBeenCalledTimes(1));
    expect(postRaw.mock.calls[0][0]).toBe("/api/backup/restore");
    expect(postRaw.mock.calls[0][1]).toBeInstanceOf(Blob);
  });

  it("surfaces an import error through the page handler", async () => {
    const onError = vi.fn();
    render(<SettingsPage onError={onError} onOK={vi.fn()} />);
    await screen.findByText("Import YAML");

    postRaw.mockRejectedValue(new Error("invalid configuration file"));
    const input = document.querySelector('input[accept=".yaml,.yml,.enc"]') as HTMLInputElement;
        const bad = new File(["nope"], "config.yaml", { type: "application/yaml" });
    Object.defineProperty(bad, "arrayBuffer", { value: async () => new TextEncoder().encode("nope").buffer });
    fireEvent.change(input, { target: { files: [bad] } });

    await waitFor(() => expect(onError).toHaveBeenCalledWith("invalid configuration file"));
  });
});
