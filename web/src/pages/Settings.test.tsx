import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import SettingsPage from "./Settings";
import type { Me } from "../types";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), postRaw: vi.fn(), download: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const put = vi.mocked(api.put);
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
    put.mockReset();
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

  it("leaves host-wide keys out of a non-default site's save", async () => {
    get.mockImplementation(async (path: string) => {
      switch (path) {
        case "/api/settings":
          return {
            wan_ip: "192.168.1.2", max_body: "131072", retention_days: "7",
            host_wide_keys: "wan_ip,max_body", kernel: "active", geoip: "false",
          };
        case "/api/backup/schedule":
          return { config: backupConfig, status: {} };
        case "/api/geoip":
          return { available: false };
        case "/api/crowdsec/status":
          return { configured: false };
        case "/api/audit":
          return [];
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
    const me = { username: "ops", site: "bravo", site_name: "Bravo", permissions: [] } as unknown as Me;
    render(<SettingsPage onError={vi.fn()} onOK={vi.fn()} me={me} />);

    const retention = (await screen.findByText(/Event retention/)).parentElement?.querySelector("input");
    if (!retention) throw new Error("retention field not found");
    fireEvent.change(retention, { target: { value: "3" } });
    fireEvent.click(screen.getByText("Save settings"));

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
    const body = put.mock.calls[0][1] as Record<string, string>;
    expect(body.retention_days).toBe("3");
    expect(body.wan_ip).toBeUndefined();
    expect(body.max_body).toBeUndefined();
    expect(body.host_wide_keys).toBeUndefined();
  });

  const mockHA = (status: Record<string, unknown>) => {
    const base = get.getMockImplementation();
    get.mockImplementation(async (path: string) => {
      if (path === "/api/ha") return status;
      return base ? base(path) : {};
    });
  };

  it("puts the HA switch directly above Backup and saves it with the page", async () => {
    renderPage();
    const toggle = await screen.findByRole("switch", { name: /enable high availability/i });
    expect((toggle as HTMLInputElement).checked).toBe(false);
    expect(document.getElementById("ha")?.nextElementSibling?.id).toBe("backup");

    fireEvent.click(toggle);
    fireEvent.click(screen.getByText("Save settings"));
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
    expect((put.mock.calls[0][1] as Record<string, string>).ha_enabled).toBe("1");
  });

  it("refreshes the HA help and the nav after saving", async () => {
    let haCalls = 0;
    const base = get.getMockImplementation();
    get.mockImplementation(async (path: string) => {
      if (path === "/api/ha") {
        haCalls++;
        return haCalls === 1
          ? { enabled: false, boot_enabled: true }
          : { enabled: true, boot_enabled: true, paired: false };
      }
      return base ? base(path) : {};
    });
    const onMeChanged = vi.fn();
    render(<SettingsPage onError={vi.fn()} onOK={vi.fn()} onMeChanged={onMeChanged} />);
    const toggle = await screen.findByRole("switch", { name: /enable high availability/i });
    fireEvent.click(toggle);
    fireEvent.click(screen.getByText("Save settings"));
    await screen.findByText(/not paired yet/);
    expect(onMeChanged).toHaveBeenCalledTimes(1);
  });

  it("says the boot switch is in the way and disables the toggle", async () => {
    mockHA({ enabled: false, boot_enabled: false, paired: false, reason: "this host booted with WAFPROXY_HA_ENABLE=0" });
    renderPage();
    const toggle = await screen.findByRole("switch", { name: /enable high availability/i });
    await screen.findByText(/WAFPROXY_HA_ENABLE=0/);
    expect((toggle as HTMLInputElement).disabled).toBe(true);
  });

  it("distinguishes a paired node from one that still needs pairing", async () => {
    mockHA({ enabled: true, boot_enabled: true, paired: true });
    renderPage();
    await screen.findByText(/This node is paired/);
    cleanup();

    mockHA({ enabled: true, boot_enabled: true, paired: false });
    renderPage();
    await screen.findByText(/not paired yet/);
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
