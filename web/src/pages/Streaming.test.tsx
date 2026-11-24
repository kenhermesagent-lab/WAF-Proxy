import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import StreamingPage from "./Streaming";
import type { AccessList, StreamingService } from "../types";

vi.mock("../api", () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(),
    post: vi.fn(),
  },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const put = vi.mocked(api.put);

const base: StreamingService = {
  firewall: [],
  id: "plex",
  label: "Plex",
  group: "media",
  notes: "TLS passes through.",
  default_port: 32400,
  enabled: false,
  listen_ip: "",
  protocol: "tcp",
  port: 0,
  port_count: 0,
  upstream: "",
  upstream_port: 0,
  allow: [],
  max_conns: 0,
  max_per_source: 0,
  idle_seconds: 0,
  max_datagram: 0,
  require_allow: false,
  list_ids: [],
  bound: false,
  listen_addr: "",
  upstream_base: "",
  active: 0,
  active_sessions: 0,
  total: 0,
  blocked: 0,
  banned: 0,
  dropped: 0,
  oversize: 0,
  bytes_in: 0,
  bytes_out: 0,
  packets_in: 0,
  packets_out: 0,
  refused: 0,
  sessions: [],
  last_error: "",
  default: {
    listen_ip: "192.168.1.20",
    protocol: "tcp",
    port: 32400,
    port_count: 1,
    upstream: "10.0.0.10:32400",
    upstream_port: 32400,
    max_conns: 256,
    max_per_source: 8,
    idle_seconds: 60,
    max_datagram: 1500,
  },
};

type Override = Partial<Omit<StreamingService, "default">> & { default?: Partial<StreamingService["default"]> };

function service(over: Override = {}): StreamingService {
  return { ...base, ...over, default: { ...base.default, ...(over.default ?? {}) } };
}

function serve(services: StreamingService[], lists: AccessList[] = []) {
  get.mockImplementation(async (path: string) =>
    path === "/api/lists" ? lists : { services, env: { path: "", error: "" } },
  );
}

function valheim(over: Override = {}): StreamingService {
  return service({
    id: "valheim",
    label: "Valheim",
    group: "game",
    protocol: "udp",
    port: 2456,
    port_count: 3,
    notes: "2456-2458 in one card.",
    default: { protocol: "udp", port: 2456, port_count: 3, upstream: "10.0.0.10:2456", upstream_port: 2456 },
    ...over,
  });
}

function renderPage() {
  const onError = vi.fn();
  const onOK = vi.fn();
  render(<StreamingPage head={false} onError={onError} onOK={onOK} />);
  return { onError, onOK };
}

describe("Streaming page", () => {
  beforeEach(() => {
    get.mockReset();
    put.mockReset();
    vi.mocked(api.post).mockReset();
    serve([]);
  });

  afterEach(() => {
    cleanup();
  });

  it("gives every service its own tab and shows only that service", async () => {
    serve([service(), valheim(), service({ id: "custom", label: "Custom TCP/UDP", group: "custom" })]);
    renderPage();

    const tabs = await screen.findAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Plex", "Valheim", "Custom TCP/UDP"]);
    expect(screen.getByText("Plex forwarding")).toBeTruthy();
    expect(screen.queryByText("Valheim forwarding")).toBeNull();
    expect(screen.getByRole("heading", { name: "Media" })).toBeTruthy();

    fireEvent.click(screen.getByRole("tab", { name: "Valheim" }));
    expect(screen.getByText("Valheim forwarding")).toBeTruthy();
    expect(screen.queryByText("Plex forwarding")).toBeNull();
    expect(screen.getByRole("heading", { name: "Game servers" })).toBeTruthy();
    // The preset note rides along with the card title.
    expect(screen.getByText("2456-2458 in one card.")).toBeTruthy();
  });

  it("opens on the first enabled service", async () => {
    serve([service(), valheim({ enabled: true, bound: true, listen_addr: "192.168.1.20:2456-2458" })]);
    renderPage();

    expect(await screen.findByText("Valheim forwarding")).toBeTruthy();
    expect(screen.queryByText("Plex forwarding")).toBeNull();
  });

  it("shows the UDP limits only on a card that uses UDP", async () => {
    serve([service(), valheim()]);
    renderPage();

    await screen.findByText("Plex forwarding");
    expect(screen.queryByText("Max sessions per source")).toBeNull();

    fireEvent.click(screen.getByRole("tab", { name: "Valheim" }));
    expect(screen.getByText("Max sessions per source")).toBeTruthy();
  });

  it("names the ports the host firewall opened", async () => {
    serve([service({ enabled: true, bound: true, firewall: ["32400/tcp"] })]);
    renderPage();

    await screen.findByText("Plex forwarding");
    expect(screen.getByText("Host firewall")).toBeTruthy();
    expect(screen.getByText("32400/tcp")).toBeTruthy();
  });

  it("sends the protocol and the range on save", async () => {
    serve([
      service({
        id: "custom",
        label: "Custom TCP/UDP",
        group: "custom",
        default: { port: 0, upstream: "", upstream_port: 0 },
      }),
    ]);
    put.mockResolvedValue({ applied: true, error: "", env: { path: "", error: "" } });
    renderPage();

    await screen.findByText("Custom TCP/UDP forwarding");
    fireEvent.change(screen.getByRole("combobox", { name: "Custom TCP/UDP protocol" }), { target: { value: "both" } });
    fireEvent.change(screen.getByRole("spinbutton", { name: "Custom TCP/UDP listen port" }), { target: { value: "26900" } });
    fireEvent.change(screen.getByRole("spinbutton", { name: "Custom TCP/UDP port count" }), { target: { value: "4" } });
    fireEvent.change(screen.getByRole("textbox", { name: "Custom TCP/UDP server" }), { target: { value: "10.0.0.10:26900" } });
        fireEvent.change(screen.getByRole("textbox", { name: "Custom TCP/UDP listen address" }), {
      target: { value: "192.168.1.20" },
    });
    fireEvent.click(screen.getByRole("checkbox", { name: "Custom TCP/UDP require an allow list" }));

    expect(screen.getByText(/Listens on 26900-26903/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(put).toHaveBeenCalled());
    const [path, body] = put.mock.calls[0];
    expect(path).toBe("/api/streaming/custom");
    expect(body).toMatchObject({
      enabled: false,
      protocol: "both",
      listen_ip: "192.168.1.20",
      port: 26900,
      port_count: 4,
      upstream: "10.0.0.10:26900",
      require_allow: true,
    });
  });

  it("warns only when a UDP card answers anyone", async () => {
    serve([
      valheim(),
      service({ id: "ark", label: "ARK", group: "game", protocol: "udp", allow: ["10.0.0.0/8"] }),
    ]);
    renderPage();

    await screen.findByText("Valheim forwarding");
    expect(screen.getAllByText(/answers any source/)).toHaveLength(1);
  });

  it("hides the warning once the card refuses sources without a list", async () => {
    serve([valheim()]);
    renderPage();

    await screen.findByText("Valheim forwarding");
    expect(screen.getByText(/answers any source/)).toBeTruthy();

    fireEvent.click(screen.getByRole("checkbox", { name: "Valheim require an allow list" }));
    expect(screen.queryByText(/answers any source/)).toBeNull();
  });

  it("does not warn when a whitelist is attached", async () => {
    serve(
      [valheim({ list_ids: [7] })],
      [{ id: 7, kind: "whitelist", name: "friends", ips: "10.0.0.0/8", countries: "" }],
    );
    renderPage();

    await screen.findByText("Valheim forwarding");
    expect(screen.queryByText(/answers any source/)).toBeNull();
  });

  it("renders a TCP service without the UDP fields or a range summary", async () => {
    serve([service()]);
    renderPage();

    await screen.findByText("Plex forwarding");
    expect((screen.getByRole("combobox", { name: "Plex protocol" }) as HTMLSelectElement).value).toBe("tcp");
    expect(screen.queryByText("Max sessions per source")).toBeNull();
    expect(screen.queryByText(/Listens on/)).toBeNull();
    expect(screen.getByText("0 connections")).toBeTruthy();
  });

  it("shows the live counters and the busiest source", async () => {
    serve([
      service({
        enabled: true,
        bound: true,
        listen_addr: "192.168.1.20:32400",
        protocol: "both",
        active: 1,
        active_sessions: 2,
        bytes_in: 1536,
        bytes_out: 512,
        oversize: 3,
        sessions: [
          {
            addr: "203.0.113.7",
            port: 32400,
            protocol: "TCP",
            bytes_in: 1024,
            bytes_out: 0,
            packets_in: 8,
            packets_out: 0,
            started: "2026-11-24T00:00:00Z",
          },
        ],
      }),
    ]);
    renderPage();

    await screen.findByText("Plex forwarding");
    expect(screen.getByText("1 connection · 2 sessions")).toBeTruthy();
    expect(screen.getByText("↓ 1.5 KB · ↑ 512 B")).toBeTruthy();
    expect(screen.getByText("203.0.113.7 · 1.0 KB")).toBeTruthy();
    expect(screen.getByText("Dropped (oversize)")).toBeTruthy();
  });
});
