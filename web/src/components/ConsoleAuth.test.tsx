import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import ConsoleAuthForm from "./ConsoleAuth";
import type { ConsoleAuth } from "../types";

vi.mock("../api", () => ({
  api: { get: vi.fn(), put: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const put = vi.mocked(api.put);

const saved: ConsoleAuth = {
  id: 4,
  kind: "tacacs",
  enabled: true,
  host: "127.0.0.1",
  port: 49,
  base_dn: "",
  bind_dn: "",
  user_filter: "",
  group_filter: "",
  email_attr: "mail",
  use_tls: false,
  start_tls: false,
  skip_verify: false,
  timeout_seconds: 8,
  default_role_id: 1,
  role_map: "15=Administrator",
  has_secret: true,
  has_bind_password: false,
};

beforeEach(() => {
  get.mockImplementation(async (path: string) => {
    if (path === "/api/console-auth") return [saved];
    return { roles: [{ id: 1, name: "Administrator", description: "", builtin: true, permissions: ["*"] }] };
  });
  put.mockResolvedValue(saved);
});

afterEach(cleanup);

describe("ConsoleAuthForm", () => {
  it("sends only editable directory fields when saving a loaded provider", async () => {
    render(<ConsoleAuthForm kind="tacacs" canWrite onError={vi.fn()} onOK={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Save TACACS+" }));

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
    expect(put).toHaveBeenCalledWith("/api/console-auth/tacacs", {
      enabled: true,
      host: "127.0.0.1",
      port: 49,
      secret: "",
      base_dn: "",
      bind_dn: "",
      bind_password: "",
      user_filter: "",
      group_filter: "",
      email_attr: "mail",
      use_tls: false,
      start_tls: false,
      skip_verify: false,
      timeout_seconds: 8,
      default_role_id: 1,
      role_map: "15=Administrator",
    });
  });
});
