import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import Account from "../pages/Account";
import type { AdminUser, Me, PermissionArea, Role } from "../types";

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
const post = vi.mocked(api.post);

const areas: PermissionArea[] = [
  { key: "dashboard", label: "Dashboard and live traffic" },
  { key: "traffic", label: "Logs, analytics, IPs and audit" },
];

const adminRole: Role = {
  id: 1,
  name: "Administrator",
  description: "Full access, including accounts and system settings.",
  builtin: true,
  permissions: ["*"],
};

const users: AdminUser[] = [
  {
    id: 1,
    username: "admin",
    email: "admin@example.com",
    role_id: 1,
    role: "Administrator",
    totp_enabled: true,
    created_at: "2026-01-02T03:04:05Z",
  },
];

function me(permissions: string[], role = "Viewer"): Me {
  return {
    username: "admin",
    csrf: "csrf",
    version: "1.20.0",
    base_domain: "demo.test",
    totp_enabled: true,
    email: "admin@example.com",
    role,
    permissions,
  };
}

function mockTeam() {
  get.mockImplementation(async (path: string) => {
    if (path === "/api/users") return { users, roles: [adminRole], areas };
    return {};
  });
}

function renderAccount(account: Me, onError = vi.fn(), onOK = vi.fn()) {
  return render(
    <Account me={account} onError={onError} onOK={onOK} onSignedOut={vi.fn()} />,
  );
}

describe("Account administrators and roles", () => {
  beforeEach(() => {
    get.mockReset();
    // Account always asks for the signed-in administrator's remembered
    // browsers; a test that cares about another endpoint overrides this.
    get.mockImplementation(async () => ({ devices: [] }));
    post.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("hides the whole team section from a viewer", async () => {
    renderAccount(me(["dashboard.read"], "Viewer"));

    expect(await screen.findByRole("heading", { name: "Change password" })).toBeTruthy();
    expect(screen.queryByText(/Administrators \(/)).toBeNull();
    expect(screen.queryByText("Roles")).toBeNull();
    expect(screen.queryByRole("button", { name: "Add administrator" })).toBeNull();
    expect(screen.queryByRole("button", { name: "New role" })).toBeNull();
    expect(get.mock.calls.some(([path]) => path === "/api/users")).toBe(false);
  });

  it("shows accounts to a read-only account admin without any controls", async () => {
    mockTeam();
    renderAccount(me(["accounts.read"], "Read-only"));

    expect(await screen.findByText("Administrators (1)")).toBeTruthy();
    expect(screen.getByText("Roles")).toBeTruthy();
    expect(screen.getByText("admin")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Add administrator" })).toBeNull();
    expect(screen.queryByRole("button", { name: "New role" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Reset password" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("lets an administrator create a role with the chosen permissions", async () => {
    mockTeam();
    post.mockResolvedValue({ id: 2 });
    const onOK = vi.fn();
    renderAccount(me(["*"], "Administrator"), vi.fn(), onOK);

    await screen.findByText("Administrators (1)");
    fireEvent.click(screen.getByRole("button", { name: "New role" }));

    const modal = document.querySelector(".modal") as HTMLElement;
    const inputs = within(modal).getAllByRole("textbox");
    fireEvent.change(inputs[0], { target: { value: "Auditor" } });
    fireEvent.change(inputs[1], { target: { value: "Reads traffic and certificates" } });
    fireEvent.click(within(modal).getByRole("checkbox", { name: "Logs, analytics, IPs and audit: view" }));
    fireEvent.click(within(modal).getByRole("button", { name: "Create role" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/roles", expect.objectContaining({
        name: "Auditor",
        description: "Reads traffic and certificates",
        permissions: ["dashboard.read", "traffic.read"],
      })),
    );
    expect(onOK).toHaveBeenCalledWith("Role created");
  });

  it("refuses to submit a role with no permissions", async () => {
    mockTeam();
    renderAccount(me(["*"], "Administrator"));

    await screen.findByText("Administrators (1)");
    fireEvent.click(screen.getByRole("button", { name: "New role" }));

    const modal = document.querySelector(".modal") as HTMLElement;
    fireEvent.change(within(modal).getAllByRole("textbox")[0], { target: { value: "Empty" } });
    // The new-role draft starts with dashboard view; removing it leaves nothing
    // to grant, which the server rejects, so the dialog must not submit it.
    fireEvent.click(within(modal).getByRole("checkbox", { name: "Dashboard and live traffic: view" }));

    const create = within(modal).getByRole("button", { name: "Create role" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    fireEvent.click(create);
    expect(post).not.toHaveBeenCalled();
  });
});
