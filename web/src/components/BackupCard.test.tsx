import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import BackupCard from "./BackupCard";

vi.mock("../api", () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
}));

import { api } from "../api";

const get = vi.mocked(api.get);
const put = vi.mocked(api.put);

const config = {
  enabled: true,
  transport: "local",
  schedule: "daily",
  time: "03:00",
  weekday: 0,
  keep: 7,
  local_dir: "/var/lib/waf-proxy/data/backups",
  git_dir: "",
  git_remote: "",
  git_branch: "",
  host: "",
  port: 22,
  user: "",
  dir: "",
  host_key: "",
  password: "",
  has_password: false,
  encrypt: false,
  passphrase: "",
  has_passphrase: false,
};

describe("Backup schedule card", () => {
  beforeEach(() => {
    get.mockReset();
    put.mockReset();
    get.mockResolvedValue({ config, status: {} });
  });

  afterEach(() => {
    cleanup();
  });

  it("reveals the passphrase field and saves it with encryption on", async () => {
    const onOK = vi.fn();
    render(<BackupCard onError={vi.fn()} onOK={onOK} />);
    await screen.findByText("Backup schedule");

    fireEvent.click(screen.getByLabelText(/encrypt backups/i));
        const field = await screen.findByPlaceholderText("At least 16 characters");
    fireEvent.change(field, { target: { value: "a-16-character-passphrase" } });

    put.mockResolvedValue({ config: { ...config, encrypt: true, has_passphrase: true }, status: {} });
    fireEvent.click(screen.getByText("Save"));

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
    expect(put.mock.calls[0][0]).toBe("/api/backup/schedule");
    expect(put.mock.calls[0][1]).toMatchObject({ encrypt: true, passphrase: "a-16-character-passphrase" });
    expect(onOK).toHaveBeenCalledWith("Backup schedule saved");
  });
});
