import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import IncidentReport, { reportFilename } from "./IncidentReport";

describe("incident report", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("names the file after the subject", () => {
    expect(reportFilename("203.0.113.7")).toMatch(/^incident-203-0-113-7-\d{8}-\d{4}\.md$/);
  });

  it("copies the Markdown and offers a download", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const onOK = vi.fn();
    const md = "# Incident report — 203.0.113.7\n\n- Window: last 24h";
    render(<IncidentReport report={md} filename="incident-x.md" onClose={vi.fn()} onError={vi.fn()} onOK={onOK} />);

    expect(screen.getByLabelText("Incident report in Markdown").textContent).toContain("Window: last 24h");
    fireEvent.click(screen.getByRole("button", { name: "Copy Markdown" }));
    expect(writeText).toHaveBeenCalledWith(md);
    await waitFor(() => expect(onOK).toHaveBeenCalledWith("Report copied as Markdown"));
    expect(screen.getByRole("button", { name: "Download .md" })).toBeTruthy();
  });
});
