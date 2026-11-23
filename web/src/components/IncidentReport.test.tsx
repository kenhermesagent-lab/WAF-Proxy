import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import IncidentReport, { buildReport, reportFilename } from "./IncidentReport";
import type { Event } from "../types";

const event: Event = {
  id: 7,
  ts: "2026-11-22T10:04:00Z",
  src_ip: "203.0.113.7",
  host: "app.example.com",
  method: "GET",
  path: "/.env",
  stage: "waf",
  action: "ban",
  rule_id: "930120",
  rule_msg: "Path traversal",
  status: 403,
  latency_ms: 2,
  bytes_out: 120,
  country: "RU",
  asn: 64500,
} as Event;

describe("incident report", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("writes the window, verdicts and timeline from the fetched events", () => {
    const md = buildReport({
      subject: "203.0.113.7",
      window: "last 24h",
      summary: ["Requests: 2 · blocked 1 (50%)"],
      events: [event],
      total: 1,
      audit: [{ id: 3, ts: "2026-11-22T10:05:00Z", user: "alice", action: "ban.create", detail: "203.0.113.7", ip: "10.0.0.9" }],
    });
    expect(md).toContain("# Incident report — 203.0.113.7");
    expect(md).toContain("- Window: last 24h");
    expect(md).toContain("| waf | ban | 1 |");
    expect(md).toContain("| app.example.com");
    expect(md).toContain("Path traversal");
    expect(md).toContain("| ban.create |");
  });

  it("writes a dash rather than a blank cell when a rule has no message", () => {
    const md = buildReport({
      subject: "log window",
      window: "every event",
      summary: ["Matching events: 1"],
      events: [{ ...event, stage: "route", action: "allow", rule_id: "", rule_msg: "" }],
    });
    expect(md).toContain("| route | allow | 1 |");
    expect(md).toContain("| route | — | 403 |");
  });

  it("says so when the window has no events instead of inventing any", () => {
    const md = buildReport({ subject: "198.51.100.9", window: "last 1h", summary: ["Requests: 0"], events: [], total: 0 });
    expect(md).toContain("## No events");
    expect(md).toContain("nothing further to report");
    expect(md).not.toContain("## Timeline");
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
