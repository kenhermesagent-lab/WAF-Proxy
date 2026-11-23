import { Drawer, errText, fmtTime } from "../ui";
import type { AuditEntry, Event } from "../types";

export type ReportInput = {
  subject: string;
  window: string;
  summary: string[];
  events: Event[];
  total?: number;
  audit?: AuditEntry[];
};

function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "console";
}

function cell(text?: string | number | null): string {
  return String(text ?? "—").replace(/\|/g, "\\|");
}

export function reportFilename(subject: string): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `incident-${slug(subject)}-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}.md`;
}

/**
 * A self-contained Markdown write-up from data the console already has. It
 * states what it does not know rather than filling the gap: an empty window
 * produces an explicit "no events" section.
 */
export function buildReport({ subject, window, summary, events, total, audit = [] }: ReportInput): string {
  const lines = [
    `# Incident report — ${subject}`,
    "",
    `- Window: ${window}`,
    `- Generated: ${fmtTime(new Date().toISOString())}`,
    "",
    "## Summary",
    "",
  ];
  for (const line of summary) lines.push(`- ${line}`);

  if (events.length === 0) {
    lines.push(
      "",
      "## No events",
      "",
      "No requests matched this window, so there is nothing further to report.",
    );
    if (total !== undefined) lines.push("", `Matching events recorded by the console: ${total}.`);
    return lines.join("\n");
  }

  const verdicts = new Map<string, number>();
  for (const e of events) {
    const key = `${e.stage || "unknown"} / ${e.action || "unknown"}`;
    verdicts.set(key, (verdicts.get(key) ?? 0) + 1);
  }
  lines.push("", "## Verdicts", "", "| Stage | Action | Events |", "|---|---|---|");
  for (const [key, count] of [...verdicts].sort((a, b) => b[1] - a[1])) {
    const [stage, action] = key.split(" / ");
    lines.push(`| ${cell(stage)} | ${cell(action)} | ${count} |`);
  }

  lines.push("", "## Timeline (newest first)", "", "| Time | Source | Host | Request | Stage | Rule | Status |", "|---|---|---|---|---|---|---|");
  for (const e of events.slice(0, 50)) {
    lines.push(
      `| ${cell(fmtTime(e.ts))} | ${cell(e.src_ip)} | ${cell(e.host)} | ${cell(`${e.method} ${e.path}`)} | ${cell(e.stage)} | ${cell(e.rule_msg || e.rule_id)} | ${cell(e.status)} |`,
    );
  }
  if (events.length > 50) lines.push("", `The newest 50 of ${events.length} events fetched for this report are listed.`);
  if (total !== undefined && total > events.length) {
    lines.push("", `The console holds ${total.toLocaleString()} matching events for this window.`);
  }

  lines.push("", "## Actions taken", "");
  if (audit.length === 0) {
    lines.push("No administrator action mentioning this subject was recorded in the exported window.");
  } else {
    lines.push("| Time | Actor | Action | Detail |", "|---|---|---|---|");
    for (const a of audit.slice(0, 30)) {
      lines.push(`| ${cell(fmtTime(a.ts))} | ${cell(a.user || "system")} | ${cell(a.action)} | ${cell(a.detail)} |`);
    }
  }
  return lines.join("\n");
}

export default function IncidentReport({
  report,
  filename,
  onClose,
  onError,
  onOK,
}: {
  report: string;
  filename: string;
  onClose: () => void;
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(report);
      onOK("Report copied as Markdown");
    } catch (e) {
      onError(`${errText(e)} — select the text and copy it manually`);
    }
  };

  const download = () => {
    const url = URL.createObjectURL(new Blob([report], { type: "text/markdown;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Drawer
      title="Incident report"
      sub={<span className="mono">{filename}</span>}
      wide
      onClose={onClose}
      footer={
        <>
          <button onClick={copy}>Copy Markdown</button>
          <button onClick={download}>Download .md</button>
          <button onClick={() => window.print()}>Print</button>
          <button className="primary" onClick={onClose}>Done</button>
        </>
      }
    >
      <pre className="report-preview" aria-label="Incident report in Markdown">{report}</pre>
    </Drawer>
  );
}
