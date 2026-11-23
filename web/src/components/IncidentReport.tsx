import { Drawer, errText } from "../ui";

function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "console";
}

export function reportFilename(subject: string): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `incident-${slug(subject)}-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}.md`;
}

/**
 * Shows the Markdown the server rendered for this report. The rendering lives
 * in one place (internal/api/incident_report.go) so the browser, a cron job
 * and a runbook all read the same write-up.
 */
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
