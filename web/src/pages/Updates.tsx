import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, errText, fmtAgo } from "../ui";
import type { UpdatePackage, UpdatesSnapshot } from "../types";

function severityTone(severity?: string): "bad" | "warn" | "info" | "" {
  if (severity === "critical" || severity === "high") return "bad";
  if (severity === "medium") return "warn";
  if (severity === "low") return "info";
  return "";
}

function statusLabel(p: UpdatePackage): string {
  switch (p.status) {
    case "security":
      return "security update";
    case "vulnerable":
      return "vulnerable";
    case "update":
      return "update available";
    case "current":
      return "up to date";
    case "missing":
      return "not installed";
    default:
      return "unknown";
  }
}

export default function UpdatesPage({
  onError,
  onOK,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [snap, setSnap] = useState<UpdatesSnapshot | null>(null);
  const [loadError, setLoadError] = useState("");
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState<string | null>(null);
  const [output, setOutput] = useState("");

  const load = () =>
    api
      .get<UpdatesSnapshot>("/api/updates")
      .then((v) => {
        setSnap(v);
        setLoadError("");
      })
      .catch((e) => {
        setLoadError(errText(e));
        onError(errText(e));
      });

  useEffect(() => {
    load();
  }, []);

  const check = async () => {
    setChecking(true);
    try {
      const next = await api.post<UpdatesSnapshot>("/api/updates/check");
      setSnap(next);
      onOK("Package index refreshed");
    } catch (e) {
      onError(errText(e));
    } finally {
      setChecking(false);
    }
  };

  const apply = async (p: UpdatePackage) => {
    if (!confirm(`Update ${p.name} from ${p.current || "the installed version"} to ${p.candidate}?`)) return;
    setUpdating(p.name);
    setOutput("");
    try {
      const res = await api.post<{ snapshot: UpdatesSnapshot; output?: string }>("/api/updates/apply", {
        package: p.name,
      });
      setSnap(res.snapshot);
      setOutput(res.output || "");
      onOK(`${p.name} updated`);
    } catch (e) {
      onError(errText(e));
      await load();
    } finally {
      setUpdating(null);
    }
  };

  if (loadError && !snap) {
    return <Card title="Updates"><p className="err-text">{loadError}</p></Card>;
  }
  if (!snap) {
    return <Card title="Updates"><p className="muted">Loading…</p></Card>;
  }

  const high = snap.packages.filter((p) => p.severity === "critical" || p.severity === "high");
  const security = snap.packages.filter((p) => p.security || p.status === "security" || p.status === "vulnerable");
  const updates = snap.packages.filter((p) => p.can_update || p.status === "security" || p.status === "update");
  const current = snap.packages.filter((p) => p.status === "current");
  const busy = checking || updating !== null || snap.updating;

  return (
    <div className="grid" style={{ gap: 14 }}>
      <Card
        title="Host updates"
        actions={
          <button className="small" onClick={check} disabled={!snap.available || busy}>
            {checking ? "Checking…" : "Check for updates"}
          </button>
        }
      >
        {!snap.available ? (
          <>
            <p className="err-text" style={{ marginTop: 0 }}>{snap.reason || "Host package updates are unavailable."}</p>
            <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
              {snap.container
                ? "This page only manages host packages on a native systemd install. Docker deployments receive these packages through the WAF-Proxy image, so update the image and recreate the container instead."
                : "This page only manages host packages on a Debian or Ubuntu systemd install with apt. Use the distribution package manager or rebuild the image on an unsupported host."}
            </p>
          </>
        ) : (
          <>
            <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
              <div className="muted" style={{ fontSize: 12 }}>
                {snap.platform || "Debian/Ubuntu"} · checked {snap.checked_at ? fmtAgo(snap.checked_at) : "not yet"}
              </div>
              <div className="muted" style={{ fontSize: 12 }}>
                {snap.helper_ready ? "Privileged helper ready" : "Update helper unavailable"}
              </div>
            </div>
            {high.length > 0 && (
              <div className="card" style={{ borderColor: "#5b2530", background: "#1b1114", padding: 12, marginBottom: 14 }}>
                <strong style={{ color: "#f2a7b3" }}>
                  {high.length} high/critical security {high.length === 1 ? "advisory" : "advisories"}
                </strong>
                <p className="muted" style={{ fontSize: 12, margin: "4px 0 0" }}>
                  Review the advisory detail below; update the affected package where a newer version is available.
                </p>
              </div>
            )}
            {!snap.helper_ready && (
              <p className="err-text">
                {snap.helper_error || "The native update helper is not installed or is not running."} Run{" "}
                <code>sudo ./deploy/install.sh</code> on the host to install it, then reload this page.
              </p>
            )}
            {snap.advisory_error && (
              <p className="muted" style={{ fontSize: 12, borderLeft: "2px solid #8a6d1d", paddingLeft: 10 }}>
                Security advisory feed unavailable: {snap.advisory_error}. Package update availability is still
                shown; security severity may be incomplete.
              </p>
            )}
            <div className="grid cols-4">
              <div className="stat"><div className="v" style={{ color: high.length ? "#f2a7b3" : undefined }}>{high.length}</div><div className="k">High / critical</div></div>
              <div className="stat"><div className="v">{security.length}</div><div className="k">Security</div></div>
              <div className="stat"><div className="v">{updates.length}</div><div className="k">Available</div></div>
              <div className="stat"><div className="v">{current.length}</div><div className="k">Up to date</div></div>
            </div>
          </>
        )}
      </Card>

      {snap.available && (
        <Card title="Managed host packages">
          {snap.packages.length === 0 ? (
            <Empty>No managed packages were found.</Empty>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table>
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Installed</th>
                    <th>Available</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {snap.packages.map((p) => (
                    <tr key={p.name}>
                      <td>
                        <div><span className="mono">{p.name}</span></div>
                        {p.role && <div className="muted" style={{ fontSize: 12 }}>{p.role}</div>}
                        {p.advisories && p.advisories.length > 0 && (
                          <div style={{ marginTop: 8, display: "grid", gap: 6 }}>
                            {p.advisories.map((a) => (
                              <div key={a.id} className="muted" style={{ fontSize: 12, lineHeight: 1.5 }}>
                                <span className="mono">{a.id}</span>{" "}
                                <Badge tone={severityTone(a.severity)}>{a.severity}</Badge>{" "}
                                {a.summary}
                              </div>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="mono">{p.current || "—"}</td>
                      <td className="mono">{p.candidate || "—"}</td>
                      <td>
                        <Badge tone={p.status === "security" || p.status === "vulnerable" ? "bad" : p.status === "update" ? "warn" : p.status === "current" ? "ok" : ""}>
                          {statusLabel(p)}
                        </Badge>
                        {p.severity && p.severity !== "unknown" && (
                          <div style={{ marginTop: 5 }}><Badge tone={severityTone(p.severity)}>{p.severity}</Badge></div>
                        )}
                        {p.note && <div className="muted" style={{ fontSize: 11.5, marginTop: 5 }}>{p.note}</div>}
                      </td>
                      <td>
                        {p.can_update ? (
                          <button className="small primary" onClick={() => apply(p)} disabled={busy}>
                            {updating === p.name ? "Updating…" : "Update"}
                          </button>
                        ) : (
                          <span className="muted" style={{ fontSize: 12 }}>
                            {p.status === "current" ? "No action" : p.note || "No upgrade available"}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="muted" style={{ fontSize: 12, marginTop: 10, lineHeight: 1.6 }}>
            Only the fixed host-package allowlist is managed here. Security severity is matched against the OSV
            advisory database for the installed package version; the distribution package index remains the
            authority for what can be installed. A package marked vulnerable with no newer candidate needs an
            updated distribution repository or an application image upgrade.
          </p>
        </Card>
      )}

      {output && (
        <Card title="Last update output">
          <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, margin: 0 }}>{output}</pre>
        </Card>
      )}

      <Card title="Application dependencies">
        <div className="bar-row">
          <div>WAF-Proxy binary</div>
          <div className="mono">v{snap.app_version || "?"}{snap.app_commit ? ` · ${snap.app_commit}` : ""}</div>
        </div>
        <div className="bar-row">
          <div>Go runtime used to build</div>
          <div className="mono">{snap.go_version || "—"}</div>
        </div>
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>Go modules and console dependencies</div>
          <div className="muted" style={{ fontSize: 12 }}>compiled into the binary</div>
        </div>
        <p className="muted" style={{ fontSize: 12, marginBottom: 0, lineHeight: 1.6 }}>
          Application modules are not changed on the host. Build or deploy a newer WAF-Proxy release to update
          them; this page deliberately cannot rebuild or replace the running binary.
        </p>
      </Card>
    </div>
  );
}
