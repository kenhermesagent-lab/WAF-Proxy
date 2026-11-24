import { useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, Info, errText, fmtAgo, fmtTime, PageHead } from "../ui";
import type { UpdatePackage, UpdatesSnapshot } from "../types";
import AutoUpdateCard from "../components/AutoUpdateCard";

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
  head = true,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  head?: boolean;
}) {
  const [snap, setSnap] = useState<UpdatesSnapshot | null>(null);
  const [loadError, setLoadError] = useState("");
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [appOutput, setAppOutput] = useState("");
  const [sourceDir, setSourceDir] = useState("");
  const [savingDir, setSavingDir] = useState(false);
  const [output, setOutput] = useState("");

  const load = () =>
    api
      .get<UpdatesSnapshot>("/api/updates")
      .then((v) => {
        setSnap(v);
        setSourceDir(v.app_source_dir || "");
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
      onOK("Update check refreshed");
    } catch (e) {
      onError(errText(e));
    } finally {
      setChecking(false);
    }
  };

  const waitForAppUpdate = async (target: string) => {
    for (let i = 0; i < 800; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      let st: { updating: boolean; error?: string; output?: string };
      try {
        st = await api.get<{ updating: boolean; error?: string; output?: string }>("/api/updates/app");
      } catch {
        // Docker recreates this container; wait for the new one to listen.
        continue;
      }
      if (st.output) setAppOutput(st.output);
      if (st.updating) continue;
      if (st.error) {
        onError(st.error);
        await load();
        return;
      }
      if (!target) {
        await new Promise((r) => setTimeout(r, 2000));
        await load();
        onOK("Update applied");
        return;
      }
      try {
        const v = await api.get<{ commit: string }>("/api/version");
        if (v.commit && (target.startsWith(v.commit) || v.commit.startsWith(target))) {
          await load();
          onOK("Update applied");
          return;
        }
      } catch {
        // The service is between the old and new process.
      }
    }
    onError(
      "The update did not finish in time. Check Last update output below, or run the manual steps on the host: sudo journalctl -u wafproxy-updates -n 80",
    );
  };

  const applyApp = async () => {
    if (!snap) return;
    if (!(await confirmDialog("Pull the tracked branch, rebuild the application, then restart or recreate WAF-Proxy? The console will be unavailable for a short time."))) return;
    setApplying(true);
    setAppOutput("");
    const target = (snap.app_remote_commit || "").slice(0, 12);
    try {
      await api.post("/api/updates/app");
      onOK(snap.container ? "Rebuilding the image and recreating the container" : "Rebuilding; the service will restart when it finishes");
      await waitForAppUpdate(target);
    } catch (e) {
      onError(errText(e));
      await load();
    } finally {
      setApplying(false);
    }
  };

  const saveSourceDir = async () => {
    const path = sourceDir.trim();
    if (!path) return;
    setSavingDir(true);
    try {
      const next = await api.post<UpdatesSnapshot>("/api/updates/app/config", { path });
      setSnap(next);
      setSourceDir(next.app_source_dir || path);
      onOK(
        next.app_update_supported
          ? "Repository directory recorded; the Update button is now available"
          : next.app_update_reason || "Repository directory recorded",
      );
    } catch (e) {
      onError(errText(e));
    } finally {
      setSavingDir(false);
    }
  };

  const apply = async (p: UpdatePackage) => {
    if (!(await confirmDialog(`Update ${p.name} from ${p.current || "the installed version"} to ${p.candidate}?`))) return;
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
  const busy = checking || updating !== null || applying || snap.updating || snap.app_updating;

  return (
    <div className="grid" style={{ gap: 14 }}>
      {head && <PageHead sub="Console and host package versions, with the restart that applies a rebuild." />}
      <Card
        title="WAF-Proxy application"
        actions={
          <>
            <button className="small" onClick={check} disabled={busy}>
              {checking ? "Checking…" : "Check for updates"}
            </button>
            {snap.app_update_available && snap.app_update_supported ? (
              <button className="small primary" onClick={applyApp} disabled={busy}>
                {applying
                  ? "Rebuilding and restarting…"
                  : snap.app_remote_version
                    ? `Update to v${snap.app_remote_version}`
                    : "Update application"}
              </button>
            ) : null}
          </>
        }
      >
        <div className="bar-row">
          <div>Running</div>
          <div className="mono">v{snap.app_version || "?"}{snap.app_commit ? ` · ${snap.app_commit}` : ""}</div>
        </div>
        <div className="bar-row">
          <div>Repository {snap.app_remote_branch || "branch"}</div>
          <div className="mono">
            {snap.app_remote_version ? `v${snap.app_remote_version}` : "—"}
            {snap.app_remote_commit ? ` · ${snap.app_remote_commit.slice(0, 12)}` : ""}
          </div>
        </div>
        <div className="bar-row" style={{ borderBottom: 0 }}>
          <div>Status</div>
          <div>
            {snap.app_update_available ? (
              <Badge tone="warn">
                update available{snap.app_remote_version ? ` · v${snap.app_remote_version}` : ""}
              </Badge>
            ) : snap.app_update_error ? (
              <Badge tone="bad">check failed</Badge>
            ) : (
              <Badge tone="ok">up to date</Badge>
            )}
          </div>
        </div>
        {snap.app_last_update && (
          <div className="bar-row" style={{ borderBottom: 0 }}>
            <div style={{ whiteSpace: "nowrap" }}>Last update</div>
            <div>
              <Badge tone={snap.app_last_update.status === "ok" ? "ok" : "bad"}>
                {snap.app_last_update.status === "ok" ? "installed" : "failed"}
              </Badge>{" "}
              <span className="muted" style={{ fontSize: 12 }}>
                {snap.app_last_update.message}
                {snap.app_last_update.at ? ` · ${fmtTime(snap.app_last_update.at)}` : ""}
              </span>
            </div>
          </div>
        )}
        {snap.app_remote_date && (
          <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
            Latest commit {fmtAgo(snap.app_remote_date)} on {snap.app_remote_branch || "the tracked branch"}
            {snap.app_remote_url?.startsWith("http") ? <> · <a href={snap.app_remote_url} target="_blank" rel="noreferrer">view commit</a></> : null}
          </p>
        )}
        {!snap.app_update_supported && (
          <div style={{ borderLeft: "2px solid #8a6d1d", paddingLeft: 10, marginTop: 10 }}>
            <p style={{ fontSize: 13, margin: "0 0 4px" }}>
              <strong>
                {snap.app_update_available
                  ? "The Update button is unavailable on this host."
                  : "Automatic application updates are not set up on this host."}
              </strong>
            </p>
            <p className="muted" style={{ fontSize: 12, lineHeight: 1.7, margin: "0 0 8px" }}>
              {snap.app_update_reason || "This deployment cannot rebuild itself."}
              {!snap.helper_ready
                ? " To enable the button, install the root helper once from the git checkout: sudo ./deploy/install.sh, then reload this page."
                : null}
            </p>
            {!snap.container && snap.helper_ready && (
              <>
                <label
                  htmlFor="app-source-dir"
                  className="muted"
                  style={{ fontSize: 12, display: "block", marginBottom: 4 }}
                >
                  WAF-Proxy checkout directory on this host
                </label>
                <div className="row" style={{ gap: 8, marginBottom: 4 }}>
                  <input
                    id="app-source-dir"
                    value={sourceDir}
                    onChange={(e) => setSourceDir(e.target.value)}
                    placeholder="/var/lib/waf-proxy/src"
                    disabled={savingDir}
                    style={{ flex: 1 }}
                  />
                  <button className="small" onClick={saveSourceDir} disabled={savingDir || !sourceDir.trim()}>
                    {savingDir ? "Saving…" : "Use this directory"}
                  </button>
                </div>
                <p className="muted" style={{ fontSize: 11.5, lineHeight: 1.6, margin: "0 0 8px" }}>
                  The root helper only records this path and rebuilds that checkout. It must be a git checkout
                  of WAF-Proxy with an origin remote, and the installed update scripts must come from
                  install.sh: re-run <code>sudo ./deploy/install.sh</code> if the page says they are missing.
                  The default is the root-owned checkout at <code>/var/lib/waf-proxy/src</code>.
                </p>
              </>
            )}
            {snap.app_update_available && (
              <>
                <p className="muted" style={{ fontSize: 12, margin: "0 0 4px" }}>
                  Manual fallback, until the button is available:
                </p>
                {snap.container ? (
                  <p className="muted" style={{ fontSize: 12, lineHeight: 1.7, margin: 0 }}>
                    On the host run <code>git checkout -- internal/webui/dist</code>,{" "}
                    <code>git pull --ff-only</code>, then{" "}
                    <code>docker compose -f deploy/docker-compose.yml up -d --build</code>.
                  </p>
                ) : (
                  <pre
                    className="mono"
                    style={{ fontSize: 12, margin: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
                  >{`cd /var/lib/waf-proxy/src\nsudo git checkout -- internal/webui/dist\nsudo git clean -fdq internal/webui/dist\nsudo git pull --ff-only\nsudo ./deploy/wafproxy-self-update.sh`}</pre>
                )}
              </>
            )}
          </div>
        )}
        {snap.app_update_supported && snap.app_update_available && (
          <p className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
            {snap.container
              ? "The host helper pulls the recorded checkout as its owner, rebuilds the image and recreates the wafproxy container. The named data volume is preserved."
              : "The privileged helper pulls the recorded checkout, rebuilds the console and both Go binaries, refreshes the bundled helper scripts, installs them into /var/lib/waf-proxy and restarts the service. Data in /var/lib/waf-proxy/data is not touched."}
          </p>
        )}
        {snap.app_update_error && (
          <p className="muted" style={{ fontSize: 12, borderLeft: "2px solid #8a6d1d", paddingLeft: 10 }}>
            The latest version could not be checked, so the installed version is shown instead.{" "}
            <Info label="Repository check detail">{snap.app_update_error}</Info>
          </p>
        )}
      </Card>

      <Card
        title="Host updates"
        actions={
          <button className="small" onClick={check} disabled={busy}>
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
                {snap.platform || "Debian/Ubuntu"} · checked {snap.checked_at ? fmtAgo(snap.checked_at) : "not yet"} · refreshed daily
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

      <AutoUpdateCard onError={onError} onOK={onOK} />

      {snap.available && (
        <Card title="Managed host packages">
          {snap.packages.length === 0 ? (
            <Empty>No managed packages were found.</Empty>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <div className="table-wrap"><table className="packages-table">
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
              </table></div>
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

      {(output || appOutput) && (
        <Card title="Last update output">
          <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12, margin: 0 }}>{[appOutput, output].filter(Boolean).join("\n")}</pre>
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
          Native installs can apply the application update above through the fixed root helper. Docker installs
          rebuild from the host with <code>docker compose up -d --build</code>, because the runtime image has no
          build toolchain or Docker socket.
        </p>
      </Card>
    </div>
  );
}
