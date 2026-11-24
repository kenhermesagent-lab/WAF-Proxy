import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Field, errText, fmtTime } from "../ui";

type Config = {
  enabled: boolean;
  transport: string;
  schedule: string;
  time: string;
  weekday: number;
  keep: number;
  daily_enabled: boolean;
  daily_time: string;
  daily_keep: number;
  local_dir: string;
  git_dir: string;
  git_remote: string;
  git_branch: string;
  host: string;
  port: number;
  user: string;
  dir: string;
  host_key: string;
  password?: string;
  has_password: boolean;
  encrypt: boolean;
  passphrase?: string;
  has_passphrase: boolean;
};

type Status = {
  last_run?: string;
  last_error?: string;
  last_file?: string;
  last_target?: string;
  next_run?: string;
  last_daily_run?: string;
  last_daily_file?: string;
  next_daily_run?: string;
};

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

export default function BackupCard({ onError, onOK }: { onError: (m: string) => void; onOK: (m: string) => void }) {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [status, setStatus] = useState<Status>({});
  const [password, setPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);

  const load = () =>
    api
      .get<{ config: Config; status: Status }>("/api/backup/schedule")
      .then((r) => {
        setCfg({ ...r.config, password: "" });
        setStatus(r.status);
      })
      .catch((e) => onError(errText(e)));

  useEffect(() => {
    load();
  }, []);

  const set = (patch: Partial<Config>) => setCfg((c) => (c ? { ...c, ...patch } : c));

  const save = async () => {
    if (!cfg) return;
    setSaving(true);
    try {
      const body = { ...cfg, password: password || undefined, passphrase: passphrase || undefined };
      const r = await api.put<{ config: Config; status: Status }>("/api/backup/schedule", body);
      setCfg({ ...r.config, password: "" });
      setStatus(r.status);
      setPassword("");
      setPassphrase("");
      onOK("Backup schedule saved");
    } catch (e) {
      onError(errText(e));
    } finally {
      setSaving(false);
    }
  };

  const runNow = async () => {
    setRunning(true);
    try {
      const r = await api.post<{ status: Status }>("/api/backup/schedule/run");
      setStatus(r.status);
      onOK("Backup written");
    } catch (e) {
      onError(errText(e));
    } finally {
      setRunning(false);
    }
  };

  const remote = cfg?.transport === "sftp" || cfg?.transport === "ftp";

  return (
    <Card
      title="Backup schedule"
      actions={
        <div className="row">
          <button className="small" onClick={runNow} disabled={running || !cfg}>{running ? "Writing…" : "Back up now"}</button>
          <button className="small primary" onClick={save} disabled={saving || !cfg}>{saving ? "Saving…" : "Save"}</button>
        </div>
      }
    >
      {!cfg ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          <div className="row grow">
            <label style={{ margin: "18px 0 0", display: "flex", gap: 6, alignItems: "center", textTransform: "none", letterSpacing: 0 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> scheduled
            </label>
            <Field label="Destination">
              <select value={cfg.transport} onChange={(e) => set({ transport: e.target.value })}>
                <option value="local">Local directory</option>
                <option value="git">Git repository</option>
                <option value="sftp">SFTP (over SSH)</option>
                <option value="ftp">FTP (unencrypted)</option>
              </select>
            </Field>
            <Field label="Schedule">
              <select value={cfg.schedule} onChange={(e) => set({ schedule: e.target.value })}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </Field>
            {cfg.schedule === "weekly" && (
              <Field label="Day">
                <select value={cfg.weekday} onChange={(e) => set({ weekday: Number(e.target.value) })}>
                  {WEEKDAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
                </select>
              </Field>
            )}
            <Field label="Time (HH:MM)">
              <input value={cfg.time} onChange={(e) => set({ time: e.target.value })} placeholder="03:00" />
            </Field>
            <Field label="Keep (copies)">
              <input type="number" min={1} max={365} value={cfg.keep} onChange={(e) => set({ keep: Number(e.target.value) })} />
            </Field>
          </div>

          <div className="bar-row">
            <div>
              Daily copies <span className="faint small-text">an extra, complete copy every day, kept separately from the
              {cfg.schedule} copies above</span>
            </div>
            <div>
              <input
                type="checkbox"
                aria-label="Daily copies"
                style={{ width: "auto" }}
                checked={cfg.daily_enabled}
                onChange={(e) => set({ daily_enabled: e.target.checked })}
              />
            </div>
          </div>
          {cfg.daily_enabled && (
            <div className="row grow">
              <Field label="Daily time (HH:MM)">
                <input value={cfg.daily_time} onChange={(e) => set({ daily_time: e.target.value })} />
              </Field>
              <Field label="Daily copies to keep">
                <input type="number" min={1} max={365} value={cfg.daily_keep} onChange={(e) => set({ daily_keep: Number(e.target.value) })} />
              </Field>
            </div>
          )}
          {cfg.daily_enabled && (
            <p className="faint small-text">
              Daily files (<span className="mono">wafproxy-daily-…</span>) prune by their own count, so an expired daily copy never
              deletes a {cfg.schedule} one. Both still run on a day the times coincide.
            </p>
          )}

          {cfg.transport === "local" && (
            <Field label="Directory (absolute, on this host)">
              <input value={cfg.local_dir} onChange={(e) => set({ local_dir: e.target.value })} placeholder="/var/lib/waf-proxy/data/backups" />
            </Field>
          )}

          {cfg.transport === "git" && (
            <>
              <Field label="Git working directory (absolute)">
                <input value={cfg.git_dir} onChange={(e) => set({ git_dir: e.target.value })} placeholder="/srv/wafproxy-backups" />
              </Field>
              <div className="row grow">
                <Field label="Push to remote (optional)">
                  <input value={cfg.git_remote} onChange={(e) => set({ git_remote: e.target.value })} placeholder="origin" />
                </Field>
                <Field label="Remote branch">
                  <input value={cfg.git_branch} onChange={(e) => set({ git_branch: e.target.value })} placeholder="main" />
                </Field>
              </div>
            </>
          )}

          {remote && cfg && (
            <>
              {cfg.transport === "ftp" && (
                <p className="muted" style={{ fontSize: 12 }}>
                  <Badge tone="warn">unencrypted</Badge> FTP sends the archive and the password in clear text. Use SFTP
                  unless the destination only offers FTP.
                </p>
              )}
              <div className="row grow">
                <Field label="Host">
                  <input value={cfg.host} onChange={(e) => set({ host: e.target.value })} placeholder="backup.example.com" />
                </Field>
                <Field label="Port">
                  <input type="number" min={1} max={65535} value={cfg.port} onChange={(e) => set({ port: Number(e.target.value) })} />
                </Field>
                <Field label="User">
                  <input value={cfg.user} onChange={(e) => set({ user: e.target.value })} />
                </Field>
              </div>
              <div className="row grow">
                <Field label="Remote directory">
                  <input value={cfg.dir} onChange={(e) => set({ dir: e.target.value })} placeholder="/backups/wafproxy" />
                </Field>
                <Field label={cfg.has_password ? "Password (leave blank to keep)" : "Password"}>
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </Field>
              </div>
              {cfg.transport === "sftp" && (
                <Field label="SSH host key fingerprint (SHA256)">
                  <input
                    value={cfg.host_key}
                    onChange={(e) => set({ host_key: e.target.value })}
                    placeholder="ssh-keyscan -t ed25519 host | ssh-keygen -lf -"
                  />
                </Field>
              )}
            </>
          )}

          <div className="bar-row">
            <div>Encrypt backups <span className="faint small-text">AES-256-GCM, restoring needs the same passphrase</span></div>
            <div>
              <input
                type="checkbox"
                aria-label="Encrypt backups"
                style={{ width: "auto" }}
                checked={cfg.encrypt}
                onChange={(e) => set({ encrypt: e.target.checked })}
              />
            </div>
          </div>
          {cfg.encrypt && (
            <Field label={cfg.has_passphrase ? "Passphrase (leave blank to keep)" : "Passphrase (16+ characters)"}>
              <input
                type="password"
                minLength={16}
                placeholder="At least 16 characters"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
              />
            </Field>
          )}
          {cfg.encrypt && (
            <p className="faint small-text">
              Lose the passphrase and the files cannot be opened.
            </p>
          )}

          <div className="bar-row" style={{ borderBottom: 0 }}>
            <div>Last run</div>
            <div className="muted">
              {status.last_run ? fmtTime(status.last_run) : "never"}
              {status.last_file && <span className="mono"> · {status.last_file}</span>}
            </div>
          </div>
          <div className="bar-row" style={{ borderBottom: 0 }}>
            <div>Next run</div>
            <div className="muted">{status.next_run ? fmtTime(status.next_run) : "not scheduled"}</div>
          </div>
          {cfg.daily_enabled && (
            <>
              <div className="bar-row" style={{ borderBottom: 0 }}>
                <div>Last daily copy</div>
                <div className="muted">
                  {status.last_daily_run ? fmtTime(status.last_daily_run) : "never"}
                  {status.last_daily_file && <span className="mono"> · {status.last_daily_file}</span>}
                </div>
              </div>
              <div className="bar-row" style={{ borderBottom: 0 }}>
                <div>Next daily copy</div>
                <div className="muted">{status.next_daily_run ? fmtTime(status.next_daily_run) : "not scheduled"}</div>
              </div>
            </>
          )}
          {status.last_error && <p className="err-text" style={{ fontSize: 12 }}>{status.last_error}</p>}
        </>
      )}
    </Card>
  );
}
