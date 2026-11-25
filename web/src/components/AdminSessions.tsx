import { useEffect, useState } from "react";
import { api } from "../api";
import { confirmDialog, Badge, Card, Empty, errText, fmtAgo, fmtTime } from "../ui";

type AdminSession = {
  username: string;
  role: string;
  ip: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  current: boolean;
};

// The Admins tab lists every live console session. Expiry slides with activity,
// so the idle column also shows which browser has been quiet longest.
export default function AdminSessions({
  onError,
  onOK,
  onSignedOut,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  onSignedOut: () => void;
}) {
  const [rows, setRows] = useState<AdminSession[] | null>(null);

  const load = () => {
    api
      .get<{ sessions: AdminSession[] }>("/api/sessions")
      .then((r) => setRows(r.sessions ?? []))
      .catch((e) => onError(errText(e)));
  };

  useEffect(load, []);

  const logoutAll = async () => {
    if (!(await confirmDialog("Sign out every browser, including this one?"))) return;
    try {
      await api.post("/api/account/logout-all");
      onOK("Every administrator session was signed out");
      onSignedOut();
    } catch (e) {
      onError(errText(e));
    }
  };

  return (
    <Card
      title="Sessions"
      actions={<button className="small danger" onClick={logoutAll}>Sign out everywhere</button>}
      sub="Every live administrator session, on every browser and device."
    >
      {rows === null ? (
        <p className="muted">Loading…</p>
      ) : rows.length === 0 ? (
        <Empty>No administrator sessions are active.</Empty>
      ) : (
        <div className="table-wrap"><table>
          <thead>
            <tr><th>Administrator</th><th>Address</th><th>Browser</th><th>Signed in</th><th>Idle until</th></tr>
          </thead>
          <tbody>
            {rows.map((s, i) => (
              <tr key={`${s.username}-${s.ip}-${i}`}>
                <td>
                  {s.username} {s.current ? <Badge tone="ok">this browser</Badge> : <span className="faint">{s.role}</span>}
                </td>
                <td className="mono">{s.ip || "unknown"}</td>
                <td title={s.user_agent}>{s.user_agent ? s.user_agent.slice(0, 48) : "unknown"}</td>
                <td title={fmtTime(s.created_at)}>{fmtAgo(s.created_at)}</td>
                <td title={fmtTime(s.expires_at)}>{fmtAgo(s.expires_at)}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
      <p className="muted" style={{ fontSize: 12 }}>
        Password and authenticator rotations already revoke other browsers. Use “Sign out everywhere” when a
        device is lost or a session may be stolen.
      </p>
    </Card>
  );
}
