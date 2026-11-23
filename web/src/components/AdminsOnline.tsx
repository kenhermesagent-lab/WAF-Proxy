import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Modal, errText, fmtAgo, fmtTime } from "../ui";

type AdminSession = {
  username: string;
  role: string;
  ip: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  current: boolean;
};

// Signed in lists the live console sessions. Expiry slides with activity, so it
// also tells an operator which browser has been idle longest.
export default function AdminsOnline({ onClose, onError }: { onClose: () => void; onError: (m: string) => void }) {
  const [rows, setRows] = useState<AdminSession[] | null>(null);

  useEffect(() => {
    let live = true;
    api
      .get<{ sessions: AdminSession[] }>("/api/sessions")
      .then((r) => {
        if (live) setRows(r.sessions ?? []);
      })
      .catch((e) => {
        if (!live) return;
        onError(errText(e));
        onClose();
      });
    return () => {
      live = false;
    };
  }, []);

  return (
    <Modal title="Signed-in administrators" onClose={onClose} footer={<button onClick={onClose}>Close</button>}>
      {rows === null ? (
        <p className="muted">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted">No administrator sessions are active.</p>
      ) : (
        <>
          <p className="muted small-text" style={{ marginTop: 0 }}>
            {rows.length === 1 ? "1 administrator session is active." : `${rows.length} administrator sessions are active.`}
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Administrator</th>
                  <th>Address</th>
                  <th>Browser</th>
                  <th>Signed in</th>
                  <th>Idle until</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((s, i) => (
                  <tr key={`${s.username}-${s.ip}-${i}`}>
                    <td>
                      {s.username} {s.current ? <Badge tone="ok">this browser</Badge> : <span className="faint">{s.role}</span>}
                    </td>
                    <td>{s.ip || "unknown"}</td>
                    <td title={s.user_agent}>{s.user_agent ? s.user_agent.slice(0, 40) : "unknown"}</td>
                    <td title={fmtTime(s.created_at)}>{fmtAgo(s.created_at)}</td>
                    <td title={fmtTime(s.expires_at)}>{fmtAgo(s.expires_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Modal>
  );
}
