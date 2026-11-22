import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { countryFlag, countryName } from "../countries";
import type { IPDetail, IntelLookup } from "../types";
import { Badge, Drawer, Empty, Skeleton, confirmDialog, errText, fmtAgo, fmtTime } from "../ui";

const WINDOWS: [number, string][] = [
  [1, "1h"],
  [24, "24h"],
  [168, "7d"],
  [720, "30d"],
];

/**
 * Everything the console knows about one source address, in one place: traffic
 * totals, recent requests, threat-intel matches and the ban state. Every entry
 * point opens this same drawer so an operator never has to guess which page
 * owns a source.
 */
export default function SourceDrawer({
  ip,
  canWrite,
  onClose,
  onError,
  onOK,
}: {
  ip: string;
  canWrite: boolean;
  onClose: () => void;
  onError: (m: string) => void;
  onOK: (m: string) => void;
}) {
  const [hours, setHours] = useState(24);
  const [detail, setDetail] = useState<IPDetail | null>(null);
  const [intel, setIntel] = useState<IntelLookup | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState("Manual ban from source investigation");
  // Toasts are recreated on every App render; reading them through a ref keeps
  // the fetch from repeating whenever one appears.
  const handlers = useRef({ onError, onOK });
  handlers.current = { onError, onOK };

  const reload = (window = hours) =>
    api.get<IPDetail>(`/api/ips/${encodeURIComponent(ip)}?hours=${window}`).then(setDetail);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .get<IPDetail>(`/api/ips/${encodeURIComponent(ip)}?hours=${hours}`)
      .then((r) => {
        if (alive) setDetail(r);
      })
      .catch((e) => {
        if (alive) handlers.current.onError(errText(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [ip, hours]);

  // Intel is supplementary: a node with no feeds configured simply has none.
  useEffect(() => {
    let alive = true;
    setIntel(null);
    api
      .get<IntelLookup>(`/api/intel/lookup?ip=${encodeURIComponent(ip)}`)
      .then((r) => {
        if (alive) setIntel(r);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [ip]);

  const ban = async () => {
    const ok = await confirmDialog(
      `Every request from ${ip} will be refused for 24 hours. The ban is audited and can be released from here.`,
      { title: "Ban source", confirmLabel: "Ban 24h" },
    );
    if (!ok) return;
    setBusy(true);
    try {
      await api.post("/api/bans", {
        cidr: ip,
        reason: reason.trim() || "manual from console",
        permanent: false,
        ttl_seconds: 86400,
      });
      handlers.current.onOK(`${ip} banned for 24 hours`);
      await reload();
    } catch (e) {
      handlers.current.onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const unban = async () => {
    const id = detail?.summary.ban_id;
    if (!id) {
      handlers.current.onError("Ban id is unavailable; remove it from the Policies page");
      return;
    }
    if (!(await confirmDialog(`Release the ban on ${ip}?`, { title: "Release ban", confirmLabel: "Unban" }))) return;
    setBusy(true);
    try {
      await api.del(`/api/bans/${id}`);
      handlers.current.onOK(`${ip} unbanned`);
      await reload();
    } catch (e) {
      handlers.current.onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const s = detail?.summary;
  const banned = !!s?.banned;
  const windowLabel = WINDOWS.find(([h]) => h === hours)?.[1] ?? `${hours}h`;

  return (
    <Drawer
      title={<span className="mono">{ip}</span>}
      sub={
        s
          ? `${countryFlag(s.country) || "•"} ${countryName(s.country) || "Unknown"} · AS${s.asn || "?"} · last seen ${fmtAgo(s.last_seen)}`
          : "Source investigation"
      }
      onClose={onClose}
      footer={
        <>
          <div className="btn-group" style={{ marginRight: "auto" }}>
            {WINDOWS.map(([h, label]) => (
              <button
                key={h}
                className={`xsmall ${hours === h ? "primary" : ""}`}
                onClick={() => setHours(h)}
                aria-pressed={hours === h}
              >
                {label}
              </button>
            ))}
          </div>
          {canWrite && !banned && (
            <input
              aria-label="Ban reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Reason"
              style={{ maxWidth: 240 }}
            />
          )}
          {canWrite &&
            (banned ? (
              <button className="danger" onClick={unban} disabled={busy}>
                {busy ? "Working…" : "Release ban"}
              </button>
            ) : (
              <button className="danger" onClick={ban} disabled={busy}>
                {busy ? "Working…" : "Ban 24h"}
              </button>
            ))}
          <button onClick={onClose}>Close</button>
        </>
      }
    >
      {loading && !detail ? (
        <>
          <Skeleton kind="line" count={3} />
          <Skeleton kind="block" />
        </>
      ) : !s ? (
        <Empty title="Source unavailable" icon="search">
          This address has no stored events in the selected window.
        </Empty>
      ) : (
        <>
          <div className="grid cols-4 mb">
            <div className="stat">
              <div className="k">Requests</div>
              <div className="v">{s.requests.toLocaleString()}</div>
              <div className="sub">{windowLabel} window</div>
            </div>
            <div className="stat">
              <div className="k">Blocked</div>
              <div className="v">{s.blocked.toLocaleString()}</div>
              <div className="sub">{s.requests ? `${((s.blocked / s.requests) * 100).toFixed(0)}% of requests` : "—"}</div>
            </div>
            <div className="stat">
              <div className="k">Hosts</div>
              <div className="v">{s.hosts}</div>
              <div className="sub">distinct hostnames</div>
            </div>
            <div className="stat">
              <div className="k">Ban</div>
              <div className="v" style={{ fontSize: 13 }}>
                {banned ? <Badge tone="bad">{s.permanent ? "permanent" : "temporary"}</Badge> : <Badge tone="ok">clean</Badge>}
              </div>
              <div className="sub">{banned ? s.ban_reason || "no reason recorded" : "not banned"}</div>
            </div>
          </div>

          <div className="facts mb">
            <span>
              First seen <b>{fmtTime(s.first_seen)}</b>
            </span>
            <span>
              Last seen <b>{fmtTime(s.last_seen)}</b>
            </span>
            {banned && s.ban_expires ? (
              <span>
                Expires <b>{fmtTime(s.ban_expires)}</b>
              </span>
            ) : null}
            {banned && s.ban_source ? (
              <span>
                Source <b>{s.ban_source}</b>
              </span>
            ) : null}
          </div>

          {intel && (intel.feed || intel.ban) ? (
            <div className="grid" style={{ gap: 8, marginBottom: 14 }}>
              {intel.feed ? (
                <div className="banner warn" role="status">
                  <span>
                    Listed in feed <b>{intel.feed.name}</b> · action <b>{intel.feed.action}</b>
                  </span>
                </div>
              ) : null}
              {intel.ban ? (
                <div className="banner bad" role="status">
                  <span>
                    Intel ban on record: <b>{intel.ban.reason || "no reason"}</b> · {intel.ban.source}
                  </span>
                </div>
              ) : null}
            </div>
          ) : null}

          {detail.events.length === 0 ? (
            <Empty title="No requests in this window" icon="logs">
              Widen the window to see earlier requests from this address.
            </Empty>
          ) : (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Request</th>
                      <th className="hide-tablet">Host</th>
                      <th>Stage</th>
                      <th className="num">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.events.map((e) => (
                      <tr key={e.id}>
                        <td className="muted" style={{ whiteSpace: "nowrap" }} title={fmtTime(e.ts)}>
                          {fmtAgo(e.ts)}
                        </td>
                        <td
                          className="mono"
                          style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                          title={`${e.method} ${e.path}`}
                        >
                          {e.method} {e.path}
                        </td>
                        <td className="muted hide-tablet">{e.host}</td>
                        <td>
                          <Badge tone={e.action === "allow" ? "" : e.action === "log" ? "info" : "bad"}>{e.stage || "—"}</Badge>
                        </td>
                        <td className="num">{e.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="muted" style={{ fontSize: 12 }}>
                Showing the newest {detail.events.length} of {detail.total.toLocaleString()} matching events.
              </p>
            </>
          )}
        </>
      )}
    </Drawer>
  );
}
