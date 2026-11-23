import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Badge, Card, Drawer, Empty, Field, PageHead, Skeleton, confirmDialog, errText, fmtAgo, fmtTime } from "../ui";
import { can } from "../types";
import type { AuditEntry, AuditSnapshot } from "../types";

const ENTITY_AREAS: Record<string, string> = {
  proxy: "proxies",
  policy: "policies",
  profile: "policies",
  protection_profile: "policies",
  access_profile: "policies",
  access_list: "policies",
};

type Loaded = { entry: AuditEntry; snapshot: AuditSnapshot | null };

// A proxy snapshot wraps the row and its children; the other entities are flat.
function flatten(raw?: string): Record<string, unknown> {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (parsed && typeof parsed === "object" && "proxy" in parsed) {
      return {
        ...(parsed.proxy as Record<string, unknown>),
        upstreams: parsed.upstreams ?? [],
        routes: parsed.routes ?? [],
      };
    }
    return parsed;
  } catch {
    return {};
  }
}

function show(value: unknown): string {
  if (value === undefined || value === null || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function diffFields(before?: string, after?: string): { field: string; from: string; to: string }[] {
  const a = flatten(before);
  const b = flatten(after);
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  const out = [];
  for (const key of keys) {
    const from = JSON.stringify(a[key] ?? null);
    const to = JSON.stringify(b[key] ?? null);
    if (from !== to) out.push({ field: key, from: show(a[key]), to: show(b[key]) });
  }
  return out;
}

export default function Activity({
  onError,
  onOK,
  permissions,
}: {
  onError: (m: string) => void;
  onOK: (m: string) => void;
  permissions: string[];
}) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [actor, setActor] = useState("");
  const [family, setFamily] = useState("");
  const [hours, setHours] = useState("24");
  const [open, setOpen] = useState<Loaded | null>(null);
  const [opening, setOpening] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      setEntries((await api.get<AuditEntry[]>("/api/audit")) ?? []);
    } catch (e) {
      onError(errText(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const families = useMemo(
    () => [...new Set(entries.map((e) => e.action.split(".")[0]))].sort(),
    [entries],
  );

  const visible = useMemo(() => {
    const needle = actor.trim().toLowerCase();
    const since = Date.now() - Number(hours) * 3600000;
    return entries.filter((e) => {
      if (needle && !e.user.toLowerCase().includes(needle)) return false;
      if (family && !e.action.startsWith(family + ".")) return false;
      return Date.parse(e.ts) >= since;
    });
  }, [actor, entries, family, hours]);

  const openEntry = async (entry: AuditEntry) => {
    setOpening(true);
    try {
      setOpen(await api.get<Loaded>(`/api/audit/${entry.id}`));
    } catch (e) {
      onError(errText(e));
    } finally {
      setOpening(false);
    }
  };

  const rollback = async () => {
    if (!open) return;
    const ok = await confirmDialog(
      `Restore the previous state of this ${open.snapshot?.entity.replace("_", " ")}? The rollback is recorded as a new entry.`,
      { title: "Roll back this change", confirmLabel: "Roll back" },
    );
    if (!ok) return;
    setBusy(true);
    try {
      await api.post(`/api/audit/${open.entry.id}/rollback`);
      onOK("Change rolled back");
      setOpen(null);
      await load();
    } catch (e) {
      onError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const snap = open?.snapshot;
  const changes = snap ? diffFields(snap.before, snap.after) : [];
  const canRollback =
    !!snap?.before && !!snap?.after && !!ENTITY_AREAS[snap.entity] && can(permissions, `${ENTITY_AREAS[snap.entity]}.write`);

  return (
    <div className="grid" style={{ gap: 14 }}>
      <PageHead
        title="Activity"
        sub="Every administrator action, with what it changed. The newest 200 entries are shown."
        actions={<button className="small" onClick={load} disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>}
      />

      <Card title="Filters">
        <div className="row grow">
          <Field label="Actor">
            <input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="alice" />
          </Field>
          <Field label="Area">
            <select value={family} onChange={(e) => setFamily(e.target.value)}>
              <option value="">any</option>
              {families.map((f) => <option key={f} value={f}>{f}</option>)}
            </select>
          </Field>
          <Field label="Window">
            <select value={hours} onChange={(e) => setHours(e.target.value)}>
              <option value="24">24 hours</option>
              <option value="168">7 days</option>
              <option value="720">30 days</option>
              <option value="8760">1 year</option>
            </select>
          </Field>
        </div>
      </Card>

      <Card title={`Entries (${visible.length})`}>
        {loading && entries.length === 0 ? (
          <Skeleton kind="line" count={6} />
        ) : visible.length === 0 ? (
          <Empty title="No matching entries" icon="clock">
            Widen the window or clear the actor filter.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th className="hide-tablet">Detail</th>
                  <th className="hide-tablet">From</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {visible.map((e) => (
                  <tr key={e.id}>
                    <td className="muted" style={{ whiteSpace: "nowrap" }} title={fmtTime(e.ts)}>{fmtAgo(e.ts)}</td>
                    <td>{e.user || "system"}</td>
                    <td><Badge tone={e.action.endsWith(".rollback") ? "warn" : e.entity ? "info" : ""}>{e.action}</Badge></td>
                    <td className="muted hide-tablet" style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.detail}>{e.detail || "—"}</td>
                    <td className="mono hide-tablet" style={{ fontSize: 11.5 }}>{e.ip || "—"}</td>
                    <td className="right" style={{ whiteSpace: "nowrap" }}>
                      {e.entity ? (
                        <button className="small" onClick={() => openEntry(e)} disabled={opening}>Changes</button>
                      ) : (
                        <span className="faint small-text">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {open && (
        <Drawer
          title={`${open.entry.action} · ${open.entry.user || "system"}`}
          sub={`${fmtTime(open.entry.ts)} · ${open.entry.ip || "unknown address"}`}
          onClose={() => setOpen(null)}
          footer={
            <>
              {canRollback ? (
                <button className="danger" onClick={rollback} disabled={busy}>
                  {busy ? "Rolling back…" : "Roll back"}
                </button>
              ) : null}
              <button onClick={() => setOpen(null)}>Close</button>
            </>
          }
        >
          {!snap ? (
            <Empty title="No stored state" icon="file">
              This action predates change tracking or does not modify an entity.
            </Empty>
          ) : (
            <>
              <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
                {snap.entity.replace("_", " ")} #{snap.entity_id}
                {!snap.before ? " · created by this action" : !snap.after ? " · removed by this action" : ""}
              </p>
              {!snap.after ? (
                <div className="banner warn" role="status">
                  <span>Rollback restores edits. Recreate this {snap.entity.replace("_", " ")} from its page.</span>
                </div>
              ) : null}
              {changes.length === 0 ? (
                <Empty title="Nothing changed" icon="check">
                  The saved state matches the recorded change.
                </Empty>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr><th>Field</th><th>Before</th><th>After</th></tr>
                    </thead>
                    <tbody>
                      {changes.map((c) => (
                        <tr key={c.field}>
                          <td className="mono" style={{ fontSize: 11.5 }}>{c.field}</td>
                          <td className="muted" style={{ overflowWrap: "anywhere" }}>{c.from}</td>
                          <td style={{ overflowWrap: "anywhere" }}>{c.to}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </Drawer>
      )}
    </div>
  );
}
